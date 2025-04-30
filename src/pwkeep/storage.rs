use std::{error, fmt, fs};
use std::path::{Path, PathBuf};
use pkcs8::{EncryptedPrivateKeyInfo, PrivateKeyInfo};
use pem::parse;
use std::error::Error;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use sha2::Sha512;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use hkdf::Hkdf;
use pkcs8::rand_core::OsRng;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};


#[derive(Debug, Clone)]
struct KeyLoadError {
    error: String,
}


impl fmt::Display for KeyLoadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Cannot load pem key: {}", self.error)
    }
}


impl From<pkcs8::Error> for KeyLoadError {
    fn from(item: pkcs8::Error) -> Self {
        KeyLoadError {
            error: item.to_string(),
        }
    }
}

impl error::Error for KeyLoadError {}


#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedEntry {
    pub algorithm: String,
    pub mac: String,
    pub rounds: u32,
    pub public_key: [u8; 32],
    pub salt: [u8; 16],
    pub content: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Entry {
    pub last_edit: DateTime<Utc>,
    pub name: String,
    pub content: String,
}

impl Entry {
    pub fn new(name: &str) -> Self {
        Entry {
            last_edit: Utc::now(),
            name: name.to_string(),
            content: String::new(),
        }
    }
}

#[derive(Debug)]
pub struct Storage<> {
   pub home: PathBuf,
   keypair: Option<Vec<u8>>,
}

impl Storage {
    pub fn new(home: &Path) -> Storage {
        Storage {home: home.to_path_buf(), keypair: None}
    }

    pub fn loaded(&self) -> bool {
        !self.keypair.is_none()
    }

    fn hash_value(&self, salt: Option<&[u8]>, input: &[u8], iter: u32, bytes: usize) -> Vec<u8> {
        let mut hash_bytes = Vec::from(input);
        for i in 0..iter {
            let hk = Hkdf::<Sha512>::new(salt, hash_bytes.as_slice());
            let mut hashed = vec![0; bytes];
            match hk.expand(i.to_be_bytes().as_slice(), &mut hashed) {
                Ok(_) => {}
                Err(e) => { panic!("{e}"); }
            };
            hash_bytes = Vec::from(hashed);
        }
        return hash_bytes;
    }

    fn name_to_path(&self, name: &str) -> Result<PathBuf, Box<dyn Error>> {
        let Some(ref key_bytes) = self.keypair else { panic!("Missing keypair") };
        let name_bytes = self.hash_value(Some(key_bytes.as_slice()), name.as_bytes(), 6_000, 60);

        /* base64 encode */
        let mut b = PathBuf::from(self.home.as_path());
        b.push("system-".to_owned() + &URL_SAFE.encode(name_bytes));
        Ok(b)
    }

    fn encrypt(&self, content: Vec<u8>) -> Vec<u8> {
        let Some(ref key_bytes) = self.keypair else { panic!("Missing keypair") };
        let private_key_info = PrivateKeyInfo::try_from(key_bytes.as_slice()).expect("Cannot load private key");
        let sk_array: [u8; 32] = private_key_info.private_key[2..34].try_into().expect("Not X25519 key?");
        let sk = StaticSecret::from(sk_array);
        let public_key = PublicKey::from(&sk);
        let eph_secret = EphemeralSecret::random_from_rng(OsRng);

        let mut encrypted_entry = EncryptedEntry {
            algorithm: "ChaCha20".to_string(),
            mac: "Poly1305".to_string(),
            rounds: 10_000,
            public_key: [0u8; 32],
            salt: [0u8; 16],
            content: Vec::new(),
        };
        rand::fill(&mut encrypted_entry.salt);
        encrypted_entry.public_key = PublicKey::from(&eph_secret).to_bytes();

        // create shared key
        let shared_secret = eph_secret.diffie_hellman(&public_key);
        let key_material = self.hash_value(Some(encrypted_entry.salt.as_slice()), shared_secret.as_bytes(), encrypted_entry.rounds, 12+32);
        let nonce = Nonce::from_slice(&key_material[0..12]);
        let key = Key::from_slice(&key_material[12..44]);
        let cipher = ChaCha20Poly1305::new(key);
        let entry_bytes = content;
        let ciphertext = cipher.encrypt(nonce, entry_bytes.as_ref()).expect("Encryption failed");
        encrypted_entry.content = Vec::from(ciphertext);
        serde_cbor::to_vec(&encrypted_entry).expect("CBOR data")
    }

    fn decrypt(&self, content: Vec<u8>) -> Vec<u8> {
        let encrypted_entry: EncryptedEntry = serde_cbor::from_slice(&content).expect("Encrypted entry");

        /* Decode data */
        let Some(ref key_bytes) = self.keypair else { panic!("Missing keypair") };
        let private_key_info = PrivateKeyInfo::try_from(key_bytes.as_slice()).expect("Cannot load private key");
        let sk_array: [u8; 32] = private_key_info.private_key[2..34].try_into().expect("Not X25519 key?");
        let sk = StaticSecret::from(sk_array);
        let pk = PublicKey::from(encrypted_entry.public_key);
        let shared_secret = sk.diffie_hellman(&pk);
        let key_material = self.hash_value(Some(encrypted_entry.salt.as_slice()), shared_secret.as_bytes(), encrypted_entry.rounds, 12+32);
        let nonce = Nonce::from_slice(&key_material[0..12]);
        let key = Key::from_slice(&key_material[12..44]);
        let cipher = ChaCha20Poly1305::new(key);
        cipher.decrypt(nonce, encrypted_entry.content.as_ref()).expect("Encryption failed")
    }


    pub fn set_entry(&self, name: &str, content: String) -> Result<(), Box<dyn Error>> {
        let path = self.name_to_path(name)?;

        let entry = Entry {
            last_edit: Utc::now(),
            name: name.to_string(),
            content: content,
        };

        let cbor_data = self.encrypt(serde_cbor::to_vec(&entry)?);
        fs::write(path.as_path(), &cbor_data)?;

        /* update index */
        let mut index = self.load_index()?;
        match index.binary_search(&name.to_string()) {
            Ok(_) => {},
            _ => {
                index.push(name.to_string());
                index.sort();
                match self.save_index(index) {
                    Ok(_) => {},
                    Err(e) => { panic!("{e}") },
                }
            }
        }
        Ok(())
    }

    pub fn get_entry(&self, name: &str) -> Result<Entry, Box<dyn Error>> {
        let path = self.name_to_path(name)?;
        let data = fs::read(path.as_path())?;
        let plaintext = self.decrypt(data);

        let entry: Entry = serde_cbor::from_slice(&plaintext)?;
        Ok(entry)
    }

    pub fn delete_entry(&self, name: &str) -> Result<(), Box<dyn Error>> {
        let path = self.name_to_path(name)?;
        fs::remove_file(path.as_path())?;
        Ok(())
    }

    pub fn load_index(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let path = self.home.join(".index");

        if path.as_path().exists() == false {
            return Ok(Vec::<String>::new());
        }

        let data = fs::read(path.as_path())?;
        let plaintext = self.decrypt(data);

        Ok(serde_cbor::from_slice(&plaintext)?)
    }

    fn save_index(&self, index: Vec<String>) -> Result<(), Box<dyn Error>> {
        let path = self.home.join(".index");
        let data = serde_cbor::to_vec(&index)?;
        let ciphertext = self.encrypt(data);

        Ok(fs::write(path, ciphertext)?)
    }

    pub fn load(&mut self, password: String) -> Result<(), Box<dyn Error>> {
        let private_key_path = self.home.join("private.pem");

        // try load key
        let pem_data = fs::read_to_string(private_key_path.as_path())?;
        let pem = parse(pem_data)?;
        Ok(EncryptedPrivateKeyInfo::try_from(pem.contents()).or_else(|e| Err(KeyLoadError::from(e)))
            .and_then(|key| {
                key.decrypt(password).or_else(|e| Err(KeyLoadError::from(e)))
                    .and_then(|secret_doc| {
                        self.keypair = Some(secret_doc.as_bytes().to_vec());
                        Ok(())
                    })
            })?)
    }
}
