PassWord Keep (pwkeep)
======================
Simple password storage system. 

Quick start guide
=================

To initialize, create $XDG\_DATA\_HOME/pwkeep (defaults to ~/.local/share/pwkeep on my system)
Run `openssl genpkey -algorithm X25519 -aes-256-cbc -out ~/.local/share/pwkeep/private.pem` to generate encryption key.

If you want to place it somewhere else, set $XDG\_DATA\_HOME environment variable, or use -H (--home) parameter when running pwkeep. 

To add credentials, use

    pwkeep -c -n <name of cred>

To modify them

    pwkeep -e -n <name>

And to show

    pwkeep -v -n <name>

See --help for more options.

Features
========

Password keep is intended to be simple and easy to use. It uses X25519 + ChaChaPoly1305 encryption for your credentials. The
data is not restricted to usernames and passwords, you can store whatever you want.

Editing is done with $EDITOR or editor. 

You can provide password also with $PASSWORD environment variable.

File formats
============

The private.pem file contains your private key. It is fully manipulatable with openssl binary without any specialities.

system-\* files contain actual credentials. The file name consists from system- prefix and hashed system name. The system
name is hashed by appending your public key in DER format, then hashed iterations time with chosen hash, SHA512 by default.

The actual file format is CBOR structure. The data is contained in content key, which contains second CBOR structure, encrypted.
 
Following is a sample code for decrypting an entry

```
import os
import cbor2
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from getpass import getpass
from struct import pack

def cbor_bytes(l):
    return b''.join([x.to_bytes() for x in l])

def main():
    private_key = load_pem_private_key(open("~/.local/share/pwkeep/private.pem","rb").read(), getpass().encode())
    obj = cbor2.load(open("~/.local/share/pwkeep/system-cDTwuq1oQgTRgr118mh5acTQAYOnRsi4pPlvR4s0JFpQWejAhSFtp1wODfdyICCiiHoeul2eXmhQ72JJ", "rb"))
    public_key = X25519PublicKey.from_public_bytes(cbor_bytes(obj['public_key']))
    shared_key = private_key.exchange(public_key)
    salt = cbor_bytes(obj['salt'])

    # then perform HKDF
    key = shared_key
    for i in range(0, obj['rounds']):
        hk = HKDF(algorithm = hashes.SHA512(), length=44, salt=salt, info=pack('>I', i))
        key = hk.derive(key)

    nonce = key[0:12]
    key = key[12:]
    chacha = ChaCha20Poly1305(key)
    obj = cbor2.loads(chacha.decrypt(nonce, cbor_bytes(obj['content']), b''))
    print(obj)

main()```
