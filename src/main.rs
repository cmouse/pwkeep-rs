mod pwkeep;

use std::path::PathBuf;
use std::io::{Read, stdin, Write};
use std::env;
use spawn_editor::spawn_editor;
use std::fs;
use clap::{ArgAction, CommandFactory, Parser};
use dirs::data_dir;
use std::string::String;
use tempfile::NamedTempFile;
use crate::pwkeep::storage::Entry;
use rpassword;
use passwords::PasswordGenerator;

fn generate_home() -> String {
    let mut root = data_dir().unwrap();
    root.push("pwkeep");
    return root.as_path().display().to_string();
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about)]
struct Cli {
    #[clap(long, short, action=ArgAction::SetTrue)]
    import_entry: bool,
    #[clap(long, short, action=ArgAction::SetTrue)]
    create_entry: bool,
    #[clap(long, short, action=ArgAction::SetTrue)]
    view_entry: bool,
    #[clap(long, short, action=ArgAction::SetTrue)]
    edit_entry: bool,
    #[clap(long, short, action=ArgAction::SetTrue)]
    delete_entry: bool,
    #[clap(long, short, action=ArgAction::SetTrue)]
    list_entries: bool,
    #[clap(long, short='H', default_value_t=generate_home())]
    home: String,
    #[clap(long, short)]
    name: Option<String>,
    #[clap(long, short)]
    search: Option<String>,
}

fn random_password(len: usize) -> String {
    let pg = PasswordGenerator {
       length: len,
       numbers: true,
       lowercase_letters: true,
       uppercase_letters: true,
       symbols: false,
       spaces: false,
       exclude_similar_characters: true,
       strict: true,
    };

    pg.generate_one().unwrap()
}

fn store_results(storage: &pwkeep::storage::Storage, entry: &str, contents: String)
{
    match storage.set_entry(entry, contents) {
        Ok(_) => {}
        Err(e) => { eprintln!("Cannot write {entry}: {e}");
                    std::process::exit(1); }
    }
}

fn update_entry(storage: &pwkeep::storage::Storage, entry: &Entry, path: &PathBuf) {
    let binding = env::var("EDITOR");
    let editor = binding.as_deref().unwrap_or("editor");

    match spawn_editor(Some(editor), &[path.to_str().expect("Path to tempfile")]) {
        Ok(status) => {
            if !status.success() {
                eprintln!("File edit failed: {status}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            panic!("Cannot run {editor}: {e}");
        }
     };

     let new_contents = fs::read_to_string(path).unwrap();

     if new_contents != entry.content {
         store_results(&storage, entry.name.as_str(), new_contents);
     } else {
         println!("Nothing changed, not updating");
     }
}

fn main() {
    let args = Cli::parse();
    let home = PathBuf::from(args.home.as_str());
    let mut storage = pwkeep::storage::Storage::new(home.as_path());

    if !args.import_entry && !args.create_entry && !args.view_entry && !args.edit_entry && !args.delete_entry && !args.list_entries {
        let mut cmd = <Cli as CommandFactory>::command();
        let _ = cmd.print_help();
        std::process::exit(1);
    }

    // ask password 3 times

    for _ in 0..3 {
        let password = rpassword::prompt_password("Password: ").expect("Password");
        match storage.load(password) {
            Ok(_) => { break; }
            Err(e) => { eprintln!("{e}") }
        }
    }

    if storage.loaded() == false {
        eprintln!("Failed to load storage");
        std::process::exit(1);
    } else if args.view_entry {
        let name = args.name.clone().expect("Name required");
        match storage.get_entry(name.as_str()) {
            Ok(entry) => {
                println!("last_edit: {}", entry.last_edit);
                println!("");
                println!("{}", entry.content);
            }
            Err(e) => {
                eprintln!("Cannot open {name}: {e}");
                std::process::exit(1);
            }
        };
    } else if args.edit_entry {
        let name = args.name.clone().expect("Name required");
        let entry: Entry;
        match storage.get_entry(name.as_str()) {
            Ok(e) => {
                entry = e;
            }
            Err(e) => {
                eprintln!("Cannot open {name}: {e}");
                std::process::exit(1);
            }
        };
        let mut file = NamedTempFile::new().expect("Tempfile");
        write!(file, "{}", entry.content).unwrap();
        let path = file.into_temp_path();
        update_entry(&storage, &entry, &path.to_path_buf());
        match path.close() {
            Ok(_) => {},
            Err(e) => { panic!("{e}"); }
        };
    } else if args.import_entry {
        let name = args.name.clone().expect("Name required");
        let mut contents = String::new();
        match stdin().read_to_string(&mut contents) {
            Ok(_) => {
                store_results(&storage, name.as_str(), contents);
            }
            Err(e) => {
                panic!("{e}");
            }
        };
    } else if args.create_entry {
        let name = args.name.clone().expect("Name required");
        match storage.get_entry(name.as_str()) {
            Ok(_) => {
                eprintln!("{name} already exists!");
                std::process::exit(1);
            }
            Err(_) => {}
        };

        let mut file = NamedTempFile::new().expect("Tempfile");
        let mut entry = Entry::new(name.as_str());
        let password = random_password(12);
        entry.content = format!("Username: \nPassword: {password}\n").to_string();
        write!(file, "{}", entry.content).unwrap();
        let path = file.into_temp_path();
        update_entry(&storage, &entry, &path.to_path_buf());
        match path.close() {
            Ok(_) => {},
            Err(e) => { panic!("{e}"); }
        };
    } else if args.delete_entry {
        let name = args.name.clone().expect("Name required");
        match storage.delete_entry(name.as_str()) {
            Ok(_) => {
                println!("{name} removed");
            }
            Err(e) => {
                eprintln!("Cannot delete {name}: {e}");
                std::process::exit(1);
            }
        }
    } else if args.list_entries {
        let index = storage.load_index().expect("Index");
        println!("List of entries:\n");
        for entry in index {
            if args.search.is_none() ||
               (entry.find(args.search.clone().expect("Search value").as_str()) != None) {
                println!("\t{entry}");
            }
        }
    }
}
