use clap::{Parser, Subcommand};
use std::path::PathBuf;
use base64::Engine;
use hex;

/// Simple sled DB admin tool for this project.
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Path to the sled database directory (default: chat_server_db)
    #[arg(short, long)]
    db: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List available tree names in the DB
    Trees,
    /// List all key => value entries in a tree
    List { tree: String },
    /// Show keys only for a tree
    Keys { tree: String },
    /// Get a single key from a tree
    Get { tree: String, key: String },
    /// Delete a single key from a tree
    Delete { tree: String, key: String },
    /// Remove/clear a whole tree (DANGEROUS)
    Clear { tree: String },
}

fn print_bytes(b: &[u8]) {
    if let Ok(s) = std::str::from_utf8(b) {
        println!("UTF-8: {}", s);
    } else {
        println!("HEX: {}", hex::encode(b));
        println!("BASE64: {}", base64::engine::general_purpose::STANDARD.encode(b));
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let db_path = cli.db.unwrap_or_else(|| PathBuf::from("chat_server_db"));
    let db = sled::open(&db_path).map_err(|e| anyhow::anyhow!(e))?;

    match cli.cmd {
        Command::Trees => {
            println!("Trees in {:?}:", db_path);
            for name in db.tree_names() {
                let vec = name.to_vec();
                if let Ok(s) = String::from_utf8(vec.clone()) {
                    println!("- {}", s);
                } else {
                    println!("- {}", hex::encode(vec));
                }
            }
        }

        Command::List { tree } => {
            let t = db.open_tree(tree.as_bytes())?;
            println!("Entries in tree '{}':", tree);
            for kv in t.iter() {
                let (k, v) = kv?;
                print!("key: "); print_bytes(&k);
                print!("value: "); print_bytes(&v);
                println!("---");
            }
        }

        Command::Keys { tree } => {
            let t = db.open_tree(tree.as_bytes())?;
            println!("Keys in tree '{}':", tree);
            for k in t.iter().keys() {
                let k = k?;
                let vec = k.to_vec();
                if let Ok(s) = String::from_utf8(vec.clone()) {
                    println!("- {}", s);
                } else {
                    println!("- {}", hex::encode(vec));
                }
            }
        }

        Command::Get { tree, key } => {
            let t = db.open_tree(tree.as_bytes())?;
            match t.get(key.as_bytes())? {
                Some(v) => {
                    println!("Found key '{}' in '{}':", key, tree);
                    print_bytes(&v);
                }
                None => println!("Key '{}' not found in tree '{}'", key, tree),
            }
        }

        Command::Delete { tree, key } => {
            let t = db.open_tree(tree.as_bytes())?;
            match t.remove(key.as_bytes())? {
                Some(v) => {
                    println!("Deleted key '{}' from '{}'. Previous value:", key, tree);
                    print_bytes(&v);
                }
                None => println!("Key '{}' not found in tree '{}'", key, tree),
            }
            t.flush()?;
        }

        Command::Clear { tree } => {
            println!("Clearing tree '{}' - this is destructive. Continue? (y/N)", tree);
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim().to_lowercase() == "y" {
                let _ = db.drop_tree(tree.as_bytes())?;
                println!("Tree cleared.");
            } else {
                println!("Aborted.");
            }
        }
    }

    Ok(())
}
