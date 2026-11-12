use clap::{Parser, Subcommand};
use signal_client::{tui, Client};
use signal_storage::Store;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "signal_client",
    about = "Signal-inspired end-to-end encrypted terminal messenger"
)]
struct Arguments {
    #[arg(long, help = "Path to the encrypted SQLite vault")]
    vault: Option<PathBuf>,
    #[arg(long, help = "HTTPS relay URL; HTTP is permitted only on loopback")]
    server: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Register {
        #[arg(help = "3-32 lowercase letters, digits, underscores, or hyphens")]
        username: String,
    },
    Tui,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let vault = arguments.vault.unwrap_or_else(|| {
        std::env::var_os("SIGNAL_VAULT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("signal_client.sqlite"))
    });
    let server = arguments.server.unwrap_or_else(|| {
        std::env::var("SIGNAL_SERVER").unwrap_or_else(|_| "http://127.0.0.1:3000".to_owned())
    });
    match arguments.command {
        Some(Command::Register { username }) => {
            let passphrase = tui::read_passphrase("New vault passphrase: ")?;
            if passphrase.len() < 12 {
                anyhow::bail!("use a passphrase of at least 12 UTF-8 bytes");
            }
            let confirmation = tui::read_passphrase("Confirm vault passphrase: ")?;
            if passphrase != confirmation {
                anyhow::bail!("passphrases do not match");
            }
            let store = Store::open(&vault, &passphrase)?;
            let client = Client::register(store, &server, &username).await?;
            println!(
                "Registered {} as {}. The bearer token and private keys are stored only in the encrypted vault.",
                client.username(),
                client.user_id()
            );
        }
        Some(Command::Tui) | None => {
            let passphrase = tui::read_passphrase("Vault passphrase: ")?;
            let store = Store::open(&vault, &passphrase)?;
            let client = Client::open(store, &server)?;
            tui::run(client).await?;
        }
    }
    Ok(())
}
