use signal_server::{app, Database};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("SIGNAL_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://signal_server.db?mode=rwc".into());
    let bind_address = std::env::var("SIGNAL_BIND").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let database = Database::connect(&database_url).await?;
    let listener = TcpListener::bind(&bind_address).await?;
    println!("signal_server listening on {bind_address}");
    axum::serve(listener, app(database)).await?;
    Ok(())
}
