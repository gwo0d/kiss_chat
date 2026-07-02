//! Thin binary wrapper around the `kiss_chat` library: parse the command line and
//! hand off to [`kiss_chat::run`]. All application logic lives in the library crate.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let peer_arg = std::env::args().nth(1);
    if matches!(peer_arg.as_deref(), Some("-h" | "--help")) {
        kiss_chat::print_usage();
        return Ok(());
    }
    kiss_chat::run(peer_arg).await
}
