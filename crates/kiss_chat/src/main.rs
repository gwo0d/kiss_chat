//! kiss_chat — the terminal (ratatui) frontend.
//!
//! Parses the command line and hands off to `app::run`. Everything that isn't
//! a user interface — identity, contacts, transport, framing, the in-band
//! protocol, and the crypto — lives in [`kiss_chat_core`].
//!
//! # Usage
//!
//! ```text
//! kiss_chat              come up in the lobby: share your address, then wait or /connect
//! kiss_chat <ADDRESS>    come up and immediately dial that peer (an iroh EndpointId)
//! kiss_chat --version    print the version and exit (also -v)
//! ```
//!
//! # In-app commands
//!
//! The input line is a command prompt until a peer is connected.
//!
//! | Command | Description |
//! | --- | --- |
//! | `/connect <peer-id>` | dial a peer (switches peers if already connected) |
//! | `/accept`, `/reject` | accept or reject a peer after comparing the safety words |
//! | `/safety` | re-show the current session's safety words |
//! | `/contacts` | list the peers you've accepted before |
//! | `/address` | show your own address to share |
//! | `/name [text]` | set your (optional) display name; only shared after `/accept` |
//! | `/clear` | clear the screen |
//! | `/version` | show the version (also `/v`) |
//! | `/help` | list commands |
//! | `/quit` | exit (also `Esc` / `Ctrl-C`) |

mod app;
mod ui;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let peer_arg = std::env::args().nth(1);
    match peer_arg.as_deref() {
        Some("-h" | "--help") => {
            app::print_usage();
            return Ok(());
        }
        Some("-v" | "--version") => {
            app::print_version();
            return Ok(());
        }
        _ => {}
    }
    app::run(peer_arg).await
}
