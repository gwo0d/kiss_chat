//! kiss_chat — the terminal (ratatui) frontend, and a headless one for programs.
//!
//! Parses the command line and hands off to whichever frontend was asked for.
//! Everything that isn't a user interface — identity, contacts, transport,
//! framing, the in-band protocol, and the crypto — lives in [`kiss_chat_core`];
//! the connection driver both frontends share lives in [`net`].
//!
//! # Usage
//!
//! ```text
//! kiss_chat                     come up in the lobby: share your address, then wait or /connect
//! kiss_chat <ADDRESS>           come up and immediately dial that peer (an iroh EndpointId)
//! kiss_chat --config-dir <DIR>  keep this session's identity in DIR instead of the default
//! kiss_chat --headless …        speak newline-delimited JSON on stdio instead of drawing a UI
//! kiss_chat --version           print the version and exit (also -v)
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
//!
//! # Headless mode
//!
//! `--headless` runs the same protocol with no terminal, driven by another program
//! over stdin/stdout. See [`headless`] for the wire format.

mod app;
mod cli;
mod headless;
mod net;
mod ui;

use std::process::ExitCode;

use anyhow::Result;

use cli::Invocation;

#[tokio::main]
async fn main() -> Result<ExitCode> {
    let invocation = match cli::parse(std::env::args().skip(1)) {
        Ok(invocation) => invocation,
        Err(message) => {
            eprintln!("kiss_chat: {message}\n");
            app::print_usage_to(&mut std::io::stderr());
            return Ok(ExitCode::from(1));
        }
    };

    match invocation {
        Invocation::Help => {
            app::print_usage();
            Ok(ExitCode::SUCCESS)
        }
        Invocation::Version => {
            app::print_version();
            Ok(ExitCode::SUCCESS)
        }
        Invocation::Tui { config_dir, peer } => {
            app::run(config_dir, peer).await?;
            Ok(ExitCode::SUCCESS)
        }
        // A headless failure is reported to the controlling program through the
        // exit code, since it has no terminal to read a message from.
        Invocation::Headless(options) => {
            let exit = headless::run(options).await?;
            Ok(ExitCode::from(u8::try_from(exit.code()).unwrap_or(1)))
        }
    }
}
