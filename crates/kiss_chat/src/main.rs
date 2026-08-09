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
//! kiss_chat <ADDRESS>           come up and immediately dial that peer (hex, kiss1…, or 24 words)
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
//! | `/connect <address>` | dial a peer (switches peers if already connected) |
//! | `/accept`, `/reject` | accept or reject a peer after comparing the safety words |
//! | `/safety` | re-show the current session's safety words |
//! | `/contacts` | list the peers you've accepted before |
//! | `/address [words\|hex]` | show your own address to share — `kiss1…` by default |
//! | `/qr` | show your own address as a QR code |
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

use anyhow::{Context, Result};

use cli::Invocation;

/// Stack size for the thread the application runs on, and for tokio's workers.
///
/// The post-quantum key material is large, and building an ML-DSA-87 identity
/// needs far more stack than a modest default allows — especially in an
/// unoptimised build, where the compiler keeps intermediates alive. Windows gives
/// a process's *main* thread only 1 MiB, which is not enough, so we don't run on
/// it: everything happens on a thread we size ourselves. The reservation is
/// virtual, so asking for more than we use costs nothing.
const STACK_SIZE: usize = 8 * 1024 * 1024;

fn main() -> Result<ExitCode> {
    // Parse before spawning, so a usage error costs nothing and prints from here.
    let invocation = match cli::parse(std::env::args().skip(1)) {
        Ok(invocation) => invocation,
        Err(message) => {
            eprintln!("kiss_chat: {message}\n");
            app::print_usage_to(&mut std::io::stderr());
            return Ok(ExitCode::from(1));
        }
    };

    let worker = std::thread::Builder::new()
        .name("kiss_chat".into())
        .stack_size(STACK_SIZE)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(STACK_SIZE)
                .build()
                .context("failed to start the async runtime")?;
            runtime.block_on(run(invocation))
        })
        .context("failed to start the main thread")?;

    // A panic on that thread has already printed its message; propagate it as the
    // conventional panic exit code rather than swallowing it into a success.
    worker.join().unwrap_or(Ok(ExitCode::from(101)))
}

async fn run(invocation: Invocation) -> Result<ExitCode> {
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
