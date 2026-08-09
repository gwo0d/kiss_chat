//! End-to-end checks on the built binary's headless mode.
//!
//! The protocol itself is exercised in-process by the unit tests in
//! `src/headless.rs`, which drive two full sessions over loopback. What can only
//! be checked out here is the *process* contract an embedding application depends
//! on: that the binary starts, speaks JSON lines on stdio, honours the identity
//! rules, and exits with the documented code.
//!
//! Nothing here needs the network beyond binding a local socket.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The binary under test, built by cargo for this integration test.
const BIN: &str = env!("CARGO_BIN_EXE_kiss_chat");

/// How long to wait for the process to say or do anything expected.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Wait for the child to exit, killing it if it overruns, and return its status.
fn wait_for_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().expect("wait on child") {
            return status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("headless process did not exit within {TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn headless_emits_a_ready_line_and_quits_cleanly() {
    let mut child = Command::new(BIN)
        .args(["--headless", "--ephemeral"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn kiss_chat");

    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read the ready line");

    let ready: serde_json::Value = serde_json::from_str(&line)
        .unwrap_or_else(|err| panic!("first line must be JSON ({err}): {line:?}"));
    assert_eq!(ready["event"], "ready");
    assert_eq!(ready["proto"], 1);

    // The address and fingerprint are what an invitation is built from, so they
    // must be present and well-formed, not merely non-empty.
    for field in ["address", "fingerprint"] {
        let value = ready[field].as_str().expect(field);
        assert_eq!(value.len(), 64, "{field} should be 64 hex characters");
        assert!(
            value.chars().all(|c| c.is_ascii_hexdigit()),
            "{field} should be hex: {value}"
        );
    }

    // A quit command is honoured, and the process exits successfully.
    let mut stdin = child.stdin.take().expect("stdin");
    writeln!(stdin, r#"{{"cmd":"quit"}}"#).expect("write quit");
    stdin.flush().expect("flush");
    drop(stdin);

    let status = wait_for_exit(&mut child);
    assert_eq!(status.code(), Some(0), "quit should exit 0");
}

#[test]
fn closing_stdin_ends_the_process() {
    // The lifetime contract embedding applications rely on: when the parent goes
    // away, the child does too, rather than lingering with an open endpoint.
    let mut child = Command::new(BIN)
        .args(["--headless", "--ephemeral"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn kiss_chat");

    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read the ready line");
    assert!(line.contains("\"ready\""));

    drop(child.stdin.take());
    let status = wait_for_exit(&mut child);
    assert_eq!(status.code(), Some(0), "EOF on stdin should exit 0");
}

#[test]
fn headless_refuses_to_share_the_users_identity() {
    // Without --config-dir or --ephemeral there is no safe default: falling back
    // to the user's own directory would bind a second endpoint on their address.
    let output = Command::new(BIN)
        .arg("--headless")
        .output()
        .expect("run kiss_chat");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--config-dir"), "{stderr}");
    assert!(stderr.contains("--ephemeral"), "{stderr}");
    assert!(
        output.stdout.is_empty(),
        "a usage failure must not emit protocol lines on stdout"
    );
}

#[test]
fn a_malformed_expected_fingerprint_is_refused_at_startup() {
    let output = Command::new(BIN)
        .args(["--headless", "--ephemeral", "--expect", "nonsense"])
        .output()
        .expect("run kiss_chat");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("fingerprint"));
}

#[test]
fn unknown_options_are_refused_rather_than_ignored() {
    let output = Command::new(BIN)
        .args(["--headless", "--ephemeral", "--turbo"])
        .output()
        .expect("run kiss_chat");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown option"));
}

#[test]
fn help_and_version_describe_the_headless_mode() {
    let help = Command::new(BIN)
        .arg("--help")
        .output()
        .expect("run --help");
    assert_eq!(help.status.code(), Some(0));
    let text = String::from_utf8_lossy(&help.stdout);
    for expected in ["--headless", "--ephemeral", "--config-dir", "--expect"] {
        assert!(text.contains(expected), "usage should mention {expected}");
    }

    let version = Command::new(BIN)
        .arg("--version")
        .output()
        .expect("run --version");
    assert_eq!(version.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&version.stdout).contains(env!("CARGO_PKG_VERSION")),
        "--version should report the crate version"
    );
}

/// Starting up must not depend on a roomy main-thread stack.
///
/// Building a post-quantum identity needs a lot of stack, and Windows gives a
/// process's main thread only 1 MiB — so running the app there crashes before it
/// can emit anything, a failure invisible on Linux and macOS (8 MiB) until CI's
/// Windows leg says so. Constraining the limit here reproduces that condition on
/// any unix, which is where this is most likely to be noticed early.
#[cfg(unix)]
#[test]
fn startup_survives_a_one_megabyte_main_thread_stack() {
    // `exec` so the limit applies to kiss_chat itself, not just the shell.
    let script = format!(
        "ulimit -s 1024 2>/dev/null || exit 99; exec '{}' --headless --ephemeral",
        BIN.replace('\'', r"'\''")
    );
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(&script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn kiss_chat under a reduced stack limit");

    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    stdout.read_line(&mut line).ok();

    if line.is_empty() {
        // Either the shell refused the limit (exit 99) or startup crashed. Only
        // the first is acceptable, and only on a platform that won't let us ask.
        drop(child.stdin.take());
        let status = wait_for_exit(&mut child);
        assert_eq!(
            status.code(),
            Some(99),
            "kiss_chat produced no output under a 1 MiB main-thread stack — \
             it is doing heavy work on the main thread again, which is fatal on Windows"
        );
        return;
    }

    let ready: serde_json::Value =
        serde_json::from_str(&line).expect("startup must emit a ready line, not crash");
    assert_eq!(ready["event"], "ready");

    drop(child.stdin.take());
    assert_eq!(wait_for_exit(&mut child).code(), Some(0));
}

#[test]
fn a_persistent_identity_survives_a_restart() {
    // The property an application depends on when it wants a stable address to
    // share: same directory, same identity, run after run.
    let dir = std::env::temp_dir().join(format!("kiss_chat-bin-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");

    let read_ready = || {
        let mut child = Command::new(BIN)
            .arg("--headless")
            .arg("--config-dir")
            .arg(&dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn kiss_chat");
        let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read the ready line");
        drop(child.stdin.take());
        wait_for_exit(&mut child);
        serde_json::from_str::<serde_json::Value>(&line).expect("ready line is JSON")
    };

    let first = read_ready();
    let second = read_ready();
    assert_eq!(first["address"], second["address"]);
    assert_eq!(first["fingerprint"], second["fingerprint"]);

    std::fs::remove_dir_all(&dir).ok();
}
