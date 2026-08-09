//! Command-line parsing.
//!
//! Hand-rolled, and deliberately so: the whole surface is a handful of flags, and
//! a parser small enough to read in one sitting is easier to trust than a
//! dependency. It is a plain function over the argument list, so every rule below
//! is unit-testable without spawning anything.

use std::path::PathBuf;

use crate::headless;

/// Which frontend to run, and how.
#[derive(Debug, PartialEq, Eq)]
pub enum Invocation {
    /// The terminal UI.
    Tui {
        config_dir: Option<PathBuf>,
        peer: Option<String>,
    },
    /// The headless (machine-driven) frontend.
    Headless(headless::Options),
    /// Print usage and exit.
    Help,
    /// Print the version and exit.
    Version,
}

/// A fingerprint is a SHA-256 hex digest: 64 lowercase hex characters.
const FINGERPRINT_CHARS: usize = 64;

/// Parse the argument list (excluding the program name).
///
/// # Errors
///
/// Returns a human-readable message for anything unusable — an unknown flag, a
/// flag missing its value, a malformed fingerprint, or a headless invocation that
/// hasn't said where its identity lives.
pub fn parse<I, S>(args: I) -> Result<Invocation, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();

    let mut headless = false;
    let mut config_dir: Option<PathBuf> = None;
    let mut ephemeral = false;
    let mut expect: Vec<String> = Vec::new();
    let mut name: Option<String> = None;
    let mut once = false;
    let mut peer: Option<String> = None;

    let mut iter = args.into_iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Invocation::Help),
            "-v" | "--version" => return Ok(Invocation::Version),
            "--headless" => headless = true,
            "--ephemeral" => ephemeral = true,
            "--once" => once = true,
            "--config-dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--config-dir needs a path".to_string())?;
                config_dir = Some(PathBuf::from(value));
            }
            "--expect" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--expect needs an identity fingerprint".to_string())?;
                expect.push(validate_fingerprint(&value)?);
            }
            "--name" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--name needs a value".to_string())?;
                name = Some(value);
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option: {other}"));
            }
            other => {
                if peer.is_some() {
                    return Err(format!("unexpected extra argument: {other}"));
                }
                peer = Some(other.to_string());
            }
        }
    }

    if !headless {
        // Flags that only mean something to the headless frontend are refused
        // rather than ignored, so a typo can't silently change nothing.
        for (flag, present) in [
            ("--ephemeral", ephemeral),
            ("--once", once),
            ("--expect", !expect.is_empty()),
            ("--name", name.is_some()),
        ] {
            if present {
                return Err(format!("{flag} is only available with --headless"));
            }
        }
        return Ok(Invocation::Tui { config_dir, peer });
    }

    let identity = match (config_dir, ephemeral) {
        (Some(_), true) => {
            return Err("choose either --config-dir or --ephemeral, not both".into());
        }
        (Some(dir), false) => headless::Identity::Dir(dir),
        (None, true) => headless::Identity::Ephemeral,
        // Refused rather than defaulted: falling back to the user's own config
        // directory would bind a second endpoint claiming their address, and would
        // entangle an application's trusted-peer list with the user's.
        (None, false) => {
            return Err(
                "--headless needs somewhere to keep its identity: pass --config-dir <path> \
                 to persist one, or --ephemeral for a throwaway identity"
                    .into(),
            );
        }
    };

    Ok(Invocation::Headless(headless::Options {
        identity,
        expect,
        name,
        once,
        peer,
    }))
}

/// Check a `--expect` value looks like a fingerprint, so a mistyped one fails at
/// startup rather than silently matching no peer.
fn validate_fingerprint(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    let normalized = trimmed.to_ascii_lowercase();
    if normalized.len() == FINGERPRINT_CHARS && normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(normalized);
    }
    Err(format!(
        "--expect wants a {FINGERPRINT_CHARS}-character hex fingerprint, got: {trimmed}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A syntactically valid fingerprint (SHA-256 hex), as `--expect` wants.
    const FP: &str = "6dfb0a06d769e0e0aaebe008b81e37a3a32689246e01676dfcd05b87f8ee7352";

    fn parse_ok(args: &[&str]) -> Invocation {
        parse(args.iter().copied()).expect("should parse")
    }

    fn parse_err(args: &[&str]) -> String {
        parse(args.iter().copied()).expect_err("should be rejected")
    }

    fn headless_options(args: &[&str]) -> headless::Options {
        match parse_ok(args) {
            Invocation::Headless(options) => options,
            other => panic!("expected a headless invocation, got {other:?}"),
        }
    }

    #[test]
    fn no_arguments_runs_the_terminal_ui() {
        assert_eq!(
            parse_ok(&[]),
            Invocation::Tui {
                config_dir: None,
                peer: None
            }
        );
    }

    #[test]
    fn a_bare_argument_is_the_peer_to_dial() {
        assert_eq!(
            parse_ok(&["abc123"]),
            Invocation::Tui {
                config_dir: None,
                peer: Some("abc123".into())
            }
        );
    }

    #[test]
    fn help_and_version_win_over_everything_else() {
        assert_eq!(parse_ok(&["--headless", "--help"]), Invocation::Help);
        assert_eq!(parse_ok(&["-h"]), Invocation::Help);
        assert_eq!(parse_ok(&["--version"]), Invocation::Version);
        assert_eq!(parse_ok(&["-v"]), Invocation::Version);
    }

    #[test]
    fn headless_requires_an_identity_choice() {
        // The important rule: never silently share the user's own identity.
        let err = parse_err(&["--headless"]);
        assert!(err.contains("--config-dir"), "{err}");
        assert!(err.contains("--ephemeral"), "{err}");
    }

    #[test]
    fn headless_refuses_both_identity_choices_at_once() {
        let err = parse_err(&["--headless", "--ephemeral", "--config-dir", "/tmp/kc"]);
        assert!(err.contains("not both"), "{err}");
    }

    #[test]
    fn headless_with_an_explicit_directory() {
        let options = headless_options(&["--headless", "--config-dir", "/tmp/kc"]);
        assert_eq!(
            options.identity,
            headless::Identity::Dir(PathBuf::from("/tmp/kc"))
        );
        assert!(!options.once);
        assert!(options.expect.is_empty());
    }

    #[test]
    fn headless_flags_can_come_in_any_order() {
        let a = headless_options(&[
            "--headless",
            "--ephemeral",
            "--once",
            "--expect",
            FP,
            "--name",
            "Chess",
            "peer-id",
        ]);
        let b = headless_options(&[
            "peer-id",
            "--name",
            "Chess",
            "--expect",
            FP,
            "--once",
            "--ephemeral",
            "--headless",
        ]);
        assert_eq!(a.identity, headless::Identity::Ephemeral);
        assert_eq!(a.peer.as_deref(), Some("peer-id"));
        assert_eq!(a.name.as_deref(), Some("Chess"));
        assert!(a.once);
        assert_eq!(a.expect, vec![FP.to_string()]);
        assert_eq!(a.expect, b.expect);
        assert_eq!(a.peer, b.peer);
        assert_eq!(a.once, b.once);
    }

    #[test]
    fn expect_may_be_repeated() {
        let other = "1".repeat(64);
        let options = headless_options(&[
            "--headless",
            "--ephemeral",
            "--expect",
            FP,
            "--expect",
            &other,
        ]);
        assert_eq!(options.expect, vec![FP.to_string(), other]);
    }

    #[test]
    fn expect_normalises_case_so_a_pasted_fingerprint_still_matches() {
        let options =
            headless_options(&["--headless", "--ephemeral", "--expect", &FP.to_uppercase()]);
        assert_eq!(options.expect, vec![FP.to_string()]);
    }

    #[test]
    fn a_malformed_fingerprint_is_refused_at_startup() {
        // Better a clear failure now than a process that quietly matches no peer.
        for bad in ["", "not-hex", "abc", &"z".repeat(64), &"a".repeat(63)] {
            let err = parse_err(&["--headless", "--ephemeral", "--expect", bad]);
            assert!(err.contains("fingerprint"), "{bad}: {err}");
        }
    }

    #[test]
    fn flags_that_need_values_say_so_when_they_are_missing() {
        assert!(parse_err(&["--headless", "--config-dir"]).contains("path"));
        assert!(parse_err(&["--headless", "--ephemeral", "--expect"]).contains("fingerprint"));
        assert!(parse_err(&["--headless", "--ephemeral", "--name"]).contains("--name"));
    }

    #[test]
    fn unknown_flags_are_an_error_not_silently_ignored() {
        let err = parse_err(&["--headles"]);
        assert!(err.contains("unknown option"), "{err}");
    }

    #[test]
    fn headless_only_flags_are_refused_for_the_terminal_ui() {
        for args in [
            vec!["--ephemeral"],
            vec!["--once"],
            vec!["--expect", FP],
            vec!["--name", "x"],
        ] {
            let err = parse_err(&args);
            assert!(err.contains("--headless"), "{args:?}: {err}");
        }
    }

    #[test]
    fn the_terminal_ui_accepts_an_explicit_config_dir() {
        assert_eq!(
            parse_ok(&["--config-dir", "/tmp/kc", "peer"]),
            Invocation::Tui {
                config_dir: Some(PathBuf::from("/tmp/kc")),
                peer: Some("peer".into()),
            }
        );
    }

    #[test]
    fn a_second_bare_argument_is_refused() {
        assert!(parse_err(&["one", "two"]).contains("extra argument"));
    }
}
