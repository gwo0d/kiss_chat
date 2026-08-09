# Implementation plan: headless mode

**Status:** proposed
**Target release:** v0.7.0 (both crates)
**Date:** 2026-08-09

kiss_chat today is a terminal chat for humans. This plan adds a second frontend —
a **headless mode** — so any application (a Python chess game, a shell script, a
bot) can spawn `kiss_chat --headless` as a child process and use it as a secure,
peer-to-peer transport for the duration of its runtime: newline-delimited JSON
on stdin/stdout in, end-to-end post-quantum-encrypted frames over iroh out.

The plan covers the design, a phased work breakdown with acceptance criteria,
and the full release procedure (crates.io + GitHub releases) at the end.

---

## 1. Goals and non-goals

### Goals

1. A machine-drivable mode of the existing `kiss_chat` binary: spawn it, speak
   newline-delimited JSON (NDJSON) over stdin/stdout, exchange text payloads
   with exactly one peer, exit when the parent does.
2. **No weakening of the trust model.** The safety-word ritual is *delegated*
   to the controlling application (which shows the words to its human), or
   replaced by an out-of-band pre-pinned identity fingerprint (`--expect`) —
   never silently skipped.
3. **Identity isolation.** A headless instance never fights the human TUI over
   `~/.config/kiss_chat/`; embedding applications get their own identity
   directory or an ephemeral in-memory identity.
4. The TUI's behaviour is unchanged, and the wire protocol is unchanged —
   v0.7.0 headless interoperates with a v0.6.x TUI peer.
5. Tests, documentation (protocol spec + a Python example), and a released
   version on crates.io and GitHub releases.

### Non-goals (recorded as future work, §10)

- Group/multi-peer sessions — the protocol stays strictly one peer at a time.
- Binary payloads — applications tunnel JSON/text through chat messages
  (≤ `message::MAX_MESSAGE_CHARS` = 4096 chars).
- Language bindings (PyO3 etc.) — the subprocess model is the polyglot answer.
- A daemon serving multiple local clients — one child process per session.

---

## 2. Where the codebase stands (what this plan builds on)

Facts this design leans on, verified against the current tree:

- The workspace already splits protocol (`kiss_chat_core`) from UI
  (`kiss_chat`), and core's docs say other frontends are meant to build on it.
- The connection machinery in `crates/kiss_chat/src/app.rs` —
  `dial_and_handshake`, `accept_and_handshake`, `spawn_reader`, `spawn_writer`,
  `farewell`, plus the `Established`/`ConnResult`/`LiveSession` types — is
  already UI-free: it touches only core types and tokio channels. Only the
  `event_loop` and `NetEvent`'s current home (`ui.rs`) tie it to ratatui.
- `identity` and `contacts` already have path-parameterised internals
  (`load_display_name_in(dir)`, `recognize_in(dir, …)`, …); only the zero-arg
  wrappers hardcode `config_dir()`. Promoting the `_in` variants to `pub` is a
  tiny, additive diff.
- `transport::bind()` hardcodes `identity::load_or_create_endpoint_secret()`;
  it needs a `bind_with(secret)` sibling for custom-dir and ephemeral identities.
- `contacts::fingerprint()` (SHA-256 of the encoded ML-DSA verifying key,
  lowercase hex, 64 chars) is private; `--expect` and the `ready` event need it
  public.
- `transport::dial` already accepts `impl Into<EndpointAddr>`, and the loopback
  tests dial via `endpoint.addr()` with direct socket addresses — the pattern
  the hermetic headless tests will reuse.
- Versions are workspace-shared (`0.6.1`), and `[workspace.dependencies]` pins
  `kiss_chat_core = { path = …, version = "0.6.1" }` with a comment requiring
  the pin to move in step with `[workspace.package] version` on release bumps.
- Releases are driven by publishing a GitHub release (e.g. `gh release create`),
  which triggers `.github/workflows/release.yml` to build and attach binaries
  for six targets with SHA-256 checksums. crates.io publishing is manual.

---

## 3. Design

### 3.1 Mode of use: child process speaking NDJSON on stdio

`kiss_chat --headless [OPTIONS] [PEER_ID]` runs without a terminal UI. It
prints one JSON object per line on **stdout** (events), reads one JSON object
per line from **stdin** (commands), and logs human-oriented diagnostics to
**stderr** only. Protocol spec in §4.

Why stdio rather than a socket or daemon:

- Every language can `Popen` and read lines with zero dependencies.
- No ports, no discovery of the local service, no permission questions.
- Lifetime is naturally tied to the parent: when the parent exits, stdin hits
  EOF and the child performs a graceful farewell and exits. "Used for the
  duration of their runtime" falls out of process semantics.
- Backpressure comes for free: events flow reader-task → bounded channel →
  stdout. If the parent stops reading, the pipe fills, the stdout write awaits,
  the bounded channel fills, the reader task stalls, and QUIC flow control
  throttles the peer — the same chain `app.rs` builds deliberately with
  `NET_EVENT_QUEUE`.

### 3.2 Trust model: delegate the ritual, or pre-pin the identity

Two policies, both preserving the existing trust anchors:

1. **Delegated verification (default).** When a channel comes up, headless
   emits a `verify` event carrying the safety words, the peer's identity
   fingerprint, and the TOFU pin status (`new` / `known` / `changed`), then
   holds the session exactly as the TUI does — suppressing inbound chat text —
   until the controlling application answers with `accept` or `reject`. The
   application shows the words in *its* UI and asks its human. The ritual
   survives; only the screen it happens on moves. Accepting pins the peer via
   `contacts::remember_in`, same as the TUI.

2. **Pre-pinned identity (`--expect <fingerprint>`).** The flag (repeatable)
   names identity fingerprints the process may talk to. When a channel comes
   up, the peer's fingerprint is compared: match → auto-accept (and pin);
   mismatch → emit a `disconnected` event with the reason, drop the
   connection, and (under `--once`) exit with code 2. This is sound because
   the players already exchange the dialing address out-of-band — the
   invitation simply carries `address + fingerprint` together, moving the
   out-of-band verification *before* the connection instead of after it. The
   invitation channel is the trust anchor, exactly as the safety words are.

Security-behaviour parity with the TUI is a requirement, specifically:

- Inbound chat text is **suppressed until accepted** (the "it's me, just
  accept!" countermeasure in `event_loop`'s `NetEvent::Message` arm).
- A peer-shared name is recorded pre-accept but only surfaced/cached after.
- Received names go through `message::sanitize_name` before appearing in any
  event (they already do, core-side).

### 3.3 Identity isolation

- `--config-dir <path>`: use `<path>` instead of `$XDG_CONFIG_HOME/kiss_chat`
  for `secret.key`, `auth.key`, `name`, and `contacts`.
- `--ephemeral`: generate both secrets in memory; never touch disk. Contacts
  are not read or written (every peer classifies as `new`); combine with
  `--expect` for non-interactive trust.
- **Headless refuses to start with neither flag.** Sharing the default config
  dir with a (possibly running) TUI means two live endpoints with the same
  iroh `EndpointId`, which breaks dialing and discovery in confusing ways, and
  silently entangles the human's contact pins with an application's. The error
  message names both flags. (The TUI keeps its current default behaviour;
  `--config-dir` also works there for symmetry.)

### 3.4 CLI surface

The project deliberately hand-rolls its argument parsing (two flags today);
this stays hand-rolled — a small `Args` struct + parser function with unit
tests, no clap. New surface:

```
kiss_chat [--config-dir <path>] [PEER_ID]        # TUI (unchanged defaults)
kiss_chat --headless (--config-dir <path> | --ephemeral)
          [--expect <fp64>]...  [--name <text>]  [--once]  [PEER_ID]
kiss_chat --help | --version
```

- `PEER_ID` — auto-dial this peer on startup (exists today).
- `--name <text>` — display name for this run, not persisted. Without it,
  headless uses the saved name from the config dir (if any); headless never
  writes the `name` file.
- `--once` — exit after the first established session ends (peer leaves,
  connection drops, or local `quit`). The natural mode for "one game, one
  process". Without it, headless returns to the lobby and re-arms accept,
  like the TUI.
- Unknown flags are an error (usage to stderr, exit 1), not silently ignored.

### 3.5 New dependency: `serde` + `serde_json`

Hand-rolling JSON output means hand-rolling string escaping — a bug class this
project doesn't need. `serde` (derive) + `serde_json` are added to the
**`kiss_chat` binary crate only**; `kiss_chat_core` stays serde-free. Both are
ubiquitous, MSRV-compatible with 1.91, and clean in `cargo audit` today.
Event/command enums derive `Serialize`/`Deserialize` with
`#[serde(tag = "event", rename_all = "snake_case")]` (resp. `tag = "cmd"`), so
the wire shape is declared in one place.

---

## 4. The headless NDJSON protocol, v1

This section is the protocol's specification; it lands verbatim (edited for
context) in the README and in the rustdoc of the new `headless` module.

### 4.1 Framing

- One JSON object per line, UTF-8, `\n`-terminated (a trailing `\r` is
  tolerated on input for Windows parents). No pretty-printing on output.
- Consumers **must ignore unknown fields** and unknown event types; the
  process ignores unknown fields in commands and answers unknown `cmd` values
  with an `error` event. This is the forward-compatibility rule.
- `ready` carries `"proto": 1`. Additive changes (new fields, new events)
  don't bump it; a change that would break a conforming consumer does.
- Input lines are capped (64 KiB) to bound memory; an over-long or
  syntactically invalid line yields an `error` event and the line is dropped.

### 4.2 Events (stdout)

| Event | Fields | When |
|---|---|---|
| `ready` | `proto` (int), `address` (64-hex iroh EndpointId), `fingerprint` (64-hex own ML-DSA fingerprint), `name` (string\|null), `direct_addrs` (array of `"ip:port"`) | Once, after the endpoint is bound. Everything an app needs to build an invitation. |
| `connecting` | `peer` | A dial started (startup arg or `connect` command). |
| `verify` | `peer`, `words` (12 space-separated safety words), `fingerprint` (peer's), `pin` (`"new"`\|`"known"`\|`"changed"`), `known_name` (string\|null) | Channel established and awaiting an `accept`/`reject` decision. Not emitted when `--expect` decides. |
| `connected` | `peer`, `fingerprint` | The local side accepted (via command or `--expect` match). |
| `peer_name` | `name` (string\|null) | Peer shared or cleared their (sanitised) display name. Post-accept only. |
| `message` | `text` | A decrypted chat message. Post-accept only. |
| `disconnected` | `reason` | Session over (peer left, connection lost, local reject, `--expect` mismatch). The process is back in the lobby afterwards — or exiting, under `--once`. |
| `error` | `message` | A non-fatal problem: malformed/unknown command, `send` while not connected, over-long message, invalid peer id. |

### 4.3 Commands (stdin)

| Command | Fields | Meaning |
|---|---|---|
| `connect` | `peer` (EndpointId hex), `addrs` (optional array of `"ip:port"`) | Dial. `addrs` enables direct dialing without discovery (LAN, tests); normally omitted. If already in a session: farewell the current peer first, exactly like the TUI's `/connect`. |
| `accept` | — | Accept the peer under verification (pin + share own name, per §3.2). |
| `reject` | — | Reject and return to the lobby. |
| `send` | `text` | Send a chat message (≤ 4096 chars, else `error`). |
| `quit` | — | Graceful farewell, then exit 0. **EOF on stdin is equivalent to `quit`.** |

### 4.4 Lifecycle and exit codes

```
        ┌───────── lobby (accept armed) ◄────────────┐
        │  connect cmd / PEER_ID arg    │            │ disconnected
        ▼                               │ inbound    │ (unless --once)
   connecting ──established──► verifying ──accept──► chatting
        │                       │  --expect match ▲     │
        └── dial failed ──►     │  (skips verify) │     │
            lobby               └─reject/mismatch─┴──► lobby / exit
```

- `0` — clean exit: `quit`, stdin EOF, or (under `--once`) a session that
  ended normally.
- `1` — fatal: bind failure, unreadable config dir, bad CLI usage, or
  (`--once`) a dial/handshake that never established.
- `2` — refused a peer whose identity did not match `--expect` (under
  `--once`; without `--once` it's a `disconnected` event and the lobby).

One deliberate gap, documented rather than papered over: `connected` reports
the **local** accept. The wire protocol has no accept-acknowledgement frame,
so the peer's acceptance is only observable when their first frame (a name
share or message) arrives. Applications that need a rendezvous should
exchange an application-level hello as their first message. (A protocol-level
ack is future work, §10 — it changes the wire format.)

### 4.5 Example session (chess app's view)

```jsonl
← {"event":"ready","proto":1,"address":"96aede…fa39","fingerprint":"3c9a…","name":null,"direct_addrs":["192.168.1.7:52400"]}
→ {"cmd":"connect","peer":"b1c2…88ef"}
← {"event":"connecting","peer":"b1c2…88ef"}
← {"event":"verify","peer":"b1c2…88ef","words":"vault sketch tide …","fingerprint":"77aa…","pin":"new","known_name":null}
→ {"cmd":"accept"}
← {"event":"connected","peer":"b1c2…88ef","fingerprint":"77aa…"}
→ {"cmd":"send","text":"{\"move\":\"e2e4\"}"}
← {"event":"message","text":"{\"move\":\"e7e5\"}"}
→ {"cmd":"quit"}
```

---

## 5. Work plan

Phases are ordered by dependency; 0 and 1 are pure groundwork with no
behaviour change. Suggested PR split in §6.

### Phase 0 — core groundwork (`kiss_chat_core`, all additive)

| Change | File | Notes |
|---|---|---|
| Promote `config_dir()` to `pub` | `identity.rs` | So frontends can *display* the default location. |
| `pub fn load_or_create_endpoint_secret_in(dir)` / `load_or_create_auth_seed_in(dir)` | `identity.rs` | Thin wrappers over the existing `load_or_create_key`; zero-arg functions delegate to them. |
| Promote `load_display_name_in` / `save_display_name_in` to `pub` | `identity.rs` | Already exist privately with tests. |
| Promote `recognize_in` / `remember_in` / `set_name_in` / `known_peers_in` to `pub` | `contacts.rs` | Already exist privately with tests. |
| `pub fn fingerprint(identity_key: &[u8]) -> String` | `contacts.rs` | Document as *the* fingerprint format (pins, `--expect`, `ready`/`verify` events). |
| `pub async fn bind_with(secret: SecretKey) -> Result<Endpoint>` | `transport.rs` | `bind()` becomes `bind_with(identity::load_or_create_endpoint_secret()?)`. Covers custom-dir and ephemeral binds. |

Doc comments on every promoted/new item (the rustdoc CI job denies warnings).
Existing zero-arg APIs keep working — the TUI compiles untouched at this point.

**Acceptance:** `cargo test -p kiss_chat_core` green; `cargo doc` clean; no
call-site changes required in `kiss_chat`.

### Phase 1 — extract the frontend-neutral net driver (`kiss_chat` crate)

New module `crates/kiss_chat/src/net.rs`, moved verbatim (plus doc tweaks)
from `app.rs`:

- Types: `Established`, `ConnResult`, `LiveSession`, and `NetEvent` (moves
  here from `ui.rs`; `ui` imports it from `net` — it never belonged to the
  terminal).
- Constants: `HANDSHAKE_TIMEOUT`, `FAREWELL_TIMEOUT`, `NET_EVENT_QUEUE`.
- Tasks: `arm_accept`, `spawn_dial`, `dial_and_handshake`,
  `accept_and_handshake`, `farewell`, `spawn_reader`, `spawn_writer`.
- One signature change: `dial_and_handshake` takes `impl Into<EndpointAddr>`
  (like `transport::dial` already does) so the headless `connect` command's
  optional `addrs` field works. The TUI keeps passing a bare `EndpointId`.

`app.rs` keeps only the TUI event loop, terminal input bridge, and
`print_usage`/`print_version`.

**Acceptance:** pure refactor — `cargo test --workspace`, `cargo clippy
--workspace --all-targets`, and a manual TUI smoke test (lobby, dial, accept,
chat, quit) all behave exactly as before.

### Phase 2 — the headless event loop and NDJSON codec

New module `crates/kiss_chat/src/headless.rs`:

- `Event` / `Cmd` serde enums per §4.2–4.3, with encode/decode unit tests
  (including: unknown fields ignored, unknown `cmd` rejected, escaping of
  quotes/newlines in message text).
- `pub async fn run(opts: HeadlessOpts) -> Result<ExitCode>` — resolves
  identity per §3.3 (custom dir or ephemeral), binds via
  `transport::bind_with`, then calls the loop.
- `async fn event_loop(endpoint, opts, input: impl AsyncBufRead + Unpin,
  output: impl AsyncWrite + Unpin) -> Result<ExitCode>` — **generic over its
  stdio** so tests inject `tokio::io::duplex` pipes. Structure mirrors
  `app::event_loop`: a `tokio::select!` over parsed input lines, `ConnResult`s,
  and `NetEvent`s, with the same state machine (lobby / connecting / verifying
  / chatting), the same pre-accept suppression, the same pin/name logic on
  accept, and the same farewell paths — minus rendering, plus `Event`
  emission.
- Ephemeral mode: contacts reads/writes are skipped (pin status constant
  `new`); nothing is persisted.
- `--expect`: on `ConnResult::Established`, compare
  `contacts::fingerprint(session.peer_identity())` against the allowed set
  and short-circuit the verifying state per §3.2.
- `main.rs` grows `mod headless;` and tokio features `io-std`, `io-util` in
  `crates/kiss_chat/Cargo.toml`; stdin is bridged with
  `BufReader::new(tokio::io::stdin()).lines()`.

**Acceptance:** unit tests for the codec; the loop compiles against duplex
pipes (exercised properly in Phase 4).

### Phase 3 — CLI parsing

Replace the `args().nth(1)` match in `main.rs` with a small hand-rolled
parser producing `enum Invocation { Tui { config_dir, peer }, Headless(HeadlessOpts), Help, Version }`.

- `HeadlessOpts`: `identity: ConfigDir(PathBuf) | Ephemeral`, `expect:
  Vec<String>` (validated: 64 lowercase hex), `name: Option<String>`
  (sanitised via `message::sanitize_name`), `once: bool`, `peer:
  Option<String>`.
- Enforce §3.3's "config-dir or ephemeral, not neither, not both" rule with a
  message that names the flags.
- Update `print_usage` to cover the new surface.

**Acceptance:** table-driven unit tests for the parser (valid combinations,
each rejection path, flag order independence).

### Phase 4 — tests

1. **Codec + parser units** (Phases 2–3, in-module).
2. **Hermetic full-stack integration test**
   (`crates/kiss_chat/tests/headless_loopback.rs`): bind two
   discovery-free loopback endpoints (the `presets::Minimal` +
   `bind_addr("127.0.0.1:0")` pattern from `transport.rs` tests, dialing via
   `endpoint.addr()`), run two `headless::event_loop`s over duplex pipes, and
   script the whole conversation: both `ready` events → `connect` with
   `addrs` → both `verify` events with **identical safety words** → both
   `accept` → `connected` → message round-trip in both directions →
   `quit` → the peer sees `disconnected` with the peer-left reason.
   Variants: `--expect` match (no `verify`, straight to `connected`),
   `--expect` mismatch (`disconnected` + exit path 2), `reject`, `--once`
   exit, pre-accept message suppression (a message sealed before accept is
   never emitted as an event until after).
3. **Identity isolation test:** two ephemeral instances produce distinct
   addresses; a `--config-dir` instance reuses its keys across restarts and
   pins survive to produce `pin:"known"` on reconnect.
4. **Binary smoke test** using `env!("CARGO_BIN_EXE_kiss_chat")`: spawn
   `--headless --ephemeral`, read the `ready` line, assert well-formed JSON
   with a 64-hex address, send `quit` on stdin, assert exit 0. (No network
   beyond binding.)
5. **Long-idle soak (manual, pre-release):** two real instances, accept, then
   30+ minutes idle, then a move — verifies QUIC idle/keepalive behaviour for
   the think-time-heavy chess case. If sessions die idle, configure the
   endpoint keepalive in `transport` and fold that into the release.

CI needs no changes: the existing jobs (fmt, clippy, 3-OS test, msrv 1.91,
rustdoc, audit) pick the new code up via `--workspace`.

**Acceptance:** all of the above green on the three CI OSes.

### Phase 5 — documentation and example

- **README:** new *Headless mode* section — motivation, invocation, the §4
  protocol tables, the identity-isolation rule, an invitation convention
  ("share `address` and `fingerprint` from `ready` with your opponent"), and
  the Python snippet below. Update the usage block and in-app tables' intro
  to mention the second frontend.
- **rustdoc:** module docs for `headless` (the spec's normative copy for Rust
  readers), `net`, and the promoted core items; `crates/kiss_chat_core/README.md`
  gets one line noting the second in-tree consumer.
- **`examples/python/`** at the repo root (outside both crate packages):
  - `kiss_pipe.py` (~60 lines, stdlib only): `KissChat` class wrapping
    `subprocess.Popen`, with `events()` iterator and `send()`/`accept()`/
    `connect()` helpers.
  - `demo_chat.py`: minimal two-terminal usage showing the verify/accept flow.
- The plan document you are reading moves to "implemented" status or is
  replaced by the README section (author's choice at merge time).

**Acceptance:** `cargo doc --workspace --no-deps` warning-free; the Python
demo runs against a locally built binary on Linux and macOS.

---

## 6. Suggested PR breakdown

1. **PR 1 — groundwork (no behaviour change):** Phases 0 + 1. Easy review:
   core diff is visibility promotions + `bind_with`; frontend diff is a code
   move. CI green proves the TUI is untouched.
2. **PR 2 — headless mode:** Phases 2 + 3 + 4. The feature, its CLI, and its
   tests, reviewable against the §4 spec.
3. **PR 3 — docs + example:** Phase 5. Optionally folded into PR 2.

Then the release (§7) from `main`.

---

## 7. Release plan: v0.7.0

### 7.1 Version reasoning

- `kiss_chat_core` 0.6.1 → **0.7.0**: additive API, but pre-1.0 the crate's
  own policy is "expect breaking changes between minor versions", and a minor
  bump is the honest signal for new public surface.
- `kiss_chat` 0.6.1 → **0.7.0**: new feature; versions are workspace-shared
  anyway (`[workspace.package] version`).
- **Wire compatibility:** ALPN (`kiss-chat/0`), the handshake, and the framed
  message protocol are untouched — a 0.7.0 headless client interoperates with
  a 0.6.x TUI. Say so in the release notes.
- The **NDJSON protocol** starts at `proto: 1`, versioned independently of
  the crate version (§4.1).

### 7.2 Pre-release checklist (on `main`, after the PRs merge)

1. CI fully green on `main`, including the weekly-audit-sensitive `audit` job.
2. The manual long-idle soak (Phase 4.5) done, with any keepalive fix landed.
3. Release commit ("release: v0.7.0"), touching exactly:
   - `[workspace.package] version` → `0.7.0`;
   - `[workspace.dependencies] kiss_chat_core.version` → `0.7.0` (the
     Cargo.toml comment demands these move together — this is what the
     published `kiss_chat` requires of `kiss_chat_core` on crates.io);
   - `Cargo.lock` (via `cargo build`);
   - README version-sensitive text if any (MSRV stays 1.91 — no dependency
     floor changed).
4. `cargo package --list -p kiss_chat_core` and `-p kiss_chat`: eyeball that
   nothing unexpected ships (the Python examples at the repo root are outside
   both packages; `bip39-english.txt` and the crate READMEs are inside, as
   today).
5. `cargo publish --dry-run -p kiss_chat_core` (the `kiss_chat` dry-run only
   works after core is really published, since the path dep is stripped —
   expected, not a failure).

### 7.3 Publish to crates.io (order matters)

```bash
cargo publish -p kiss_chat_core          # must land first
# wait ~1 minute for the sparse index; confirm:
#   https://crates.io/crates/kiss_chat_core/0.7.0
cargo publish -p kiss_chat               # depends on core 0.7.0 from the index
```

Requires a crates.io token with publish rights for both crates (owner-held;
publishing stays manual, per the project's current flow).

### 7.4 GitHub release (triggers the binary build)

```bash
git tag v0.7.0 <release-commit>          # matches the workflow's v-prefixed TAG convention
git push origin v0.7.0
gh release create v0.7.0 --title "kiss_chat v0.7.0" --notes-file <notes>
```

Publishing the release fires `.github/workflows/release.yml`, which checks
out the tag and builds/attaches archives + `.sha256` files for all six
targets (x86_64/aarch64 Linux gnu, x86_64 musl, both macOS, Windows MSVC).

Release-notes skeleton:

- **Headless mode** — spawn `kiss_chat --headless` from any language; NDJSON
  protocol v1 on stdio (link the README section); `--config-dir`,
  `--ephemeral`, `--expect`, `--name`, `--once`.
- **`kiss_chat_core` additions** — path-parameterised identity/contacts APIs,
  `transport::bind_with`, public `contacts::fingerprint`.
- **Compatibility** — wire protocol unchanged; interoperates with 0.6.x. TUI
  behaviour unchanged. MSRV 1.91.
- Checksums note (as released binaries already carry).

### 7.5 Post-release verification

1. Release workflow green; 12 assets (6 archives + 6 checksums) attached.
2. `cargo install kiss_chat --locked` on a clean machine → `kiss_chat
   --version` prints 0.7.0; `kiss_chat --headless --ephemeral` emits a valid
   `ready` line; `printf '{"cmd":"quit"}\n' | kiss_chat --headless
   --ephemeral` exits 0.
3. docs.rs builds green for both crates (the rustdoc CI job makes surprises
   unlikely); README badges show 0.7.0.
4. Python demo runs against an installed (not locally built) binary.

### 7.6 Contingencies

- A target fails in the release workflow → fix, then re-run via the
  workflow's `workflow_dispatch` input (`tag: v0.7.0`) — it re-attaches to
  the existing release.
- `kiss_chat` publish fails after core published → fix forward; if the fix
  touches core, that's core 0.7.1 (crates.io versions are immutable; yank
  only if 0.7.0 core is actually broken, since yanking strands `--locked`
  installs).
- A protocol-spec bug found post-release → additive fixes ride 0.7.x with
  `proto` still 1; a breaking fix bumps `proto` to 2 and the crate to 0.8.0.

---

## 8. Security considerations (summary of decisions)

- The safety-word ritual is never skipped, only **relocated** (to the
  embedding app's UI) or **replaced by an equivalent out-of-band check**
  (`--expect`, where the invitation channel carrying address+fingerprint is
  the anchor). Auto-accept-everything is deliberately not offered.
- Pre-accept inbound text stays suppressed in headless — the countermeasure
  matters *more* when a program relays the verify screen.
- Pins live per config dir, so an application's TOFU state is isolated from
  the human's; `--ephemeral` never trusts silently (everything is `new`).
- The existing caveat that a local attacker can rewrite `contacts` applies
  unchanged to app-owned config dirs, and is already documented in the README.
- Payloads are the application's business: kiss_chat delivers sanitised text;
  a chess app must still treat `{"move":…}` from the peer as untrusted input
  (say so in the README's headless section and the Python example).
- The unaudited-primitives disclaimer (ml-kem / ml-dsa crates) carries over
  verbatim: casual projects, not hardened production.

## 9. Risks and open questions

| Risk | Mitigation |
|---|---|
| QUIC idle timeout kills long-think sessions (chess!) | Phase 4.5 soak test before release; endpoint keepalive config in `transport` if needed. |
| serde_json dependency growth in the binary crate | Accepted: correctness of JSON escaping beats hand-rolling; core stays serde-free. |
| Parent never reads stdout → child stalls | By design (backpressure); documented for integrators. |
| Windows stdio quirks (CRLF, EOF signalling) | Tolerant input framing (§4.1); binary smoke test runs on the Windows CI leg. |
| No peer-accept ack in the wire protocol | Documented gap + app-level hello convention (§4.4); protocol-level ack is future work. |
| Two processes sharing one identity dir | Hard-refused in headless (§3.3); README warns for the TUI. |

## 10. Future work (explicitly out of scope)

- A protocol-level *accepted* control frame (new message tag — a coordinated
  wire change, since unknown tags currently read as `Malformed` and disconnect).
- A documented offline/LAN mode (`--offline`) promoting the test-only direct
  dialing path to a user feature — no relay/discovery infrastructure at all.
- PyO3 / N-API bindings to `kiss_chat_core` for in-process embedding.
- Group sessions, file transfer, message history — per the README's existing
  "Not (yet) included" list.
