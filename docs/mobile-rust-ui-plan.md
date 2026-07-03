# kiss_chat — All-Rust Mobile UI: Implementation Plan

> Status: proposal / first-step plan. No code changes yet — this document is the
> deliverable for the "write a detailed implementation plan" step.
>
> Scope: a small, lightweight, cross-platform (iOS + Android) mobile frontend built
> **entirely in Rust**, sharing the existing crypto/transport/protocol core with the
> terminal CLI. The CLI remains the primary interface; the mobile app is strictly
> additive.

## 1. Goals, non-goals, constraints

**Goals**

- One mobile app, all-Rust, running on both iOS and Android.
- Reuse the existing, security-critical core (handshake, encryption, P2P transport)
  byte-for-byte — no re-implementation of anything cryptographic.
- Keep the CLI working exactly as today. It and the mobile app become two thin UIs
  over one shared engine.
- Preserve the project ethos: small, readable, few dependencies, nothing clever you
  have to reverse-engineer.

**Non-goals (for this plan)**

- No servers, relays, or push infrastructure of our own (kiss_chat stays serverless).
- No group chat, on-disk message history, or file transfer — out of scope, unchanged
  from the CLI's "Not (yet) included" list.
- No web/JS UI, no Flutter/Dart, no native SwiftUI/Compose. This plan is the all-Rust
  route specifically.

**Hard constraints that shape the design**

- **Mobile background execution is restricted.** kiss_chat has no push server by
  design, so a peer is reachable only while the app is in the foreground (and, on
  Android, optionally under a foreground Service). "Message arrives while the phone is
  locked" is out of reach without violating the no-servers principle. We design around
  this rather than fighting it (see §9).
- **Secrets must not sit in a plaintext file on mobile.** The two 32-byte secrets
  (`secret.key`, `auth.key`) move behind the platform keystore (iOS Keychain / Android
  Keystore). This is the one genuinely invasive change to existing modules.

## 2. Guiding principle: one engine, many UIs

Today the code is already a library + thin binary, cleanly layered:

```
crypto · proto · message · transport   ← pure, UI-agnostic, already portable
identity · contacts                     ← portable logic, filesystem-bound storage
app.rs (event_loop)                     ← orchestration, but wired to ratatui types
ui.rs (ratatui)                         ← terminal only
```

The single structural idea of this whole plan: **extract the orchestration in
`app.rs` into a headless `engine` that speaks in `Command`/`Event` values instead of
ratatui's `Action`/`NetEvent`.** Both the CLI and the mobile UI then become
translators — key/tap → `Command`, `Event` → screen update — over the same engine.

```
            ┌───────────────────────── kiss_chat_core ─────────────────────────┐
            │  crypto  proto  message  transport  identity  contacts            │
            │                         │                                         │
            │                    engine (async)  ── Command in / Event out ──   │
            └───────────────────────────────────────────────────────────────────┘
                        ▲                                     ▲
                        │ Command / Event                     │ Command / Event
             ┌──────────┴───────────┐              ┌──────────┴───────────┐
             │  CLI UI (ratatui)    │              │  Mobile UI (Slint)   │
             │  src/main.rs         │              │  desktop + iOS +      │
             │                      │              │  Android              │
             └──────────────────────┘              └──────────────────────┘
```

The networking tasks in `app.rs` — `dial_and_handshake`, `accept_and_handshake`,
`spawn_reader`, `spawn_writer`, `farewell`, `arm_accept` — are **already
UI-independent** (they touch only `crypto`/`proto`/`transport`/`message`). The only
ratatui coupling lives in `event_loop`, so the extraction is real but contained.

## 3. Target repository layout

A Cargo **workspace**, staged so the CLI never breaks:

```
kiss_chat/                      (workspace root; Cargo.toml = [workspace])
├── crates/
│   ├── kiss-chat-core/         library: crypto, proto, message, transport,
│   │                           identity, contacts, engine, storage trait
│   ├── kiss-chat-cli/          binary: ratatui UI + main.rs (today's app)
│   └── kiss-chat-mobile/       Slint UI; builds as:
│                                 • desktop binary (dev/iteration)
│                                 • cdylib/staticlib for Android & iOS
└── docs/
    └── mobile-rust-ui-plan.md  (this file)
```

Staging note: the split can be done in two commits without a big-bang move — first
add the `engine` + `storage` modules inside the current crate and rewire `main.rs`
(CLI still ships), then physically split into workspace crates once the mobile crate
needs `kiss-chat-core` as a dependency. `crates.io` publishing of `kiss_chat` stays
possible: publish `kiss-chat-cli` (or keep the umbrella crate name on the CLI).

## 4. The headless engine API

New module `kiss-chat-core/src/engine.rs`. It owns the tokio machinery currently in
`event_loop` and exposes a channel pair. Sketch (names/shape, not final):

```rust
/// Commands a UI sends into the engine.
pub enum Command {
    Connect(String),          // dial a peer id (text form of an EndpointId)
    Accept,                   // accept the peer under verification
    Reject,                   // reject and return to the lobby
    Send(String),             // send a chat line
    SetName(Option<String>),  // set/clear our display name
    ListContacts,             // request the known-peers list
    Quit,                     // graceful shutdown (farewell if connected)
}

/// Events the engine emits to whichever UI is attached.
pub enum Event {
    Address(String),                 // our own address, at startup
    Lobby(String),                   // back in the lobby, with a reason
    Connecting { peer_short: String },
    Verifying {                      // channel up, held at the trust gate
        peer_short: String,
        safety_words: String,        // the 12-word phrase, verbatim
        pin: contacts::PinStatus,    // New / Known / Changed
        known_name: Option<String>,
    },
    PeerMessage { text: String, at_utc: String },
    PeerName(Option<String>),
    System(String),                  // ordinary status chatter
    Warning(String),                 // security-relevant notice (e.g. changed key)
    Disconnected(String),
    Contacts(Vec<contacts::KnownPeer>),
}

/// Handle returned by `Engine::start`.
pub struct Engine {
    pub commands: tokio::sync::mpsc::Sender<Command>,
    pub events:   tokio::sync::mpsc::Receiver<Event>,
}

impl Engine {
    /// Bind the endpoint, load identity via `store`, arm the listener, optionally
    /// auto-dial, and run the select loop until `Command::Quit`.
    pub async fn start(store: Arc<dyn KeyStore>, dial: Option<String>) -> Result<Engine>;
}
```

Internally, `Engine::start` moves the body of `event_loop` almost verbatim, replacing:

- `terminal.draw(... app.render ...)` → nothing (the engine has no view);
- `app.on_key(key)` → reading a `Command` off the inbound channel;
- every `app.push_*` / `app.set_*` call → emitting the corresponding `Event`;
- `identity::*` / `contacts::*` free calls → methods on the injected `store` (§5).

The `LiveSession`, `ConnResult`, `Established` structs and the three `tokio::select!`
arms (input → now command; `conn_rx`; `net_rx`) carry over unchanged in spirit. This
keeps the exact, already-reviewed connection lifecycle (arm/abort listener, farewell,
backpressure via the bounded `NET_EVENT_QUEUE`).

**CLI after the refactor:** `ui.rs` keeps its `App` state machine, but `main.rs` (or a
slim `cli.rs`) becomes: spawn `Engine`, forward crossterm keys as `Command`s, and map
`Event`s onto `app.push_*` / `app.set_*`. No behavioural change; the existing
integration tests still exercise the layers beneath the engine.

## 5. Storage abstraction (the one invasive change)

`identity.rs` and `contacts.rs` already thread a directory through internal
`*_in(dir: &Path)` helpers — the public functions are just `config_dir()` + `*_in`.
We formalise that seam as a trait so mobile can supply a different backend:

```rust
pub trait KeyStore: Send + Sync {
    // secrets
    fn endpoint_secret(&self) -> Result<iroh::SecretKey>;   // load-or-create
    fn auth_seed(&self) -> Result<[u8; 32]>;                // load-or-create
    // non-secret prefs
    fn display_name(&self) -> Result<Option<String>>;
    fn set_display_name(&self, name: Option<&str>) -> Result<()>;
    // contacts (pinning / TOFU)
    fn recognize(&self, address: &str, key: &[u8]) -> Result<contacts::Recognition>;
    fn remember(&self, address: &str, key: &[u8]) -> Result<()>;
    fn set_contact_name(&self, address: &str, name: Option<&str>) -> Result<()>;
    fn known_peers(&self) -> Result<Vec<contacts::KnownPeer>>;
}
```

- **`FileStore` (CLI / desktop):** thin wrapper over the existing `*_in(config_dir())`
  functions. Behaviour identical to today — zero user-visible change.
- **`MobileStore` (iOS / Android):**
  - The two 32-byte secrets live in the **platform keystore** — iOS Keychain
    (`kSecClassGenericPassword`, `WhenUnlockedThisDeviceOnly`) and Android Keystore /
    `EncryptedSharedPreferences`. Reached from Rust via a tiny FFI shim per platform
    (Objective-C/Swift bridge on iOS; JNI on Android). This is new code but small and
    well-trodden.
  - The non-secret `contacts` and `name` stay as files in the app sandbox
    (`FileManager`/`Context.filesDir`) — reuse `*_in(sandbox_dir)` directly.

Everything above the trait (engine, crypto, transport) is unaffected.

## 6. UI toolkit: Slint (recommended), with egui as the fallback

For an all-Rust, *lightweight*, battery-conscious mobile UI, **Slint** is the best
fit and the recommendation:

- Official **iOS and Android** support; ships an Android template and a Winit/Skia
  iOS backend.
- **Retained/declarative** UI (`.slint` markup) → redraws only on change, which is
  kind to battery — unlike an immediate-mode loop.
- Clean separation: layout in `.slint`, logic in Rust, wired by generated typed
  bindings. Matches kiss_chat's "small and readable" ethos.
- Small runtime, no web engine, no JS.

**Fallback: egui/eframe.** Simpler to stand up and excellent for a desktop prototype,
but immediate-mode continuous redraw is heavier on battery and its iOS packaging story
is rougher. Good for M3's throwaway prototype if Slint's iOS path hits friction; not
the recommended shipping choice.

(Dioxus native is maturing but its mobile story is younger than Slint's — not chosen.)

## 7. Screen design (mapped from the terminal UI)

Four screens, one-to-one with the CLI's `Mode` states so behaviour stays identical:

| CLI `Mode` | Mobile screen | Contents |
|---|---|---|
| `Lobby` | **Home** | Your address (copy button + QR to share/scan), "Connect to peer" field/scan, `/contacts` list, name setting |
| `Connecting` | **Connecting** | Spinner + short peer id, cancel → back to Home |
| `Verifying` | **Verify gate** | The 12 **safety words** in a bold numbered grid; `New`/`Changed`/`Known` badge; Accept / Reject buttons. `Changed` shows the prominent warning; `Known` shows the light re-connect consent + cached name |
| `Connected` | **Chat** | Scrolling history (You/Peer/System/Warning styles), UTC timestamps, input + send, status bar with peer name, a "safety words" affordance (the `/safety` equivalent) |

Command mapping: buttons/fields emit the same `Command`s the CLI derives from
`/connect`, `/accept`, `/reject`, `/name`, `/contacts`, `/safety`, `/quit`. QR
scan/share is a mobile-only convenience over the same address string — no protocol
change.

## 8. Async runtime ↔ UI event loop

Slint runs its own event loop on the UI thread; tokio runs the engine off-thread:

1. Start a multi-thread tokio runtime on a background thread; `Engine::start` runs
   there and owns all networking.
2. **UI → engine:** Slint callbacks (tap/send) push `Command`s onto the engine's
   `commands` sender (cloned into the callbacks).
3. **Engine → UI:** a small forwarder task drains `events` and marshals each onto the
   Slint thread via `slint::invoke_from_event_loop` + a `slint::Weak<MainWindow>`,
   updating view-models (history model, status, safety words).

This mirrors the CLI's current three-source `select!` — just with the "view" on the
far side of a thread boundary instead of a `terminal.draw`.

## 9. Lifecycle & the background-execution caveat

Honest, simple behaviour rather than fragile background hacks:

- **Foreground = online.** A live session is scoped to the app being active.
- **On background/suspend:** send `Bye` (reuse `farewell`) and tear the session down
  cleanly so the peer sees "peer left the chat" rather than a stall. Persisted
  identity means reconnecting is one tap.
- **On resume:** return to Home (or offer "reconnect to last peer").
- **Android** may optionally hold a **foreground Service** (with the standard ongoing
  notification) to keep a socket alive during an active chat; still not a substitute
  for push.
- **iOS** gets no general background sockets without VoIP/push entitlements we won't
  add — foreground-only is the documented, expected behaviour.

The UI copy should set this expectation plainly (a one-line "you're reachable while
kiss_chat is open").

## 10. Platform build & packaging

- **Android:** build `kiss-chat-mobile` as a `cdylib` for the NDK targets
  (`aarch64-linux-android`, `armv7`, `x86_64`); package with `cargo-ndk` + Gradle (or
  `cargo-apk`/`xbuild`) using Slint's Android template. Manifest permission:
  `INTERNET` (UDP for iroh). JNI shim for Keystore.
- **iOS:** build a `staticlib`/`cdylib`, wrap in an Xcode project (Slint iOS
  instructions / `cargo-xcode`), produce an `.app`/`.ipa`. Device builds need signing;
  simulator builds don't. Objective-C/Swift shim for Keychain.
- **Desktop (dev):** `kiss-chat-mobile` also builds as a normal desktop binary so the
  whole UI can be iterated with `slint-viewer` live preview — no device round-trip for
  most work.
- **Crypto export compliance:** the app uses standardised PQC (ML-KEM/ML-DSA) +
  ChaCha20-Poly1305; expect the routine App Store / Play export-compliance
  questionnaire. Note it; no code impact.

## 11. Testing strategy

- **Core (unchanged):** existing unit + loopback integration tests keep passing; they
  live below the engine and are untouched by the refactor.
- **Engine:** new integration test driving **two `Engine`s over iroh loopback** purely
  through `Command`/`Event` — connect → verify → accept → round-trip → `Bye`. This is
  the CLI's behaviour asserted at the new API boundary and is the regression guard for
  the extraction.
- **Storage:** `FileStore` tested against a temp dir (mirrors current `*_in` tests);
  `MobileStore` secret round-trip tested on emulator/simulator in CI.
- **UI:** Slint live-preview for manual screen work; optional interaction snapshots.
  Keep UI logic thin so most behaviour is covered at the engine layer.

## 12. Milestones (each an independently shippable step)

| # | Milestone | Deliverable / exit criteria |
|---|---|---|
| **M0** | **De-risk spike** | Cross-compile `crypto` + `transport` to an iOS simulator and an Android emulator; run the existing loopback handshake test on-device. **Gate:** iroh completes a P2P handshake from a phone (incl. a real cellular/NAT check). Everything else depends on this. |
| **M1** | Headless engine | `engine.rs` added; `event_loop` guts moved in; CLI rewired to `Command`/`Event`; all existing tests green + new engine loopback test. **No CLI behaviour change.** (Safe first PR.) |
| **M2** | Storage trait | `KeyStore` + `FileStore`; engine takes `Arc<dyn KeyStore>`; CLI unchanged in behaviour. |
| **M3** | Desktop Slint prototype | All four screens driven by the engine on desktop; feature parity with the CLI. Fast iteration, no device needed. |
| **M4** | Android | `cdylib` + `cargo-ndk` + Slint Android; `MobileStore` Keystore secrets; APK built in CI; on-device chat works. |
| **M5** | iOS | Xcode packaging; Keychain secrets; unsigned build in CI on a macOS runner; on-device/simulator chat works. |
| **M6** | Lifecycle & polish | Foreground/background handling, reconnect UX, QR share/scan, safety-word screen, accessibility, release packaging + docs. |

## 13. CI additions

Extend the existing GitHub Actions:

- Keep `cargo test` / `cargo clippy` for the core (already present).
- Add a desktop build of `kiss-chat-mobile` (fast feedback on the UI crate).
- Android job: `cargo-ndk` build → APK artifact.
- iOS job on `macos-latest`: build the app (unsigned) → artifact.

## 14. Risks & open questions

| Risk | Severity | Mitigation |
|---|---|---|
| iroh P2P doesn't work reliably from mobile / cellular NAT | **High** | M0 spike gates the whole effort before UI work starts |
| iOS background socket limits surprise users | Medium | Foreground-only by design; set expectation in UI copy (§9) |
| Slint iOS maturity / packaging friction | Medium | Desktop-first prototype (M3); egui fallback for the prototype if needed |
| Keychain/Keystore FFI complexity | Medium | Small, well-trodden shims; isolate behind `MobileStore` |
| Binary size / startup with PQC + Slint + iroh | Low–Med | Existing release profile already `lto`/`strip`; measure in M4/M5 |
| App Store crypto export review | Low | Standard questionnaire; note in submission |

**Open questions to settle before M3:** (a) QR for address exchange in v1, or plain
copy/paste only? (b) Android foreground Service in v1, or strictly foreground-only to
match iOS? (c) Publish shape on crates.io after the workspace split.

## 15. Rough effort

Spike M0: ~1–2 days (and it's the go/no-go gate). M1–M2: ~1 week. M3: ~1–2 weeks.
M4: ~1 week. M5: ~1–2 weeks. M6: ~1 week. Order-of-magnitude: **~6–8 weeks of
part-time work** to a working cross-platform app, with the crypto/transport risk
retired up front by the spike.

## 16. Recommended immediate next step

Do **M1 first as a pure refactor** (headless engine + CLI rewired, no mobile code) —
it's low-risk, keeps the CLI shipping, and is the foundation everything else sits on —
**in parallel** with the M0 spike, which is the real go/no-go signal. If the spike
shows iroh won't traverse from a phone, we learn it before investing in UI.
</content>
</invoke>
