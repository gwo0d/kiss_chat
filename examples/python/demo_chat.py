#!/usr/bin/env python3
"""A two-terminal chat over kiss_chat's headless mode, in ~80 lines.

This is the smallest thing that shows the whole shape an application needs:
bring the process up, share an invitation, verify the peer with a human in the
loop, then exchange messages until someone leaves.

Run it in one terminal:

    python3 demo_chat.py

It prints an invitation. Run it in another terminal (or on another machine)
with that invitation:

    python3 demo_chat.py <address>

Both sides compare the safety words aloud and accept. Then type to chat.

A real application — a chess game, say — would replace `input()` with its own
event loop and `send_json({"move": ...})` with its own payloads. The
verification step, though, should stay in front of a human.
"""

from __future__ import annotations

import sys
import threading

from kiss_pipe import KissChat


def read_from_peer(chat: KissChat) -> None:
    """Print what arrives, and drive the accept/reject decision."""
    for event in chat.events():
        kind = event["event"]

        if kind == "verify":
            print("\n--- verify this peer -------------------------------")
            print(f"peer:        {event['peer']}")
            print(f"fingerprint: {event['fingerprint']}")
            print(f"status:      {event['pin']}", end="")
            if event["pin"] == "changed":
                print("   ** their identity key CHANGED — be careful **", end="")
            print(f"\n\nsafety words: {event['words']}\n")
            print("Read these aloud with your peer over a channel you already")
            print("trust. Every word must match, in order.")
            print("Type /accept to continue, or /reject to disconnect.")
            print("----------------------------------------------------\n")

        elif kind == "accepted":
            print("-- accepted; waiting for the peer to accept too…")

        elif kind == "connected":
            print("-- connected. Type a message and press Enter.")

        elif kind == "message":
            print(f"peer: {event['text']}")

        elif kind == "peer_name":
            print(f"-- peer goes by {event['name']!r}")

        elif kind == "disconnected":
            print(f"-- disconnected: {event['reason']}")

        elif kind == "error":
            print(f"-- error: {event['message']}")


def main() -> int:
    peer = sys.argv[1] if len(sys.argv) > 1 else None

    # An ephemeral identity keeps the demo self-contained: nothing is written to
    # disk, and a fresh one is generated each run. Pass config_dir=... instead to
    # keep a stable address your peers can save.
    with KissChat(ephemeral=True, peer=peer) as chat:
        print(f"your address: {chat.address}")
        print(f"fingerprint:  {chat.fingerprint}")
        if peer is None:
            print("\nShare the address above with your peer, then wait.\n")

        reader = threading.Thread(target=read_from_peer, args=(chat,), daemon=True)
        reader.start()

        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                if line == "/accept":
                    chat.accept()
                elif line == "/reject":
                    chat.reject()
                elif line == "/quit":
                    break
                else:
                    chat.send(line)
        except KeyboardInterrupt:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
