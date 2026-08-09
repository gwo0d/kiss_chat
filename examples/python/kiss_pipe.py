"""A tiny Python wrapper around `kiss_chat --headless`.

Standard library only — the point of the headless mode is that talking to it
needs nothing but a subprocess and JSON.

    from kiss_pipe import KissChat

    with KissChat(ephemeral=True) as chat:
        print("my address:", chat.address)
        print("my fingerprint:", chat.fingerprint)
        chat.connect(peer_address)
        for event in chat.events():
            ...

Security note: everything that arrives from a peer is untrusted input. kiss_chat
authenticates and decrypts it, and strips control characters, but the *meaning*
of a message is your application's business — validate it as you would anything
off a network socket.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Iterator


class KissChatError(RuntimeError):
    """The kiss_chat process could not be started or died unexpectedly."""


class KissChat:
    """A running `kiss_chat --headless` process.

    The process lives as long as this object: closing it (or leaving the `with`
    block) shuts the connection down cleanly, telling the peer we've gone.
    """

    def __init__(
        self,
        *,
        config_dir: str | None = None,
        ephemeral: bool = False,
        expect: list[str] | None = None,
        name: str | None = None,
        once: bool = False,
        peer: str | None = None,
        binary: str = "kiss_chat",
    ) -> None:
        if (config_dir is None) == (not ephemeral):
            raise ValueError(
                "choose exactly one of config_dir=... (a persistent identity) "
                "or ephemeral=True (a throwaway one)"
            )
        if shutil.which(binary) is None and "/" not in binary:
            raise KissChatError(
                f"{binary!r} is not on PATH — install it with `cargo install kiss_chat`, "
                "or pass binary='/path/to/kiss_chat'"
            )

        argv: list[str] = [binary, "--headless"]
        if ephemeral:
            argv.append("--ephemeral")
        else:
            argv += ["--config-dir", str(config_dir)]
        for fingerprint in expect or []:
            argv += ["--expect", fingerprint]
        if name is not None:
            argv += ["--name", name]
        if once:
            argv.append("--once")
        if peer is not None:
            argv.append(peer)

        self._process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,  # line buffered: one JSON object per line, both ways
        )

        ready = self._read_event()
        if ready is None or ready.get("event") != "ready":
            raise KissChatError(f"expected a ready event, got: {ready!r}")
        self.proto: int = ready["proto"]
        self.address: str = ready["address"]
        self.fingerprint: str = ready["fingerprint"]
        self.direct_addrs: list[str] = ready.get("direct_addrs", [])

    # --- reading events ---------------------------------------------------

    def _read_event(self) -> dict[str, Any] | None:
        """The next event, or None once the process has finished."""
        assert self._process.stdout is not None
        line = self._process.stdout.readline()
        if not line:
            return None
        return json.loads(line)

    def events(self) -> Iterator[dict[str, Any]]:
        """Yield events until the process exits.

        Unknown event types are yielded like any other: a newer kiss_chat may
        emit events this wrapper predates, and ignoring what you don't
        recognise is how the protocol stays compatible.
        """
        while True:
            event = self._read_event()
            if event is None:
                return
            yield event

    def wait_for(self, *names: str) -> dict[str, Any]:
        """Read events until one of `names` arrives, and return it."""
        for event in self.events():
            if event["event"] in names:
                return event
        raise KissChatError(f"process ended while waiting for {names}")

    # --- sending commands -------------------------------------------------

    def _send(self, **command: Any) -> None:
        assert self._process.stdin is not None
        if self._process.poll() is not None:
            raise KissChatError("kiss_chat has exited")
        self._process.stdin.write(json.dumps(command) + "\n")
        self._process.stdin.flush()

    def connect(self, peer: str, addrs: list[str] | None = None) -> None:
        """Dial a peer by address, optionally at explicit `ip:port` addresses."""
        if addrs:
            self._send(cmd="connect", peer=peer, addrs=addrs)
        else:
            self._send(cmd="connect", peer=peer)

    def accept(self) -> None:
        """Accept the peer being verified.

        Only do this once your user has confirmed the safety words from the
        `verify` event match what their peer reads out — that comparison is what
        the security of the channel rests on.
        """
        self._send(cmd="accept")

    def reject(self) -> None:
        """Reject the peer being verified."""
        self._send(cmd="reject")

    def send(self, text: str) -> None:
        """Send a chat message. Only valid after the `connected` event."""
        self._send(cmd="send", text=text)

    def send_json(self, payload: Any) -> None:
        """Send any JSON-serialisable payload as a message."""
        self.send(json.dumps(payload))

    # --- lifecycle --------------------------------------------------------

    def close(self, timeout: float = 5.0) -> int:
        """Say goodbye to the peer and wait for the process to exit."""
        if self._process.poll() is None:
            try:
                self._send(cmd="quit")
            except (KissChatError, BrokenPipeError, ValueError):
                pass
            if self._process.stdin is not None:
                try:
                    self._process.stdin.close()
                except BrokenPipeError:
                    pass
            try:
                self._process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
        return self._process.returncode

    def __enter__(self) -> "KissChat":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
