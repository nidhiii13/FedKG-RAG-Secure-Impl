"""Unprivileged TCP-link emulation for local MP-SPDZ experiments.

This module is deliberately a userspace fallback for machines where isolated
Linux network namespaces and ``tc netem`` are unavailable.  It delays and
rate-limits the byte streams between parties, but it is not a packet-level WAN
emulator and must not be described as a real multi-host deployment.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


@dataclass(frozen=True)
class WanProfile:
    """Symmetric link parameters for a three-party TCP experiment."""

    name: str
    rtt_ms: float
    bandwidth_mbps: float

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("_", "").replace("-", "").isalnum():
            raise ValueError("profile name must contain letters, digits, '_' or '-'")
        if self.rtt_ms < 0:
            raise ValueError("rtt_ms must be non-negative")
        if self.bandwidth_mbps <= 0:
            raise ValueError("bandwidth_mbps must be positive")

    @property
    def one_way_delay_seconds(self) -> float:
        return self.rtt_ms / 2000.0

    @property
    def bytes_per_second(self) -> float:
        return self.bandwidth_mbps * 1_000_000 / 8

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "configured_rtt_ms": self.rtt_ms,
            "configured_bandwidth_mbps_per_direction": self.bandwidth_mbps,
            "emulator": "userspace TCP payload proxy",
            "packet_loss_percent": 0,
            "jitter_ms": 0,
            "limitations": (
                "Models propagation delay and serialization rate on established "
                "TCP byte streams; does not model TCP handshake delay, packet loss, "
                "kernel queueing, route variation, or independently administered hosts."
            ),
        }


def reserve_tcp_port() -> int:
    """Return a currently unused loopback TCP port."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class TcpWanProxy:
    """Bidirectional TCP proxy with symmetric delay and per-direction rate."""

    def __init__(
        self,
        destination: tuple[str, int],
        profile: WanProfile,
        *,
        listen_port: int = 0,
        connect_timeout: float = 60,
    ) -> None:
        self.destination = destination
        self.profile = profile
        self.connect_timeout = connect_timeout
        self.requested_port = listen_port
        self.port = 0
        self._ready = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop: asyncio.Event | None = None
        self._failure: BaseException | None = None
        self._thread = threading.Thread(target=self._thread_main, daemon=True)

    def start(self) -> None:
        self._thread.start()
        if not self._ready.wait(timeout=5):
            raise RuntimeError("TCP WAN proxy did not start")
        if self._failure is not None:
            raise RuntimeError("TCP WAN proxy failed to start") from self._failure

    def close(self) -> None:
        if self._loop is not None and self._stop is not None:
            self._loop.call_soon_threadsafe(self._stop.set)
        self._thread.join(timeout=5)

    def __enter__(self) -> "TcpWanProxy":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _thread_main(self) -> None:
        try:
            asyncio.run(self._serve())
        except BaseException as exc:
            self._failure = exc
            self._ready.set()

    async def _serve(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._stop = asyncio.Event()
        server = await asyncio.start_server(
            self._handle, "127.0.0.1", self.requested_port, backlog=256
        )
        self.port = int(server.sockets[0].getsockname()[1])
        self._ready.set()
        await self._stop.wait()
        server.close()
        await server.wait_closed()
        current = asyncio.current_task()
        pending = [
            task for task in asyncio.all_tasks() if task is not current and not task.done()
        ]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    async def _connect_destination(
        self,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        deadline = time.monotonic() + self.connect_timeout
        while True:
            try:
                return await asyncio.open_connection(*self.destination)
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                await asyncio.sleep(0.02)

    async def _handle(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        try:
            upstream_reader, upstream_writer = await self._connect_destination()
        except OSError:
            client_writer.close()
            await client_writer.wait_closed()
            return
        await asyncio.gather(
            self._relay(client_reader, upstream_writer),
            self._relay(upstream_reader, client_writer),
        )

    async def _relay(
        self, source: asyncio.StreamReader, destination: asyncio.StreamWriter
    ) -> None:
        next_delivery = 0.0
        try:
            while True:
                data = await source.read(64 * 1024)
                if not data:
                    break
                now = time.monotonic()
                serialization = len(data) / self.profile.bytes_per_second
                delivery = max(now + self.profile.one_way_delay_seconds, next_delivery)
                next_delivery = delivery + serialization
                remaining = delivery - now
                if remaining > 0:
                    await asyncio.sleep(remaining)
                destination.write(data)
                await destination.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            with contextlib.suppress(OSError, RuntimeError):
                destination.write_eof()


class ThreePartyProxyNetwork:
    """Create the directed proxies used by MP-SPDZ's higher-to-lower links."""

    def __init__(self, profile: WanProfile, directory: Path) -> None:
        self.profile = profile
        self.directory = directory
        self.backend_ports = [reserve_tcp_port() for _ in range(3)]
        # MP-SPDZ party j connects to every party i where i < j.
        self.proxies = {
            (source, destination): TcpWanProxy(
                ("127.0.0.1", self.backend_ports[destination]), profile
            )
            for source in range(3)
            for destination in range(source)
        }

    def __enter__(self) -> "ThreePartyProxyNetwork":
        self.directory.mkdir(parents=True, exist_ok=True)
        for proxy in self.proxies.values():
            proxy.start()
        for party in range(3):
            lines = []
            for destination in range(3):
                if destination == party:
                    port = self.backend_ports[destination]
                elif destination < party:
                    port = self.proxies[(party, destination)].port
                else:
                    # Higher-number parties initiate these connections, so this
                    # entry is never used by this party.
                    port = self.backend_ports[destination]
                lines.append(f"127.0.0.1:{port}")
            (self.directory / f"hosts_party_{party}.txt").write_text(
                "\n".join(lines) + "\n", encoding="utf-8"
            )
        return self

    def __exit__(self, *_: object) -> None:
        for proxy in self.proxies.values():
            proxy.close()

    def hosts_file(self, party: int) -> Path:
        if party not in range(3):
            raise ValueError("party must be 0, 1, or 2")
        return self.directory / f"hosts_party_{party}.txt"


def copy_stream(source: BinaryIO, destination: BinaryIO) -> None:
    """Compatibility helper retained for simple proxy calibration tools."""

    while block := source.read(64 * 1024):
        destination.write(block)
        destination.flush()
