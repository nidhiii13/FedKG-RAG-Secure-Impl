import socket
import threading
import time
from pathlib import Path

import pytest

from doram_t2_3pc.wan_emulation import (
    ThreePartyProxyNetwork,
    TcpWanProxy,
    WanProfile,
)


def require_loopback_socket() -> None:
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except PermissionError:
        pytest.skip("sandbox forbids local sockets")
    else:
        probe.close()


def test_wan_profile_validation_and_metadata():
    profile = WanProfile("regional_20ms", 20, 100)
    assert profile.one_way_delay_seconds == pytest.approx(0.01)
    assert profile.bytes_per_second == pytest.approx(12_500_000)
    assert profile.as_dict()["emulator"] == "userspace TCP payload proxy"
    with pytest.raises(ValueError):
        WanProfile("bad profile", 20, 100)
    with pytest.raises(ValueError):
        WanProfile("bad", -1, 100)
    with pytest.raises(ValueError):
        WanProfile("bad", 1, 0)


def test_three_party_hosts_route_higher_parties_through_proxies(tmp_path: Path):
    require_loopback_socket()
    with ThreePartyProxyNetwork(WanProfile("test", 0, 1000), tmp_path) as network:
        files = [
            [line.strip() for line in network.hosts_file(i).read_text().splitlines()]
            for i in range(3)
        ]
        assert len(files) == 3
        assert all(len(lines) == 3 for lines in files)
        assert files[1][0].rsplit(":", 1)[1] == str(network.proxies[(1, 0)].port)
        assert files[2][0].rsplit(":", 1)[1] == str(network.proxies[(2, 0)].port)
        assert files[2][1].rsplit(":", 1)[1] == str(network.proxies[(2, 1)].port)
        assert files[0][0].rsplit(":", 1)[1] == str(network.backend_ports[0])


def test_tcp_proxy_forwards_bidirectionally_with_delay():
    require_loopback_socket()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    backend_port = listener.getsockname()[1]

    def echo() -> None:
        connection, _ = listener.accept()
        with connection:
            connection.sendall(connection.recv(1024))
        listener.close()

    thread = threading.Thread(target=echo, daemon=True)
    thread.start()
    profile = WanProfile("delay", 20, 1000)
    with TcpWanProxy(("127.0.0.1", backend_port), profile) as proxy:
        with socket.create_connection(("127.0.0.1", proxy.port)) as client:
            started = time.perf_counter()
            client.sendall(b"hello")
            assert client.recv(5) == b"hello"
            elapsed = time.perf_counter() - started
    thread.join(timeout=1)
    assert elapsed >= 0.018
