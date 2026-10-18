import socket
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Any

import httpx
import pytest


class AbortingHTTPHandler(BaseHTTPRequestHandler):
    """HTTP Handler that forcibly closes socket connection to simulate server process kill mid-request."""

    def do_GET(self) -> None:
        # Abruptly close underlying connection before completing HTTP response
        try:
            self.request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.request.close()

    def log_message(self, format: str, *args: Any) -> None:
        pass


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


@pytest.mark.chaos
def test_chaos_badge_server_killed_mid_request() -> None:
    """Kill badge server mid-request and verify client catches connection error cleanly."""
    port = _find_free_port()
    server = HTTPServer(("127.0.0.1", port), AbortingHTTPHandler)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        url = f"http://127.0.0.1:{port}/badge.svg"
        client = httpx.Client(timeout=2.0)

        with pytest.raises((httpx.RemoteProtocolError, httpx.RequestError, httpx.HTTPError, httpx.ReadError)) as exc_info:
            client.get(url)

        assert exc_info.type in (
            httpx.RemoteProtocolError,
            httpx.ReadError,
            httpx.ConnectError,
            httpx.RequestError,
            httpx.HTTPError,
        )
    finally:
        server.shutdown()
        server.server_close()
        client.close()


@pytest.mark.chaos
def test_chaos_badge_server_restart_recovery() -> None:
    """Kill server mid-request and prove client recovers once server restarts."""
    port = _find_free_port()

    # Phase 1: Server running
    class OkHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            resp = b"<svg>ok</svg>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def log_message(self, format: str, *args: Any) -> None:
            pass

    server1 = HTTPServer(("127.0.0.1", port), OkHandler)
    t1 = Thread(target=server1.serve_forever, daemon=True)
    t1.start()

    client = httpx.Client(timeout=5.0)
    res1 = client.get(f"http://127.0.0.1:{port}")
    assert res1.status_code == 200

    # Phase 2: Kill server
    server1.shutdown()
    server1.server_close()

    with pytest.raises(httpx.RequestError):
        client.get(f"http://127.0.0.1:{port}")

    # Phase 3: Restart server and prove client recovers
    server2 = HTTPServer(("127.0.0.1", port), OkHandler)
    t2 = Thread(target=server2.serve_forever, daemon=True)
    t2.start()

    try:
        time.sleep(0.1)
        res2 = client.get(f"http://127.0.0.1:{port}")
        assert res2.status_code == 200
        assert b"<svg>ok</svg>" in res2.content
    finally:
        server2.shutdown()
        server2.server_close()
        client.close()
