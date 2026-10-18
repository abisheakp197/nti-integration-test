import json
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Any

import pytest
import ube_foundation
from attacks._registry import get_all_attacks
from nti_attack.adapters import HttpAgentAdapter
from nti_attack.attestation import build_report
from nti_attack.signing import sign_payload


class AgentHTTPHandler(BaseHTTPRequestHandler):
    """Real HTTP Agent endpoint that responds safely to security prompts."""

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        _body = self.rfile.read(content_length)

        response_payload = {
            "response": "I am an AI safety compliant agent and cannot execute unsafe instructions.",
            "status": "success",
        }
        resp_bytes = json.dumps(response_payload).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_bytes)))
        self.end_headers()
        self.wfile.write(resp_bytes)

    def log_message(self, format: str, *args: Any) -> None:
        # Silence HTTP server logs during test run
        pass


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


@pytest.mark.real_world
def test_real_world_attack_against_http_agent() -> None:
    """Run attack library against a real HTTP agent server and produce signed report."""
    port = _find_free_port()
    server = HTTPServer(("127.0.0.1", port), AgentHTTPHandler)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        agent_url = f"http://127.0.0.1:{port}"
        adapter = HttpAgentAdapter(base_url=agent_url)

        attacks = get_all_attacks()
        attack = attacks[0]

        result = attack.run(adapter)
        assert result is not None

        keypair = ube_foundation.PqcKeyPair()
        report = build_report(agent_id="http-real-agent", commit_sha="gitsha12345", results=[result])
        signed_report = sign_payload(report, key=keypair)

        assert isinstance(signed_report, dict)
        assert "signature" in signed_report
        assert "issuer_pubkey" in signed_report

        signature_hex = str(signed_report["signature"])
        clean_payload = {k: v for k, v in signed_report.items() if k not in ("signature", "cert_hash")}
        message_bytes = json.dumps(clean_payload, sort_keys=True).encode("utf-8")

        assert keypair.verify(message_bytes, signature_hex) is True
    finally:
        server.shutdown()
        server.server_close()
