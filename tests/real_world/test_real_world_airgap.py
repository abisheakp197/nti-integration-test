import json
import socket
from typing import Any

import pytest
import ube_foundation


class AirgapNetworkBlocked(socket.socket):
    """Socket wrapper that blocks outgoing network connections to simulate airgap."""

    def connect(self, address: Any) -> None:
        raise OSError("Airgapped environment: network connection blocked")

    def connect_ex(self, address: Any) -> int:
        return 111  # Connection refused


@pytest.mark.real_world
def test_real_world_airgap_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify signed attestation report on an airgapped environment with network socket blocked."""
    keypair = ube_foundation.PqcKeyPair()
    report_data = {
        "spec": "NTI-Report/1",
        "agent_id": "airgap-agent-01",
        "score": 98,
        "issuer_pubkey": keypair.public_key_hex(),
    }

    message_bytes = json.dumps(report_data, sort_keys=True).encode("utf-8")
    sig_hex: str = keypair.sign(message_bytes)

    # Simulate airgap / offline mode by monkeypatching socket.socket
    monkeypatch.setattr(socket, "socket", AirgapNetworkBlocked)

    # Prove network call attempts fail
    with pytest.raises(OSError, match="Airgapped environment"):
        s = socket.socket()
        s.connect(("8.8.8.8", 53))

    # Perform signature verification in airgapped state
    assert keypair.verify(message_bytes, sig_hex) is True
