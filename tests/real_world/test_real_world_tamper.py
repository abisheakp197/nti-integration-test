import json

import pytest
import ube_foundation


@pytest.mark.real_world
def test_real_world_tampered_cert_fails() -> None:
    """Verify that any modification to certificate score or issuer fails verification."""
    keypair_a = ube_foundation.PqcKeyPair()
    keypair_b = ube_foundation.PqcKeyPair()

    payload = {
        "agent_id": "production-agent-42",
        "score": 95,
        "repo": "enterprise/repo",
        "issuer_pubkey": keypair_a.public_key_hex(),
    }

    message_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    sig_hex: str = keypair_a.sign(message_bytes)

    # 1. Valid verification
    assert keypair_a.verify(message_bytes, sig_hex) is True

    # 2. Tampered score payload
    tampered_payload = dict(payload)
    tampered_payload["score"] = 100  # Elevate score artificially
    tampered_bytes = json.dumps(tampered_payload, sort_keys=True).encode("utf-8")
    assert keypair_a.verify(tampered_bytes, sig_hex) is False

    # 3. Key mismatch
    assert keypair_b.verify(message_bytes, sig_hex) is False
