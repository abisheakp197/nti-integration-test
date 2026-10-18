import json

import pytest
import ube_foundation


class CertReplayTracker:
    """Registry verifier with nonces / cert_hash replay protection cache."""

    def __init__(self) -> None:
        self.seen_signatures: set[str] = set()

    def process_and_verify_cert(self, cert: dict[str, str], keypair: ube_foundation.PqcKeyPair) -> tuple[bool, str]:
        sig = cert.get("signature", "")
        if sig in self.seen_signatures:
            return False, "REJECTED_REPLAY"

        clean_payload = {k: v for k, v in cert.items() if k not in ("signature", "cert_hash")}
        message_bytes = json.dumps(clean_payload, sort_keys=True).encode("utf-8")

        if not keypair.verify(message_bytes, sig):
            return False, "REJECTED_INVALID_SIGNATURE"

        self.seen_signatures.add(sig)
        return True, "ACCEPTED"


@pytest.mark.chaos
def test_chaos_replay_signed_cert_100_times() -> None:
    """Replay a signed cert 100 times and verify only the first is accepted, subsequent 99 rejected."""
    keypair = ube_foundation.PqcKeyPair()
    tracker = CertReplayTracker()

    cert = {
        "spec": "NTI-Cert/1",
        "agent_id": "agent-replay-test",
        "score": "95",
        "nonce": "nonce-987654321",
        "issuer_pubkey": keypair.public_key_hex(),
    }

    clean_payload = {k: v for k, v in cert.items() if k not in ("signature", "cert_hash")}
    message_bytes = json.dumps(clean_payload, sort_keys=True).encode("utf-8")
    cert["signature"] = keypair.sign(message_bytes)

    # 1st attempt -> Accepted
    ok, status = tracker.process_and_verify_cert(cert, keypair)
    assert ok is True
    assert status == "ACCEPTED"

    # Next 99 replay attempts -> Rejected
    replay_results = []
    for _ in range(99):
        ok_r, status_r = tracker.process_and_verify_cert(cert, keypair)
        replay_results.append((ok_r, status_r))

    assert len(replay_results) == 99
    assert all(ok is False for ok, _ in replay_results)
    assert all(status == "REJECTED_REPLAY" for _, status in replay_results)
