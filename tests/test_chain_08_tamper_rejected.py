import pytest
import ube_foundation


def test_chain_08_tampered_signature_rejected():
    """Sign with key A, flip one byte in signature, verify with key A fails."""
    key = ube_foundation.PqcKeyPair()
    payload = b"Important NTI report payload"
    sig = key.sign(payload)

    # Flip signature hex characters (first character)
    tampered_sig = ("0" if sig[0] != "0" else "1") + sig[1:]

    assert not key.verify(payload, tampered_sig)


def test_chain_08_tampered_payload_rejected():
    """Sign valid payload, modify one byte in payload, verify fails."""
    key = ube_foundation.PqcKeyPair()
    payload = b"Original unaltered payload"
    sig = key.sign(payload)

    tampered_payload = b"Original unaltered payloaD"

    assert not key.verify(tampered_payload, sig)


def test_chain_08_wrong_issuer_rejected():
    """Sign with key A, verify with key B fails."""
    key_a = ube_foundation.PqcKeyPair()
    key_b = ube_foundation.PqcKeyPair()
    payload = b"Payload signed by key A"
    sig = key_a.sign(payload)

    assert not key_b.verify(payload, sig)


@pytest.mark.skip(
    reason="SKIPPED: ube_foundation.PqcKeyPair does not expose nonce or timestamp replay protection in current API."
)
def test_chain_08_replay_rejected():
    """Replay protection test skipped as it is not implemented in ube_foundation."""
    pass
