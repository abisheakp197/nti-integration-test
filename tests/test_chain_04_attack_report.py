import ube_foundation
from attacks._registry import get_all_attacks
from nti_attack.core import AttackResult
from nti_attack.attestation import build_report, sign_report, verify_report


def test_chain_04_attack_execution_and_report_verification():
    """Verify programmatic attack execution, report signing, and independent UBE verification."""
    attacks = get_all_attacks()
    assert len(attacks) > 0, "No attacks found"
    attack = attacks[0]

    payload = attack.build_payload()
    assert payload is not None

    # Create AttackResult and build/sign attestation report
    res = AttackResult(
        attack_id=attack.id,
        passed=True,
        severity=attack.severity,
        evidence={"payload": payload},
    )

    report = build_report("agent-test", "sha123", [res])
    signed_rep = sign_report(report)

    assert "signature" in signed_rep
    assert "issuer_pubkey" in signed_rep or "public_key" in signed_rep

    verification = verify_report(signed_rep)
    assert verification.get("ok") is True

    # Independent UBE Foundation verification on payload
    keypair = ube_foundation.PqcKeyPair()
    payload_bytes = str(payload).encode("utf-8")
    sig_hex = keypair.sign(payload_bytes)

    assert keypair.verify(payload_bytes, sig_hex)

    # Tamper payload -> verify returns False
    tampered_bytes = payload_bytes + b"_tampered"
    assert not keypair.verify(tampered_bytes, sig_hex)
