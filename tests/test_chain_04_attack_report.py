import json
from attacks._registry import get_all_attacks
from nti_attack.adapters.callable_adapter import CallableAdapter
from nti_attack.attestation import build_report
from nti_attack.signing import sign_payload
import ube_foundation


def test_chain_04_attack_report_verified_by_ube():
    """Execute an attack programmatically, sign report, and verify using ube_foundation."""
    # Execute one attack programmatically using CallableAdapter
    def safe_agent(prompt):
        return "I cannot fulfill this request."

    adapter = CallableAdapter(safe_agent)
    attacks = get_all_attacks()
    attack = attacks[0]
    result = attack.run(adapter)

    # Build report and sign payload with explicit ube_foundation PqcKeyPair
    keypair = ube_foundation.PqcKeyPair()
    report = build_report(agent_id="agent-chain-04", commit_sha="abc12345", results=[result])
    signed_report = sign_payload(report, key=keypair)

    # Extract signature and public key
    signature_hex = signed_report.get("signature")
    public_key_hex = signed_report.get("issuer_pubkey")

    assert signature_hex is not None and isinstance(signature_hex, str)
    assert public_key_hex is not None and isinstance(public_key_hex, str)
    assert public_key_hex == keypair.public_key_hex()

    # Reconstruct canonical message bytes without signature and cert_hash
    clean_payload = {k: v for k, v in signed_report.items() if k not in ("signature", "cert_hash")}
    message_bytes = json.dumps(clean_payload, sort_keys=True).encode("utf-8")

    # Verify independently using ube_foundation.PqcKeyPair.verify
    assert keypair.verify(message_bytes, signature_hex) is True


def test_chain_04_tampered_payload_rejected_by_ube():
    """Verify ube_foundation PqcKeyPair.verify returns False on a tampered payload."""
    adapter = CallableAdapter(lambda prompt: "I cannot fulfill this request.")
    attack = get_all_attacks()[0]
    result = attack.run(adapter)

    keypair = ube_foundation.PqcKeyPair()
    report = build_report(agent_id="agent-chain-04", commit_sha="abc12345", results=[result])
    signed_report = sign_payload(report, key=keypair)

    signature_hex = signed_report["signature"]

    # Tamper with payload field (agent_id)
    clean_payload = {k: v for k, v in signed_report.items() if k not in ("signature", "cert_hash")}
    clean_payload["agent_id"] = "tampered-agent-id"
    tampered_message_bytes = json.dumps(clean_payload, sort_keys=True).encode("utf-8")

    # Assert verify returns False
    assert keypair.verify(tampered_message_bytes, signature_hex) is False
