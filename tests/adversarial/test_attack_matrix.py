import json
from typing import Any

import pytest
import ube_foundation
from attacks._registry import get_all_attacks
from nti_attack.adapters.callable_adapter import CallableAdapter
from nti_attack.attestation import build_report
from nti_attack.signing import sign_payload


def _make_synthetic_agent() -> CallableAdapter:
    """Create a synthetic agent adapter that handles security attacks safely."""
    def safe_agent(prompt: str) -> str:
        return "I cannot fulfill this request as an AI safety compliant agent."
    return CallableAdapter(safe_agent)


def _verify_report_signature(signed_report: dict[str, Any], keypair: ube_foundation.PqcKeyPair) -> bool:
    """Helper to verify signed report using ube_foundation.PqcKeyPair directly."""
    signature_hex = str(signed_report.get("signature"))
    clean_payload = {k: v for k, v in signed_report.items() if k not in ("signature", "cert_hash")}
    message_bytes = json.dumps(clean_payload, sort_keys=True).encode("utf-8")
    is_valid: bool = keypair.verify(message_bytes, signature_hex)
    return is_valid


@pytest.mark.adversarial
@pytest.mark.parametrize("attack", get_all_attacks(), ids=lambda a: getattr(a, "id", "unknown"))
def test_attack_matrix_single_attack(attack: Any) -> None:
    """Test each attack in nti-attack-library against a synthetic agent.
    Assert signed report produced, verify signature, verify required fields, assert determinism."""
    agent = _make_synthetic_agent()
    keypair = ube_foundation.PqcKeyPair()

    # Run attack
    result1 = attack.run(agent)
    report1 = build_report(agent_id="matrix-agent-01", commit_sha="sha12345678", results=[result1])
    signed_report1 = sign_payload(report1, key=keypair)

    # 1. Assert signed report is produced
    assert isinstance(signed_report1, dict)
    assert "signature" in signed_report1
    assert "issuer_pubkey" in signed_report1

    # 2. Verify report signature
    assert _verify_report_signature(signed_report1, keypair) is True

    # 3. Assert report contains required fields
    required_fields = [
        "spec",
        "id",
        "agent_id",
        "commit_sha",
        "run_at",
        "attacks_run",
        "attacks_passed",
        "attacks_failed",
        "resistance_score",
        "results",
        "issuer_pubkey",
        "signature",
    ]
    for field in required_fields:
        assert field in signed_report1, f"Report missing required field: {field}"

    assert signed_report1["agent_id"] == "matrix-agent-01"
    assert signed_report1["commit_sha"] == "sha12345678"
    assert len(signed_report1["results"]) == 1
    assert signed_report1["results"][0]["attack_id"] == attack.id

    # 4. Assert report is deterministic given the same input
    agent2 = _make_synthetic_agent()
    result2 = attack.run(agent2)

    assert result1.attack_id == result2.attack_id
    assert result1.passed == result2.passed
    assert result1.severity == result2.severity
    assert result1.vulnerability_confirmed == result2.vulnerability_confirmed
    assert result1.evidence == result2.evidence


@pytest.mark.adversarial
def test_attack_matrix_cross_attack_interference() -> None:
    """Test cross-attack interference:
    - Run all attacks in sequence against the same agent
    - Assert all produce valid reports
    - Assert reports are independent (attack N's report is not affected by attack N-1)
    - Assert running the same attack twice produces the same result."""
    attacks = get_all_attacks()
    agent = _make_synthetic_agent()
    keypair = ube_foundation.PqcKeyPair()

    results_seq = []
    signed_reports = []

    # Run all attacks in sequence against the same agent
    for attack in attacks:
        res = attack.run(agent)
        results_seq.append(res)
        report = build_report(agent_id="cross-attack-agent", commit_sha="seqsha123", results=[res])
        signed_rep = sign_payload(report, key=keypair)
        signed_reports.append(signed_rep)

    # Assert all produce valid reports
    assert len(signed_reports) == len(attacks)
    for signed_rep in signed_reports:
        assert _verify_report_signature(signed_rep, keypair) is True

    # Assert reports are independent: run each attack in isolation and compare result
    for i, attack in enumerate(attacks):
        isolated_agent = _make_synthetic_agent()
        isolated_res = attack.run(isolated_agent)

        seq_res = results_seq[i]
        assert seq_res.attack_id == isolated_res.attack_id
        assert seq_res.passed == isolated_res.passed
        assert seq_res.vulnerability_confirmed == isolated_res.vulnerability_confirmed
        assert seq_res.evidence == isolated_res.evidence

    # Assert running the same attack twice produces the same result
    for attack in attacks:
        res_run_1 = attack.run(agent)
        res_run_2 = attack.run(agent)

        assert res_run_1.attack_id == res_run_2.attack_id
        assert res_run_1.passed == res_run_2.passed
        assert res_run_1.vulnerability_confirmed == res_run_2.vulnerability_confirmed
        assert res_run_1.evidence == res_run_2.evidence
