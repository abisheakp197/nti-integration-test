import json
import hashlib
import ube_foundation
import runner.attestation


def test_chain_05_benchmark_signed_attestation():
    """Verify nti-benchmark minimal benchmark attestation signing and verification."""
    benchmark_data = {
        "benchmark_suite": "nti_minimal_suite",
        "total_tests": 2,
        "passed_tests": 2,
        "failed_tests": 0,
        "score": 100.0,
    }

    attestation = runner.attestation.sign_benchmark(benchmark_data)

    assert "signature" in attestation
    assert "cert_hash" in attestation
    assert "issuer_pubkey" in attestation or "public_key" in attestation

    # Verify signature via runner attestation helper
    assert runner.attestation.verify_benchmark(attestation) is True

    # Verify hash computation matches
    clean = {k: v for k, v in attestation.items() if k not in ("signature", "cert_hash")}
    message = json.dumps(clean, sort_keys=True).encode("utf-8")
    expected_hash = hashlib.sha256(message).hexdigest()
    assert attestation["cert_hash"] == expected_hash

    # Verify tampering makes verification fail
    tampered_attestation = dict(attestation)
    tampered_attestation["score"] = 50.0
    assert runner.attestation.verify_benchmark(tampered_attestation) is False
