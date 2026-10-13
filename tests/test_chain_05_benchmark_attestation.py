import json
from runner.run_benchmark import run_all
from runner.attestation import sign_benchmark, verify_benchmark
import ube_foundation


def test_chain_05_benchmark_signed_attestation():
    """Run minimal benchmark, produce signed attestation, and verify required fields and signature."""
    # Run minimal benchmark in-process
    bench_data = run_all()
    assert isinstance(bench_data, dict)

    # Produce signed attestation
    attestation = sign_benchmark(bench_data)

    # Assert attestation has required fields
    required_fields = [
        "spec",
        "run_at",
        "framework_count",
        "attack_count",
        "results",
        "issuer_pubkey",
        "signature",
        "cert_hash",
    ]
    for field in required_fields:
        assert field in attestation, f"Attestation missing required field '{field}'"

    assert attestation["spec"] == "NTI-Benchmark/1"
    assert isinstance(attestation["signature"], str) and len(attestation["signature"]) > 0
    assert isinstance(attestation["issuer_pubkey"], str) and len(attestation["issuer_pubkey"]) > 0

    # Verify signature and integrity using runner.attestation helper
    assert verify_benchmark(attestation) is True

    # Verify signature mechanics using ube_foundation PqcKeyPair
    keypair = ube_foundation.PqcKeyPair()
    clean_payload = {k: v for k, v in attestation.items() if k not in ("signature", "cert_hash")}
    clean_payload["issuer_pubkey"] = keypair.public_key_hex()
    message_bytes = json.dumps(clean_payload, sort_keys=True).encode("utf-8")
    sig = keypair.sign(message_bytes)

    assert keypair.verify(message_bytes, sig) is True
