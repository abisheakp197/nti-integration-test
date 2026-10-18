import json
from typing import Any

import pytest
import ube_foundation
from runner.attestation import sign_benchmark, verify_benchmark
from runner.run_benchmark import run_all


@pytest.mark.real_world
def test_real_world_benchmark_end_to_end() -> None:
    """Run benchmark end-to-end and verify produced signed attestation."""
    # 1. Run benchmark suite
    bench_data: dict[str, Any] = run_all()
    assert isinstance(bench_data, dict)
    assert "frameworks" in bench_data or "results" in bench_data or "summary" in bench_data

    # 2. Produce signed attestation
    attestation = sign_benchmark(bench_data)
    assert isinstance(attestation, dict)
    assert "signature" in attestation
    assert "issuer_pubkey" in attestation

    # 3. Verify signature using runner helper
    assert verify_benchmark(attestation) is True

    # 4. Verify signature mechanics directly using ube_foundation.PqcKeyPair
    keypair = ube_foundation.PqcKeyPair()
    clean_payload = {k: v for k, v in attestation.items() if k not in ("signature", "cert_hash")}
    clean_payload["issuer_pubkey"] = keypair.public_key_hex()
    message_bytes = json.dumps(clean_payload, sort_keys=True).encode("utf-8")
    sig = keypair.sign(message_bytes)

    assert keypair.verify(message_bytes, sig) is True
