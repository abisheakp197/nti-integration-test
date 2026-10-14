import json
import hashlib
import concurrent.futures
import httpx
import pytest
import ube_foundation
import nti_badge
from runner.run_benchmark import run_all
from runner.attestation import sign_benchmark, verify_benchmark

REGISTRY_BASE_URL = "https://nti-registry.vercel.app"


@pytest.mark.adversarial
def test_concurrent_sign_100_parallel():
    """100 signatures generated in parallel across threads, all verify."""
    keypair = ube_foundation.PqcKeyPair()

    def worker(i: int):
        msg = f"Parallel message payload {i}".encode("utf-8")
        sig_hex = keypair.sign(msg)
        is_valid = keypair.verify(msg, sig_hex)
        return is_valid

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(worker, range(100)))

    assert len(results) == 100
    assert all(r is True for r in results)


@pytest.mark.adversarial
def test_concurrent_verify_1000_parallel():
    """1000 verifications in parallel, all return True for valid, False for tampered."""
    keypair = ube_foundation.PqcKeyPair()
    valid_msg = b"Valid test message for concurrent verify"
    valid_sig = keypair.sign(valid_msg)

    # Tampered signature (bit flipped)
    sig_bytes = bytearray.fromhex(valid_sig)
    sig_bytes[0] ^= 1
    tampered_sig = sig_bytes.hex()

    def worker(i: int):
        if i % 2 == 0:
            # Valid case
            return keypair.verify(valid_msg, valid_sig) is True
        else:
            # Tampered case
            try:
                return keypair.verify(valid_msg, tampered_sig) is False
            except Exception:
                return True  # Graceful exception on invalid signature is acceptable

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        results = list(executor.map(worker, range(1000)))

    assert len(results) == 1000
    assert all(r is True for r in results)


@pytest.mark.adversarial
def test_concurrent_registry_reads_50_parallel():
    """50 concurrent HTTP reads to https://nti-registry.vercel.app/api/list, all return 200."""
    url = f"{REGISTRY_BASE_URL}/api/list"
    client = httpx.Client(timeout=30.0, limits=httpx.Limits(max_connections=20, max_keepalive_connections=10))

    def fetch_endpoint(_: int):
        for attempt in range(3):
            try:
                response = client.get(url)
                if response.status_code == 200 and "entries" in response.json():
                    return True
            except httpx.RequestError:
                pass
        return False

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(fetch_endpoint, range(50)))
    finally:
        client.close()

    assert len(results) == 50
    assert all(r is True for r in results)


@pytest.mark.adversarial
def test_concurrent_badge_generation_25_parallel():
    """25 badge generations in parallel, all produce unique signed badges."""
    keypair = ube_foundation.PqcKeyPair()

    def generate_badge(i: int):
        cert_id = f"cert-concurrent-{i}"
        cert_payload = {
            "spec": nti_badge.CERT_SPEC,
            "issuer": "nti-integration-test",
            "issued_at": "2025-01-01T00:00:00Z",
            "id": cert_id,
            "repo": "neuraltrust/nti-integration-test",
            "commit_sha": f"sha-{i:08d}",
            "score": 90 + (i % 10),
            "profile": "NTI-1",
            "signature_alg": "dilithium5",
            "issuer_pubkey": keypair.public_key_hex(),
        }

        clean_payload = {k: v for k, v in cert_payload.items() if k not in ("signature", "cert_hash")}
        message_bytes = json.dumps(clean_payload, sort_keys=True).encode("utf-8")
        cert_payload["signature"] = keypair.sign(message_bytes)
        cert_payload["cert_hash"] = hashlib.sha256(message_bytes).hexdigest()

        parsed = nti_badge.parse_certificate(cert_payload)
        is_valid = nti_badge.is_valid_signature(cert_payload)
        return cert_id, cert_payload["signature"], is_valid, parsed["score"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(generate_badge, range(25)))

    assert len(results) == 25
    ids = {r[0] for r in results}
    signatures = {r[1] for r in results}

    assert len(ids) == 25, "Cert IDs must be unique"
    assert len(signatures) == 25, "Signatures must be unique"
    assert all(r[2] is True for r in results), "All badge signatures must be valid"


@pytest.mark.adversarial
def test_concurrent_benchmark_runs_5_parallel():
    """5 benchmark runs in parallel, all produce distinct signed attestations."""
    def run_bench(i: int):
        bench_data = run_all()
        attestation = sign_benchmark(bench_data)
        is_valid = verify_benchmark(attestation)
        return attestation, is_valid

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(run_bench, range(5)))

    assert len(results) == 5
    for attestation, is_valid in results:
        assert is_valid is True
        assert attestation["spec"] == "NTI-Benchmark/1"
        assert len(attestation["signature"]) > 0

    # Ensure attestations have distinct signatures or run timestamps / cert hashes
    signatures = {r[0]["signature"] for r in results}
    assert len(signatures) == 5, "All 5 parallel benchmark runs must produce distinct signed attestations"
