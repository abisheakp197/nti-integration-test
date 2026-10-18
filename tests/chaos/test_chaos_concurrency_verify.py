import concurrent.futures
import tracemalloc

import pytest
import ube_foundation


@pytest.mark.chaos
def test_chaos_1000_concurrent_verifications() -> None:
    """Run 1000 concurrent verifications across parallel threads and assert zero crashes and memory stability."""
    tracemalloc.start()
    tracemalloc.reset_peak()
    start_mem, _ = tracemalloc.get_traced_memory()

    keypair = ube_foundation.PqcKeyPair()
    valid_payload = b"High concurrency test payload for Dilithium signature verification"
    valid_signature: str = keypair.sign(valid_payload)

    def verify_worker(i: int) -> bool:
        if i % 10 == 0:
            # Tampered signature case
            tampered_sig = valid_signature[:-4] + "0000"
            try:
                is_valid: bool = keypair.verify(valid_payload, tampered_sig)
                return is_valid is False
            except (ValueError, TypeError):
                return True
        else:
            # Valid signature case
            is_valid_valid: bool = keypair.verify(valid_payload, valid_signature)
            return is_valid_valid is True

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(verify_worker, range(1000)))

    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    mem_growth_mb = (peak_mem - start_mem) / (1024.0 * 1024.0)

    assert len(results) == 1000
    assert all(r is True for r in results), "All 1000 concurrent verifications must execute cleanly"
    assert mem_growth_mb < 30.0, f"Memory growth ({mem_growth_mb:.2f} MB) exceeded 30 MB threshold"
