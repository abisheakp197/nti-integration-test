import time
import tracemalloc
import pytest
import ube_foundation


@pytest.mark.soak
@pytest.mark.adversarial
def test_soak_10000_sign_verify_iterations():
    """Long-running soak test:
    - Sign/verify 10,000 messages sequentially
    - Assert memory usage does not grow more than 50 MB across the run
    - Assert average sign+verify time is under 50 ms
    - Assert no failures across all 10,000 iterations
    """
    tracemalloc.start()
    keypair = ube_foundation.PqcKeyPair()

    iterations = 10_000
    failures = 0

    tracemalloc.reset_peak()
    start_mem, _ = tracemalloc.get_traced_memory()
    start_time = time.perf_counter()

    for i in range(iterations):
        msg = f"Soak iteration payload #{i}".encode("utf-8")
        try:
            sig_hex = keypair.sign(msg)
            is_valid = keypair.verify(msg, sig_hex)
            if not is_valid:
                failures += 1
        except Exception:
            failures += 1

    end_time = time.perf_counter()
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    total_time_s = end_time - start_time
    avg_latency_ms = (total_time_s / iterations) * 1000.0
    mem_growth_mb = (peak_mem - start_mem) / (1024.0 * 1024.0)

    print(f"\n[Soak Test Summary]")
    print(f"Iterations: {iterations}")
    print(f"Total Runtime: {total_time_s:.2f} s")
    print(f"Average Sign+Verify Latency: {avg_latency_ms:.3f} ms")
    print(f"Peak Memory Growth: {mem_growth_mb:.2f} MB")
    print(f"Failures: {failures}")

    # Assertions required by prompt
    assert failures == 0, f"Expected 0 failures, got {failures}"
    assert avg_latency_ms < 50.0, f"Average sign+verify time ({avg_latency_ms:.2f} ms) exceeded limit of 50 ms"
    assert mem_growth_mb < 50.0, f"Memory growth ({mem_growth_mb:.2f} MB) exceeded limit of 50 MB"
