# nti-integration-test

Ecosystem integration test suite for Neural Trust Infrastructure (NTI).

## Integration Chains

- **Chain 01:** ube-foundation sign/verify
- **Chain 02:** nti-attack library load
- **Chain 03:** nti-scanner on real target
- **Chain 04:** nti-attack report verified by ube
- **Chain 05:** nti-benchmark signed attestation
- **Chain 06:** nti-badge + live registry read endpoints
- **Chain 07:** registry federation manifest
- **Chain 08:** tamper rejection

## Phase 2 Status

- **Chain 01:** DONE (`ube_foundation.PqcKeyPair` sign and verify integration tested)
- **Chain 02:** DONE (`nti-attack-library` package loaded and 11 registered attacks verified across 6 categories)
- **Chain 03:** DONE (`nti-scanner` scan_directory tested on real target)
- **Chain 04:** DONE (`nti-attack` attack run and report signed/verified by `ube_foundation.PqcKeyPair`)
- **Chain 05:** DONE (`nti-benchmark` in-process run, attestation signature and required fields verified by `ube_foundation`)
- **Chain 06:** DONE (Live registry read endpoints `/api/health`, `/api/list`, `/api/stats`, `/api/search` verified; `nti-badge` SVG generation and certificate signing/verification tested)
- **Chain 07:** DONE (Registry federation manifest `/api/federation` schema, spec `NTI-Registry-Federation/1`, endpoints, peers, and timestamps verified)
- **Chain 08:** DONE (`ube_foundation.PqcKeyPair` signature, payload, and wrong-issuer tamper detection verified; replay protection test SKIPPED as replay protection API is not exposed)

## Adversarial Test Suite

Enterprise-tier continuous adversarial test suite in `tests/adversarial/`:

- **Property-based testing** (1000+ examples per property using Hypothesis for PqcKeyPair signing/verification, tampered signatures, wrong key rejection, canonical JSON reordering, unicode roundtrip, empty and 1 MB large message payloads, high entropy inputs)
- **Attack matrix** (all 11 registered attacks run against synthetic agent, attestation report signature verification, required fields check, determinism, and cross-attack interference)
- **Concurrency** (100 parallel signatures, 1000 parallel verifications, 50 parallel live registry HTTP reads, 25 parallel badge generations, and 5 parallel benchmark runs across threads without race conditions or crashes)
- **Adversarial inputs** (malformed signatures: empty, zero bytes, random high entropy, truncated, bit/byte flips; canonical JSON edge cases: None values, 10-level nesting, unicode/emoji/RTL, large lists, casing; registry HTTP error handling: invalid URL, timeout, HTML, empty body, 500)
- **Soak test** (10,000 sequential sign/verify iterations with memory growth < 50 MB and average sign+verify latency < 50 ms)

## Running Tests

```bash
pip install -e .

# Fast adversarial test suite
pytest tests/adversarial/ -v -m "not soak"

# Soak test suite (run on demand)
pytest tests/adversarial/ -v -m "soak"

# Full integration and adversarial test suite
pytest -n auto -v
```
