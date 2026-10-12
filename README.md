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
- **Chain 02:** DEFERRED (`nti-attack` package not published on PyPI)
- **Chain 03:** DONE (`nti-scanner` scan_directory tested on real target)
- **Chain 04:** DEFERRED (`nti-attack` package not published on PyPI)
- **Chain 05:** DEFERRED (`nti-benchmark` depends on `nti-attack` which is not on PyPI)
- **Chain 06:** DONE (Live registry read endpoints `/api/health`, `/api/list`, `/api/stats`, `/api/search` return valid JSON; badge registration DEFERRED as `nti-badge` is not published on PyPI)
- **Chain 07:** DONE (Registry federation manifest `/api/federation` schema, spec `NTI-Registry-Federation/1`, endpoints, peers, and timestamps verified)
- **Chain 08:** DONE (`ube_foundation.PqcKeyPair` signature, payload, and wrong-issuer tamper detection verified; replay protection test SKIPPED as replay protection API is not exposed)

## Running Tests

```bash
pip install -e .
pytest -n auto -v
```
