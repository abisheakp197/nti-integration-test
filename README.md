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
- **Chain 02:** DONE (`nti-attack-library` loaded and validated 11 attacks across 6 categories)
- **Chain 03:** DONE (`nti-scanner` scan_directory tested on real target)
- **Chain 04:** DONE (Programmatic attack execution, report signing, and independent UBE verification tested)
- **Chain 05:** DONE (Minimal benchmark attestation signed and verified via `runner.attestation` and `ube_foundation`)
- **Chain 06:** DONE (`nti_badge` package SVG rendering, cert validation, and live badge service read endpoints verified)
- **Chain 07:** DONE (Registry federation manifest `/api/federation` schema, spec `NTI-Registry-Federation/1`, endpoints, peers, and timestamps verified)
- **Chain 08:** DONE (`ube_foundation.PqcKeyPair` signature, payload, and wrong-issuer tamper detection verified; replay protection test SKIPPED as replay protection API is not exposed)
- **Live Web Tests:** DONE (HTTP integration tests against live deployed services `nti-registry` and `nti-badge` on Vercel)

## Running Tests

```bash
pip install -e .
pytest -n auto -v
```
