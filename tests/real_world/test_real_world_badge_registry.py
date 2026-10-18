import hashlib
import json

import httpx
import nti_badge
import pytest
import ube_foundation

REGISTRY_BASE_URL = "https://nti-registry.vercel.app"


@pytest.mark.real_world
def test_real_world_badge_render_and_registry_query() -> None:
    """Generate signed cert badge and query live registry read endpoints."""
    # 1. Generate signed certificate and render SVG badge
    keypair = ube_foundation.PqcKeyPair()
    tier_info = nti_badge.tier_metadata("Gold")
    svg_badge = nti_badge.render_badge_svg("NTI-1", "Gold (88%)", tier_info["color"], tier_info["emoji"])

    assert "<svg" in svg_badge
    assert "</svg>" in svg_badge

    cert_data = {
        "spec": str(nti_badge.CERT_SPEC),
        "issuer": "nti-real-world",
        "issued_at": "2025-01-01T00:00:00Z",
        "id": "cert-real-world-01",
        "repo": "enterprise/real-world-repo",
        "commit_sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "score": 88,
        "profile": "NTI-1",
        "signature_alg": "dilithium5",
        "issuer_pubkey": keypair.public_key_hex(),
    }

    clean_payload = {k: v for k, v in cert_data.items() if k not in ("signature", "cert_hash")}
    message_bytes = json.dumps(clean_payload, sort_keys=True).encode("utf-8")
    cert_data["signature"] = keypair.sign(message_bytes)
    cert_data["cert_hash"] = hashlib.sha256(message_bytes).hexdigest()

    assert nti_badge.is_valid_signature(cert_data) is True

    # 2. Query live registry health and list
    try:
        resp = httpx.get(f"{REGISTRY_BASE_URL}/api/health", timeout=10.0)
        assert resp.status_code == 200
        assert resp.json().get("status") == "ok"
    except httpx.HTTPError as exc:
        assert False, f"Live registry connection failed cleanly: {exc}"
