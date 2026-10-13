import json
import hashlib
import httpx
import ube_foundation
import nti_badge

REGISTRY_BASE_URL = "https://nti-registry.vercel.app"


def test_chain_06_import_nti_badge():
    """Verify nti_badge package can be imported and exposes core metadata."""
    assert hasattr(nti_badge, "CERT_SPEC")
    assert hasattr(nti_badge, "render_badge_svg")
    assert hasattr(nti_badge, "parse_certificate")


def test_chain_06_registry_health():
    """Verify registry health endpoint returns HTTP 200 and status ok."""
    response = httpx.get(f"{REGISTRY_BASE_URL}/api/health", timeout=10.0)
    assert response.status_code == 200
    data = response.json()
    assert data.get("status") == "ok"


def test_chain_06_registry_list_returns_json():
    """Verify registry list endpoint returns valid JSON with count and entries fields."""
    response = httpx.get(f"{REGISTRY_BASE_URL}/api/list", timeout=10.0)
    assert response.status_code == 200
    data = response.json()
    assert "count" in data
    assert "entries" in data
    assert isinstance(data["entries"], list)


def test_chain_06_registry_stats_returns_json():
    """Verify registry stats endpoint returns valid JSON."""
    response = httpx.get(f"{REGISTRY_BASE_URL}/api/stats", timeout=10.0)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)
    assert "spec" in data or "total_entries" in data


def test_chain_06_registry_search_returns_json():
    """Verify registry search endpoint returns valid JSON with query field matching query."""
    response = httpx.get(f"{REGISTRY_BASE_URL}/api/search?q=nti", timeout=10.0)
    assert response.status_code == 200
    data = response.json()
    assert data.get("query") == "nti"
    assert "entries" in data
    assert "count" in data


def test_chain_06_badge_generation_and_signature_verification():
    """Verify nti_badge generates valid signed badge certificate verified by ube_foundation."""
    # 1. Generate SVG badge
    tier_info = nti_badge.tier_metadata("Platinum")
    svg = nti_badge.render_badge_svg("NTI-1", f"Platinum (95%)", tier_info["color"], tier_info["emoji"])
    assert isinstance(svg, str)
    assert "<svg" in svg
    assert "</svg>" in svg

    # 2. Create signed certificate payload using ube_foundation PqcKeyPair
    keypair = ube_foundation.PqcKeyPair()
    cert_payload = {
        "spec": nti_badge.CERT_SPEC,
        "issuer": "nti-integration-test",
        "issued_at": "2025-01-01T00:00:00Z",
        "id": "cert-chain-06-test",
        "repo": "neuraltrust/nti-integration-test",
        "commit_sha": "1234567890abcdef1234567890abcdef12345678",
        "score": 95,
        "profile": "NTI-1",
        "signature_alg": "dilithium5",
        "issuer_pubkey": keypair.public_key_hex(),
    }

    clean_payload = {k: v for k, v in cert_payload.items() if k not in ("signature", "cert_hash")}
    message_bytes = json.dumps(clean_payload, sort_keys=True).encode("utf-8")
    cert_payload["signature"] = keypair.sign(message_bytes)
    cert_payload["cert_hash"] = hashlib.sha256(message_bytes).hexdigest()

    # 3. Parse certificate with nti_badge
    parsed_cert = nti_badge.parse_certificate(cert_payload)
    assert parsed_cert["id"] == "cert-chain-06-test"
    assert parsed_cert["score"] == 95

    # 4. Verify signature using ube_foundation keypair and nti_badge validator
    assert keypair.verify(message_bytes, cert_payload["signature"]) is True
    assert nti_badge.is_valid_signature(cert_payload) is True
