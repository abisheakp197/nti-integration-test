import json
import hashlib
import httpx
import ube_foundation
import nti_badge

REGISTRY_BASE_URL = "https://nti-registry.vercel.app"
BADGE_BASE_URL = "https://nti-badge-svs1.vercel.app"


def test_chain_06_badge_package_generation_and_verification():
    """Verify nti_badge package SVG rendering, certificate signing, and verification with ube_foundation."""
    # 1. SVG Badge Rendering
    svg = nti_badge.render_badge_svg(
        label="NTI-1",
        value="95/100 Platinum",
        color="#e5e4e2",
        tier_emoji="🏆",
    )
    assert isinstance(svg, str)
    assert "<svg" in svg

    # 2. Certificate Generation and Signing
    keypair = ube_foundation.PqcKeyPair()
    cert_payload = {
        "spec": "NTI-Cert/1",
        "id": "cert-chain-06-test",
        "repo": "testorg/testrepo",
        "commit_sha": "abc1234567890",
        "profile": "NTI-1",
        "issuer": "nti-badge-test-issuer",
        "issued_at": "2026-10-13T00:00:00Z",
        "signature_alg": "dilithium5",
        "score": 95,
        "tier": "Platinum",
        "issuer_pubkey": keypair.public_key_hex(),
    }

    message = json.dumps(cert_payload, sort_keys=True).encode("utf-8")
    cert_payload["signature"] = keypair.sign(message)
    cert_payload["cert_hash"] = hashlib.sha256(message).hexdigest()

    parsed_cert = nti_badge.parse_certificate(cert_payload)
    assert parsed_cert is not None
    assert nti_badge.is_valid_signature(parsed_cert) is True
    assert nti_badge.verify_cert_integrity(parsed_cert) is True

    # 3. Tampered Certificate Rejection
    tampered_cert = dict(parsed_cert)
    tampered_cert["score"] = 10
    assert nti_badge.verify_cert_integrity(tampered_cert) is False


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


def test_chain_06_live_badge_service_endpoints():
    """Verify live nti-badge service read endpoints respond with HTTP 200."""
    response_root = httpx.get(BADGE_BASE_URL, timeout=10.0)
    assert response_root.status_code == 200

    response_reg = httpx.get(f"{BADGE_BASE_URL}/api/registry", timeout=10.0)
    assert response_reg.status_code == 200
    assert "entries" in response_reg.json() or "count" in response_reg.json()

    response_lb = httpx.get(f"{BADGE_BASE_URL}/api/leaderboard", timeout=10.0)
    assert response_lb.status_code == 200
    assert "leaderboard" in response_lb.json()

    response_badge = httpx.get(f"{BADGE_BASE_URL}/api/badge?repo=testorg/testrepo", timeout=10.0)
    assert response_badge.status_code == 200
    assert "image/svg+xml" in response_badge.headers.get("content-type", "")
