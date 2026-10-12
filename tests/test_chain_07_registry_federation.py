import httpx

REGISTRY_BASE_URL = "https://nti-registry.vercel.app"


def test_chain_07_federation_manifest_valid():
    """Verify GET /api/federation returns HTTP 200 and valid JSON."""
    response = httpx.get(f"{REGISTRY_BASE_URL}/api/federation", timeout=10.0)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)


def test_chain_07_federation_has_spec():
    """Verify manifest contains spec field equal to NTI-Registry-Federation/1."""
    response = httpx.get(f"{REGISTRY_BASE_URL}/api/federation", timeout=10.0)
    assert response.status_code == 200
    data = response.json()
    assert data.get("spec") == "NTI-Registry-Federation/1"


def test_chain_07_federation_has_endpoints():
    """Verify manifest contains endpoints map with required keys."""
    response = httpx.get(f"{REGISTRY_BASE_URL}/api/federation", timeout=10.0)
    assert response.status_code == 200
    data = response.json()
    endpoints = data.get("endpoints", {})
    required_keys = ["register", "list", "verify", "search", "federation"]
    for key in required_keys:
        assert key in endpoints, f"Missing key '{key}' in endpoints map"


def test_chain_07_federation_has_peers_field():
    """Verify manifest contains peers field (may be empty list)."""
    response = httpx.get(f"{REGISTRY_BASE_URL}/api/federation", timeout=10.0)
    assert response.status_code == 200
    data = response.json()
    assert "peers" in data
    assert isinstance(data["peers"], list)


def test_chain_07_federation_issued_at_present():
    """Verify manifest contains issued_at timestamp in ISO 8601."""
    response = httpx.get(f"{REGISTRY_BASE_URL}/api/federation", timeout=10.0)
    assert response.status_code == 200
    data = response.json()
    assert "issued_at" in data
    assert isinstance(data["issued_at"], str)
