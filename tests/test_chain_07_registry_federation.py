import httpx

REGISTRY_BASE_URL = "https://nti-registry.vercel.app"


def test_chain_07_federation_manifest_valid() -> None:
    """Verify GET /api/federation returns HTTP 200 and valid JSON."""
    try:
        response = httpx.get(f"{REGISTRY_BASE_URL}/api/federation", timeout=10.0)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)
    except httpx.HTTPError as exc:
        assert False, f"Federation manifest fetch failed cleanly: {exc}"


def test_chain_07_federation_has_spec() -> None:
    """Verify manifest contains spec field equal to NTI-Registry-Federation/1."""
    try:
        response = httpx.get(f"{REGISTRY_BASE_URL}/api/federation", timeout=10.0)
        assert response.status_code == 200
        data = response.json()
        assert data.get("spec") == "NTI-Registry-Federation/1"
    except httpx.HTTPError as exc:
        assert False, f"Federation spec check failed cleanly: {exc}"


def test_chain_07_federation_has_endpoints() -> None:
    """Verify manifest contains endpoints map with required keys."""
    try:
        response = httpx.get(f"{REGISTRY_BASE_URL}/api/federation", timeout=10.0)
        assert response.status_code == 200
        data = response.json()
        endpoints = data.get("endpoints", {})
        required_keys = ["register", "list", "verify", "search", "federation"]
        for key in required_keys:
            assert key in endpoints, f"Missing key '{key}' in endpoints map"
    except httpx.HTTPError as exc:
        assert False, f"Federation endpoints check failed cleanly: {exc}"


def test_chain_07_federation_has_peers_field() -> None:
    """Verify manifest contains peers field (may be empty list)."""
    try:
        response = httpx.get(f"{REGISTRY_BASE_URL}/api/federation", timeout=10.0)
        assert response.status_code == 200
        data = response.json()
        assert "peers" in data
        assert isinstance(data["peers"], list)
    except httpx.HTTPError as exc:
        assert False, f"Federation peers check failed cleanly: {exc}"


def test_chain_07_federation_issued_at_present() -> None:
    """Verify manifest contains issued_at timestamp in ISO 8601."""
    try:
        response = httpx.get(f"{REGISTRY_BASE_URL}/api/federation", timeout=10.0)
        assert response.status_code == 200
        data = response.json()
        assert "issued_at" in data
        assert isinstance(data["issued_at"], str)
    except httpx.HTTPError as exc:
        assert False, f"Federation issued_at check failed cleanly: {exc}"
