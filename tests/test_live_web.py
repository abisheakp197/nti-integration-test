import httpx
import pytest

REGISTRY_BASE_URL = "https://nti-registry.vercel.app"
BADGE_BASE_URL = "https://nti-badge-svs1.vercel.app"


@pytest.mark.live
def test_live_registry_root_returns_html():
    """Verify registry root endpoint returns HTTP 200 and HTML content."""
    response = httpx.get(REGISTRY_BASE_URL, timeout=10.0)
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "<html" in response.text.lower() or "<!doctype html" in response.text.lower()


@pytest.mark.live
def test_live_registry_health_returns_ok_json():
    """Verify registry health endpoint returns HTTP 200 and valid JSON with status ok."""
    response = httpx.get(f"{REGISTRY_BASE_URL}/api/health", timeout=10.0)
    assert response.status_code == 200
    assert "application/json" in response.headers.get("content-type", "")
    data = response.json()
    assert data.get("status") == "ok"


@pytest.mark.live
def test_live_registry_list_returns_valid_json():
    """Verify registry list endpoint returns HTTP 200 and valid JSON."""
    response = httpx.get(f"{REGISTRY_BASE_URL}/api/list", timeout=10.0)
    assert response.status_code == 200
    assert "application/json" in response.headers.get("content-type", "")
    data = response.json()
    assert "count" in data
    assert "entries" in data


@pytest.mark.live
def test_live_registry_stats_returns_valid_json():
    """Verify registry stats endpoint returns HTTP 200 and valid JSON."""
    response = httpx.get(f"{REGISTRY_BASE_URL}/api/stats", timeout=10.0)
    assert response.status_code == 200
    assert "application/json" in response.headers.get("content-type", "")
    data = response.json()
    assert isinstance(data, dict)


@pytest.mark.live
def test_live_registry_search_returns_valid_json():
    """Verify registry search endpoint returns HTTP 200 and valid JSON."""
    response = httpx.get(f"{REGISTRY_BASE_URL}/api/search?q=nti", timeout=10.0)
    assert response.status_code == 200
    assert "application/json" in response.headers.get("content-type", "")
    data = response.json()
    assert data.get("query") == "nti"


@pytest.mark.live
def test_live_registry_federation_returns_valid_json():
    """Verify registry federation endpoint returns HTTP 200 and valid JSON."""
    response = httpx.get(f"{REGISTRY_BASE_URL}/api/federation", timeout=10.0)
    assert response.status_code == 200
    assert "application/json" in response.headers.get("content-type", "")
    data = response.json()
    assert isinstance(data, dict)


@pytest.mark.live
def test_live_registry_federation_spec_version():
    """Verify registry federation spec version is NTI-Registry-Federation/1."""
    response = httpx.get(f"{REGISTRY_BASE_URL}/api/federation", timeout=10.0)
    assert response.status_code == 200
    data = response.json()
    assert data.get("spec") == "NTI-Registry-Federation/1"


@pytest.mark.live
def test_live_registry_all_endpoints_return_200():
    """Verify all public registry endpoints respond with HTTP 200."""
    endpoints = [
        "/",
        "/api/health",
        "/api/list",
        "/api/stats",
        "/api/search?q=nti",
        "/api/federation",
    ]
    for endpoint in endpoints:
        res = httpx.get(f"{REGISTRY_BASE_URL}{endpoint}", timeout=10.0)
        assert res.status_code == 200, f"Endpoint {endpoint} failed with status {res.status_code}"


@pytest.mark.live
def test_live_badge_root_reachable():
    """Verify badge service root is reachable and returns HTTP 200 HTML."""
    response = httpx.get(BADGE_BASE_URL, timeout=10.0)
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


@pytest.mark.live
def test_live_badge_health_or_status_endpoint():
    """Verify badge status / federation endpoint returns HTTP 200 and valid JSON."""
    response = httpx.get(f"{BADGE_BASE_URL}/api/federation", timeout=10.0)
    assert response.status_code == 200
    assert "application/json" in response.headers.get("content-type", "")
    data = response.json()
    assert "protocol" in data or "federation_version" in data


@pytest.mark.live
def test_live_badge_signed_badge_verifiable():
    """Verify badge rendering endpoint returns SVG image."""
    response = httpx.get(f"{BADGE_BASE_URL}/api/badge?repo=testorg/testrepo", timeout=10.0)
    assert response.status_code == 200
    assert "image/svg+xml" in response.headers.get("content-type", "")
    assert "<svg" in response.text
