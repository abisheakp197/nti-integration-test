import httpx
import pytest

REGISTRY_BASE_URL = "https://nti-registry.vercel.app"


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


@pytest.mark.skip(
    reason="DEFERRED: nti-badge package is not published on PyPI, so signed badge creation and registration cannot be tested."
)
def test_chain_06_badge_registration():
    """Deferred: nti-badge generation and POST /api/register verification."""
    pass
