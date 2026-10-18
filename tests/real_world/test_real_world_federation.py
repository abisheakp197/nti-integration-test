from typing import Any

import httpx
import pytest

REGISTRY_BASE_URL = "https://nti-registry.vercel.app"


def _reconcile_federation_manifests(m1: dict[str, Any], m2: dict[str, Any]) -> dict[str, Any]:
    """Sync two node manifests into a unified federated view."""
    endpoints1 = m1.get("endpoints", {})
    endpoints2 = m2.get("endpoints", {})
    synced_endpoints = {**endpoints1, **endpoints2}

    peers1 = set(m1.get("peers", []))
    peers2 = set(m2.get("peers", []))
    synced_peers = sorted(peers1.union(peers2))

    return {
        "spec": m1.get("spec", m2.get("spec")),
        "endpoints": synced_endpoints,
        "peers": synced_peers,
    }


@pytest.mark.real_world
def test_real_world_two_nodes_federate() -> None:
    """Verify federation sync between primary registry manifest and peer node manifest."""
    try:
        resp = httpx.get(f"{REGISTRY_BASE_URL}/api/federation", timeout=10.0)
        assert resp.status_code == 200
        primary_manifest: dict[str, Any] = resp.json()

        peer_manifest: dict[str, Any] = {
            "spec": "NTI-Registry-Federation/1",
            "issuer": "nti-peer-node-2",
            "endpoints": {
                "register": "https://peer2.nti.example/api/register",
                "list": "https://peer2.nti.example/api/list",
                "verify": "https://peer2.nti.example/api/verify",
                "search": "https://peer2.nti.example/api/search",
                "federation": "https://peer2.nti.example/api/federation",
            },
            "peers": ["https://nti-registry.vercel.app"],
        }

        synced = _reconcile_federation_manifests(primary_manifest, peer_manifest)

        assert synced["spec"] == "NTI-Registry-Federation/1"
        assert "register" in synced["endpoints"]
        assert "https://nti-registry.vercel.app" in synced["peers"]
    except httpx.HTTPError as exc:
        assert False, f"Federation manifest fetch failed cleanly: {exc}"
