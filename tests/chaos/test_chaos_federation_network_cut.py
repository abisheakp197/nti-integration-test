from typing import Any

import httpx
import pytest


class ResilientFederationSyncer:
    """Federation manager that reconciles peer registry nodes and survives network cuts."""

    def __init__(self, primary_url: str) -> None:
        self.primary_url = primary_url
        self.peers: list[str] = []
        self.synced_count = 0

    def sync_from_peer(self, peer_url: str, client: httpx.Client) -> bool:
        try:
            resp = client.get(f"{peer_url}/api/federation")
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            new_peers: list[str] = data.get("peers", [])
            for p in new_peers:
                if p not in self.peers and p != self.primary_url:
                    self.peers.append(p)
            self.synced_count += 1
            return True
        except (httpx.HTTPError, httpx.RequestError):
            # Network cut or peer unreachable
            return False


@pytest.mark.chaos
def test_chaos_federation_network_cut_and_reconnect(monkeypatch: pytest.MonkeyPatch) -> None:
    """Network cut during federation sync handles error cleanly, then reconciles on reconnect."""
    syncer = ResilientFederationSyncer("https://node1.example.org")

    def mock_get_online(url: str, **kwargs: Any) -> httpx.Response:
        req = httpx.Request("GET", url)
        return httpx.Response(
            200,
            json={
                "spec": "NTI-Registry-Federation/1",
                "endpoints": {"federation": f"{url}/api/federation"},
                "peers": ["https://node2.example.org", "https://node3.example.org"],
            },
            request=req,
        )

    def mock_get_network_cut(url: str, **kwargs: Any) -> httpx.Response:
        raise httpx.ConnectError("Network cut during federation sync", request=httpx.Request("GET", url))

    # Phase 1: Network Cut -> Attempt sync, verify graceful failure without state corruption
    client = httpx.Client()
    monkeypatch.setattr(client, "get", mock_get_network_cut)

    success_cut = syncer.sync_from_peer("https://node2.example.org", client)
    assert success_cut is False
    assert syncer.synced_count == 0
    assert syncer.peers == []

    # Phase 2: Reconnect -> Attempt sync, verify state reconciles cleanly
    monkeypatch.setattr(client, "get", mock_get_online)

    success_reconnect = syncer.sync_from_peer("https://node2.example.org", client)
    assert success_reconnect is True
    assert syncer.synced_count == 1
    target_node_2 = "https://node2.example.org"
    target_node_3 = "https://node3.example.org"
    assert any(peer == target_node_2 for peer in syncer.peers) or any(peer == target_node_3 for peer in syncer.peers)

    client.close()
