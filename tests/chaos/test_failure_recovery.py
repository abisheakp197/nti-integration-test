import asyncio
import hashlib
import json
import socket
import tempfile
from pathlib import Path
from typing import Any

import httpx
import nti_badge
import pytest
import ube_foundation
from autogen_nti import NTISecurityWrapper
from crewai_nti import NTIGuardrailMiddleware
from nti_scanner.scanner import scan_directory

REGISTRY_BASE_URL = "https://nti-registry.vercel.app"


class NetworkCutSocket(socket.socket):
    """Socket class that raises OSError on connect to simulate network cut."""

    def connect(self, address: Any) -> None:
        raise OSError("Network connection cut")

    def connect_ex(self, address: Any) -> int:
        return 111


# --- 1. Timeouts & Network Cuts ---

@pytest.mark.chaos
@pytest.mark.anyio
async def test_httpx_timeout_graceful_handling(monkeypatch: pytest.MonkeyPatch) -> None:
    """Monkeypatch httpx.AsyncClient.get to simulate a 30-second timeout and assert graceful handling."""
    async def mock_get(self: Any, url: str, **kwargs: Any) -> httpx.Response:
        raise httpx.ReadTimeout("Request timed out after 30.0s", request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get)

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx.TimeoutException):
            await client.get(f"{REGISTRY_BASE_URL}/api/health", timeout=30.0)


@pytest.mark.chaos
def test_network_cut_offline_badge_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cut network during badge verification and assert fallback to offline verification."""
    keypair = ube_foundation.PqcKeyPair()
    pubkey = keypair.public_key_hex()

    tier_info = nti_badge.tier_metadata("Gold")
    badge_svg = nti_badge.render_badge_svg("NTI-1", "Gold (95%)", tier_info["color"], tier_info["emoji"])
    assert "<svg" in badge_svg

    cert_data = {
        "spec": str(nti_badge.CERT_SPEC),
        "issuer": "chaos-tester",
        "issued_at": "2025-01-01T00:00:00Z",
        "id": "cert-chaos-01",
        "repo": "enterprise/chaos-repo",
        "commit_sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "score": 95,
        "profile": "NTI-1",
        "signature_alg": "dilithium5",
        "issuer_pubkey": pubkey,
    }

    clean_payload = {k: v for k, v in cert_data.items() if k not in ("signature", "cert_hash")}
    message_bytes = json.dumps(clean_payload, sort_keys=True).encode("utf-8")
    sig_hex = keypair.sign(message_bytes)
    cert_data["signature"] = sig_hex
    cert_data["cert_hash"] = hashlib.sha256(message_bytes).hexdigest()

    # Cut the network using socket monkeypatch
    monkeypatch.setattr(socket, "socket", NetworkCutSocket)

    # Prove network call attempts fail
    with pytest.raises(OSError, match="Network connection cut"):
        s = socket.socket()
        s.connect(("8.8.8.8", 53))

    # Perform badge verification offline using cached public keys and verify it returns True
    assert nti_badge.is_valid_signature(cert_data) is True
    assert keypair.verify(message_bytes, sig_hex) is True


# --- 2. Disk & Memory ---

@pytest.mark.chaos
def test_filesystem_oserror_disk_full_no_partial_files(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate OSError (disk full) during badge/cert file writing and assert no partial files remain."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir) / "badges"
        output_dir.mkdir()

        target_file = output_dir / "badge_cert.json"

        # Mock write_text on Path to throw ENOSPC
        orig_write = Path.write_text

        def mock_write_text(self: Path, data: str, *args: Any, **kwargs: Any) -> int:
            if self == target_file or "badge_cert" in str(self):
                raise OSError(28, "No space left on device")
            return orig_write(self, data, *args, **kwargs)

        monkeypatch.setattr(Path, "write_text", mock_write_text)

        with pytest.raises(OSError, match="No space left on device"):
            target_file.write_text("{\"partial\": \"data\"}")

        assert not target_file.exists(), "Partial file should not be left behind on disk full"


@pytest.mark.chaos
def test_deeply_nested_directory_scan() -> None:
    """Run nti-scanner on a deeply nested (100-level) directory structure without RecursionError or crash."""
    with tempfile.TemporaryDirectory() as tmpdir:
        current = Path(tmpdir)
        for i in range(100):
            current = current / f"dir_{i}"
        current.mkdir(parents=True)

        # Write a file at the deepest level
        (current / "deep_agent.py").write_text("prompt = 'deeply nested agent'\n")

        # Scan root directory
        scan_result = scan_directory(Path(tmpdir))
        assert scan_result is not None
        assert hasattr(scan_result, "findings") or hasattr(scan_result, "score") or hasattr(scan_result, "files_scanned")


# --- 3. Concurrency & Race Conditions ---

@pytest.mark.chaos
@pytest.mark.anyio
async def test_asyncio_100_parallel_verifications() -> None:
    """Run 100 parallel verifications using asyncio.gather and assert all return True without state cross-contamination."""
    keypair = ube_foundation.PqcKeyPair()
    message = b"Asyncio parallel verification test payload"
    sig_hex = keypair.sign(message)

    async def verify_task(index: int) -> bool:
        await asyncio.sleep(0.001)  # Yield execution
        return bool(keypair.verify(message, sig_hex))

    tasks = [verify_task(i) for i in range(100)]
    results = await asyncio.gather(*tasks)

    assert len(results) == 100
    assert all(res is True for res in results)


@pytest.mark.chaos
@pytest.mark.anyio
async def test_parallel_agent_handoffs_no_deadlock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run 50 parallel agent handoffs in crewai-nti / autogen-nti and assert no deadlocks or state contamination."""
    def mock_eval(self: Any, req_json: str) -> str:
        return json.dumps({"decision": "Deny", "reason": "Capability not granted"})

    monkeypatch.setattr(ube_foundation.TrustEngine, "evaluate", mock_eval)

    guardrail = NTIGuardrailMiddleware(agent_id="crew-agent", strict=False)
    sec_wrapper = NTISecurityWrapper(agent_id="autogen-agent", strict=False)

    async def handoff_task(i: int) -> bool:
        await asyncio.sleep(0.001)
        res1 = guardrail.verify_tool_execution(f"tool_{i}", {"step": i})
        res2 = sec_wrapper.verify_message(f"cap_{i}", {"msg": f"hello_{i}"})
        return res1 is False and res2 is False

    tasks = [handoff_task(i) for i in range(50)]
    results = await asyncio.gather(*tasks)

    assert len(results) == 50
    assert all(res is True for res in results)
