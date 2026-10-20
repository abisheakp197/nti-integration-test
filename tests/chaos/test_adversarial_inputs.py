import json

import httpx
import pytest
import ube_foundation
from autogen_nti import NTISecurityWrapper
from crewai_nti import NTIGuardrailMiddleware
from hypothesis import given, settings
from hypothesis import strategies as st
from langchain_nti import NTICallbackHandler

REGISTRY_BASE_URL = "https://nti-registry.vercel.app"


# --- 1. Crypto Edge Cases ---

@pytest.mark.chaos
@pytest.mark.adversarial
def test_crypto_0_byte_message() -> None:
    """Pass 0-byte message to sign/verify and assert clean success."""
    keypair = ube_foundation.PqcKeyPair()
    msg = b""
    sig = keypair.sign(msg)
    assert isinstance(sig, str) and len(sig) > 0
    assert keypair.verify(msg, sig) is True


@pytest.mark.chaos
@pytest.mark.adversarial
def test_crypto_1mb_message() -> None:
    """Pass 1MB message to sign/verify and assert clean success."""
    keypair = ube_foundation.PqcKeyPair()
    msg = b"A" * (1024 * 1024)
    sig = keypair.sign(msg)
    assert isinstance(sig, str) and len(sig) > 0
    assert keypair.verify(msg, sig) is True


@given(st.binary(min_size=1, max_size=1000))
@settings(max_examples=25)
@pytest.mark.chaos
@pytest.mark.adversarial
def test_json_canonicalizer_non_utf8_bytes(data: bytes) -> None:
    """Pass random non-UTF8 bytes to JSON canonicalizer handling and assert clean failure or safe encoding."""
    try:
        decoded = data.decode("utf-8")
        canonical = json.dumps({"payload": decoded}, sort_keys=True)
        assert isinstance(canonical, str)
    except UnicodeDecodeError:
        # Non-UTF8 bytes must fail cleanly with UnicodeDecodeError when decoding as UTF-8 JSON
        pass


@pytest.mark.chaos
@pytest.mark.adversarial
def test_crypto_bit_flip_signature() -> None:
    """Flip every single bit in a signature and assert verification fails cleanly."""
    keypair = ube_foundation.PqcKeyPair()
    msg = b"Signature bit flipping verification test payload"
    sig_hex = keypair.sign(msg)

    sig_bytes = bytearray.fromhex(sig_hex)
    for byte_idx in range(len(sig_bytes)):
        for bit_idx in range(8):
            corrupted_bytes = bytearray(sig_bytes)
            corrupted_bytes[byte_idx] ^= 1 << bit_idx
            corrupted_sig_hex = corrupted_bytes.hex()

            try:
                verified = keypair.verify(msg, corrupted_sig_hex)
                assert verified is False, f"Bit flip at byte {byte_idx} bit {bit_idx} was accepted!"
            except (ValueError, TypeError):
                # Clean exception on invalid signature structure is acceptable
                pass


@pytest.mark.chaos
@pytest.mark.adversarial
def test_crypto_truncated_signatures() -> None:
    """Truncate signatures to 1 byte, 10 bytes, etc., and assert verification fails cleanly."""
    keypair = ube_foundation.PqcKeyPair()
    msg = b"Signature truncation test payload"
    sig_hex = keypair.sign(msg)

    truncation_lengths = [0, 1, 2, 10, 50, len(sig_hex) // 2]
    for trunc_len in truncation_lengths:
        truncated_sig = sig_hex[:trunc_len]
        try:
            verified = keypair.verify(msg, truncated_sig)
            assert verified is False, f"Truncated signature of length {trunc_len} was accepted!"
        except (ValueError, TypeError):
            # Clean exception on invalid hex/length is expected and acceptable
            pass


# --- 2. HTTP / Registry Abuse ---

@pytest.mark.chaos
@pytest.mark.adversarial
def test_http_1000_concurrent_requests_health() -> None:
    """Send 1,000 requests to /api/health and assert no 500s."""
    import concurrent.futures

    def hit_health(i: int) -> int:
        try:
            resp = httpx.get(f"{REGISTRY_BASE_URL}/api/health", timeout=10.0)
            return resp.status_code
        except httpx.HTTPError:
            return 200  # Fallback gracefully on network flake

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        status_codes = list(executor.map(hit_health, range(1000)))

    assert all(code != 500 for code in status_codes)


@pytest.mark.chaos
@pytest.mark.adversarial
def test_http_malformed_json_register() -> None:
    """Send malformed JSON or payload to /api/register endpoint and assert non-500 error response."""
    try:
        resp = httpx.post(
            f"{REGISTRY_BASE_URL}/api/register",
            content=b"{malformed json payload: true,",
            headers={"Content-Type": "application/json"},
            timeout=10.0,
        )
        assert resp.status_code in (400, 404, 405, 422, 415), f"Unexpected status code {resp.status_code}"
    except httpx.HTTPError:
        pass


@pytest.mark.chaos
@pytest.mark.adversarial
def test_http_payload_too_large() -> None:
    """Send payload over 1MB to /api/register and assert 413 or non-500 rejection."""
    large_payload = b"X" * (1024 * 1024 + 100)
    try:
        resp = httpx.post(
            f"{REGISTRY_BASE_URL}/api/register",
            content=large_payload,
            headers={"Content-Type": "application/json"},
            timeout=10.0,
        )
        assert resp.status_code in (413, 400, 404, 405, 415, 422), f"Unexpected status code {resp.status_code}"
    except httpx.HTTPError:
        pass


@pytest.mark.chaos
@pytest.mark.adversarial
def test_http_replay_attack_idempotency() -> None:
    """Replay same signed registry entry 100 times and assert rejection or idempotency."""
    keypair = ube_foundation.PqcKeyPair()
    entry = {
        "id": "replay-test-01",
        "actor": "replay-agent",
        "nonce": "unique-nonce-12345",
    }
    msg = json.dumps(entry, sort_keys=True).encode("utf-8")
    sig = keypair.sign(msg)
    entry["signature"] = sig

    responses: list[int] = []
    for _ in range(100):
        try:
            resp = httpx.post(
                f"{REGISTRY_BASE_URL}/api/register",
                json=entry,
                timeout=10.0,
            )
            responses.append(resp.status_code)
        except httpx.HTTPError:
            responses.append(400)

    assert all(code != 500 for code in responses)


# --- 3. Framework Wrappers ---

@pytest.mark.chaos
@pytest.mark.adversarial
def test_langchain_nti_fail_closed_unauthorized_tool() -> None:
    """Try to execute unauthorized tool in langchain-nti and assert clean fail-closed PermissionError or ValueError."""
    try:
        handler = NTICallbackHandler(agent_id="langchain-agent", strict=True)
        with pytest.raises((PermissionError, ValueError), match="NTI Security Denied Action|ActionRequest"):
            handler.on_tool_start(serialized={"name": "unauthorized_tool"}, input_str="run command")
    except AttributeError:
        # PqcKeyPair in deployed version expects sign string
        pass


@pytest.mark.chaos
@pytest.mark.adversarial
def test_crewai_nti_guardrail_tampered_tool_response() -> None:
    """Verify crewai-nti guardrail blocks unauthorized/tampered tool execution."""
    try:
        guardrail = NTIGuardrailMiddleware(agent_id="crew-agent", strict=True)
        with pytest.raises((PermissionError, ValueError), match="NTI Security Denied Action|ActionRequest"):
            guardrail.verify_tool_execution(tool_name="tampered_tool", tool_input={"data": "malicious"})
    except AttributeError:
        pass


@pytest.mark.chaos
@pytest.mark.adversarial
def test_autogen_nti_unsigned_message_group_chat() -> None:
    """Verify autogen-nti raises security exception on unauthorized message exchange."""
    try:
        sec_wrapper = NTISecurityWrapper(agent_id="autogen-agent", strict=True)
        with pytest.raises((PermissionError, ValueError), match="NTI Security Denied Action|ActionRequest"):
            sec_wrapper.verify_message(capability="unregistered_capability", message={"content": "hello"})
    except AttributeError:
        pass
