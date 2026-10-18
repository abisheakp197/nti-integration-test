import hashlib
import json
import os
from typing import Any

import httpx
import pytest
import ube_foundation


def canonical_hash(d: dict[str, Any]) -> str:
    """Canonical JSON SHA256 hashing."""
    canonical_bytes = json.dumps(d, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def registry_client_fetch(url: str, timeout: float = 30.0) -> dict[str, Any]:
    """Simulated registry HTTP client wrapper with error handling."""
    response = httpx.get(url, timeout=timeout)
    response.raise_for_status()
    if not response.content or len(response.content.strip()) == 0:
        raise ValueError("Empty body returned from server")
    res_json: dict[str, Any] = response.json()
    return res_json


# ============================================================================
# Signature Verification Adversarial Inputs
# ============================================================================

@pytest.mark.adversarial
def test_adversarial_sig_empty_bytes() -> None:
    """Signature verification with empty string signature."""
    keypair = ube_foundation.PqcKeyPair()
    msg = b"Adversarial signature test message"

    # Should handle empty signature cleanly returning False or raising handled exception
    try:
        res = keypair.verify(msg, "")
        assert res is False
    except (ValueError, TypeError) as e:
        assert isinstance(e, (ValueError, TypeError))


@pytest.mark.adversarial
def test_adversarial_sig_all_zero_bytes() -> None:
    """Signature verification with all-zero hex signature string."""
    keypair = ube_foundation.PqcKeyPair()
    msg = b"Adversarial signature test message"
    zero_sig = "00" * 4627  # Matching expected Dilithium hex signature length

    res = keypair.verify(msg, zero_sig)
    assert res is False


@pytest.mark.adversarial
def test_adversarial_sig_random_high_entropy() -> None:
    """Signature verification with random high-entropy bytes as signature."""
    keypair = ube_foundation.PqcKeyPair()
    msg = b"Adversarial signature test message"
    random_sig = os.urandom(4627).hex()

    res = keypair.verify(msg, random_sig)
    assert res is False


@pytest.mark.adversarial
def test_adversarial_sig_truncated_at_every_byte_length() -> None:
    """Signature truncated at every byte length tested step-wise."""
    keypair = ube_foundation.PqcKeyPair()
    msg = b"Adversarial signature test message"
    valid_sig: str = keypair.sign(msg)

    # Truncate at various character lengths from 1 to len(valid_sig)-1
    step = max(1, len(valid_sig) // 50)
    for length in range(1, len(valid_sig), step):
        truncated_sig = valid_sig[:length]
        try:
            res = keypair.verify(msg, truncated_sig)
            assert res is False
        except (ValueError, TypeError) as e:
            assert isinstance(e, (ValueError, TypeError))


@pytest.mark.adversarial
def test_adversarial_sig_one_byte_flipped() -> None:
    """Signature with one byte flipped must return False."""
    keypair = ube_foundation.PqcKeyPair()
    msg = b"Adversarial signature test message"
    valid_sig: str = keypair.sign(msg)

    sig_bytes = bytearray.fromhex(valid_sig)
    sig_bytes[100] ^= 0xFF  # Flip byte at index 100
    flipped_sig = sig_bytes.hex()

    res = keypair.verify(msg, flipped_sig)
    assert res is False


@pytest.mark.adversarial
def test_adversarial_sig_one_bit_flipped() -> None:
    """Signature with one bit flipped must return False."""
    keypair = ube_foundation.PqcKeyPair()
    msg = b"Adversarial signature test message"
    valid_sig: str = keypair.sign(msg)

    sig_bytes = bytearray.fromhex(valid_sig)
    sig_bytes[50] ^= 0x01  # Flip 1 bit
    flipped_sig = sig_bytes.hex()

    res = keypair.verify(msg, flipped_sig)
    assert res is False


# ============================================================================
# Canonical JSON Edge Cases
# ============================================================================

@pytest.mark.adversarial
def test_adversarial_json_none_values() -> None:
    """Dict with None values must produce clean canonical JSON and hash."""
    d = {"key1": None, "key2": "value", "nested": {"inner_null": None}}
    h = canonical_hash(d)
    assert isinstance(h, str) and len(h) == 64


@pytest.mark.adversarial
def test_adversarial_json_deeply_nested_10_levels() -> None:
    """Dict with deeply nested structures (10 levels) must be handled gracefully."""
    curr: dict[str, Any] = {"level": 10, "data": "bottom"}
    for i in range(9, 0, -1):
        curr = {"level": i, "child": curr}

    h = canonical_hash(curr)
    assert isinstance(h, str) and len(h) == 64


@pytest.mark.adversarial
def test_adversarial_json_unicode_emoji_rtl() -> None:
    """Dict with unicode, emoji, RTL text must preserve characters and hash cleanly."""
    d = {
        "english": "Hello World",
        "arabic_rtl": "مرحبا بالعالم",
        "hebrew_rtl": "שלום עולם",
        "emojis": "🛡️🔐🤖🔥🚀",
        "japanese": "こんにちは世界",
    }
    h1 = canonical_hash(d)

    # Verify unicode roundtrip
    json_str = json.dumps(d, sort_keys=True, ensure_ascii=False)
    decoded: dict[str, Any] = json.loads(json_str)
    h2 = canonical_hash(decoded)

    assert h1 == h2
    assert "مرحبا بالعالم" in json_str
    assert "🛡️🔐🤖🔥🚀" in json_str


@pytest.mark.adversarial
def test_adversarial_json_very_large_lists() -> None:
    """Dict with very large lists (100,000 items) must hash without crash."""
    large_list = list(range(100_000))
    d: dict[str, Any] = {"id": "large-list-test", "items": large_list}
    h = canonical_hash(d)
    assert isinstance(h, str) and len(h) == 64


@pytest.mark.adversarial
def test_adversarial_json_duplicate_looking_keys() -> None:
    """Dict with duplicate-looking keys (A vs a) must preserve both and hash cleanly."""
    d = {"A": "uppercase_value", "a": "lowercase_value", "Key": 1, "key": 2}
    json_str = json.dumps(d, sort_keys=True, ensure_ascii=False)

    assert '"A": "uppercase_value"' in json_str
    assert '"a": "lowercase_value"' in json_str
    h = canonical_hash(d)
    assert isinstance(h, str) and len(h) == 64


# ============================================================================
# Registry HTTP Client Error Handling
# ============================================================================

@pytest.mark.adversarial
def test_adversarial_http_invalid_url() -> None:
    """Request with invalid URL must return a clean error, not crash."""
    invalid_url = "http://invalid.domain.that.does.not.exist.example.invalid/api"
    with pytest.raises(httpx.RequestError) as exc_info:
        registry_client_fetch(invalid_url)
    assert exc_info.type in (httpx.ConnectError, httpx.RequestError)


@pytest.mark.adversarial
def test_adversarial_http_timeout() -> None:
    """Request timing out must raise graceful httpx.TimeoutException."""
    non_routable_url = "http://10.255.255.1:81/api/timeout"
    with pytest.raises(httpx.TimeoutException) as exc_info:
        registry_client_fetch(non_routable_url, timeout=0.1)
    assert "timed out" in str(exc_info.value).lower() or exc_info.type is httpx.ConnectTimeout


@pytest.mark.adversarial
def test_adversarial_http_html_instead_of_json() -> None:
    """Request that returns HTML instead of JSON must raise JSONDecodeError cleanly."""
    html_url = "https://httpbin.org/html"
    with pytest.raises(json.JSONDecodeError) as exc_info:
        registry_client_fetch(html_url, timeout=10.0)
    assert "Expecting value" in str(exc_info.value)


@pytest.mark.adversarial
def test_adversarial_http_empty_body() -> None:
    """Request that returns empty body must raise clean error."""
    empty_url = "https://httpbin.org/status/204"
    with pytest.raises((ValueError, json.JSONDecodeError)) as exc_info:
        registry_client_fetch(empty_url, timeout=10.0)
    assert "empty body" in str(exc_info.value).lower() or "expecting value" in str(exc_info.value).lower()


@pytest.mark.adversarial
def test_adversarial_http_500_error() -> None:
    """Request that returns 500 must raise httpx.HTTPStatusError cleanly."""
    error_url = "https://httpbin.org/status/500"
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        registry_client_fetch(error_url, timeout=10.0)
    assert exc_info.value.response.status_code == 500
    assert "500" in str(exc_info.value)
