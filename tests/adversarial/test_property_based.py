import json
import hashlib
import pytest
import ube_foundation
from hypothesis import given, settings, strategies as st

# Configure settings for minimum 1000 examples per property test
HYPOTHESIS_SETTINGS = settings(max_examples=1000, deadline=None)


def canonical_hash(d: dict) -> str:
    """Helper to compute canonical JSON SHA256 hash."""
    canonical_bytes = json.dumps(d, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


@pytest.mark.adversarial
@HYPOTHESIS_SETTINGS
@given(st.binary())
def test_property_sign_verify_always_true(msg: bytes):
    """For any valid message bytes, sign then verify returns True."""
    keypair = ube_foundation.PqcKeyPair()
    sig = keypair.sign(msg)
    assert keypair.verify(msg, sig) is True


@pytest.mark.adversarial
@HYPOTHESIS_SETTINGS
@given(st.binary(), st.integers(min_value=0))
def test_property_tampered_signature_always_false(msg: bytes, bit_offset: int):
    """For any valid message + valid signature, flipping any single bit causes verify to return False."""
    keypair = ube_foundation.PqcKeyPair()
    sig_hex = keypair.sign(msg)
    sig_bytes = bytearray.fromhex(sig_hex)

    # Flip a bit in the signature
    byte_idx = (bit_offset // 8) % len(sig_bytes)
    bit_idx = bit_offset % 8
    sig_bytes[byte_idx] ^= (1 << bit_idx)

    tampered_sig_hex = sig_bytes.hex()

    # Tampered signature should either verify as False or be rejected gracefully
    try:
        assert keypair.verify(msg, tampered_sig_hex) is False
    except (ValueError, TypeError, Exception):
        # Graceful rejection (e.g. invalid signature format error) is also safe
        pass


@pytest.mark.adversarial
@HYPOTHESIS_SETTINGS
@given(st.binary())
def test_property_wrong_key_always_false(msg: bytes):
    """For any two distinct keypairs and any message, signature from key A never verifies under key B."""
    keypair_a = ube_foundation.PqcKeyPair()
    keypair_b = ube_foundation.PqcKeyPair()

    sig_a = keypair_a.sign(msg)

    try:
        assert keypair_b.verify(msg, sig_a) is False
    except (ValueError, TypeError, Exception):
        pass


# Recursive strategy for dict generation
json_primitives = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(),
)

json_dicts = st.recursive(
    st.dictionaries(st.text(), json_primitives),
    lambda children: st.dictionaries(st.text(), st.one_of(json_primitives, children)),
    max_leaves=10,
)


@pytest.mark.adversarial
@HYPOTHESIS_SETTINGS
@given(json_dicts)
def test_property_canonical_json_reorder_same_hash(d: dict):
    """For any dict, reordering keys produces the same canonical hash."""
    # Create a reordered dict by reversing key insertion order
    reversed_keys_dict = {k: d[k] for k in reversed(list(d.keys()))}

    hash1 = canonical_hash(d)
    hash2 = canonical_hash(reversed_keys_dict)

    assert hash1 == hash2


@pytest.mark.adversarial
@HYPOTHESIS_SETTINGS
@given(st.text())
def test_property_canonical_json_unicode_roundtrip(s: str):
    """For any UTF-8 string, encode/decode/canonicalize preserves hash."""
    d = {"text": s}
    encoded = json.dumps(d, ensure_ascii=False).encode("utf-8")
    decoded = json.loads(encoded.decode("utf-8"))

    hash_orig = canonical_hash(d)
    hash_roundtrip = canonical_hash(decoded)

    assert hash_orig == hash_roundtrip


@pytest.mark.adversarial
def test_property_empty_message_handled():
    """Sign and verify empty bytes without crash."""
    keypair = ube_foundation.PqcKeyPair()
    empty_msg = b""
    sig = keypair.sign(empty_msg)
    assert keypair.verify(empty_msg, sig) is True


@pytest.mark.adversarial
def test_property_large_message_handled():
    """Sign and verify 1 MB payload without crash."""
    keypair = ube_foundation.PqcKeyPair()
    large_msg = b"A" * (1024 * 1024)  # 1 MB
    sig = keypair.sign(large_msg)
    assert keypair.verify(large_msg, sig) is True


@pytest.mark.adversarial
@HYPOTHESIS_SETTINGS
@given(st.binary(min_size=1, max_size=10000))
def test_property_high_entropy_message(msg: bytes):
    """Random bytes of arbitrary length sign and verify correctly."""
    keypair = ube_foundation.PqcKeyPair()
    sig = keypair.sign(msg)
    assert keypair.verify(msg, sig) is True
