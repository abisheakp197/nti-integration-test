import ube_foundation


def test_chain_01_sign_and_verify():
    """Verify ube-foundation PqcKeyPair signing and verification."""
    keypair = ube_foundation.PqcKeyPair()
    message = b"NTI Chain 01 Test Message"

    signature_hex = keypair.sign(message)
    assert isinstance(signature_hex, str)
    assert len(signature_hex) > 0

    assert keypair.verify(message, signature_hex)


def test_chain_01_public_key():
    """Verify ube-foundation PqcKeyPair exposes public key hex."""
    keypair = ube_foundation.PqcKeyPair()
    pk_hex = keypair.public_key_hex()
    assert isinstance(pk_hex, str)
    assert len(pk_hex) > 0
