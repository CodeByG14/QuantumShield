import pytest
from quantumshield.agility.providers import ClassicalAEADProvider, create_aead_provider
from quantumshield.agility.registry import ProviderRegistry
from quantumshield.agility.providers import register_all_providers

@pytest.mark.parametrize("algorithm,key", [("AES-128-GCM", b"k"*16), ("AES-256-GCM", b"k"*32), ("ChaCha20-Poly1305", b"k"*32)])
def test_aead_round_trip_and_authentication(algorithm, key):
    provider = create_aead_provider(algorithm)
    nonce, plaintext, aad = b"n"*12, b"quantumshield", b"context"
    ciphertext = provider.encrypt(key, nonce, plaintext, aad)
    assert provider.decrypt(key, nonce, ciphertext, aad) == plaintext
    with pytest.raises(Exception): provider.decrypt(key, nonce, ciphertext, b"wrong-context")


def test_aead_validates_key_and_nonce():
    provider = create_aead_provider("AES-256-GCM")
    with pytest.raises(ValueError, match="32-byte key"): provider.encrypt(b"short", b"n"*12, b"x")
    with pytest.raises(ValueError, match="12 bytes"): provider.encrypt(b"k"*32, b"bad", b"x")


def test_aead_provider_registered_with_kind_metadata():
    registry = ProviderRegistry(); register_all_providers(registry)
    assert registry.get_metadata("AES-256-GCM").kind.value == "aead"
    assert registry.is_available("AES-256-GCM")
