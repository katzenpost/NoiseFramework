"""Tests for Diffie-Hellman functions."""

import pytest
from noiseframework.exceptions import (
    AuthenticationError, CryptoError, InvalidKeySizeError,
    UnsupportedPrimitiveError, UnsupportedPatternError,
    ValidationError, RoleNotSetError, RoleAlreadySetError,
    WrongTurnError, HandshakeCompleteError, MissingKeyError,
    NoKeySetError, NonceOverflowError
)
from noiseframework.crypto.dh import (
    Curve25519,
    Curve448,
    HybridX25519CTIDH1024,
    get_dh_function,
)


class TestCurve25519:
    """Test Curve25519 DH function."""

    def test_init(self) -> None:
        """Test Curve25519 initialization."""
        dh = Curve25519()
        assert dh.name == "25519"
        assert dh.dhlen == 32

    def test_generate_keypair(self) -> None:
        """Test key pair generation."""
        dh = Curve25519()
        private, public = dh.generate_keypair()

        assert isinstance(private, bytes)
        assert isinstance(public, bytes)
        assert len(private) == 32
        assert len(public) == 32

    def test_keypair_uniqueness(self) -> None:
        """Test that generated key pairs are unique."""
        dh = Curve25519()
        priv1, pub1 = dh.generate_keypair()
        priv2, pub2 = dh.generate_keypair()

        assert priv1 != priv2
        assert pub1 != pub2

    def test_dh_exchange(self) -> None:
        """Test DH exchange produces same shared secret."""
        dh = Curve25519()

        # Alice generates key pair
        alice_private, alice_public = dh.generate_keypair()

        # Bob generates key pair
        bob_private, bob_public = dh.generate_keypair()

        # Both compute shared secret
        alice_shared = dh.dh(alice_private, bob_public)
        bob_shared = dh.dh(bob_private, alice_public)

        # Shared secrets should match
        assert alice_shared == bob_shared
        assert len(alice_shared) == 32

    def test_dh_invalid_private_key_size(self) -> None:
        """Test DH with invalid private key size."""
        dh = Curve25519()
        _, public = dh.generate_keypair()

        with pytest.raises(InvalidKeySizeError):
            dh.dh(b"short", public)

    def test_dh_invalid_public_key_size(self) -> None:
        """Test DH with invalid public key size."""
        dh = Curve25519()
        private, _ = dh.generate_keypair()

        with pytest.raises(InvalidKeySizeError):
            dh.dh(private, b"short")


class TestCurve448:
    """Test Curve448 DH function."""

    def test_init(self) -> None:
        """Test Curve448 initialization."""
        dh = Curve448()
        assert dh.name == "448"
        assert dh.dhlen == 56

    def test_generate_keypair(self) -> None:
        """Test key pair generation."""
        dh = Curve448()
        private, public = dh.generate_keypair()

        assert isinstance(private, bytes)
        assert isinstance(public, bytes)
        assert len(private) == 56
        assert len(public) == 56

    def test_keypair_uniqueness(self) -> None:
        """Test that generated key pairs are unique."""
        dh = Curve448()
        priv1, pub1 = dh.generate_keypair()
        priv2, pub2 = dh.generate_keypair()

        assert priv1 != priv2
        assert pub1 != pub2

    def test_dh_exchange(self) -> None:
        """Test DH exchange produces same shared secret."""
        dh = Curve448()

        # Alice generates key pair
        alice_private, alice_public = dh.generate_keypair()

        # Bob generates key pair
        bob_private, bob_public = dh.generate_keypair()

        # Both compute shared secret
        alice_shared = dh.dh(alice_private, bob_public)
        bob_shared = dh.dh(bob_private, alice_public)

        # Shared secrets should match
        assert alice_shared == bob_shared
        assert len(alice_shared) == 56

    def test_dh_invalid_private_key_size(self) -> None:
        """Test DH with invalid private key size."""
        dh = Curve448()
        _, public = dh.generate_keypair()

        with pytest.raises(InvalidKeySizeError):
            dh.dh(b"short", public)

    def test_dh_invalid_public_key_size(self) -> None:
        """Test DH with invalid public key size."""
        dh = Curve448()
        private, _ = dh.generate_keypair()

        with pytest.raises(InvalidKeySizeError):
            dh.dh(private, b"short")


class TestHybridX25519CTIDH1024:
    """Test the X25519 + CTIDH1024 hybrid NIKE."""

    def test_init(self) -> None:
        """Test hybrid initialization, including asymmetric key sizes."""
        dh = HybridX25519CTIDH1024()
        assert dh.name == "Hybrid25519CTIDH1024"
        assert dh.dhlen == 160  # 32 X25519 || 128 CTIDH1024
        assert dh.privkey_size == 162  # 32 X25519 || 130 CTIDH1024 internal

    def test_generate_keypair(self) -> None:
        """Test hybrid key-pair generation."""
        dh = HybridX25519CTIDH1024()
        private, public = dh.generate_keypair()

        assert isinstance(private, bytes)
        assert isinstance(public, bytes)
        assert len(private) == 162
        assert len(public) == 160

    def test_keypair_uniqueness(self) -> None:
        """Test that generated hybrid key pairs are unique."""
        dh = HybridX25519CTIDH1024()
        priv1, pub1 = dh.generate_keypair()
        priv2, pub2 = dh.generate_keypair()

        assert priv1 != priv2
        assert pub1 != pub2

    def test_dh_exchange(self) -> None:
        """Test hybrid DH agreement: Alice and Bob derive the same secret."""
        dh = HybridX25519CTIDH1024()

        alice_private, alice_public = dh.generate_keypair()
        bob_private, bob_public = dh.generate_keypair()

        alice_shared = dh.dh(alice_private, bob_public)
        bob_shared = dh.dh(bob_private, alice_public)

        assert alice_shared == bob_shared
        # Shared secret is X25519 (32 B) || CTIDH1024 (128 B).
        assert len(alice_shared) == 160

    def test_dh_invalid_private_key_size(self) -> None:
        """Test that an undersized private key is rejected."""
        dh = HybridX25519CTIDH1024()
        _, public = dh.generate_keypair()

        with pytest.raises(InvalidKeySizeError):
            dh.dh(b"short", public)

    def test_dh_invalid_public_key_size(self) -> None:
        """Test that an undersized public key is rejected."""
        dh = HybridX25519CTIDH1024()
        private, _ = dh.generate_keypair()

        with pytest.raises(InvalidKeySizeError):
            dh.dh(private, b"short")


class TestGetDHFunction:
    """Test DH function factory."""

    def test_get_curve25519(self) -> None:
        """Test getting Curve25519."""
        dh = get_dh_function("25519")
        assert isinstance(dh, Curve25519)
        assert dh.name == "25519"

    def test_get_curve448(self) -> None:
        """Test getting Curve448."""
        dh = get_dh_function("448")
        assert isinstance(dh, Curve448)
        assert dh.name == "448"

    def test_get_hybrid_x25519_ctidh1024(self) -> None:
        """Test getting the X25519 + CTIDH1024 hybrid."""
        dh = get_dh_function("Hybrid25519CTIDH1024")
        assert isinstance(dh, HybridX25519CTIDH1024)
        assert dh.name == "Hybrid25519CTIDH1024"

    def test_unknown_dh_function(self) -> None:
        """Test unknown DH function raises error."""
        with pytest.raises(UnsupportedPrimitiveError):
            get_dh_function("unknown")


