"""Tests for Diffie-Hellman functions."""

import pytest
from py_noise.crypto.dh import Curve25519, Curve448, get_dh_function


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

        with pytest.raises(ValueError, match="Private key must be 32 bytes"):
            dh.dh(b"short", public)

    def test_dh_invalid_public_key_size(self) -> None:
        """Test DH with invalid public key size."""
        dh = Curve25519()
        private, _ = dh.generate_keypair()

        with pytest.raises(ValueError, match="Public key must be 32 bytes"):
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

        with pytest.raises(ValueError, match="Private key must be 56 bytes"):
            dh.dh(b"short", public)

    def test_dh_invalid_public_key_size(self) -> None:
        """Test DH with invalid public key size."""
        dh = Curve448()
        private, _ = dh.generate_keypair()

        with pytest.raises(ValueError, match="Public key must be 56 bytes"):
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

    def test_unknown_dh_function(self) -> None:
        """Test unknown DH function raises error."""
        with pytest.raises(ValueError, match="Unknown DH function"):
            get_dh_function("unknown")
