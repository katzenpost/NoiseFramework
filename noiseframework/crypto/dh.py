"""
Diffie-Hellman functions for the Noise Protocol Framework.

Supports Curve25519 (X25519) and Curve448 (X448).
"""

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import x25519, x448
from cryptography.hazmat.primitives import serialization
from noiseframework.exceptions import InvalidKeySizeError, UnsupportedPrimitiveError


class DHFunction:
    """Base class for Diffie-Hellman functions."""

    def __init__(self, name: str, dhlen: int) -> None:
        """
        Initialize a DH function.

        Args:
            name: Name of the DH function (e.g., "25519", "448")
            dhlen: Length of public keys and DH outputs in bytes
        """
        self.name = name
        self.dhlen = dhlen

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new key pair.

        Returns:
            Tuple of (private_key, public_key) as bytes
        """
        raise NotImplementedError

    def dh(self, private_key: bytes, public_key: bytes) -> bytes:
        """
        Perform Diffie-Hellman operation.

        Args:
            private_key: Our private key
            public_key: Their public key

        Returns:
            Shared secret as bytes

        Raises:
            ValueError: If key sizes are invalid
        """
        raise NotImplementedError


class Curve25519(DHFunction):
    """Curve25519 (X25519) Diffie-Hellman function."""

    def __init__(self) -> None:
        """Initialize Curve25519 DH function."""
        super().__init__("25519", 32)

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new Curve25519 key pair.

        Returns:
            Tuple of (private_key, public_key) as 32-byte values
        """
        private = x25519.X25519PrivateKey.generate()
        public = private.public_key()

        private_bytes = private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        return private_bytes, public_bytes

    def dh(self, private_key: bytes, public_key: bytes) -> bytes:
        """
        Perform X25519 Diffie-Hellman.

        Args:
            private_key: 32-byte private key
            public_key: 32-byte public key

        Returns:
            32-byte shared secret

        Raises:
            ValueError: If key sizes are invalid
        """
        if len(private_key) != 32:
            raise InvalidKeySizeError(
                f"Curve25519 private key must be exactly 32 bytes, got {len(private_key)} bytes. "
                f"Check your key generation or loading process."
            )
        if len(public_key) != 32:
            raise InvalidKeySizeError(
                f"Curve25519 public key must be exactly 32 bytes, got {len(public_key)} bytes. "
                f"Check that the remote party is using Curve25519."
            )

        private = x25519.X25519PrivateKey.from_private_bytes(private_key)
        public = x25519.X25519PublicKey.from_public_bytes(public_key)

        shared = private.exchange(public)
        return shared


class Curve448(DHFunction):
    """Curve448 (X448) Diffie-Hellman function."""

    def __init__(self) -> None:
        """Initialize Curve448 DH function."""
        super().__init__("448", 56)

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new Curve448 key pair.

        Returns:
            Tuple of (private_key, public_key) as 56-byte values
        """
        private = x448.X448PrivateKey.generate()
        public = private.public_key()

        private_bytes = private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        return private_bytes, public_bytes

    def dh(self, private_key: bytes, public_key: bytes) -> bytes:
        """
        Perform X448 Diffie-Hellman.

        Args:
            private_key: 56-byte private key
            public_key: 56-byte public key

        Returns:
            56-byte shared secret

        Raises:
            ValueError: If key sizes are invalid
        """
        if len(private_key) != 56:
            raise InvalidKeySizeError(
                f"Curve448 private key must be exactly 56 bytes, got {len(private_key)} bytes. "
                f"Check your key generation or loading process."
            )
        if len(public_key) != 56:
            raise InvalidKeySizeError(
                f"Curve448 public key must be exactly 56 bytes, got {len(public_key)} bytes. "
                f"Check that the remote party is using Curve448."
            )

        private = x448.X448PrivateKey.from_private_bytes(private_key)
        public = x448.X448PublicKey.from_public_bytes(public_key)

        shared = private.exchange(public)
        return shared


def get_dh_function(name: str) -> DHFunction:
    """
    Get a DH function by name.

    Args:
        name: DH function name ("25519" or "448")

    Returns:
        DHFunction instance

    Raises:
        UnsupportedPrimitiveError: If DH function name is not recognized
    """
    if name == "25519":
        return Curve25519()
    elif name == "448":
        return Curve448()
    else:
        raise UnsupportedPrimitiveError(
            f"Unknown DH function: '{name}'. "
            f"Supported DH functions: 25519 (Curve25519), 448 (Curve448)."
        )
