"""
Diffie-Hellman functions for the Noise Protocol Framework.

Supports Curve25519 (X25519), Curve448 (X448), and the hybrid NIKE
``Hybrid25519CTIDH1024`` (X25519 + CTIDH1024).
"""

from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import x25519, x448
from cryptography.hazmat.primitives import serialization

from hpqc.nike.hybrid import HybridNIKE
from hpqc.nike.x25519 import X25519 as HpqcX25519
from hpqc.nike.ctidh1024 import CTIDH1024 as HpqcCTIDH1024

from noiseframework.exceptions import InvalidKeySizeError, UnsupportedPrimitiveError


class DHFunction:
    """Base class for Diffie-Hellman functions."""

    def __init__(self, name: str, dhlen: int, privkey_size: Optional[int] = None) -> None:
        """
        Initialize a DH function.

        Args:
            name: Name of the DH function (e.g., "25519", "448")
            dhlen: Length of public keys and DH outputs in bytes
            privkey_size: Length of private keys in bytes; defaults to
                ``dhlen`` for symmetric NIKEs (X25519, X448). Hybrid
                schemes that combine an elliptic-curve and an isogeny
                NIKE typically have private keys longer than public.
        """
        self.name = name
        self.dhlen = dhlen
        self.privkey_size = privkey_size if privkey_size is not None else dhlen

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


class HybridX25519CTIDH1024(DHFunction):
    """Hybrid X25519 + CTIDH1024 NIKE for post-quantum hedge.

    Public keys are 160 bytes (32 X25519 || 128 CTIDH1024). Private
    keys are 162 bytes; the CTIDH1024 component carries two extra
    bytes of internal scheme state beyond its public-key length. The
    shared secret is the byte concatenation of the X25519 and
    CTIDH1024 secrets, which the SymmetricState's HKDF in mix_key
    handles uniformly regardless of input length.

    The Noise pattern token for this scheme is ``Hybrid25519CTIDH1024``.
    """

    _NAME = "Hybrid25519CTIDH1024"
    _PUBKEY_SIZE = 160
    _PRIVKEY_SIZE = 162

    def __init__(self) -> None:
        super().__init__(
            self._NAME,
            dhlen=self._PUBKEY_SIZE,
            privkey_size=self._PRIVKEY_SIZE,
        )
        # Pin the scheme name so deserialisation labels match what the
        # Noise pattern string declares; HybridNIKE accepts an explicit
        # ``name`` to override the default ``first.name-second.name``.
        self._scheme = HybridNIKE(HpqcX25519(), HpqcCTIDH1024(), name=self._NAME)

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a fresh hybrid keypair as (private_bytes, public_bytes)."""
        pub, priv = self._scheme.generate_keypair()
        return priv.to_bytes(), pub.to_bytes()

    def dh(self, private_key: bytes, public_key: bytes) -> bytes:
        """Compute the hybrid shared secret as X25519_ss || CTIDH1024_ss."""
        if len(private_key) != self.privkey_size:
            raise InvalidKeySizeError(
                f"{self.name} private key must be exactly {self.privkey_size} bytes, "
                f"got {len(private_key)} bytes."
            )
        if len(public_key) != self.dhlen:
            raise InvalidKeySizeError(
                f"{self.name} public key must be exactly {self.dhlen} bytes, "
                f"got {len(public_key)} bytes."
            )
        priv = self._scheme.private_key_from_bytes(private_key)
        pub = self._scheme.public_key_from_bytes(public_key)
        return self._scheme.derive_secret(priv, pub)


def get_dh_function(name: str) -> DHFunction:
    """
    Get a DH function by name.

    Args:
        name: DH function name ("25519", "448", or "Hybrid25519CTIDH1024")

    Returns:
        DHFunction instance

    Raises:
        UnsupportedPrimitiveError: If DH function name is not recognized
    """
    if name == "25519":
        return Curve25519()
    elif name == "448":
        return Curve448()
    elif name == "Hybrid25519CTIDH1024":
        return HybridX25519CTIDH1024()
    else:
        raise UnsupportedPrimitiveError(
            f"Unknown DH function: '{name}'. "
            f"Supported DH functions: 25519 (Curve25519), 448 (Curve448), "
            f"Hybrid25519CTIDH1024 (X25519 + CTIDH1024)."
        )
