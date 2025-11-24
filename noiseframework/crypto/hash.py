"""
Hash functions for the Noise Protocol Framework.

Supports SHA-256, SHA-512, BLAKE2s, and BLAKE2b.
"""

import hashlib
from typing import Optional
from noiseframework.exceptions import CryptoError, UnsupportedPrimitiveError


class HashFunction:
    """Base class for hash functions."""

    def __init__(self, name: str, hashlen: int, blocklen: int) -> None:
        """
        Initialize a hash function.

        Args:
            name: Name of the hash function
            hashlen: Length of hash output in bytes
            blocklen: Block size in bytes
        """
        self.name = name
        self.hashlen = hashlen
        self.blocklen = blocklen

    def hash(self, data: bytes) -> bytes:
        """
        Hash data.

        Args:
            data: Data to hash

        Returns:
            Hash output
        """
        raise NotImplementedError

    def hmac_hash(self, key: bytes, data: bytes) -> bytes:
        """
        HMAC-HASH function.

        Args:
            key: HMAC key
            data: Data to authenticate

        Returns:
            HMAC output
        """
        raise NotImplementedError

    def hkdf(
        self, chaining_key: bytes, input_key_material: bytes, num_outputs: int
    ) -> tuple:
        """
        HKDF key derivation function.

        Args:
            chaining_key: Chaining key (HKDF salt)
            input_key_material: Input key material (HKDF IKM)
            num_outputs: Number of output keys (2 or 3)

        Returns:
            Tuple of derived keys (2 or 3 keys depending on num_outputs)

        Raises:
            ValueError: If num_outputs is not 2 or 3
        """
        if num_outputs not in (2, 3):
            raise CryptoError(
                f"HKDF num_outputs must be 2 or 3 (per Noise spec), got {num_outputs}. "
                f"This indicates incorrect usage of the HKDF function."
            )

        # HKDF from Noise spec (simplified, two-step only)
        temp_key = self.hmac_hash(chaining_key, input_key_material)
        output1 = self.hmac_hash(temp_key, b"\x01")
        output2 = self.hmac_hash(temp_key, output1 + b"\x02")

        if num_outputs == 2:
            return output1, output2
        else:
            output3 = self.hmac_hash(temp_key, output2 + b"\x03")
            return output1, output2, output3


class SHA256(HashFunction):
    """SHA-256 hash function."""

    def __init__(self) -> None:
        """Initialize SHA-256 hash function."""
        super().__init__("SHA256", 32, 64)

    def hash(self, data: bytes) -> bytes:
        """
        Compute SHA-256 hash.

        Args:
            data: Data to hash

        Returns:
            32-byte hash
        """
        return hashlib.sha256(data).digest()

    def hmac_hash(self, key: bytes, data: bytes) -> bytes:
        """
        Compute HMAC-SHA256.

        Args:
            key: HMAC key
            data: Data to authenticate

        Returns:
            32-byte HMAC
        """
        return hashlib.pbkdf2_hmac("sha256", data, key, 1, dklen=32)


class SHA512(HashFunction):
    """SHA-512 hash function."""

    def __init__(self) -> None:
        """Initialize SHA-512 hash function."""
        super().__init__("SHA512", 64, 128)

    def hash(self, data: bytes) -> bytes:
        """
        Compute SHA-512 hash.

        Args:
            data: Data to hash

        Returns:
            64-byte hash
        """
        return hashlib.sha512(data).digest()

    def hmac_hash(self, key: bytes, data: bytes) -> bytes:
        """
        Compute HMAC-SHA512.

        Args:
            key: HMAC key
            data: Data to authenticate

        Returns:
            64-byte HMAC
        """
        return hashlib.pbkdf2_hmac("sha512", data, key, 1, dklen=64)


class BLAKE2s(HashFunction):
    """BLAKE2s hash function."""

    def __init__(self) -> None:
        """Initialize BLAKE2s hash function."""
        super().__init__("BLAKE2s", 32, 64)

    def hash(self, data: bytes) -> bytes:
        """
        Compute BLAKE2s hash.

        Args:
            data: Data to hash

        Returns:
            32-byte hash
        """
        return hashlib.blake2s(data).digest()

    def hmac_hash(self, key: bytes, data: bytes) -> bytes:
        """
        Compute HMAC-BLAKE2s.

        Args:
            key: HMAC key
            data: Data to authenticate

        Returns:
            32-byte HMAC
        """
        return hashlib.blake2s(data, key=key).digest()


class BLAKE2b(HashFunction):
    """BLAKE2b hash function."""

    def __init__(self) -> None:
        """Initialize BLAKE2b hash function."""
        super().__init__("BLAKE2b", 64, 128)

    def hash(self, data: bytes) -> bytes:
        """
        Compute BLAKE2b hash.

        Args:
            data: Data to hash

        Returns:
            64-byte hash
        """
        return hashlib.blake2b(data).digest()

    def hmac_hash(self, key: bytes, data: bytes) -> bytes:
        """
        Compute HMAC-BLAKE2b.

        Args:
            key: HMAC key
            data: Data to authenticate

        Returns:
            64-byte HMAC
        """
        return hashlib.blake2b(data, key=key).digest()


def get_hash_function(name: str) -> HashFunction:
    """
    Get a hash function by name.

    Args:
        name: Hash function name ("SHA256", "SHA512", "BLAKE2s", or "BLAKE2b")

    Returns:
        HashFunction instance

    Raises:
        UnsupportedPrimitiveError: If hash function name is not recognized
    """
    if name == "SHA256":
        return SHA256()
    elif name == "SHA512":
        return SHA512()
    elif name == "BLAKE2s":
        return BLAKE2s()
    elif name == "BLAKE2b":
        return BLAKE2b()
    else:
        raise UnsupportedPrimitiveError(
            f"Unknown hash function: '{name}'. "
            f"Supported hash functions: SHA256, SHA512, BLAKE2s, BLAKE2b."
        )
