"""
AEAD cipher functions for the Noise Protocol Framework.

Supports ChaCha20-Poly1305 and AES-256-GCM.
"""

from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from noiseframework.exceptions import CryptoError, InvalidKeySizeError, AuthenticationError, UnsupportedPrimitiveError


class CipherFunction:
    """Base class for AEAD cipher functions."""

    def __init__(self, name: str) -> None:
        """
        Initialize a cipher function.

        Args:
            name: Name of the cipher (e.g., "ChaChaPoly", "AESGCM")
        """
        self.name = name

    def encrypt(self, key: bytes, nonce: int, ad: bytes, plaintext: bytes) -> bytes:
        """
        Encrypt with associated data.

        Args:
            key: 32-byte encryption key
            nonce: 8-byte nonce as integer
            ad: Associated data
            plaintext: Data to encrypt

        Returns:
            Ciphertext with authentication tag appended

        Raises:
            ValueError: If parameters are invalid
        """
        raise NotImplementedError

    def decrypt(self, key: bytes, nonce: int, ad: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt and verify associated data.

        Args:
            key: 32-byte encryption key
            nonce: 8-byte nonce as integer
            ad: Associated data
            ciphertext: Data to decrypt (with tag)

        Returns:
            Plaintext

        Raises:
            ValueError: If parameters are invalid or authentication fails
        """
        raise NotImplementedError


class ChaChaPoly(CipherFunction):
    """ChaCha20-Poly1305 AEAD cipher."""

    def __init__(self) -> None:
        """Initialize ChaCha20-Poly1305 cipher."""
        super().__init__("ChaChaPoly")

    def encrypt(self, key: bytes, nonce: int, ad: bytes, plaintext: bytes) -> bytes:
        """
        Encrypt with ChaCha20-Poly1305.

        Args:
            key: 32-byte encryption key
            nonce: 8-byte nonce as integer (will be encoded as little-endian + 4 zero bytes)
            ad: Associated data
            plaintext: Data to encrypt

        Returns:
            Ciphertext with 16-byte authentication tag appended

        Raises:
            InvalidKeySizeError: If key size is not 32 bytes
            CryptoError: If nonce is out of valid range
        """
        if len(key) != 32:
            raise InvalidKeySizeError(
                f"ChaCha20-Poly1305 requires 32-byte key, got {len(key)} bytes. "
                f"Check your key derivation process."
            )
        if nonce < 0 or nonce >= 2**64:
            raise CryptoError(
                f"Nonce must be a 64-bit unsigned integer (0 to 2^64-1), got {nonce}. "
                f"This indicates a serious protocol violation."
            )

        # Noise uses 8-byte little-endian nonce followed by 4 zero bytes
        nonce_bytes = nonce.to_bytes(8, "little") + b"\x00\x00\x00\x00"

        cipher = ChaCha20Poly1305(key)
        return cipher.encrypt(nonce_bytes, plaintext, ad)

    def decrypt(self, key: bytes, nonce: int, ad: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt with ChaCha20-Poly1305.

        Args:
            key: 32-byte encryption key
            nonce: 8-byte nonce as integer (will be encoded as little-endian + 4 zero bytes)
            ad: Associated data
            ciphertext: Data to decrypt (with 16-byte tag)

        Returns:
            Plaintext

        Raises:
            InvalidKeySizeError: If key size is not 32 bytes
            CryptoError: If nonce is out of valid range
            AuthenticationError: If decryption or authentication fails
        """
        if len(key) != 32:
            raise InvalidKeySizeError(
                f"ChaCha20-Poly1305 requires 32-byte key, got {len(key)} bytes. "
                f"Check your key derivation process."
            )
        if nonce < 0 or nonce >= 2**64:
            raise CryptoError(
                f"Nonce must be a 64-bit unsigned integer (0 to 2^64-1), got {nonce}. "
                f"This indicates a serious protocol violation."
            )

        # Noise uses 8-byte little-endian nonce followed by 4 zero bytes
        nonce_bytes = nonce.to_bytes(8, "little") + b"\x00\x00\x00\x00"

        cipher = ChaCha20Poly1305(key)
        try:
            return cipher.decrypt(nonce_bytes, ciphertext, ad)
        except Exception as e:
            raise AuthenticationError(
                f"ChaCha20-Poly1305 decryption failed: authentication tag verification failed. "
                f"This indicates message tampering, corruption, or wrong keys. Original error: {e}"
            )


class AESGCMCipher(CipherFunction):
    """AES-256-GCM AEAD cipher."""

    def __init__(self) -> None:
        """Initialize AES-256-GCM cipher."""
        super().__init__("AESGCM")

    def encrypt(self, key: bytes, nonce: int, ad: bytes, plaintext: bytes) -> bytes:
        """
        Encrypt with AES-256-GCM.

        Args:
            key: 32-byte encryption key
            nonce: 8-byte nonce as integer (will be encoded as big-endian + 4 zero bytes)
            ad: Associated data
            plaintext: Data to encrypt

        Returns:
            Ciphertext with 16-byte authentication tag appended

        Raises:
            InvalidKeySizeError: If key size is not 32 bytes
            CryptoError: If nonce is out of valid range
        """
        if len(key) != 32:
            raise InvalidKeySizeError(
                f"AES-256-GCM requires 32-byte key, got {len(key)} bytes. "
                f"Check your key derivation process."
            )
        if nonce < 0 or nonce >= 2**64:
            raise CryptoError(
                f"Nonce must be a 64-bit unsigned integer (0 to 2^64-1), got {nonce}. "
                f"This indicates a serious protocol violation."
            )

        # Noise uses 4 zero bytes followed by 8-byte big-endian nonce for AESGCM
        nonce_bytes = b"\x00\x00\x00\x00" + nonce.to_bytes(8, "big")

        cipher = AESGCM(key)
        return cipher.encrypt(nonce_bytes, plaintext, ad)

    def decrypt(self, key: bytes, nonce: int, ad: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt with AES-256-GCM.

        Args:
            key: 32-byte encryption key
            nonce: 8-byte nonce as integer (will be encoded as big-endian + 4 zero bytes)
            ad: Associated data
            ciphertext: Data to decrypt (with 16-byte tag)

        Returns:
            Plaintext

        Raises:
            InvalidKeySizeError: If key size is not 32 bytes
            CryptoError: If nonce is out of valid range
            AuthenticationError: If decryption or authentication fails
        """
        if len(key) != 32:
            raise InvalidKeySizeError(
                f"AES-256-GCM requires 32-byte key, got {len(key)} bytes. "
                f"Check your key derivation process."
            )
        if nonce < 0 or nonce >= 2**64:
            raise CryptoError(
                f"Nonce must be a 64-bit unsigned integer (0 to 2^64-1), got {nonce}. "
                f"This indicates a serious protocol violation."
            )

        # Noise uses 4 zero bytes followed by 8-byte big-endian nonce for AESGCM
        nonce_bytes = b"\x00\x00\x00\x00" + nonce.to_bytes(8, "big")

        cipher = AESGCM(key)
        try:
            return cipher.decrypt(nonce_bytes, ciphertext, ad)
        except Exception as e:
            raise AuthenticationError(
                f"AES-256-GCM decryption failed: authentication tag verification failed. "
                f"This indicates message tampering, corruption, or wrong keys. Original error: {e}"
            )


def get_cipher_function(name: str) -> CipherFunction:
    """
    Get a cipher function by name.

    Args:
        name: Cipher function name ("ChaChaPoly" or "AESGCM")

    Returns:
        CipherFunction instance

    Raises:
        UnsupportedPrimitiveError: If cipher function name is not recognized
    """
    if name == "ChaChaPoly":
        return ChaChaPoly()
    elif name == "AESGCM":
        return AESGCMCipher()
    else:
        raise UnsupportedPrimitiveError(
            f"Unknown cipher function: '{name}'. "
            f"Supported ciphers: ChaChaPoly, AESGCM."
        )
