"""
Symmetric state and cipher state for Noise Protocol.

Implements the SymmetricState and CipherState objects from the Noise spec.
"""

import logging
from typing import Optional, Tuple
from noiseframework.crypto.cipher import CipherFunction
from noiseframework.crypto.hash import HashFunction
from noiseframework.exceptions import NoKeySetError, NonceOverflowError, InvalidKeySizeError


class CipherState:
    """
    CipherState object from Noise spec.

    Manages encryption/decryption with a key and nonce counter.
    """

    def __init__(
        self, cipher: CipherFunction, logger: Optional[logging.Logger] = None
    ) -> None:
        """
        Initialize CipherState.

        Args:
            cipher: AEAD cipher function to use
            logger: Optional logger instance for cipher operations
        """
        self.cipher = cipher
        self.key: Optional[bytes] = None
        self.nonce: int = 0
        self.logger = logger or logging.getLogger(f"{__name__}.CipherState")
        self.logger.debug("CipherState initialized")

    def initialize_key(self, key: bytes) -> None:
        """
        Set the cipher key.

        Args:
            key: 32-byte encryption key
            
        Raises:
            InvalidKeySizeError: If key size is not 32 bytes
        """
        if len(key) != 32:
            raise InvalidKeySizeError(
                f"Cipher key must be exactly 32 bytes for AEAD, got {len(key)} bytes. "
                f"Check your key derivation or key generation process."
            )
        self.key = key
        self.nonce = 0
        self.logger.debug("Cipher key initialized (nonce reset to 0)")

    def has_key(self) -> bool:
        """Check if a key is set."""
        return self.key is not None

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext with associated data.

        Args:
            ad: Associated data
            plaintext: Data to encrypt

        Returns:
            Ciphertext with authentication tag

        Raises:
            ValueError: If no key is set or nonce overflow
        """
        if self.key is None:
            raise NoKeySetError(
                "Cannot encrypt: cipher key not initialized. "
                "Ensure handshake has progressed to a point where keys are established."
            )

        if self.nonce >= 2**64:
            raise NonceOverflowError(
                f"Nonce overflow at {self.nonce}: cannot encrypt more messages. "
                f"This is a critical security limit. Create a new handshake/session."
            )

        ciphertext = self.cipher.encrypt(self.key, self.nonce, ad, plaintext)
        self.nonce += 1
        return ciphertext

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext with associated data.

        Args:
            ad: Associated data
            ciphertext: Data to decrypt

        Returns:
            Plaintext

        Raises:
            ValueError: If no key is set, nonce overflow, or authentication fails
        """
        if self.key is None:
            raise NoKeySetError(
                "Cannot decrypt: cipher key not initialized. "
                "Ensure handshake has progressed to a point where keys are established."
            )

        if self.nonce >= 2**64:
            raise NonceOverflowError(
                f"Nonce overflow at {self.nonce}: cannot decrypt more messages. "
                f"This is a critical security limit. Create a new handshake/session."
            )

        plaintext = self.cipher.decrypt(self.key, self.nonce, ad, ciphertext)
        self.nonce += 1
        return plaintext

    def rekey(self) -> None:
        """
        Rekey the cipher (not implemented in basic Noise).

        This is a placeholder for future extension.
        """
        raise NotImplementedError("Rekeying not yet implemented")


class SymmetricState:
    """
    SymmetricState object from Noise spec.

    Manages hashing and encryption during the handshake.
    """

    def __init__(
        self,
        hash_func: HashFunction,
        cipher: CipherFunction,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """
        Initialize SymmetricState.

        Args:
            hash_func: Hash function to use
            cipher: AEAD cipher function to use
            logger: Optional logger instance for symmetric operations
        """
        self.hash_func = hash_func
        self.logger = logger or logging.getLogger(f"{__name__}.SymmetricState")
        self.cipher_state = CipherState(cipher, logger=self.logger)
        self.chaining_key: bytes = b""
        self.h: bytes = b""  # Handshake hash
        self.logger.debug("SymmetricState initialized")

    def initialize_symmetric(self, protocol_name: bytes) -> None:
        """
        Initialize symmetric state with protocol name.

        Args:
            protocol_name: Noise protocol name (pattern string as bytes)
        """
        hashlen = self.hash_func.hashlen

        # If protocol_name is <= hashlen, pad with zeros; otherwise hash it
        if len(protocol_name) <= hashlen:
            self.h = protocol_name + b"\x00" * (hashlen - len(protocol_name))
        else:
            self.h = self.hash_func.hash(protocol_name)

        self.chaining_key = self.h

    def mix_key(self, input_key_material: bytes) -> None:
        """
        Mix key material into chaining key.

        Args:
            input_key_material: Key material to mix (e.g., DH output)
        """
        self.logger.debug(f"Mixing key material ({len(input_key_material)} bytes)")
        ck, temp_key = self.hash_func.hkdf(self.chaining_key, input_key_material, 2)
        self.chaining_key = ck
        self.cipher_state.initialize_key(temp_key)

    def mix_hash(self, data: bytes) -> None:
        """
        Mix data into handshake hash.

        Args:
            data: Data to mix into hash
        """
        self.h = self.hash_func.hash(self.h + data)

    def mix_key_and_hash(self, input_key_material: bytes) -> None:
        """
        Mix key material into both chaining key and handshake hash.

        Used for pre-shared symmetric keys (PSK).

        Args:
            input_key_material: Key material to mix
        """
        ck, temp_h, temp_key = self.hash_func.hkdf(
            self.chaining_key, input_key_material, 3
        )
        self.chaining_key = ck
        self.mix_hash(temp_h)
        self.cipher_state.initialize_key(temp_key)

    def get_handshake_hash(self) -> bytes:
        """
        Get current handshake hash.

        Returns:
            Current handshake hash value
        """
        return self.h

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext and mix ciphertext into hash.

        Args:
            plaintext: Data to encrypt

        Returns:
            Ciphertext (or plaintext if no key set)
        """
        if self.cipher_state.has_key():
            ciphertext = self.cipher_state.encrypt_with_ad(self.h, plaintext)
        else:
            ciphertext = plaintext

        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext and mix it into hash.

        Args:
            ciphertext: Data to decrypt

        Returns:
            Plaintext

        Raises:
            ValueError: If authentication fails
        """
        if self.cipher_state.has_key():
            plaintext = self.cipher_state.decrypt_with_ad(self.h, ciphertext)
        else:
            plaintext = ciphertext

        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> Tuple[CipherState, CipherState]:
        """
        Split into two CipherStates for transport.

        Returns:
            Tuple of (send_cipher, receive_cipher)
        """
        temp_k1, temp_k2 = self.hash_func.hkdf(self.chaining_key, b"", 2)

        c1 = CipherState(self.cipher_state.cipher)
        c1.initialize_key(temp_k1)

        c2 = CipherState(self.cipher_state.cipher)
        c2.initialize_key(temp_k2)

        return c1, c2
