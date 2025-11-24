"""
Transport layer for post-handshake encrypted communication.

Provides a simple wrapper around cipher states for ongoing encryption.
"""

import logging
from typing import Optional
from noiseframework.noise.state import CipherState


class NoiseTransport:
    """
    Transport layer for encrypted communication after handshake completion.

    Wraps send and receive cipher states for bidirectional encrypted communication.
    """

    def __init__(
        self,
        send_cipher: CipherState,
        receive_cipher: CipherState,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """
        Initialize transport with cipher states.

        Args:
            send_cipher: CipherState for sending messages
            receive_cipher: CipherState for receiving messages
            logger: Optional logger instance for transport operations
        """
        self.send_cipher = send_cipher
        self.receive_cipher = receive_cipher
        self.logger = logger or logging.getLogger(f"{__name__}.NoiseTransport")
        self.logger.debug("NoiseTransport initialized")

    def send(self, plaintext: bytes, ad: bytes = b"") -> bytes:
        """
        Encrypt and send a message.

        Args:
            plaintext: Data to encrypt
            ad: Associated data (optional)

        Returns:
            Ciphertext with authentication tag

        Raises:
            ValueError: If encryption fails or nonce overflow
        """
        self.logger.debug(
            f"Encrypting message (plaintext={len(plaintext)} bytes, ad={len(ad)} bytes, nonce={self.send_cipher.nonce})"
        )
        
        # Check for approaching nonce limit (2^64 - 1)
        if self.send_cipher.nonce >= 2**63:
            self.logger.warning(
                f"Send cipher nonce high: {self.send_cipher.nonce} (approaching 2^64 limit - consider rekeying)"
            )
        
        try:
            ciphertext = self.send_cipher.encrypt_with_ad(ad, plaintext)
            self.logger.info(f"Sent encrypted message (ciphertext={len(ciphertext)} bytes)")
            return ciphertext
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise

    def receive(self, ciphertext: bytes, ad: bytes = b"") -> bytes:
        """
        Receive and decrypt a message.

        Args:
            ciphertext: Encrypted data
            ad: Associated data (optional)

        Returns:
            Plaintext

        Raises:
            ValueError: If decryption or authentication fails
        """
        self.logger.debug(
            f"Decrypting message (ciphertext={len(ciphertext)} bytes, ad={len(ad)} bytes, nonce={self.receive_cipher.nonce})"
        )
        
        try:
            plaintext = self.receive_cipher.decrypt_with_ad(ad, ciphertext)
            self.logger.info(f"Received decrypted message (plaintext={len(plaintext)} bytes)")
            return plaintext
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise

    def get_send_nonce(self) -> int:
        """
        Get current send nonce value.

        Returns:
            Current send nonce
        """
        return self.send_cipher.nonce

    def get_receive_nonce(self) -> int:
        """
        Get current receive nonce value.

        Returns:
            Current receive nonce
        """
        return self.receive_cipher.nonce
