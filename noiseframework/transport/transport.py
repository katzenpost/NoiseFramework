"""
Transport layer for post-handshake encrypted communication.

Provides a simple wrapper around cipher states for ongoing encryption.
"""

from typing import Optional
from noiseframework.noise.state import CipherState


class NoiseTransport:
    """
    Transport layer for encrypted communication after handshake completion.

    Wraps send and receive cipher states for bidirectional encrypted communication.
    """

    def __init__(self, send_cipher: CipherState, receive_cipher: CipherState) -> None:
        """
        Initialize transport with cipher states.

        Args:
            send_cipher: CipherState for sending messages
            receive_cipher: CipherState for receiving messages
        """
        self.send_cipher = send_cipher
        self.receive_cipher = receive_cipher

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
        return self.send_cipher.encrypt_with_ad(ad, plaintext)

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
        return self.receive_cipher.decrypt_with_ad(ad, ciphertext)

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
