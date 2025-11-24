"""
Noise Protocol handshake state machine.

This module implements the main NoiseHandshake class that orchestrates
the complete handshake flow according to the Noise specification.
"""

import logging
from typing import Optional, Tuple
from enum import Enum

from noiseframework.noise.pattern import parse_pattern, get_pattern_tokens, NoisePattern
from noiseframework.noise.state import SymmetricState, CipherState
from noiseframework.crypto.dh import get_dh_function, DHFunction
from noiseframework.crypto.cipher import get_cipher_function, CipherFunction
from noiseframework.crypto.hash import get_hash_function, HashFunction


class Role(Enum):
    """Role in the handshake."""

    INITIATOR = "initiator"
    RESPONDER = "responder"


class NoiseHandshake:
    """
    Noise Protocol handshake state machine.

    Manages the complete handshake process including key exchange,
    authentication, and transition to transport mode.
    """

    def __init__(self, pattern_string: str, logger: Optional[logging.Logger] = None) -> None:
        """
        Initialize a Noise handshake.

        Args:
            pattern_string: Noise pattern (e.g., "Noise_XX_25519_ChaChaPoly_SHA256")
            logger: Optional logger instance. If None, creates a logger for this class.

        Raises:
            ValueError: If pattern string is invalid
        """
        # Setup logging
        self.logger = logger or logging.getLogger(f"{__name__}.NoiseHandshake")
        self.logger.debug(f"Initializing NoiseHandshake with pattern: {pattern_string}")
        
        # Parse and validate pattern
        self.pattern: NoisePattern = parse_pattern(pattern_string)
        self.logger.debug(
            f"Pattern parsed: {self.pattern.handshake_pattern}, "
            f"DH={self.pattern.dh_function}, "
            f"Cipher={self.pattern.cipher_function}, "
            f"Hash={self.pattern.hash_function}"
        )

        # Initialize crypto functions
        self.dh: DHFunction = get_dh_function(self.pattern.dh_function)
        self.cipher: CipherFunction = get_cipher_function(self.pattern.cipher_function)
        self.hash: HashFunction = get_hash_function(self.pattern.hash_function)

        # Get handshake message patterns
        self.initiator_pre, self.responder_pre, self.message_patterns = get_pattern_tokens(
            self.pattern.handshake_pattern
        )

        # Initialize symmetric state
        self.symmetric = SymmetricState(self.hash, self.cipher)

        # Role and state
        self.role: Optional[Role] = None
        self.message_index: int = 0
        self.handshake_complete: bool = False

        # Key pairs
        self.static_private: Optional[bytes] = None
        self.static_public: Optional[bytes] = None
        self.ephemeral_private: Optional[bytes] = None
        self.ephemeral_public: Optional[bytes] = None

        # Remote keys
        self.remote_static_public: Optional[bytes] = None
        self.remote_ephemeral_public: Optional[bytes] = None

    def set_as_initiator(self) -> None:
        """Set this handshake as the initiator."""
        if self.role is not None:
            self.logger.error("Attempted to set role when already set")
            raise ValueError("Role already set")
        self.role = Role.INITIATOR
        self.logger.info("Role set as INITIATOR")

    def set_as_responder(self) -> None:
        """Set this handshake as the responder."""
        if self.role is not None:
            self.logger.error("Attempted to set role when already set")
            raise ValueError("Role already set")
        self.role = Role.RESPONDER
        self.logger.info("Role set as RESPONDER")

    def set_static_keypair(self, private_key: bytes, public_key: bytes) -> None:
        """
        Set static key pair.

        Args:
            private_key: Static private key
            public_key: Static public key

        Raises:
            ValueError: If key sizes are incorrect
        """
        if len(private_key) != self.dh.dhlen:
            self.logger.error(f"Invalid private key size: expected {self.dh.dhlen}, got {len(private_key)}")
            raise ValueError(
                f"Private key must be {self.dh.dhlen} bytes, got {len(private_key)}"
            )
        if len(public_key) != self.dh.dhlen:
            self.logger.error(f"Invalid public key size: expected {self.dh.dhlen}, got {len(public_key)}")
            raise ValueError(
                f"Public key must be {self.dh.dhlen} bytes, got {len(public_key)}"
            )

        self.static_private = private_key
        self.static_public = public_key
        self.logger.debug(f"Static keypair set (public key: {public_key.hex()[:16]}...)")

    def generate_static_keypair(self) -> None:
        """Generate a new static key pair."""
        self.logger.debug("Generating static keypair...")
        self.static_private, self.static_public = self.dh.generate_keypair()
        self.logger.info(f"Static keypair generated (public key: {self.static_public.hex()[:16]}...)")

    def set_remote_static_public_key(self, public_key: bytes) -> None:
        """
        Set remote party's static public key (if known in advance).

        Args:
            public_key: Remote static public key

        Raises:
            ValueError: If key size is incorrect
        """
        if len(public_key) != self.dh.dhlen:
            self.logger.error(f"Invalid remote public key size: expected {self.dh.dhlen}, got {len(public_key)}")
            raise ValueError(
                f"Public key must be {self.dh.dhlen} bytes, got {len(public_key)}"
            )
        self.remote_static_public = public_key
        self.logger.debug(f"Remote static public key set (key: {public_key.hex()[:16]}...)")

    def initialize(self) -> None:
        """
        Initialize the handshake.

        Must be called after setting role and any required keys.

        Raises:
            ValueError: If role is not set or required keys are missing
        """
        self.logger.debug("Initializing handshake...")
        
        if self.role is None:
            self.logger.error("Attempted to initialize without setting role")
            raise ValueError("Role must be set before initializing")

        # Check for required static keys based on pattern
        if self.role == Role.INITIATOR and self.initiator_pre:
            if "s" in self.initiator_pre and not self.static_private:
                self.logger.error("Initiator requires static keypair for this pattern but none provided")
                raise ValueError("Initiator requires static key pair for this pattern")

        if self.role == Role.RESPONDER and self.responder_pre:
            if "s" in self.responder_pre and not self.static_private:
                self.logger.error("Responder requires static keypair for this pattern but none provided")
                raise ValueError("Responder requires static key pair for this pattern")

        # Initialize symmetric state with protocol name
        protocol_name = self.pattern.name.encode("ascii")
        self.symmetric.initialize_symmetric(protocol_name)
        self.logger.debug(f"Symmetric state initialized with protocol: {self.pattern.name}")

        # Process pre-messages
        self._process_pre_messages()
        self.logger.info(f"Handshake initialized as {self.role.value}, ready for message exchange")

    def _process_pre_messages(self) -> None:
        """Process pre-message patterns (known keys)."""
        # Initiator pre-messages
        for token in self.initiator_pre:
            if token == "s":
                if self.role == Role.INITIATOR:
                    # We are sending our static key
                    if self.static_public:
                        self.symmetric.mix_hash(self.static_public)
                elif self.role == Role.RESPONDER:
                    # We are receiving their static key
                    if self.remote_static_public:
                        self.symmetric.mix_hash(self.remote_static_public)

        # Responder pre-messages
        for token in self.responder_pre:
            if token == "s":
                if self.role == Role.RESPONDER:
                    # We are sending our static key
                    if self.static_public:
                        self.symmetric.mix_hash(self.static_public)
                elif self.role == Role.INITIATOR:
                    # We are receiving their static key
                    if self.remote_static_public:
                        self.symmetric.mix_hash(self.remote_static_public)

    def write_message(self, payload: bytes = b"") -> bytes:
        """
        Write a handshake message.

        Args:
            payload: Optional payload to include in the message

        Returns:
            Handshake message bytes

        Raises:
            ValueError: If not in correct state or handshake is complete
        """
        if self.role is None:
            self.logger.error("Attempted to write message without setting role")
            raise ValueError("Role not set")
        if self.handshake_complete:
            self.logger.error("Attempted to write message after handshake completion")
            raise ValueError("Handshake already complete")

        # Check if it's our turn to send
        is_our_turn = (
            self.message_index % 2 == 0
            if self.role == Role.INITIATOR
            else self.message_index % 2 == 1
        )
        if not is_our_turn:
            self.logger.error(f"Attempted to send message out of turn (message_index={self.message_index})")
            raise ValueError("Not our turn to send a message")

        self.logger.debug(f"Writing handshake message {self.message_index + 1}")
        message = bytearray()
        pattern = self.message_patterns[self.message_index]
        tokens = [t.strip() for t in pattern.split(",")]
        self.logger.debug(f"Processing tokens: {tokens}")

        for token in tokens:
            if token == "e":
                # Generate and send ephemeral key
                self.ephemeral_private, self.ephemeral_public = self.dh.generate_keypair()
                message.extend(self.ephemeral_public)
                self.symmetric.mix_hash(self.ephemeral_public)
            elif token == "s":
                # Send static public key (encrypted)
                if not self.static_public:
                    raise ValueError("Static key required but not set")
                encrypted_s = self.symmetric.encrypt_and_hash(self.static_public)
                message.extend(encrypted_s)
            elif token == "ee":
                # DH between ephemeral keys
                if not self.ephemeral_private or not self.remote_ephemeral_public:
                    raise ValueError("Ephemeral keys not available for ee")
                dh_output = self.dh.dh(self.ephemeral_private, self.remote_ephemeral_public)
                self.symmetric.mix_key(dh_output)
            elif token == "es":
                # DH between ephemeral and static
                if self.role == Role.INITIATOR:
                    if not self.ephemeral_private or not self.remote_static_public:
                        raise ValueError("Keys not available for es")
                    dh_output = self.dh.dh(self.ephemeral_private, self.remote_static_public)
                else:
                    if not self.static_private or not self.remote_ephemeral_public:
                        raise ValueError("Keys not available for es")
                    dh_output = self.dh.dh(self.static_private, self.remote_ephemeral_public)
                self.symmetric.mix_key(dh_output)
            elif token == "se":
                # DH between static and ephemeral
                if self.role == Role.INITIATOR:
                    if not self.static_private or not self.remote_ephemeral_public:
                        raise ValueError("Keys not available for se")
                    dh_output = self.dh.dh(self.static_private, self.remote_ephemeral_public)
                else:
                    if not self.ephemeral_private or not self.remote_static_public:
                        raise ValueError("Keys not available for se")
                    dh_output = self.dh.dh(self.ephemeral_private, self.remote_static_public)
                self.symmetric.mix_key(dh_output)
            elif token == "ss":
                # DH between static keys
                if not self.static_private or not self.remote_static_public:
                    raise ValueError("Static keys not available for ss")
                dh_output = self.dh.dh(self.static_private, self.remote_static_public)
                self.symmetric.mix_key(dh_output)

        # Encrypt payload
        encrypted_payload = self.symmetric.encrypt_and_hash(payload)
        message.extend(encrypted_payload)

        self.message_index += 1
        message_bytes = bytes(message)
        self.logger.info(f"Sent handshake message {self.message_index} ({len(message_bytes)} bytes, payload={len(payload)} bytes)")

        # Check if handshake is complete
        if self.message_index >= len(self.message_patterns):
            self.handshake_complete = True
            self.logger.info("Handshake complete - ready for transport mode")

        return message_bytes

    def read_message(self, message: bytes) -> bytes:
        """
        Read a handshake message.

        Args:
            message: Handshake message bytes

        Returns:
            Decrypted payload

        Raises:
            ValueError: If not in correct state or message is invalid
        """
        if self.role is None:
            self.logger.error("Attempted to read message without setting role")
            raise ValueError("Role not set")
        if self.handshake_complete:
            self.logger.error("Attempted to read message after handshake completion")
            raise ValueError("Handshake already complete")

        # Check if it's our turn to receive
        is_our_turn = (
            self.message_index % 2 == 1
            if self.role == Role.INITIATOR
            else self.message_index % 2 == 0
        )
        if not is_our_turn:
            self.logger.error(f"Attempted to receive message out of turn (message_index={self.message_index})")
            raise ValueError("Not our turn to receive a message")

        self.logger.debug(f"Reading handshake message {self.message_index + 1} ({len(message)} bytes)")
        pattern = self.message_patterns[self.message_index]
        tokens = [t.strip() for t in pattern.split(",")]
        self.logger.debug(f"Processing tokens: {tokens}")

        offset = 0

        for token in tokens:
            if token == "e":
                # Read ephemeral public key
                self.remote_ephemeral_public = message[offset : offset + self.dh.dhlen]
                offset += self.dh.dhlen
                self.symmetric.mix_hash(self.remote_ephemeral_public)
            elif token == "s":
                # Read static public key (encrypted)
                tag_len = 16 if self.symmetric.cipher_state.has_key() else 0
                encrypted_s = message[offset : offset + self.dh.dhlen + tag_len]
                offset += self.dh.dhlen + tag_len
                self.remote_static_public = self.symmetric.decrypt_and_hash(encrypted_s)
            elif token == "ee":
                # DH between ephemeral keys
                if not self.ephemeral_private or not self.remote_ephemeral_public:
                    raise ValueError("Ephemeral keys not available for ee")
                dh_output = self.dh.dh(self.ephemeral_private, self.remote_ephemeral_public)
                self.symmetric.mix_key(dh_output)
            elif token == "es":
                # DH between ephemeral and static
                if self.role == Role.INITIATOR:
                    if not self.ephemeral_private or not self.remote_static_public:
                        raise ValueError("Keys not available for es")
                    dh_output = self.dh.dh(self.ephemeral_private, self.remote_static_public)
                else:
                    if not self.static_private or not self.remote_ephemeral_public:
                        raise ValueError("Keys not available for es")
                    dh_output = self.dh.dh(self.static_private, self.remote_ephemeral_public)
                self.symmetric.mix_key(dh_output)
            elif token == "se":
                # DH between static and ephemeral
                if self.role == Role.INITIATOR:
                    if not self.static_private or not self.remote_ephemeral_public:
                        raise ValueError("Keys not available for se")
                    dh_output = self.dh.dh(self.static_private, self.remote_ephemeral_public)
                else:
                    if not self.ephemeral_private or not self.remote_static_public:
                        raise ValueError("Keys not available for se")
                    dh_output = self.dh.dh(self.ephemeral_private, self.remote_static_public)
                self.symmetric.mix_key(dh_output)
            elif token == "ss":
                # DH between static keys
                if not self.static_private or not self.remote_static_public:
                    raise ValueError("Static keys not available for ss")
                dh_output = self.dh.dh(self.static_private, self.remote_static_public)
                self.symmetric.mix_key(dh_output)

        # Decrypt payload
        encrypted_payload = message[offset:]
        payload = self.symmetric.decrypt_and_hash(encrypted_payload)

        self.message_index += 1
        self.logger.info(f"Received handshake message {self.message_index} (payload={len(payload)} bytes)")

        # Check if handshake is complete
        if self.message_index >= len(self.message_patterns):
            self.handshake_complete = True
            self.logger.info("Handshake complete - ready for transport mode")

        return payload

    def get_handshake_hash(self) -> bytes:
        """
        Get the current handshake hash.

        Returns:
            Handshake hash value

        Raises:
            ValueError: If handshake is not complete
        """
        if not self.handshake_complete:
            raise ValueError("Handshake not yet complete")
        return self.symmetric.get_handshake_hash()

    def to_transport(self) -> Tuple[CipherState, CipherState]:
        """
        Split into transport cipher states.

        Returns:
            Tuple of (send_cipher, receive_cipher)

        Raises:
            ValueError: If handshake is not complete
        """
        if not self.handshake_complete:
            raise ValueError("Handshake not yet complete")

        c1, c2 = self.symmetric.split()

        # Initiator sends with c1, receives with c2
        # Responder sends with c2, receives with c1
        if self.role == Role.INITIATOR:
            return c1, c2
        else:
            return c2, c1
