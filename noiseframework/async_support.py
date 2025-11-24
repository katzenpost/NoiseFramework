"""
Async/await support for NoiseFramework.

This module provides asyncio-compatible wrappers around the synchronous
Noise Protocol Framework implementation, enabling seamless integration
with modern async Python applications.
"""

import asyncio
import logging
import struct
from typing import Optional, Tuple

from noiseframework.noise.handshake import NoiseHandshake
from noiseframework.transport.transport import NoiseTransport
from noiseframework.framing import (
    FramingError,
    FRAME_HEADER_SIZE,
    FRAME_HEADER_FORMAT,
    DEFAULT_MAX_MESSAGE_SIZE,
)
from noiseframework.exceptions import ValidationError


class AsyncNoiseHandshake:
    """
    Async wrapper for NoiseHandshake.
    
    This class provides async methods that wrap the synchronous NoiseHandshake
    implementation, making it safe to use in asyncio applications without
    blocking the event loop.
    
    Example:
        async def client():
            handshake = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
            await handshake.set_as_initiator()
            await handshake.generate_static_keypair()
            await handshake.initialize()
            
            msg1 = await handshake.write_message(b"")
            # Send msg1 over network...
    """
    
    def __init__(self, pattern: str, logger: Optional[logging.Logger] = None):
        """
        Initialize async handshake wrapper.
        
        Args:
            pattern: Noise pattern string (e.g., "Noise_XX_25519_ChaChaPoly_SHA256")
            logger: Optional logger for debugging
        """
        self._handshake = NoiseHandshake(pattern, logger=logger)
        self._executor = None  # Use default executor
    
    async def set_as_initiator(self) -> None:
        """Set this handshake as the initiator (async)."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._handshake.set_as_initiator)
    
    async def set_as_responder(self) -> None:
        """Set this handshake as the responder (async)."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._handshake.set_as_responder)
    
    async def generate_static_keypair(self) -> None:
        """Generate a new static keypair (async)."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._handshake.generate_static_keypair)
    
    async def set_static_keypair(self, private_key: bytes, public_key: bytes) -> None:
        """Set static keypair from existing keys (async)."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            self._executor, 
            self._handshake.set_static_keypair, 
            private_key, 
            public_key
        )
    
    async def set_remote_static_public_key(self, public_key: bytes) -> None:
        """Set the remote party's static public key (async)."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            self._executor,
            self._handshake.set_remote_static_public_key,
            public_key
        )
    
    async def set_psk(self, psk: bytes) -> None:
        """Set pre-shared key for PSK patterns (async)."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            self._executor,
            self._handshake.set_psk,
            psk
        )
    
    async def initialize(self) -> None:
        """Initialize the handshake state (async)."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._handshake.initialize)
    
    async def write_message(self, payload: bytes = b"") -> bytes:
        """Write a handshake message (async)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self._handshake.write_message,
            payload
        )
    
    async def read_message(self, message: bytes) -> bytes:
        """Read a handshake message (async)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self._handshake.read_message,
            message
        )
    
    async def to_transport(self) -> "AsyncNoiseTransport":
        """
        Convert completed handshake to async transport mode.
        
        Returns:
            AsyncNoiseTransport instance for encrypted communication
        """
        loop = asyncio.get_event_loop()
        send_cipher, receive_cipher = await loop.run_in_executor(
            self._executor,
            self._handshake.to_transport
        )
        return AsyncNoiseTransport(
            send_cipher,
            receive_cipher,
            logger=self._handshake.logger
        )
    
    async def get_handshake_hash(self) -> bytes:
        """Get the handshake hash (async)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self._handshake.get_handshake_hash
        )
    
    async def start_fallback(self, remote_ephemeral_public_key: bytes) -> None:
        """
        Initiate a fallback handshake (async).
        
        This method is called by the responder when it cannot decrypt the initiator's 
        first message. It converts the current pattern to a fallback pattern.
        
        Args:
            remote_ephemeral_public_key: Alice's ephemeral public key from the failed message
            
        Raises:
            RoleNotSetError: If role is not set as responder
            ValidationError: If fallback cannot be applied to this pattern
            HandshakeCompleteError: If handshake is already complete
        """
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            self._executor,
            self._handshake.start_fallback,
            remote_ephemeral_public_key
        )
    
    @property
    def is_complete(self) -> bool:
        """Check if handshake is complete (sync property)."""
        return self._handshake.handshake_complete
    
    @property
    def pattern(self):
        """Get the Noise pattern (sync property)."""
        return self._handshake.pattern


class AsyncNoiseTransport:
    """
    Async wrapper for NoiseTransport.
    
    Provides async methods for encrypted message exchange after handshake
    completion. Safe to use in asyncio applications.
    
    Example:
        transport = await handshake.to_transport()
        
        # Send encrypted message
        ciphertext = await transport.send(b"Hello!")
        await writer.write(ciphertext)
        
        # Receive encrypted message
        ciphertext = await reader.read(1024)
        plaintext = await transport.receive(ciphertext)
    """
    
    def __init__(
        self,
        send_cipher,
        receive_cipher,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize async transport wrapper.
        
        Args:
            send_cipher: CipherState for sending
            receive_cipher: CipherState for receiving
            logger: Optional logger for debugging
        """
        self._transport = NoiseTransport(send_cipher, receive_cipher, logger=logger)
        self._executor = None
    
    async def send(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        """
        Encrypt and send a message (async).
        
        Args:
            plaintext: Message to encrypt
            associated_data: Optional associated data for AEAD
            
        Returns:
            Encrypted ciphertext
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self._transport.send,
            plaintext,
            associated_data
        )
    
    async def receive(self, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        """
        Receive and decrypt a message (async).
        
        Args:
            ciphertext: Encrypted message
            associated_data: Optional associated data for AEAD
            
        Returns:
            Decrypted plaintext
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self._transport.receive,
            ciphertext,
            associated_data
        )
    
    @property
    def send_nonce(self) -> int:
        """Get current send nonce (sync property)."""
        return self._transport.get_send_nonce()
    
    @property
    def receive_nonce(self) -> int:
        """Get current receive nonce (sync property)."""
        return self._transport.get_receive_nonce()
    
    @property
    def logger(self):
        """Get the logger (sync property)."""
        return self._transport.logger


class AsyncFramedWriter:
    """
    Async writer for length-prefixed framed messages.
    
    Provides async methods for writing framed messages to asyncio streams,
    preserving message boundaries over stream-based transports.
    
    Example:
        writer = AsyncFramedWriter(stream_writer)
        await writer.write_message(b"Hello, World!")
        await writer.close()
    """
    
    def __init__(
        self,
        writer: asyncio.StreamWriter,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize async framed writer.
        
        Args:
            writer: asyncio StreamWriter to write to
            max_message_size: Maximum message size in bytes (default 16 MB)
            logger: Optional logger for debugging
            
        Raises:
            ValidationError: If max_message_size is invalid
        """
        if max_message_size <= 0 or max_message_size >= 2**32:
            raise ValidationError(
                f"max_message_size must be between 1 and 2^32-1, got {max_message_size}. "
                f"Use a reasonable value like {DEFAULT_MAX_MESSAGE_SIZE} (16 MB)."
            )
        
        self.writer = writer
        self.max_message_size = max_message_size
        self.logger = logger or logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.messages_sent = 0
    
    async def write_message(self, message: bytes) -> None:
        """
        Write a length-prefixed message (async).
        
        Args:
            message: Message bytes to write
            
        Raises:
            FramingError: If message exceeds max_message_size
        """
        message_len = len(message)
        
        # Validate message size
        if message_len > self.max_message_size:
            self.logger.error(
                f"Message size {message_len} exceeds maximum {self.max_message_size}"
            )
            raise FramingError(
                f"Message size {message_len} exceeds maximum allowed size {self.max_message_size}"
            )
        
        # Write frame header (4 bytes, big-endian length)
        header = struct.pack(FRAME_HEADER_FORMAT, message_len)
        self.writer.write(header)
        
        # Write message data
        self.writer.write(message)
        await self.writer.drain()
        
        self.messages_sent += 1
        self.logger.info(
            f"Sent framed message {self.messages_sent} ({message_len} bytes)"
        )
        self.logger.debug(f"Frame: header={message_len}, data={message_len} bytes")
    
    async def close(self) -> None:
        """Close the underlying writer."""
        self.writer.close()
        await self.writer.wait_closed()
        self.logger.debug(f"Closed writer after {self.messages_sent} messages")


class AsyncFramedReader:
    """
    Async reader for length-prefixed framed messages.
    
    Provides async methods for reading framed messages from asyncio streams,
    automatically handling partial reads and preserving message boundaries.
    
    Example:
        reader = AsyncFramedReader(stream_reader)
        message = await reader.read_message()
        await reader.close()
    """
    
    def __init__(
        self,
        reader: asyncio.StreamReader,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize async framed reader.
        
        Args:
            reader: asyncio StreamReader to read from
            max_message_size: Maximum message size in bytes (default 16 MB)
            logger: Optional logger for debugging
            
        Raises:
            ValidationError: If max_message_size is invalid
        """
        if max_message_size <= 0 or max_message_size >= 2**32:
            raise ValidationError(
                f"max_message_size must be between 1 and 2^32-1, got {max_message_size}. "
                f"Use a reasonable value like {DEFAULT_MAX_MESSAGE_SIZE} (16 MB)."
            )
        
        self.reader = reader
        self.max_message_size = max_message_size
        self.logger = logger or logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.messages_received = 0
    
    async def read_message(self) -> bytes:
        """
        Read a length-prefixed message (async).
        
        Returns:
            Message bytes
            
        Raises:
            FramingError: If frame is invalid, truncated, or oversized
        """
        try:
            # Read frame header (4 bytes)
            header_data = await self.reader.readexactly(FRAME_HEADER_SIZE)
            
            # Unpack length
            (message_len,) = struct.unpack(FRAME_HEADER_FORMAT, header_data)
            self.logger.debug(f"Frame header indicates {message_len} bytes")
            
            # Validate message length
            if message_len > self.max_message_size:
                self.logger.error(
                    f"Frame length {message_len} exceeds maximum {self.max_message_size}"
                )
                raise FramingError(
                    f"Frame length {message_len} exceeds maximum allowed size {self.max_message_size}"
                )
            
            # Read message data
            self.logger.debug(f"Reading {message_len} bytes of message data")
            message_data = await self.reader.readexactly(message_len)
            
            self.messages_received += 1
            self.logger.info(
                f"Received framed message {self.messages_received} ({message_len} bytes)"
            )
            
            return message_data
            
        except asyncio.IncompleteReadError as e:
            self.logger.error(
                f"Connection closed: expected {e.expected} bytes, got {len(e.partial)}"
            )
            raise FramingError(
                f"Connection closed: expected {e.expected} bytes, got {len(e.partial)}"
            ) from e
        except FramingError:
            raise
        except Exception as e:
            self.logger.error(f"Failed to read framed message: {e}")
            raise IOError(f"Failed to read framed message: {e}") from e
    
    async def close(self) -> None:
        """Close the underlying reader (no-op for StreamReader)."""
        self.logger.debug(f"Reader closed after {self.messages_received} messages")


# Convenience functions for async framing

async def async_write_framed_message(
    writer: asyncio.StreamWriter,
    message: bytes,
    max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE
) -> None:
    """
    Write a single framed message to an asyncio StreamWriter.
    
    Args:
        writer: asyncio StreamWriter
        message: Message bytes to write
        max_message_size: Maximum allowed message size
        
    Raises:
        FramingError: If message exceeds max_message_size
    """
    framed_writer = AsyncFramedWriter(writer, max_message_size=max_message_size)
    await framed_writer.write_message(message)


async def async_read_framed_message(
    reader: asyncio.StreamReader,
    max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE
) -> bytes:
    """
    Read a single framed message from an asyncio StreamReader.
    
    Args:
        reader: asyncio StreamReader
        max_message_size: Maximum allowed message size
        
    Returns:
        Message bytes
        
    Raises:
        FramingError: If frame is invalid, truncated, or oversized
    """
    framed_reader = AsyncFramedReader(reader, max_message_size=max_message_size)
    return await framed_reader.read_message()
