"""
High-level connection API combining handshake, transport, and framing.

Provides NoiseConnection and AsyncNoiseConnection classes that handle
the complete lifecycle of a Noise Protocol connection with automatic
handshake-to-transport transition.
"""

import asyncio
import logging
import socket
from typing import Optional, Tuple, Union

from noiseframework.noise.handshake import NoiseHandshake
from noiseframework.transport.transport import NoiseTransport
from noiseframework.framing import FramedReader, FramedWriter, DEFAULT_MAX_MESSAGE_SIZE
from noiseframework.async_support import (
    AsyncNoiseHandshake,
    AsyncNoiseTransport,
    AsyncFramedReader,
    AsyncFramedWriter,
)
from noiseframework.exceptions import HandshakeError, TransportError, ValidationError


class NoiseConnection:
    """
    High-level synchronous Noise Protocol connection.
    
    Combines handshake, transport, and framing into a single easy-to-use
    interface. Automatically transitions from handshake to transport mode.
    
    Example:
        >>> # Client (initiator)
        >>> conn = NoiseConnection("Noise_XX_25519_ChaChaPoly_SHA256", "initiator")
        >>> conn.connect(("localhost", 9999))
        >>> conn.send(b"Hello, server!")
        >>> response = conn.receive()
        >>> conn.close()
        
        >>> # Server (responder)
        >>> with NoiseConnection("Noise_XX_25519_ChaChaPoly_SHA256", "responder") as conn:
        ...     conn.accept(client_socket)
        ...     data = conn.receive()
        ...     conn.send(b"Hello, client!")
    """
    
    def __init__(
        self,
        pattern: str,
        role: str,
        static_private_key: Optional[bytes] = None,
        static_public_key: Optional[bytes] = None,
        remote_static_public_key: Optional[bytes] = None,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """
        Initialize a Noise connection.
        
        Args:
            pattern: Noise pattern string (e.g., "Noise_XX_25519_ChaChaPoly_SHA256")
            role: Either "initiator" or "responder"
            static_private_key: Optional pre-generated static private key
            static_public_key: Optional pre-generated static public key
            remote_static_public_key: Optional known remote static public key
            max_message_size: Maximum message size in bytes (default: 16 MB)
            logger: Optional logger instance
            
        Raises:
            ValidationError: If role or parameters are invalid
        """
        if role not in ("initiator", "responder"):
            raise ValidationError(
                f"Invalid role '{role}'. Must be 'initiator' or 'responder'."
            )
        
        self.pattern = pattern
        self.role = role
        self.max_message_size = max_message_size
        self.logger = logger or logging.getLogger(f"{__name__}.NoiseConnection")
        
        # Initialize handshake
        self.handshake = NoiseHandshake(pattern, logger=self.logger)
        
        # Set role
        if role == "initiator":
            self.handshake.set_as_initiator()
        else:
            self.handshake.set_as_responder()
        
        # Set static keypair if provided
        if static_private_key and static_public_key:
            self.handshake.set_static_keypair(static_private_key, static_public_key)
        else:
            # Generate new keypair
            self.handshake.generate_static_keypair()
        
        # Set remote static public key if known (for patterns like IK, NK)
        if remote_static_public_key:
            self.handshake.set_remote_static_public_key(remote_static_public_key)
        
        # Connection state
        self.transport: Optional[NoiseTransport] = None
        self.socket: Optional[socket.socket] = None
        self.reader: Optional[FramedReader] = None
        self.writer: Optional[FramedWriter] = None
        self._connected = False
        
        self.logger.info(f"NoiseConnection initialized (pattern={pattern}, role={role})")
    
    def connect(self, address: Tuple[str, int]) -> None:
        """
        Connect to a remote endpoint and perform handshake (initiator only).
        
        Args:
            address: Tuple of (host, port)
            
        Raises:
            ValidationError: If role is not initiator
            HandshakeError: If handshake fails
            ConnectionError: If connection fails
        """
        if self.role != "initiator":
            raise ValidationError("Only initiator can call connect(). Responder should use accept().")
        
        self.logger.info(f"Connecting to {address[0]}:{address[1]}")
        
        # Create socket and connect
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect(address)
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            self.socket.close()
            raise ConnectionError(f"Failed to connect to {address}: {e}") from e
        
        # Setup framing
        self.reader = FramedReader(
            self.socket.makefile('rb'),
            max_message_size=self.max_message_size,
            logger=self.logger
        )
        self.writer = FramedWriter(
            self.socket.makefile('wb'),
            max_message_size=self.max_message_size,
            logger=self.logger
        )
        
        # Perform handshake
        self._perform_handshake()
        self._connected = True
        self.logger.info(f"Connected to {address[0]}:{address[1]}")
    
    def accept(self, client_socket: socket.socket) -> None:
        """
        Accept an incoming connection and perform handshake (responder only).
        
        Args:
            client_socket: Accepted client socket
            
        Raises:
            ValidationError: If role is not responder
            HandshakeError: If handshake fails
        """
        if self.role != "responder":
            raise ValidationError("Only responder can call accept(). Initiator should use connect().")
        
        self.logger.info("Accepting incoming connection")
        
        self.socket = client_socket
        
        # Setup framing
        self.reader = FramedReader(
            self.socket.makefile('rb'),
            max_message_size=self.max_message_size,
            logger=self.logger
        )
        self.writer = FramedWriter(
            self.socket.makefile('wb'),
            max_message_size=self.max_message_size,
            logger=self.logger
        )
        
        # Perform handshake
        self._perform_handshake()
        self._connected = True
        self.logger.info("Connection accepted and handshake complete")
    
    def _perform_handshake(self) -> None:
        """
        Execute the handshake according to the pattern.
        
        Automatically determines message sequence based on role and pattern.
        
        Raises:
            HandshakeError: If handshake fails
        """
        self.logger.debug("Starting handshake")
        self.handshake.initialize()
        
        # Execute handshake messages
        # The handshake tracks whose turn it is internally via message_index
        # Initiator writes on even indices (0, 2, 4...), responder on odd (1, 3, 5...)
        while not self.handshake.handshake_complete:
            current_msg_index = self.handshake.message_index
            
            # Check if it's our turn to write
            is_our_turn = (
                (self.role == "initiator" and current_msg_index % 2 == 0) or
                (self.role == "responder" and current_msg_index % 2 == 1)
            )
            
            if is_our_turn:
                # Send message
                self.logger.debug(f"Sending handshake message {current_msg_index + 1}")
                msg = self.handshake.write_message(b"")
                self.writer.write_message(msg)
            else:
                # Receive message
                self.logger.debug(f"Receiving handshake message {current_msg_index + 1}")
                msg = self.reader.read_message()
                self.handshake.read_message(msg)
        
        # Transition to transport mode
        self.logger.debug("Handshake complete, transitioning to transport mode")
        send_cipher, recv_cipher = self.handshake.to_transport()
        self.transport = NoiseTransport(send_cipher, recv_cipher, logger=self.logger)
        self.logger.info("Handshake successful")
    
    def send(self, plaintext: bytes) -> None:
        """
        Send encrypted message to remote peer.
        
        Args:
            plaintext: Data to send
            
        Raises:
            TransportError: If not connected or transport fails
        """
        if not self._connected or not self.transport:
            raise TransportError("Not connected. Call connect() or accept() first.")
        
        self.logger.debug(f"Sending message ({len(plaintext)} bytes)")
        
        try:
            ciphertext = self.transport.send(plaintext)
            self.writer.write_message(ciphertext)
            self.logger.info(f"Sent message ({len(plaintext)} bytes plaintext)")
        except Exception as e:
            self.logger.error(f"Send failed: {e}")
            raise TransportError(f"Failed to send message: {e}") from e
    
    def receive(self) -> bytes:
        """
        Receive and decrypt message from remote peer.
        
        Returns:
            Plaintext message bytes
            
        Raises:
            TransportError: If not connected or transport fails
        """
        if not self._connected or not self.transport:
            raise TransportError("Not connected. Call connect() or accept() first.")
        
        self.logger.debug("Receiving message")
        
        try:
            ciphertext = self.reader.read_message()
            plaintext = self.transport.receive(ciphertext)
            self.logger.info(f"Received message ({len(plaintext)} bytes plaintext)")
            return plaintext
        except Exception as e:
            self.logger.error(f"Receive failed: {e}")
            raise TransportError(f"Failed to receive message: {e}") from e
    
    def close(self) -> None:
        """
        Close the connection and cleanup resources.
        """
        if not self._connected:
            return
        
        self.logger.info("Closing connection")
        
        try:
            if self.reader:
                self.reader.close()
            if self.writer:
                self.writer.close()
            if self.socket:
                self.socket.close()
        except Exception as e:
            self.logger.warning(f"Error during close: {e}")
        finally:
            self._connected = False
            self.transport = None
            self.logger.debug("Connection closed")
    
    @property
    def is_connected(self) -> bool:
        """Check if connection is established."""
        return self._connected
    
    @property
    def remote_static_public_key(self) -> Optional[bytes]:
        """Get remote peer's static public key (available after handshake)."""
        return self.handshake.remote_static_public if self.handshake else None
    
    @property
    def local_static_public_key(self) -> Optional[bytes]:
        """Get local static public key."""
        return self.handshake.static_public if self.handshake else None
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures connection is closed."""
        self.close()
        return False


class AsyncNoiseConnection:
    """
    High-level asynchronous Noise Protocol connection.
    
    Async version of NoiseConnection using asyncio for non-blocking I/O.
    
    Example:
        >>> # Client (initiator)
        >>> async def client():
        ...     conn = AsyncNoiseConnection("Noise_XX_25519_ChaChaPoly_SHA256", "initiator")
        ...     await conn.connect(("localhost", 9999))
        ...     await conn.send(b"Hello, server!")
        ...     response = await conn.receive()
        ...     await conn.close()
        
        >>> # Server (responder)
        >>> async def handle_client(reader, writer):
        ...     async with AsyncNoiseConnection("Noise_XX_25519_ChaChaPoly_SHA256", "responder") as conn:
        ...         await conn.accept_streams(reader, writer)
        ...         data = await conn.receive()
        ...         await conn.send(b"Hello, client!")
    """
    
    def __init__(
        self,
        pattern: str,
        role: str,
        static_private_key: Optional[bytes] = None,
        static_public_key: Optional[bytes] = None,
        remote_static_public_key: Optional[bytes] = None,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """
        Initialize an async Noise connection.
        
        Args:
            pattern: Noise pattern string (e.g., "Noise_XX_25519_ChaChaPoly_SHA256")
            role: Either "initiator" or "responder"
            static_private_key: Optional pre-generated static private key
            static_public_key: Optional pre-generated static public key
            remote_static_public_key: Optional known remote static public key
            max_message_size: Maximum message size in bytes (default: 16 MB)
            logger: Optional logger instance
            
        Raises:
            ValidationError: If role or parameters are invalid
        """
        if role not in ("initiator", "responder"):
            raise ValidationError(
                f"Invalid role '{role}'. Must be 'initiator' or 'responder'."
            )
        
        self.pattern = pattern
        self.role = role
        self.max_message_size = max_message_size
        self.logger = logger or logging.getLogger(f"{__name__}.AsyncNoiseConnection")
        
        # Initialize async handshake
        self.handshake = AsyncNoiseHandshake(pattern, logger=self.logger)
        
        # Store keypair info for lazy initialization
        self._static_private_key = static_private_key
        self._static_public_key = static_public_key
        self._remote_static_public_key = remote_static_public_key
        self._initialized = False
        
        # Connection state
        self.transport: Optional[AsyncNoiseTransport] = None
        self.stream_reader: Optional[asyncio.StreamReader] = None
        self.stream_writer: Optional[asyncio.StreamWriter] = None
        self.reader: Optional[AsyncFramedReader] = None
        self.writer: Optional[AsyncFramedWriter] = None
        self._connected = False
        
        self.logger.info(f"AsyncNoiseConnection initialized (pattern={pattern}, role={role})")
    
    async def _initialize_handshake(self) -> None:
        """Initialize handshake with keys (async operations)."""
        if self._initialized:
            return
        
        # Set role
        if self.role == "initiator":
            await self.handshake.set_as_initiator()
        else:
            await self.handshake.set_as_responder()
        
        # Set static keypair if provided
        if self._static_private_key and self._static_public_key:
            await self.handshake.set_static_keypair(
                self._static_private_key,
                self._static_public_key
            )
        else:
            # Generate new keypair
            await self.handshake.generate_static_keypair()
        
        # Set remote static public key if known
        if self._remote_static_public_key:
            await self.handshake.set_remote_static_public_key(self._remote_static_public_key)
        
        self._initialized = True
    
    async def connect(self, address: Tuple[str, int]) -> None:
        """
        Connect to a remote endpoint and perform handshake (initiator only).
        
        Args:
            address: Tuple of (host, port)
            
        Raises:
            ValidationError: If role is not initiator
            HandshakeError: If handshake fails
            ConnectionError: If connection fails
        """
        if self.role != "initiator":
            raise ValidationError("Only initiator can call connect(). Responder should use accept_streams().")
        
        self.logger.info(f"Connecting to {address[0]}:{address[1]}")
        
        # Initialize handshake
        await self._initialize_handshake()
        
        # Open connection
        try:
            self.stream_reader, self.stream_writer = await asyncio.open_connection(
                address[0], address[1]
            )
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            raise ConnectionError(f"Failed to connect to {address}: {e}") from e
        
        # Setup framing
        self.reader = AsyncFramedReader(
            self.stream_reader,
            max_message_size=self.max_message_size,
            logger=self.logger
        )
        self.writer = AsyncFramedWriter(
            self.stream_writer,
            max_message_size=self.max_message_size,
            logger=self.logger
        )
        
        # Perform handshake
        await self._perform_handshake()
        self._connected = True
        self.logger.info(f"Connected to {address[0]}:{address[1]}")
    
    async def accept_streams(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> None:
        """
        Accept an incoming connection from asyncio streams (responder only).
        
        Args:
            reader: StreamReader from asyncio.start_server callback
            writer: StreamWriter from asyncio.start_server callback
            
        Raises:
            ValidationError: If role is not responder
            HandshakeError: If handshake fails
        """
        if self.role != "responder":
            raise ValidationError("Only responder can call accept_streams(). Initiator should use connect().")
        
        self.logger.info("Accepting incoming connection")
        
        # Initialize handshake
        await self._initialize_handshake()
        
        self.stream_reader = reader
        self.stream_writer = writer
        
        # Setup framing
        self.reader = AsyncFramedReader(
            self.stream_reader,
            max_message_size=self.max_message_size,
            logger=self.logger
        )
        self.writer = AsyncFramedWriter(
            self.stream_writer,
            max_message_size=self.max_message_size,
            logger=self.logger
        )
        
        # Perform handshake
        await self._perform_handshake()
        self._connected = True
        self.logger.info("Connection accepted and handshake complete")
    
    async def _perform_handshake(self) -> None:
        """
        Execute the handshake according to the pattern.
        
        Raises:
            HandshakeError: If handshake fails
        """
        self.logger.debug("Starting handshake")
        await self.handshake.initialize()
        
        # Execute handshake messages
        # The handshake tracks whose turn it is internally via message_index
        # Initiator writes on even indices (0, 2, 4...), responder on odd (1, 3, 5...)
        while not self.handshake.is_complete:
            current_msg_index = self.handshake._handshake.message_index
            
            # Check if it's our turn to write
            is_our_turn = (
                (self.role == "initiator" and current_msg_index % 2 == 0) or
                (self.role == "responder" and current_msg_index % 2 == 1)
            )
            
            if is_our_turn:
                # Send message
                self.logger.debug(f"Sending handshake message {current_msg_index + 1}")
                msg = await self.handshake.write_message(b"")
                await self.writer.write_message(msg)
            else:
                # Receive message
                self.logger.debug(f"Receiving handshake message {current_msg_index + 1}")
                msg = await self.reader.read_message()
                await self.handshake.read_message(msg)
        
        # Transition to transport mode
        self.logger.debug("Handshake complete, transitioning to transport mode")
        self.transport = await self.handshake.to_transport()
        self.logger.info("Handshake successful")
    
    async def send(self, plaintext: bytes) -> None:
        """
        Send encrypted message to remote peer.
        
        Args:
            plaintext: Data to send
            
        Raises:
            TransportError: If not connected or transport fails
        """
        if not self._connected or not self.transport:
            raise TransportError("Not connected. Call connect() or accept_streams() first.")
        
        self.logger.debug(f"Sending message ({len(plaintext)} bytes)")
        
        try:
            ciphertext = await self.transport.send(plaintext)
            await self.writer.write_message(ciphertext)
            self.logger.info(f"Sent message ({len(plaintext)} bytes plaintext)")
        except Exception as e:
            self.logger.error(f"Send failed: {e}")
            raise TransportError(f"Failed to send message: {e}") from e
    
    async def receive(self) -> bytes:
        """
        Receive and decrypt message from remote peer.
        
        Returns:
            Plaintext message bytes
            
        Raises:
            TransportError: If not connected or transport fails
        """
        if not self._connected or not self.transport:
            raise TransportError("Not connected. Call connect() or accept_streams() first.")
        
        self.logger.debug("Receiving message")
        
        try:
            ciphertext = await self.reader.read_message()
            plaintext = await self.transport.receive(ciphertext)
            self.logger.info(f"Received message ({len(plaintext)} bytes plaintext)")
            return plaintext
        except Exception as e:
            self.logger.error(f"Receive failed: {e}")
            raise TransportError(f"Failed to receive message: {e}") from e
    
    async def close(self) -> None:
        """
        Close the connection and cleanup resources.
        """
        if not self._connected:
            return
        
        self.logger.info("Closing connection")
        
        try:
            if self.reader:
                await self.reader.close()
            if self.writer:
                await self.writer.close()
            if self.stream_writer:
                self.stream_writer.close()
                await self.stream_writer.wait_closed()
        except Exception as e:
            self.logger.warning(f"Error during close: {e}")
        finally:
            self._connected = False
            self.transport = None
            self.logger.debug("Connection closed")
    
    @property
    def is_connected(self) -> bool:
        """Check if connection is established."""
        return self._connected
    
    @property
    def remote_static_public_key(self) -> Optional[bytes]:
        """Get remote peer's static public key (available after handshake)."""
        return self.handshake._handshake.remote_static_public if self.handshake else None
    
    @property
    def local_static_public_key(self) -> Optional[bytes]:
        """Get local static public key."""
        return self.handshake._handshake.static_public if self.handshake else None
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - ensures connection is closed."""
        await self.close()
        return False
