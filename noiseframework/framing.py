"""
Message framing for Noise Protocol communication over streams.

Provides length-prefixed framing for sending and receiving messages over
stream-based transports (TCP sockets, pipes, etc.).
"""

import logging
import struct
from typing import BinaryIO, Optional

from noiseframework.exceptions import NoiseError, ValidationError


# Frame format: 4-byte length (big-endian unsigned int) + message data
FRAME_HEADER_SIZE = 4
FRAME_HEADER_FORMAT = "!I"  # Network byte order (big-endian), unsigned int
DEFAULT_MAX_MESSAGE_SIZE = 16 * 1024 * 1024  # 16 MB


class FramingError(NoiseError):
    """
    Exception raised for framing errors.
    
    This includes oversized messages, invalid frame headers, and
    incomplete reads from closed connections.
    """
    pass


class FramedWriter:
    """
    Writer for length-prefixed framed messages.
    
    Prepends a 4-byte length header (big-endian) to each message before writing.
    """
    
    def __init__(
        self,
        stream: BinaryIO,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """
        Initialize a framed writer.
        
        Args:
            stream: Binary stream to write to (e.g., socket.makefile('wb'))
            max_message_size: Maximum message size in bytes (default: 16 MB)
            logger: Optional logger for framing operations
        
        Raises:
            ValidationError: If max_message_size is invalid
        """
        if max_message_size <= 0:
            raise ValidationError(
                f"max_message_size must be positive, got {max_message_size}. "
                f"Use a reasonable value like {DEFAULT_MAX_MESSAGE_SIZE} (16 MB)."
            )
        if max_message_size > 2**32 - 1:
            raise ValidationError(
                f"max_message_size exceeds 32-bit limit: {max_message_size}. "
                f"Maximum allowed is {2**32 - 1} bytes (~4 GB)."
            )
        
        self.stream = stream
        self.max_message_size = max_message_size
        self.logger = logger or logging.getLogger(f"{__name__}.FramedWriter")
        self.messages_sent = 0
        
        self.logger.debug(f"FramedWriter initialized (max_message_size={max_message_size})")
    
    def write_message(self, message: bytes) -> None:
        """
        Write a framed message to the stream.
        
        Args:
            message: Message bytes to write
        
        Raises:
            FramingError: If message exceeds max_message_size
            IOError: If stream write fails
        """
        message_len = len(message)
        
        if message_len > self.max_message_size:
            self.logger.error(
                f"Message size {message_len} exceeds maximum {self.max_message_size}"
            )
            raise FramingError(
                f"Message size {message_len} exceeds maximum allowed size {self.max_message_size}"
            )
        
        self.logger.debug(f"Writing framed message ({message_len} bytes)")
        
        try:
            # Write length header (4 bytes, big-endian)
            header = struct.pack(FRAME_HEADER_FORMAT, message_len)
            self.stream.write(header)
            
            # Write message data
            self.stream.write(message)
            self.stream.flush()
            
            self.messages_sent += 1
            self.logger.info(f"Sent framed message {self.messages_sent} ({message_len} bytes)")
            
        except Exception as e:
            self.logger.error(f"Failed to write framed message: {e}")
            raise IOError(f"Failed to write framed message: {e}") from e
    
    def close(self) -> None:
        """Close the underlying stream."""
        self.logger.debug("Closing FramedWriter")
        self.stream.close()


class FramedReader:
    """
    Reader for length-prefixed framed messages.
    
    Reads 4-byte length header (big-endian) followed by message data.
    Handles partial reads and buffer management automatically.
    """
    
    def __init__(
        self,
        stream: BinaryIO,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """
        Initialize a framed reader.
        
        Args:
            stream: Binary stream to read from (e.g., socket.makefile('rb'))
            max_message_size: Maximum message size in bytes (default: 16 MB)
            logger: Optional logger for framing operations
        
        Raises:
            ValidationError: If max_message_size is invalid
        """
        if max_message_size <= 0:
            raise ValidationError(
                f"max_message_size must be positive, got {max_message_size}. "
                f"Use a reasonable value like {DEFAULT_MAX_MESSAGE_SIZE} (16 MB)."
            )
        if max_message_size > 2**32 - 1:
            raise ValidationError(
                f"max_message_size exceeds 32-bit limit: {max_message_size}. "
                f"Maximum allowed is {2**32 - 1} bytes (~4 GB)."
            )
        
        self.stream = stream
        self.max_message_size = max_message_size
        self.logger = logger or logging.getLogger(f"{__name__}.FramedReader")
        self.messages_received = 0
        
        self.logger.debug(f"FramedReader initialized (max_message_size={max_message_size})")
    
    def read_message(self) -> bytes:
        """
        Read a framed message from the stream.
        
        Returns:
            The message bytes
        
        Raises:
            FramingError: If frame header is invalid, message is oversized,
                         or connection closed unexpectedly
            IOError: If stream read fails
        """
        self.logger.debug("Reading frame header")
        
        try:
            # Read length header (4 bytes)
            header_data = self._read_exactly(FRAME_HEADER_SIZE)
            if len(header_data) < FRAME_HEADER_SIZE:
                self.logger.error(f"Connection closed while reading frame header: expected {FRAME_HEADER_SIZE} bytes, got {len(header_data)}")
                raise FramingError(f"Connection closed while reading frame header: expected {FRAME_HEADER_SIZE} bytes, got {len(header_data)}")
            
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
            message_data = self._read_exactly(message_len)
            
            if len(message_data) < message_len:
                self.logger.error(
                    f"Connection closed: expected {message_len} bytes, got {len(message_data)}"
                )
                raise FramingError(
                    f"Connection closed: expected {message_len} bytes, got {len(message_data)}"
                )
            
            self.messages_received += 1
            self.logger.info(
                f"Received framed message {self.messages_received} ({message_len} bytes)"
            )
            
            return message_data
            
        except FramingError:
            raise
        except Exception as e:
            self.logger.error(f"Failed to read framed message: {e}")
            raise IOError(f"Failed to read framed message: {e}") from e
    
    def _read_exactly(self, num_bytes: int) -> bytes:
        """
        Read exactly num_bytes from the stream, handling partial reads.
        
        Args:
            num_bytes: Number of bytes to read
        
        Returns:
            The bytes read (may be shorter if connection closed)
        """
        buffer = bytearray()
        remaining = num_bytes
        
        while remaining > 0:
            chunk = self.stream.read(remaining)
            if not chunk:
                # Connection closed
                break
            
            buffer.extend(chunk)
            remaining -= len(chunk)
        
        return bytes(buffer)
    
    def close(self) -> None:
        """Close the underlying stream."""
        self.logger.debug("Closing FramedReader")
        self.stream.close()


def write_framed_message(stream: BinaryIO, message: bytes, max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE) -> None:
    """
    Convenience function to write a single framed message.
    
    Args:
        stream: Binary stream to write to
        message: Message bytes to write
        max_message_size: Maximum message size in bytes (default: 16 MB)
    
    Raises:
        FramingError: If message exceeds max_message_size
        IOError: If stream write fails
    """
    writer = FramedWriter(stream, max_message_size=max_message_size)
    writer.write_message(message)


def read_framed_message(stream: BinaryIO, max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE) -> bytes:
    """
    Convenience function to read a single framed message.
    
    Args:
        stream: Binary stream to read from
        max_message_size: Maximum message size in bytes (default: 16 MB)
    
    Returns:
        The message bytes
    
    Raises:
        FramingError: If frame is invalid or oversized
        IOError: If stream read fails
    """
    reader = FramedReader(stream, max_message_size=max_message_size)
    return reader.read_message()
