"""
Tests for message framing functionality.

Tests cover normal operation, edge cases, error conditions, and buffer management.
"""

import io
import pytest
from noiseframework.exceptions import (
    AuthenticationError, CryptoError, InvalidKeySizeError,
    UnsupportedPrimitiveError, UnsupportedPatternError,
    ValidationError, RoleNotSetError, RoleAlreadySetError,
    WrongTurnError, HandshakeCompleteError, MissingKeyError,
    NoKeySetError, NonceOverflowError
)

from noiseframework.framing import (
    FramedReader,
    FramedWriter,
    FramingError,
    read_framed_message,
    write_framed_message,
    DEFAULT_MAX_MESSAGE_SIZE,
)


class TestFramedWriter:
    """Test FramedWriter class."""
    
    def test_write_single_message(self):
        """Test writing a single framed message."""
        buffer = io.BytesIO()
        writer = FramedWriter(buffer)
        
        writer.write_message(b"Hello, World!")
        
        buffer.seek(0)
        # Read header (4 bytes, big-endian)
        header = buffer.read(4)
        assert len(header) == 4
        assert int.from_bytes(header, 'big') == 13  # "Hello, World!" is 13 bytes
        
        # Read message
        message = buffer.read()
        assert message == b"Hello, World!"
    
    def test_write_multiple_messages(self):
        """Test writing multiple framed messages."""
        buffer = io.BytesIO()
        writer = FramedWriter(buffer)
        
        writer.write_message(b"First")
        writer.write_message(b"Second message")
        writer.write_message(b"Third")
        
        buffer.seek(0)
        
        # First message
        length1 = int.from_bytes(buffer.read(4), 'big')
        msg1 = buffer.read(length1)
        assert msg1 == b"First"
        
        # Second message
        length2 = int.from_bytes(buffer.read(4), 'big')
        msg2 = buffer.read(length2)
        assert msg2 == b"Second message"
        
        # Third message
        length3 = int.from_bytes(buffer.read(4), 'big')
        msg3 = buffer.read(length3)
        assert msg3 == b"Third"
    
    def test_write_empty_message(self):
        """Test writing an empty message."""
        buffer = io.BytesIO()
        writer = FramedWriter(buffer)
        
        writer.write_message(b"")
        
        buffer.seek(0)
        header = buffer.read(4)
        assert int.from_bytes(header, 'big') == 0
        assert buffer.read() == b""
    
    def test_write_large_message(self):
        """Test writing a large message."""
        buffer = io.BytesIO()
        writer = FramedWriter(buffer)
        
        large_message = b"X" * 1024 * 1024  # 1 MB
        writer.write_message(large_message)
        
        buffer.seek(0)
        header = buffer.read(4)
        assert int.from_bytes(header, 'big') == 1024 * 1024
        assert buffer.read() == large_message
    
    def test_write_oversized_message(self):
        """Test that oversized messages raise FramingError."""
        buffer = io.BytesIO()
        writer = FramedWriter(buffer, max_message_size=100)
        
        with pytest.raises(FramingError) as exc_info:
            writer.write_message(b"X" * 101)
        
        assert "exceeds maximum" in str(exc_info.value)
        assert "101" in str(exc_info.value)
    
    def test_write_invalid_max_size(self):
        """Test that invalid max_message_size raises ValueError."""
        buffer = io.BytesIO()
        
        with pytest.raises((RoleNotSetError, RoleAlreadySetError, WrongTurnError, HandshakeCompleteError, ValidationError, UnsupportedPatternError, MissingKeyError, NoKeySetError, InvalidKeySizeError)):
            FramedWriter(buffer, max_message_size=0)
        
        with pytest.raises((RoleNotSetError, RoleAlreadySetError, WrongTurnError, HandshakeCompleteError, ValidationError, UnsupportedPatternError, MissingKeyError, NoKeySetError, InvalidKeySizeError)):
            FramedWriter(buffer, max_message_size=-1)
        
        with pytest.raises((RoleNotSetError, RoleAlreadySetError, WrongTurnError, HandshakeCompleteError, ValidationError, UnsupportedPatternError, MissingKeyError, NoKeySetError, InvalidKeySizeError)):
            FramedWriter(buffer, max_message_size=2**32)  # Exceeds 32-bit limit
    
    def test_messages_sent_counter(self):
        """Test that messages_sent counter is incremented."""
        buffer = io.BytesIO()
        writer = FramedWriter(buffer)
        
        assert writer.messages_sent == 0
        
        writer.write_message(b"First")
        assert writer.messages_sent == 1
        
        writer.write_message(b"Second")
        assert writer.messages_sent == 2
        
        writer.write_message(b"Third")
        assert writer.messages_sent == 3


class TestFramedReader:
    """Test FramedReader class."""
    
    def test_read_single_message(self):
        """Test reading a single framed message."""
        buffer = io.BytesIO()
        # Write framed message manually
        message = b"Hello, World!"
        buffer.write((13).to_bytes(4, 'big'))  # Length header
        buffer.write(message)
        buffer.seek(0)
        
        reader = FramedReader(buffer)
        result = reader.read_message()
        
        assert result == message
    
    def test_read_multiple_messages(self):
        """Test reading multiple framed messages."""
        buffer = io.BytesIO()
        # Write three framed messages
        for msg in [b"First", b"Second message", b"Third"]:
            buffer.write(len(msg).to_bytes(4, 'big'))
            buffer.write(msg)
        buffer.seek(0)
        
        reader = FramedReader(buffer)
        
        assert reader.read_message() == b"First"
        assert reader.read_message() == b"Second message"
        assert reader.read_message() == b"Third"
    
    def test_read_empty_message(self):
        """Test reading an empty message."""
        buffer = io.BytesIO()
        buffer.write((0).to_bytes(4, 'big'))
        buffer.seek(0)
        
        reader = FramedReader(buffer)
        result = reader.read_message()
        
        assert result == b""
    
    def test_read_large_message(self):
        """Test reading a large message."""
        buffer = io.BytesIO()
        large_message = b"X" * 1024 * 1024  # 1 MB
        buffer.write(len(large_message).to_bytes(4, 'big'))
        buffer.write(large_message)
        buffer.seek(0)
        
        reader = FramedReader(buffer)
        result = reader.read_message()
        
        assert result == large_message
    
    def test_read_oversized_message(self):
        """Test that oversized message header raises FramingError."""
        buffer = io.BytesIO()
        # Write a header claiming message is 1000 bytes
        buffer.write((1000).to_bytes(4, 'big'))
        buffer.write(b"X" * 1000)
        buffer.seek(0)
        
        # Reader with max size of 100
        reader = FramedReader(buffer, max_message_size=100)
        
        with pytest.raises(FramingError) as exc_info:
            reader.read_message()
        
        assert "exceeds maximum" in str(exc_info.value)
        assert "1000" in str(exc_info.value)
    
    def test_read_truncated_header(self):
        """Test that truncated header raises FramingError."""
        buffer = io.BytesIO()
        # Write only 2 bytes of 4-byte header
        buffer.write(b"\x00\x00")
        buffer.seek(0)
        
        reader = FramedReader(buffer)
        
        with pytest.raises(FramingError) as exc_info:
            reader.read_message()
        
        assert "Connection closed" in str(exc_info.value)
    
    def test_read_truncated_message(self):
        """Test that truncated message data raises FramingError."""
        buffer = io.BytesIO()
        # Header says 100 bytes, but only provide 50
        buffer.write((100).to_bytes(4, 'big'))
        buffer.write(b"X" * 50)
        buffer.seek(0)
        
        reader = FramedReader(buffer)
        
        with pytest.raises(FramingError) as exc_info:
            reader.read_message()
        
        assert "Connection closed" in str(exc_info.value)
        assert "expected 100" in str(exc_info.value)
        assert "got 50" in str(exc_info.value)
    
    def test_read_invalid_max_size(self):
        """Test that invalid max_message_size raises ValueError."""
        buffer = io.BytesIO()
        
        with pytest.raises((RoleNotSetError, RoleAlreadySetError, WrongTurnError, HandshakeCompleteError, ValidationError, UnsupportedPatternError, MissingKeyError, NoKeySetError, InvalidKeySizeError)):
            FramedReader(buffer, max_message_size=0)
        
        with pytest.raises((RoleNotSetError, RoleAlreadySetError, WrongTurnError, HandshakeCompleteError, ValidationError, UnsupportedPatternError, MissingKeyError, NoKeySetError, InvalidKeySizeError)):
            FramedReader(buffer, max_message_size=-1)
        
        with pytest.raises((RoleNotSetError, RoleAlreadySetError, WrongTurnError, HandshakeCompleteError, ValidationError, UnsupportedPatternError, MissingKeyError, NoKeySetError, InvalidKeySizeError)):
            FramedReader(buffer, max_message_size=2**32)
    
    def test_messages_received_counter(self):
        """Test that messages_received counter is incremented."""
        buffer = io.BytesIO()
        for msg in [b"First", b"Second", b"Third"]:
            buffer.write(len(msg).to_bytes(4, 'big'))
            buffer.write(msg)
        buffer.seek(0)
        
        reader = FramedReader(buffer)
        
        assert reader.messages_received == 0
        
        reader.read_message()
        assert reader.messages_received == 1
        
        reader.read_message()
        assert reader.messages_received == 2
        
        reader.read_message()
        assert reader.messages_received == 3


class TestRoundTrip:
    """Test write-read round trips."""
    
    def test_round_trip_single_message(self):
        """Test write and read of a single message."""
        buffer = io.BytesIO()
        
        writer = FramedWriter(buffer)
        writer.write_message(b"Hello, World!")
        
        buffer.seek(0)
        reader = FramedReader(buffer)
        result = reader.read_message()
        
        assert result == b"Hello, World!"
    
    def test_round_trip_multiple_messages(self):
        """Test write and read of multiple messages."""
        buffer = io.BytesIO()
        messages = [
            b"First message",
            b"Second message with more data",
            b"Third",
            b"",  # Empty message
            b"X" * 10000,  # Large message
        ]
        
        writer = FramedWriter(buffer)
        for msg in messages:
            writer.write_message(msg)
        
        buffer.seek(0)
        reader = FramedReader(buffer)
        results = [reader.read_message() for _ in messages]
        
        assert results == messages
    
    def test_round_trip_preserves_boundaries(self):
        """Test that framing preserves message boundaries."""
        buffer = io.BytesIO()
        
        writer = FramedWriter(buffer)
        writer.write_message(b"Message1")
        writer.write_message(b"Message2")
        writer.write_message(b"Message3")
        
        buffer.seek(0)
        reader = FramedReader(buffer)
        
        # Messages are distinct, not concatenated
        assert reader.read_message() == b"Message1"
        assert reader.read_message() == b"Message2"
        assert reader.read_message() == b"Message3"


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_write_framed_message(self):
        """Test write_framed_message convenience function."""
        buffer = io.BytesIO()
        write_framed_message(buffer, b"Test message")
        
        buffer.seek(0)
        header = int.from_bytes(buffer.read(4), 'big')
        message = buffer.read()
        
        assert header == 12
        assert message == b"Test message"
    
    def test_read_framed_message(self):
        """Test read_framed_message convenience function."""
        buffer = io.BytesIO()
        buffer.write((13).to_bytes(4, 'big'))
        buffer.write(b"Hello, World!")
        buffer.seek(0)
        
        result = read_framed_message(buffer)
        assert result == b"Hello, World!"
    
    def test_convenience_functions_round_trip(self):
        """Test convenience functions in round trip."""
        buffer = io.BytesIO()
        
        write_framed_message(buffer, b"Test")
        buffer.seek(0)
        result = read_framed_message(buffer)
        
        assert result == b"Test"
    
    def test_convenience_functions_with_max_size(self):
        """Test convenience functions with custom max_message_size."""
        buffer = io.BytesIO()
        
        # Should succeed
        write_framed_message(buffer, b"Short", max_message_size=100)
        
        # Should fail
        with pytest.raises(FramingError):
            write_framed_message(buffer, b"X" * 101, max_message_size=100)


class TestPartialReads:
    """Test handling of partial reads."""
    
    def test_partial_read_simulation(self):
        """Test that _read_exactly handles partial reads correctly."""
        # Create a custom stream that returns data in chunks
        class ChunkedStream:
            def __init__(self, data, chunk_size):
                self.data = data
                self.chunk_size = chunk_size
                self.position = 0
            
            def read(self, size):
                # Return data in small chunks
                chunk_size = min(self.chunk_size, size, len(self.data) - self.position)
                chunk = self.data[self.position:self.position + chunk_size]
                self.position += chunk_size
                return chunk
        
        # Create message
        message = b"X" * 1000
        stream_data = len(message).to_bytes(4, 'big') + message
        
        # Stream that returns 10 bytes at a time
        stream = ChunkedStream(stream_data, chunk_size=10)
        reader = FramedReader(stream)
        
        result = reader.read_message()
        assert result == message


class TestErrorConditions:
    """Test error conditions and edge cases."""
    
    def test_empty_stream(self):
        """Test reading from empty stream."""
        buffer = io.BytesIO(b"")
        reader = FramedReader(buffer)
        
        with pytest.raises(FramingError) as exc_info:
            reader.read_message()
        
        assert "Connection closed" in str(exc_info.value)
    
    def test_max_32bit_size(self):
        """Test that 32-bit size limit is enforced."""
        buffer = io.BytesIO()
        
        # Maximum valid size (2^32 - 1) should be accepted
        max_valid = 2**32 - 1
        writer = FramedWriter(buffer, max_message_size=max_valid)
        assert writer.max_message_size == max_valid
        
        # Exceeding 32-bit limit should be rejected
        with pytest.raises((RoleNotSetError, RoleAlreadySetError, WrongTurnError, HandshakeCompleteError, ValidationError, UnsupportedPatternError, MissingKeyError, NoKeySetError, InvalidKeySizeError)):
            FramedWriter(buffer, max_message_size=2**32)
    
    def test_default_max_size(self):
        """Test default maximum message size."""
        buffer = io.BytesIO()
        writer = FramedWriter(buffer)
        reader = FramedReader(buffer)
        
        assert writer.max_message_size == DEFAULT_MAX_MESSAGE_SIZE
        assert reader.max_message_size == DEFAULT_MAX_MESSAGE_SIZE
        assert DEFAULT_MAX_MESSAGE_SIZE == 16 * 1024 * 1024  # 16 MB


class TestLogging:
    """Test logging functionality."""
    
    def test_custom_logger(self, caplog):
        """Test that custom logger is used."""
        import logging
        
        buffer = io.BytesIO()
        custom_logger = logging.getLogger("test.framing")
        
        writer = FramedWriter(buffer, logger=custom_logger)
        assert writer.logger is custom_logger
        
        reader = FramedReader(buffer, logger=custom_logger)
        assert reader.logger is custom_logger
    
    def test_logging_write(self, caplog):
        """Test that write operations are logged."""
        import logging
        
        buffer = io.BytesIO()
        writer = FramedWriter(buffer)
        
        with caplog.at_level(logging.INFO):
            writer.write_message(b"Test")
        
        assert "Sent framed message" in caplog.text
    
    def test_logging_read(self, caplog):
        """Test that read operations are logged."""
        import logging
        
        buffer = io.BytesIO()
        buffer.write((4).to_bytes(4, 'big'))
        buffer.write(b"Test")
        buffer.seek(0)
        
        reader = FramedReader(buffer)
        
        with caplog.at_level(logging.INFO):
            reader.read_message()
        
        assert "Received framed message" in caplog.text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
