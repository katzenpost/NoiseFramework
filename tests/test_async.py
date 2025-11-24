"""
Tests for async support in NoiseFramework.

Tests cover AsyncNoiseHandshake, AsyncNoiseTransport, AsyncFramedReader,
and AsyncFramedWriter classes.
"""

import asyncio
import io
import pytest
from noiseframework import (
    AsyncNoiseHandshake,
    AsyncNoiseTransport,
    AsyncFramedReader,
    AsyncFramedWriter,
    async_read_framed_message,
    async_write_framed_message,
    FramingError,
)


class TestAsyncNoiseHandshake:
    """Test AsyncNoiseHandshake class."""
    
    @pytest.mark.asyncio
    async def test_async_handshake_creation(self):
        """Test creating an async handshake."""
        handshake = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        assert handshake.pattern.name == "Noise_XX_25519_ChaChaPoly_SHA256"
        assert not handshake.is_complete
    
    @pytest.mark.asyncio
    async def test_async_set_as_initiator(self):
        """Test setting as initiator."""
        handshake = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await handshake.set_as_initiator()
        # Verify role was set (check role enum)
        from noiseframework.noise.handshake import Role
        assert handshake._handshake.role == Role.INITIATOR
    
    @pytest.mark.asyncio
    async def test_async_set_as_responder(self):
        """Test setting as responder."""
        handshake = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await handshake.set_as_responder()
        from noiseframework.noise.handshake import Role
        assert handshake._handshake.role == Role.RESPONDER
    
    @pytest.mark.asyncio
    async def test_async_generate_keypair(self):
        """Test async keypair generation."""
        handshake = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await handshake.set_as_initiator()
        await handshake.generate_static_keypair()
        # Verify keys were generated
        assert handshake._handshake.static_private is not None
        assert handshake._handshake.static_public is not None
    
    @pytest.mark.asyncio
    async def test_async_set_keypair(self):
        """Test setting existing keypair."""
        handshake = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await handshake.set_as_initiator()
        
        # Generate a keypair first
        await handshake.generate_static_keypair()
        private = handshake._handshake.static_private
        public = handshake._handshake.static_public
        
        # Create new handshake and set the keys
        handshake2 = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await handshake2.set_as_initiator()
        await handshake2.set_static_keypair(private, public)
        
        assert handshake2._handshake.static_private == private
        assert handshake2._handshake.static_public == public
    
    @pytest.mark.asyncio
    async def test_async_xx_handshake_complete(self):
        """Test complete XX handshake between two async parties."""
        # Create initiator
        initiator = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await initiator.set_as_initiator()
        await initiator.generate_static_keypair()
        await initiator.initialize()
        
        # Create responder
        responder = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await responder.set_as_responder()
        await responder.generate_static_keypair()
        await responder.initialize()
        
        # Perform handshake
        # Message 1: initiator -> responder
        msg1 = await initiator.write_message(b"")
        payload1 = await responder.read_message(msg1)
        assert payload1 == b""
        
        # Message 2: responder -> initiator
        msg2 = await responder.write_message(b"")
        payload2 = await initiator.read_message(msg2)
        assert payload2 == b""
        
        # Message 3: initiator -> responder
        msg3 = await initiator.write_message(b"")
        payload3 = await responder.read_message(msg3)
        assert payload3 == b""
        
        # Verify handshake is complete
        assert initiator.is_complete
        assert responder.is_complete
    
    @pytest.mark.asyncio
    async def test_async_handshake_with_payloads(self):
        """Test XX handshake with payloads in messages."""
        initiator = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await initiator.set_as_initiator()
        await initiator.generate_static_keypair()
        await initiator.initialize()
        
        responder = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await responder.set_as_responder()
        await responder.generate_static_keypair()
        await responder.initialize()
        
        # Message 1 with payload
        msg1 = await initiator.write_message(b"init payload")
        payload1 = await responder.read_message(msg1)
        assert payload1 == b"init payload"
        
        # Message 2 with payload
        msg2 = await responder.write_message(b"resp payload")
        payload2 = await initiator.read_message(msg2)
        assert payload2 == b"resp payload"
        
        # Message 3 with payload
        msg3 = await initiator.write_message(b"final payload")
        payload3 = await responder.read_message(msg3)
        assert payload3 == b"final payload"
    
    @pytest.mark.asyncio
    async def test_async_get_handshake_hash(self):
        """Test getting handshake hash after completion."""
        initiator = AsyncNoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        await initiator.set_as_initiator()
        await initiator.initialize()
        
        responder = AsyncNoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        await responder.set_as_responder()
        await responder.initialize()
        
        # Perform NN handshake (simpler, only 1 message each way)
        msg1 = await initiator.write_message(b"")
        await responder.read_message(msg1)
        
        msg2 = await responder.write_message(b"")
        await initiator.read_message(msg2)
        
        # Get handshake hashes
        init_hash = await initiator.get_handshake_hash()
        resp_hash = await responder.get_handshake_hash()
        
        assert init_hash == resp_hash
        assert len(init_hash) == 32  # SHA256


class TestAsyncNoiseTransport:
    """Test AsyncNoiseTransport class."""
    
    @pytest.mark.asyncio
    async def test_async_transport_creation(self):
        """Test creating async transport from handshake."""
        initiator = AsyncNoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        await initiator.set_as_initiator()
        await initiator.initialize()
        
        responder = AsyncNoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        await responder.set_as_responder()
        await responder.initialize()
        
        # Complete handshake
        msg1 = await initiator.write_message(b"")
        await responder.read_message(msg1)
        msg2 = await responder.write_message(b"")
        await initiator.read_message(msg2)
        
        # Create transports
        init_transport = await initiator.to_transport()
        resp_transport = await responder.to_transport()
        
        assert isinstance(init_transport, AsyncNoiseTransport)
        assert isinstance(resp_transport, AsyncNoiseTransport)
    
    @pytest.mark.asyncio
    async def test_async_transport_send_receive(self):
        """Test async send/receive with transport."""
        # Setup transports via handshake
        initiator = AsyncNoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        await initiator.set_as_initiator()
        await initiator.initialize()
        
        responder = AsyncNoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        await responder.set_as_responder()
        await responder.initialize()
        
        msg1 = await initiator.write_message(b"")
        await responder.read_message(msg1)
        msg2 = await responder.write_message(b"")
        await initiator.read_message(msg2)
        
        init_transport = await initiator.to_transport()
        resp_transport = await responder.to_transport()
        
        # Initiator sends to responder
        plaintext = b"Hello, async transport!"
        ciphertext = await init_transport.send(plaintext)
        received = await resp_transport.receive(ciphertext)
        
        assert received == plaintext
    
    @pytest.mark.asyncio
    async def test_async_transport_bidirectional(self):
        """Test bidirectional async transport communication."""
        initiator = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await initiator.set_as_initiator()
        await initiator.generate_static_keypair()
        await initiator.initialize()
        
        responder = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await responder.set_as_responder()
        await responder.generate_static_keypair()
        await responder.initialize()
        
        # Handshake
        msg1 = await initiator.write_message(b"")
        await responder.read_message(msg1)
        msg2 = await responder.write_message(b"")
        await initiator.read_message(msg2)
        msg3 = await initiator.write_message(b"")
        await responder.read_message(msg3)
        
        init_transport = await initiator.to_transport()
        resp_transport = await responder.to_transport()
        
        # Initiator -> Responder
        ct1 = await init_transport.send(b"Message 1")
        pt1 = await resp_transport.receive(ct1)
        assert pt1 == b"Message 1"
        
        # Responder -> Initiator
        ct2 = await resp_transport.send(b"Message 2")
        pt2 = await init_transport.receive(ct2)
        assert pt2 == b"Message 2"
        
        # Multiple messages
        for i in range(3, 6):
            msg = f"Message {i}".encode()
            ct = await init_transport.send(msg)
            pt = await resp_transport.receive(ct)
            assert pt == msg
    
    @pytest.mark.asyncio
    async def test_async_transport_with_associated_data(self):
        """Test async transport with associated data."""
        initiator = AsyncNoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        await initiator.set_as_initiator()
        await initiator.initialize()
        
        responder = AsyncNoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        await responder.set_as_responder()
        await responder.initialize()
        
        msg1 = await initiator.write_message(b"")
        await responder.read_message(msg1)
        msg2 = await responder.write_message(b"")
        await initiator.read_message(msg2)
        
        init_transport = await initiator.to_transport()
        resp_transport = await responder.to_transport()
        
        # Send with associated data
        ad = b"metadata"
        plaintext = b"secret message"
        ciphertext = await init_transport.send(plaintext, associated_data=ad)
        received = await resp_transport.receive(ciphertext, associated_data=ad)
        
        assert received == plaintext
    
    @pytest.mark.asyncio
    async def test_async_transport_nonce_increments(self):
        """Test that nonces increment properly."""
        initiator = AsyncNoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        await initiator.set_as_initiator()
        await initiator.initialize()
        
        responder = AsyncNoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        await responder.set_as_responder()
        await responder.initialize()
        
        msg1 = await initiator.write_message(b"")
        await responder.read_message(msg1)
        msg2 = await responder.write_message(b"")
        await initiator.read_message(msg2)
        
        init_transport = await initiator.to_transport()
        resp_transport = await responder.to_transport()
        
        # Check initial nonces
        assert init_transport.send_nonce == 0
        assert resp_transport.receive_nonce == 0
        
        # Send message
        ct = await init_transport.send(b"test")
        await resp_transport.receive(ct)
        
        # Nonces should increment
        assert init_transport.send_nonce == 1
        assert resp_transport.receive_nonce == 1


class TestAsyncFramedWriter:
    """Test AsyncFramedWriter class."""
    
    @pytest.mark.asyncio
    async def test_async_write_single_message(self):
        """Test writing a single async framed message."""
        buffer = io.BytesIO()
        reader, writer = await self._create_stream_pair(buffer)
        
        framed_writer = AsyncFramedWriter(writer)
        await framed_writer.write_message(b"Hello, Async!")
        
        # Check written data
        buffer.seek(0)
        header = buffer.read(4)
        assert len(header) == 4
        assert int.from_bytes(header, 'big') == 13
        
        message = buffer.read()
        assert message == b"Hello, Async!"
    
    @pytest.mark.asyncio
    async def test_async_write_multiple_messages(self):
        """Test writing multiple async framed messages."""
        buffer = io.BytesIO()
        reader, writer = await self._create_stream_pair(buffer)
        
        framed_writer = AsyncFramedWriter(writer)
        await framed_writer.write_message(b"First")
        await framed_writer.write_message(b"Second")
        await framed_writer.write_message(b"Third")
        
        buffer.seek(0)
        
        # First message
        assert int.from_bytes(buffer.read(4), 'big') == 5
        assert buffer.read(5) == b"First"
        
        # Second message
        assert int.from_bytes(buffer.read(4), 'big') == 6
        assert buffer.read(6) == b"Second"
        
        # Third message
        assert int.from_bytes(buffer.read(4), 'big') == 5
        assert buffer.read(5) == b"Third"
    
    @pytest.mark.asyncio
    async def test_async_write_oversized_message(self):
        """Test that oversized messages raise FramingError."""
        buffer = io.BytesIO()
        reader, writer = await self._create_stream_pair(buffer)
        
        framed_writer = AsyncFramedWriter(writer, max_message_size=100)
        
        with pytest.raises(FramingError) as exc_info:
            await framed_writer.write_message(b"X" * 101)
        
        assert "exceeds maximum" in str(exc_info.value)
    
    async def _create_stream_pair(self, buffer):
        """Helper to create async reader/writer from BytesIO."""
        # Create a simple StreamWriter wrapper
        class SimpleStreamWriter:
            def __init__(self, buf):
                self.buf = buf
                self._closed = False
            
            def write(self, data):
                self.buf.write(data)
            
            async def drain(self):
                pass
            
            def close(self):
                self._closed = True
            
            async def wait_closed(self):
                pass
            
            def get_extra_info(self, name):
                return None
        
        writer = SimpleStreamWriter(buffer)
        return None, writer


class TestAsyncFramedReader:
    """Test AsyncFramedReader class."""
    
    @pytest.mark.asyncio
    async def test_async_read_single_message(self):
        """Test reading a single async framed message."""
        buffer = io.BytesIO()
        buffer.write((13).to_bytes(4, 'big'))
        buffer.write(b"Hello, Async!")
        buffer.seek(0)
        
        reader = await self._create_stream_reader(buffer)
        framed_reader = AsyncFramedReader(reader)
        
        message = await framed_reader.read_message()
        assert message == b"Hello, Async!"
    
    @pytest.mark.asyncio
    async def test_async_read_multiple_messages(self):
        """Test reading multiple async framed messages."""
        buffer = io.BytesIO()
        for msg in [b"First", b"Second", b"Third"]:
            buffer.write(len(msg).to_bytes(4, 'big'))
            buffer.write(msg)
        buffer.seek(0)
        
        reader = await self._create_stream_reader(buffer)
        framed_reader = AsyncFramedReader(reader)
        
        assert await framed_reader.read_message() == b"First"
        assert await framed_reader.read_message() == b"Second"
        assert await framed_reader.read_message() == b"Third"
    
    @pytest.mark.asyncio
    async def test_async_read_oversized_message(self):
        """Test that oversized message header raises FramingError."""
        buffer = io.BytesIO()
        buffer.write((1000).to_bytes(4, 'big'))
        buffer.write(b"X" * 1000)
        buffer.seek(0)
        
        reader = await self._create_stream_reader(buffer)
        framed_reader = AsyncFramedReader(reader, max_message_size=100)
        
        with pytest.raises(FramingError) as exc_info:
            await framed_reader.read_message()
        
        assert "exceeds maximum" in str(exc_info.value)
    
    async def _create_stream_reader(self, buffer):
        """Helper to create async reader from BytesIO."""
        class SimpleStreamReader:
            def __init__(self, buf):
                self.buf = buf
            
            async def readexactly(self, n):
                data = self.buf.read(n)
                if len(data) < n:
                    raise asyncio.IncompleteReadError(data, n)
                return data
        
        return SimpleStreamReader(buffer)


class TestAsyncRoundTrip:
    """Test async write-read round trips."""
    
    @pytest.mark.asyncio
    async def test_async_complete_handshake_and_transport(self):
        """Test complete handshake and transport communication (in-memory)."""
        # Create initiator and responder
        initiator = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await initiator.set_as_initiator()
        await initiator.generate_static_keypair()
        await initiator.initialize()
        
        responder = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await responder.set_as_responder()
        await responder.generate_static_keypair()
        await responder.initialize()
        
        # Perform complete XX handshake
        msg1 = await initiator.write_message(b"")
        await responder.read_message(msg1)
        
        msg2 = await responder.write_message(b"")
        await initiator.read_message(msg2)
        
        msg3 = await initiator.write_message(b"")
        await responder.read_message(msg3)
        
        # Get transports
        init_transport = await initiator.to_transport()
        resp_transport = await responder.to_transport()
        
        # Exchange multiple encrypted messages
        for i in range(5):
            # Initiator -> Responder
            msg = f"Message {i} from initiator".encode()
            ct = await init_transport.send(msg)
            pt = await resp_transport.receive(ct)
            assert pt == msg
            
            # Responder -> Initiator
            msg = f"Message {i} from responder".encode()
            ct = await resp_transport.send(msg)
            pt = await init_transport.receive(ct)
            assert pt == msg


class TestAsyncConvenienceFunctions:
    """Test async convenience functions."""
    
    @pytest.mark.asyncio
    async def test_async_write_framed_message(self):
        """Test async_write_framed_message convenience function."""
        buffer = io.BytesIO()
        
        class SimpleWriter:
            def __init__(self, buf):
                self.buf = buf
            def write(self, data):
                self.buf.write(data)
            async def drain(self):
                pass
            def close(self):
                pass
            async def wait_closed(self):
                pass
            def get_extra_info(self, name):
                return None
        
        writer = SimpleWriter(buffer)
        await async_write_framed_message(writer, b"Test")
        
        buffer.seek(0)
        assert int.from_bytes(buffer.read(4), 'big') == 4
        assert buffer.read() == b"Test"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
