"""
Tests for NoiseConnection and AsyncNoiseConnection classes.
"""

import asyncio
import io
import pytest
import socket
import threading
import time
from typing import Optional

from noiseframework import NoiseConnection, AsyncNoiseConnection
from noiseframework.exceptions import ValidationError, HandshakeError, TransportError


# Test pattern
TEST_PATTERN = "Noise_XX_25519_ChaChaPoly_SHA256"


# ============================================================================
# Synchronous NoiseConnection Tests
# ============================================================================


def test_connection_init_initiator():
    """Test NoiseConnection initialization as initiator."""
    conn = NoiseConnection(TEST_PATTERN, "initiator")
    assert conn.pattern == TEST_PATTERN
    assert conn.role == "initiator"
    assert not conn.is_connected
    assert conn.local_static_public_key is not None  # Keypair generated
    conn.close()


def test_connection_init_responder():
    """Test NoiseConnection initialization as responder."""
    conn = NoiseConnection(TEST_PATTERN, "responder")
    assert conn.pattern == TEST_PATTERN
    assert conn.role == "responder"
    assert not conn.is_connected
    assert conn.local_static_public_key is not None
    conn.close()


def test_connection_init_invalid_role():
    """Test NoiseConnection with invalid role."""
    with pytest.raises(ValidationError, match="Invalid role"):
        NoiseConnection(TEST_PATTERN, "invalid")


def test_connection_with_custom_keys():
    """Test NoiseConnection with pre-generated keys."""
    # Generate keys
    temp_conn = NoiseConnection(TEST_PATTERN, "initiator")
    priv_key = temp_conn.handshake.static_private
    pub_key = temp_conn.handshake.static_public
    temp_conn.close()
    
    # Use custom keys
    conn = NoiseConnection(
        TEST_PATTERN,
        "initiator",
        static_private_key=priv_key,
        static_public_key=pub_key
    )
    assert conn.local_static_public_key == pub_key
    conn.close()


def test_connection_send_before_connect():
    """Test that send() fails before connection."""
    conn = NoiseConnection(TEST_PATTERN, "initiator")
    with pytest.raises(TransportError, match="Not connected"):
        conn.send(b"test")
    conn.close()


def test_connection_receive_before_connect():
    """Test that receive() fails before connection."""
    conn = NoiseConnection(TEST_PATTERN, "initiator")
    with pytest.raises(TransportError, match="Not connected"):
        conn.receive()
    conn.close()


def test_connection_initiator_cannot_accept():
    """Test that initiator cannot call accept()."""
    conn = NoiseConnection(TEST_PATTERN, "initiator")
    fake_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with pytest.raises(ValidationError, match="Only responder can call accept"):
        conn.accept(fake_socket)
    conn.close()
    fake_socket.close()


def test_connection_responder_cannot_connect():
    """Test that responder cannot call connect()."""
    conn = NoiseConnection(TEST_PATTERN, "responder")
    with pytest.raises(ValidationError, match="Only initiator can call connect"):
        conn.connect(("localhost", 9999))
    conn.close()


def test_connection_context_manager():
    """Test NoiseConnection as context manager."""
    with NoiseConnection(TEST_PATTERN, "initiator") as conn:
        assert not conn.is_connected
    # Connection should be closed after exiting context


def test_connection_double_close():
    """Test that closing twice doesn't raise errors."""
    conn = NoiseConnection(TEST_PATTERN, "initiator")
    conn.close()
    conn.close()  # Should not raise


def test_connection_full_communication():
    """Test complete client-server communication with NoiseConnection."""
    server_received = []
    server_ready = threading.Event()
    
    def server():
        # Create server socket
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]
        
        # Signal port to client
        server_ready.port = port
        server_ready.set()
        
        # Accept connection
        client_sock, _ = server_sock.accept()
        
        # Create responder connection
        conn = NoiseConnection(TEST_PATTERN, "responder")
        conn.accept(client_sock)
        
        # Receive message
        data = conn.receive()
        server_received.append(data)
        
        # Send response
        conn.send(b"Hello, client!")
        
        # Cleanup
        conn.close()
        server_sock.close()
    
    # Start server thread
    server_thread = threading.Thread(target=server, daemon=True)
    server_thread.start()
    
    # Wait for server to be ready
    server_ready.wait(timeout=5)
    port = server_ready.port
    
    # Client
    conn = NoiseConnection(TEST_PATTERN, "initiator")
    conn.connect(("127.0.0.1", port))
    
    # Send message
    conn.send(b"Hello, server!")
    
    # Receive response
    response = conn.receive()
    
    # Cleanup
    conn.close()
    server_thread.join(timeout=2)
    
    # Verify
    assert server_received[0] == b"Hello, server!"
    assert response == b"Hello, client!"


def test_connection_multiple_messages():
    """Test sending multiple messages in sequence."""
    server_messages = []
    server_ready = threading.Event()
    
    def server():
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]
        
        server_ready.port = port
        server_ready.set()
        
        client_sock, _ = server_sock.accept()
        conn = NoiseConnection(TEST_PATTERN, "responder")
        conn.accept(client_sock)
        
        # Receive multiple messages
        for _ in range(3):
            data = conn.receive()
            server_messages.append(data)
            conn.send(b"ack")
        
        conn.close()
        server_sock.close()
    
    server_thread = threading.Thread(target=server, daemon=True)
    server_thread.start()
    server_ready.wait(timeout=5)
    port = server_ready.port
    
    # Client sends multiple messages
    conn = NoiseConnection(TEST_PATTERN, "initiator")
    conn.connect(("127.0.0.1", port))
    
    messages = [b"message1", b"message2", b"message3"]
    for msg in messages:
        conn.send(msg)
        ack = conn.receive()
        assert ack == b"ack"
    
    conn.close()
    server_thread.join(timeout=2)
    
    assert server_messages == messages


def test_connection_remote_static_key():
    """Test accessing remote static public key after handshake."""
    server_pubkey = []
    server_ready = threading.Event()
    
    def server():
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]
        
        server_ready.port = port
        server_ready.set()
        
        client_sock, _ = server_sock.accept()
        conn = NoiseConnection(TEST_PATTERN, "responder")
        conn.accept(client_sock)
        
        # Store our public key for verification
        server_pubkey.append(conn.local_static_public_key)
        
        conn.send(b"test")
        conn.receive()
        conn.close()
        server_sock.close()
    
    server_thread = threading.Thread(target=server, daemon=True)
    server_thread.start()
    server_ready.wait(timeout=5)
    port = server_ready.port
    
    # Client
    conn = NoiseConnection(TEST_PATTERN, "initiator")
    conn.connect(("127.0.0.1", port))
    
    # After handshake, should have remote key
    conn.receive()
    conn.send(b"test")
    
    assert conn.remote_static_public_key is not None
    assert conn.remote_static_public_key == server_pubkey[0]
    
    conn.close()
    server_thread.join(timeout=2)


# ============================================================================
# Asynchronous AsyncNoiseConnection Tests
# ============================================================================


@pytest.mark.asyncio
async def test_async_connection_init_initiator():
    """Test AsyncNoiseConnection initialization as initiator."""
    conn = AsyncNoiseConnection(TEST_PATTERN, "initiator")
    assert conn.pattern == TEST_PATTERN
    assert conn.role == "initiator"
    assert not conn.is_connected
    await conn.close()


@pytest.mark.asyncio
async def test_async_connection_init_responder():
    """Test AsyncNoiseConnection initialization as responder."""
    conn = AsyncNoiseConnection(TEST_PATTERN, "responder")
    assert conn.pattern == TEST_PATTERN
    assert conn.role == "responder"
    assert not conn.is_connected
    await conn.close()


@pytest.mark.asyncio
async def test_async_connection_init_invalid_role():
    """Test AsyncNoiseConnection with invalid role."""
    with pytest.raises(ValidationError, match="Invalid role"):
        AsyncNoiseConnection(TEST_PATTERN, "invalid")


@pytest.mark.asyncio
async def test_async_connection_send_before_connect():
    """Test that send() fails before connection."""
    conn = AsyncNoiseConnection(TEST_PATTERN, "initiator")
    with pytest.raises(TransportError, match="Not connected"):
        await conn.send(b"test")
    await conn.close()


@pytest.mark.asyncio
async def test_async_connection_receive_before_connect():
    """Test that receive() fails before connection."""
    conn = AsyncNoiseConnection(TEST_PATTERN, "initiator")
    with pytest.raises(TransportError, match="Not connected"):
        await conn.receive()
    await conn.close()


@pytest.mark.asyncio
async def test_async_connection_responder_cannot_connect():
    """Test that responder cannot call connect()."""
    conn = AsyncNoiseConnection(TEST_PATTERN, "responder")
    with pytest.raises(ValidationError, match="Only initiator can call connect"):
        await conn.connect(("localhost", 9999))
    await conn.close()


@pytest.mark.asyncio
async def test_async_connection_context_manager():
    """Test AsyncNoiseConnection as async context manager."""
    async with AsyncNoiseConnection(TEST_PATTERN, "initiator") as conn:
        assert not conn.is_connected
    # Connection should be closed after exiting context


@pytest.mark.asyncio
async def test_async_connection_double_close():
    """Test that closing twice doesn't raise errors."""
    conn = AsyncNoiseConnection(TEST_PATTERN, "initiator")
    await conn.close()
    await conn.close()  # Should not raise


@pytest.mark.asyncio
async def test_async_connection_full_communication():
    """Test complete client-server communication with AsyncNoiseConnection."""
    server_received = []
    
    async def handle_client(reader, writer):
        # Create responder connection
        conn = AsyncNoiseConnection(TEST_PATTERN, "responder")
        await conn.accept_streams(reader, writer)
        
        # Receive message
        data = await conn.receive()
        server_received.append(data)
        
        # Send response
        await conn.send(b"Hello, async client!")
        
        # Cleanup
        await conn.close()
    
    # Start server
    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    
    # Start serving in background
    server_task = asyncio.create_task(server.serve_forever())
    
    try:
        # Client
        conn = AsyncNoiseConnection(TEST_PATTERN, "initiator")
        await conn.connect(("127.0.0.1", port))
        
        # Send message
        await conn.send(b"Hello, async server!")
        
        # Receive response
        response = await conn.receive()
        
        # Cleanup
        await conn.close()
        
        # Verify
        assert server_received[0] == b"Hello, async server!"
        assert response == b"Hello, async client!"
    
    finally:
        server.close()
        await server.wait_closed()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_async_connection_multiple_messages():
    """Test sending multiple messages in sequence."""
    server_messages = []
    
    async def handle_client(reader, writer):
        conn = AsyncNoiseConnection(TEST_PATTERN, "responder")
        await conn.accept_streams(reader, writer)
        
        # Receive multiple messages
        for _ in range(3):
            data = await conn.receive()
            server_messages.append(data)
            await conn.send(b"ack")
        
        await conn.close()
    
    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server_task = asyncio.create_task(server.serve_forever())
    
    try:
        # Client sends multiple messages
        conn = AsyncNoiseConnection(TEST_PATTERN, "initiator")
        await conn.connect(("127.0.0.1", port))
        
        messages = [b"message1", b"message2", b"message3"]
        for msg in messages:
            await conn.send(msg)
            ack = await conn.receive()
            assert ack == b"ack"
        
        await conn.close()
        
        assert server_messages == messages
    
    finally:
        server.close()
        await server.wait_closed()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_async_connection_remote_static_key():
    """Test accessing remote static public key after handshake."""
    server_pubkey = []
    
    async def handle_client(reader, writer):
        conn = AsyncNoiseConnection(TEST_PATTERN, "responder")
        await conn.accept_streams(reader, writer)
        
        # Store our public key for verification
        await conn._initialize_handshake()  # Ensure initialized
        server_pubkey.append(conn.local_static_public_key)
        
        await conn.send(b"test")
        await conn.receive()
        await conn.close()
    
    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server_task = asyncio.create_task(server.serve_forever())
    
    try:
        # Client
        conn = AsyncNoiseConnection(TEST_PATTERN, "initiator")
        await conn.connect(("127.0.0.1", port))
        
        # After handshake, should have remote key
        await conn.receive()
        await conn.send(b"test")
        
        # Wait a bit for server to populate server_pubkey
        await asyncio.sleep(0.1)
        
        assert conn.remote_static_public_key is not None
        assert conn.remote_static_public_key == server_pubkey[0]
        
        await conn.close()
    
    finally:
        server.close()
        await server.wait_closed()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_async_connection_large_message():
    """Test sending large messages (>1 KB)."""
    large_message = b"X" * (1024 * 100)  # 100 KB
    server_received = []
    
    async def handle_client(reader, writer):
        conn = AsyncNoiseConnection(TEST_PATTERN, "responder")
        await conn.accept_streams(reader, writer)
        data = await conn.receive()
        server_received.append(data)
        await conn.send(b"ack")
        await conn.close()
    
    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server_task = asyncio.create_task(server.serve_forever())
    
    try:
        conn = AsyncNoiseConnection(TEST_PATTERN, "initiator")
        await conn.connect(("127.0.0.1", port))
        await conn.send(large_message)
        response = await conn.receive()
        await conn.close()
        
        assert server_received[0] == large_message
        assert response == b"ack"
    
    finally:
        server.close()
        await server.wait_closed()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
