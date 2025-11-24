"""
Example demonstrating NoiseConnection and AsyncNoiseConnection.

Shows how to use the high-level connection API for simple client-server
communication without manually managing handshakes and transport.
"""

import asyncio
import socket
import threading
from noiseframework import NoiseConnection, AsyncNoiseConnection


# ============================================================================
# Synchronous Example (NoiseConnection)
# ============================================================================

def sync_server_example():
    """Run a synchronous server using NoiseConnection."""
    print("\n=== Synchronous Server Example ===\n")
    
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 9990))
    server_socket.listen(1)
    
    print("[Server] Listening on port 9990...")
    client_socket, address = server_socket.accept()
    print(f"[Server] Client connected from {address}")
    
    try:
        # Create connection and accept client
        # NoiseConnection automatically handles the handshake
        with NoiseConnection("Noise_XX_25519_ChaChaPoly_SHA256", "responder") as conn:
            conn.accept(client_socket)
            print("[Server] Handshake complete!")
            print(f"[Server] Remote public key: {conn.remote_static_public_key.hex()[:16]}...")
            
            # Receive and send messages
            for i in range(3):
                data = conn.receive()
                print(f"[Server] Received: {data.decode()}")
                
                response = f"Echo {i+1}: {data.decode()}"
                conn.send(response.encode())
                print(f"[Server] Sent: {response}")
            
            print("[Server] Communication complete")
    
    finally:
        server_socket.close()


def sync_client_example():
    """Run a synchronous client using NoiseConnection."""
    print("\n=== Synchronous Client Example ===\n")
    
    # Create connection and connect to server
    # NoiseConnection automatically handles the handshake
    with NoiseConnection("Noise_XX_25519_ChaChaPoly_SHA256", "initiator") as conn:
        conn.connect(("127.0.0.1", 9990))
        print("[Client] Connected and handshake complete!")
        print(f"[Client] Remote public key: {conn.remote_static_public_key.hex()[:16]}...")
        
        # Send and receive messages
        messages = ["Hello, server!", "How are you?", "Goodbye!"]
        for msg in messages:
            conn.send(msg.encode())
            print(f"[Client] Sent: {msg}")
            
            response = conn.receive()
            print(f"[Client] Received: {response.decode()}")
        
        print("[Client] Communication complete")


def run_sync_example():
    """Run the synchronous example with server and client."""
    # Start server in background thread
    server_thread = threading.Thread(target=sync_server_example, daemon=True)
    server_thread.start()
    
    # Give server time to start
    import time
    time.sleep(0.5)
    
    # Run client
    sync_client_example()
    
    # Wait for server to finish
    server_thread.join(timeout=2)


# ============================================================================
# Asynchronous Example (AsyncNoiseConnection)
# ============================================================================

async def async_server_example():
    """Run an asynchronous server using AsyncNoiseConnection."""
    print("\n=== Asynchronous Server Example ===\n")
    
    async def handle_client(reader, writer):
        """Handle incoming client connection."""
        addr = writer.get_extra_info('peername')
        print(f"[Server] Client connected from {addr}")
        
        try:
            # Create connection and accept client streams
            # AsyncNoiseConnection automatically handles the handshake
            async with AsyncNoiseConnection("Noise_XX_25519_ChaChaPoly_SHA256", "responder") as conn:
                await conn.accept_streams(reader, writer)
                print("[Server] Handshake complete!")
                print(f"[Server] Remote public key: {conn.remote_static_public_key.hex()[:16]}...")
                
                # Receive and send messages
                for i in range(3):
                    data = await conn.receive()
                    print(f"[Server] Received: {data.decode()}")
                    
                    response = f"Echo {i+1}: {data.decode()}"
                    await conn.send(response.encode())
                    print(f"[Server] Sent: {response}")
                
                print("[Server] Communication complete")
        
        except Exception as e:
            print(f"[Server] Error: {e}")
    
    # Start server
    server = await asyncio.start_server(handle_client, "127.0.0.1", 9991)
    addr = server.sockets[0].getsockname()
    print(f"[Server] Listening on {addr[0]}:{addr[1]}...")
    
    # Keep server running until we're done
    async with server:
        await asyncio.sleep(3)  # Wait for client to finish


async def async_client_example():
    """Run an asynchronous client using AsyncNoiseConnection."""
    print("\n=== Asynchronous Client Example ===\n")
    
    # Give server time to start
    await asyncio.sleep(0.5)
    
    # Create connection and connect to server
    # AsyncNoiseConnection automatically handles the handshake
    async with AsyncNoiseConnection("Noise_XX_25519_ChaChaPoly_SHA256", "initiator") as conn:
        await conn.connect(("127.0.0.1", 9991))
        print("[Client] Connected and handshake complete!")
        print(f"[Client] Remote public key: {conn.remote_static_public_key.hex()[:16]}...")
        
        # Send and receive messages
        messages = ["Hello, async server!", "This is async!", "Goodbye!"]
        for msg in messages:
            await conn.send(msg.encode())
            print(f"[Client] Sent: {msg}")
            
            response = await conn.receive()
            print(f"[Client] Received: {response.decode()}")
        
        print("[Client] Communication complete")


async def run_async_example():
    """Run the asynchronous example with server and client."""
    # Start server and client concurrently
    await asyncio.gather(
        async_server_example(),
        async_client_example()
    )


# ============================================================================
# Advanced Example: Custom Keys and Properties
# ============================================================================

def advanced_example():
    """Demonstrate advanced NoiseConnection features."""
    print("\n=== Advanced Example: Custom Keys ===\n")
    
    # Generate keys in advance (e.g., for persistent identity)
    temp_conn = NoiseConnection("Noise_XX_25519_ChaChaPoly_SHA256", "initiator")
    saved_private = temp_conn.handshake.static_private
    saved_public = temp_conn.handshake.static_public
    temp_conn.close()
    
    print(f"Generated identity key: {saved_public.hex()[:16]}...")
    
    def server():
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("127.0.0.1", 9992))
        server_socket.listen(1)
        print("[Server] Waiting for connection...")
        
        client_socket, _ = server_socket.accept()
        
        # Use saved keys for persistent identity
        with NoiseConnection(
            "Noise_XX_25519_ChaChaPoly_SHA256",
            "responder",
            static_private_key=saved_private,
            static_public_key=saved_public
        ) as conn:
            conn.accept(client_socket)
            print(f"[Server] Using identity: {conn.local_static_public_key.hex()[:16]}...")
            print(f"[Server] Client identity: {conn.remote_static_public_key.hex()[:16]}...")
            
            # Check connection properties
            assert conn.is_connected
            assert conn.local_static_public_key == saved_public
            
            data = conn.receive()
            print(f"[Server] Received: {data.decode()}")
            conn.send(b"Authenticated!")
        
        server_socket.close()
    
    # Start server
    server_thread = threading.Thread(target=server, daemon=True)
    server_thread.start()
    
    import time
    time.sleep(0.5)
    
    # Client connects
    with NoiseConnection("Noise_XX_25519_ChaChaPoly_SHA256", "initiator") as conn:
        conn.connect(("127.0.0.1", 9992))
        
        # Verify server identity
        server_key = conn.remote_static_public_key
        print(f"[Client] Server identity: {server_key.hex()[:16]}...")
        assert server_key == saved_public
        print("[Client] Server identity verified!")
        
        conn.send(b"Hello from verified client")
        response = conn.receive()
        print(f"[Client] Response: {response.decode()}")
    
    server_thread.join(timeout=2)
    print("\n[Advanced] Identity verification complete!")


# ============================================================================
# Main
# ============================================================================

def main():
    """Run all examples."""
    print("\n" + "="*70)
    print("NoiseConnection Examples")
    print("High-level API for secure Noise Protocol connections")
    print("="*70)
    
    # Run synchronous example
    try:
        run_sync_example()
    except Exception as e:
        print(f"\nSync example error: {e}")
    
    # Run asynchronous example
    try:
        asyncio.run(run_async_example())
    except Exception as e:
        print(f"\nAsync example error: {e}")
    
    # Run advanced example
    try:
        advanced_example()
    except Exception as e:
        print(f"\nAdvanced example error: {e}")
    
    print("\n" + "="*70)
    print("All examples completed successfully!")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
