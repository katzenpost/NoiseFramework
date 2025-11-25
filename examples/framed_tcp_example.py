"""
Example demonstrating framed TCP communication with NoiseFramework.

Shows how to use FramedReader and FramedWriter for reliable message
exchange over TCP sockets with the Noise Protocol.
"""

import socket
import threading
from noiseframework import NoiseHandshake, NoiseTransport, FramedReader, FramedWriter


def server_thread(port: int) -> None:
    """Run a simple TCP server with Noise Protocol and framing."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("localhost", port))
    server_socket.listen(1)
    
    print(f"[Server] Listening on port {port}")
    
    client_socket, address = server_socket.accept()
    print(f"[Server] Client connected from {address}")
    
    try:
        # Create framed streams
        reader = FramedReader(client_socket.makefile('rb'))
        writer = FramedWriter(client_socket.makefile('wb'))
        
        # Setup Noise handshake (responder)
        handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        handshake.set_as_responder()
        handshake.generate_static_keypair()
        handshake.initialize()
        
        print("[Server] Performing Noise handshake...")
        
        # Handshake message 1: <- e
        msg1 = reader.read_message()
        handshake.read_message(msg1)
        print("[Server] Received handshake message 1")
        
        # Handshake message 2: -> e, ee, s, es
        msg2 = handshake.write_message(b"")
        writer.write_message(msg2)
        print("[Server] Sent handshake message 2")
        
        # Handshake message 3: <- s, se
        msg3 = reader.read_message()
        handshake.read_message(msg3)
        print("[Server] Received handshake message 3")
        print("[Server] Handshake complete!")
        
        # Create transport
        send_cipher, recv_cipher = handshake.to_transport()
        transport = NoiseTransport(send_cipher, recv_cipher)
        
        # Receive encrypted messages
        for i in range(3):
            encrypted = reader.read_message()
            plaintext = transport.receive(encrypted)
            print(f"[Server] Received: {plaintext.decode()}")
            
            # Send response
            response = f"Echo: {plaintext.decode()}"
            encrypted_response = transport.send(response.encode())
            writer.write_message(encrypted_response)
            print(f"[Server] Sent: {response}")
        
        print("[Server] Communication complete")
        
    finally:
        client_socket.close()
        server_socket.close()


def client(port: int) -> None:
    """Run a simple TCP client with Noise Protocol and framing."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", port))
    
    print("[Client] Connected to server")
    
    try:
        # Create framed streams
        reader = FramedReader(client_socket.makefile('rb'))
        writer = FramedWriter(client_socket.makefile('wb'))
        
        # Setup Noise handshake (initiator)
        handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        handshake.set_as_initiator()
        handshake.generate_static_keypair()
        handshake.initialize()
        
        print("[Client] Performing Noise handshake...")
        
        # Handshake message 1: -> e
        msg1 = handshake.write_message(b"")
        writer.write_message(msg1)
        print("[Client] Sent handshake message 1")
        
        # Handshake message 2: <- e, ee, s, es
        msg2 = reader.read_message()
        handshake.read_message(msg2)
        print("[Client] Received handshake message 2")
        
        # Handshake message 3: -> s, se
        msg3 = handshake.write_message(b"")
        writer.write_message(msg3)
        print("[Client] Sent handshake message 3")
        print("[Client] Handshake complete!")
        
        # Create transport
        send_cipher, recv_cipher = handshake.to_transport()
        transport = NoiseTransport(send_cipher, recv_cipher)
        
        # Send encrypted messages
        messages = [
            "Hello, secure world!",
            "This is message 2",
            "Final message"
        ]
        
        for msg in messages:
            encrypted = transport.send(msg.encode())
            writer.write_message(encrypted)
            print(f"[Client] Sent: {msg}")
            
            # Receive response
            encrypted_response = reader.read_message()
            response = transport.receive(encrypted_response)
            print(f"[Client] Received: {response.decode()}")
        
        print("[Client] Communication complete")
        
    finally:
        client_socket.close()


def simple_example() -> None:
    """Demonstrate basic framing without Noise Protocol."""
    import io
    
    print("\n=== Simple Framing Example ===\n")
    
    # Create an in-memory "stream"
    buffer = io.BytesIO()
    
    # Write framed messages
    writer = FramedWriter(buffer)
    writer.write_message(b"First message")
    writer.write_message(b"Second message with more data")
    writer.write_message(b"Third")
    
    # Reset to beginning to read
    buffer.seek(0)
    
    # Read framed messages
    reader = FramedReader(buffer)
    msg1 = reader.read_message()
    msg2 = reader.read_message()
    msg3 = reader.read_message()
    
    print(f"Message 1: {msg1}")
    print(f"Message 2: {msg2}")
    print(f"Message 3: {msg3}")
    
    print("\n=== Framing preserves message boundaries! ===\n")


def main() -> None:
    """Run the framed TCP example."""
    import time
    
    # First show simple example
    simple_example()
    
    # Then run TCP client-server
    print("\n=== TCP Client-Server with Noise + Framing ===\n")
    
    port = 9999
    
    # Start server in background thread
    server = threading.Thread(target=server_thread, args=(port,), daemon=True)
    server.start()
    
    # Give server time to start
    time.sleep(0.5)
    
    # Run client in main thread
    client(port)
    
    # Wait for server to finish
    server.join(timeout=2.0)
    
    print("\n=== Example Complete ===\n")


if __name__ == "__main__":
    main()
