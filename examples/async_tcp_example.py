"""
Async TCP Client/Server Example with Noise Protocol

This example demonstrates how to use NoiseFramework's async support
for building async TCP servers and clients with Noise XX handshake.
"""

import asyncio
import logging
from noiseframework import (
    AsyncNoiseHandshake,
    AsyncFramedReader,
    AsyncFramedWriter,
)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
)


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """
    Handle a client connection (server side).
    
    Performs Noise XX handshake as responder, then echoes encrypted messages.
    """
    addr = writer.get_extra_info('peername')
    print(f"\n[Server] Client connected from {addr}")
    
    try:
        # Create Noise handshake (responder)
        handshake = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await handshake.set_as_responder()
        await handshake.generate_static_keypair()
        await handshake.initialize()
        
        # Create framed reader/writer
        framed_reader = AsyncFramedReader(reader)
        framed_writer = AsyncFramedWriter(writer)
        
        print("[Server] Performing XX handshake...")
        
        # XX handshake - responder receives message 1
        msg1 = await framed_reader.read_message()
        payload1 = await handshake.read_message(msg1)
        print(f"[Server] Received handshake message 1 (payload: {len(payload1)} bytes)")
        
        # XX handshake - responder sends message 2
        msg2 = await handshake.write_message(b"")
        await framed_writer.write_message(msg2)
        print("[Server] Sent handshake message 2")
        
        # XX handshake - responder receives message 3
        msg3 = await framed_reader.read_message()
        payload3 = await handshake.read_message(msg3)
        print(f"[Server] Received handshake message 3 (payload: {len(payload3)} bytes)")
        
        print("[Server] Handshake complete!")
        
        # Switch to transport mode
        transport = await handshake.to_transport()
        print("[Server] Switched to transport mode")
        
        # Echo loop - receive and echo encrypted messages
        message_count = 0
        while True:
            try:
                # Receive encrypted message
                ciphertext = await framed_reader.read_message()
                if not ciphertext:
                    break
                
                # Decrypt
                plaintext = await transport.receive(ciphertext)
                message_count += 1
                print(f"[Server] Received message {message_count}: {plaintext.decode('utf-8')}")
                
                # Echo back
                echo_text = f"Echo: {plaintext.decode('utf-8')}"
                echo_ciphertext = await transport.send(echo_text.encode('utf-8'))
                await framed_writer.write_message(echo_ciphertext)
                print(f"[Server] Sent echo {message_count}")
                
            except asyncio.IncompleteReadError:
                break
        
        print(f"[Server] Client disconnected. Echoed {message_count} messages.")
        
    except Exception as e:
        print(f"[Server] Error: {e}")
    finally:
        await framed_writer.close()


async def run_server(host: str = "127.0.0.1", port: int = 9999):
    """Run the async Noise server."""
    server = await asyncio.start_server(handle_client, host, port)
    
    addr = server.sockets[0].getsockname()
    print(f"[Server] Listening on {addr}")
    
    async with server:
        await server.serve_forever()


async def run_client(host: str = "127.0.0.1", port: int = 9999):
    """
    Run the async Noise client.
    
    Connects to server, performs XX handshake, sends encrypted messages.
    """
    print(f"\n[Client] Connecting to {host}:{port}...")
    reader, writer = await asyncio.open_connection(host, port)
    print("[Client] Connected!")
    
    try:
        # Create Noise handshake (initiator)
        handshake = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await handshake.set_as_initiator()
        await handshake.generate_static_keypair()
        await handshake.initialize()
        
        # Create framed reader/writer
        framed_reader = AsyncFramedReader(reader)
        framed_writer = AsyncFramedWriter(writer)
        
        print("[Client] Performing XX handshake...")
        
        # XX handshake - initiator sends message 1
        msg1 = await handshake.write_message(b"")
        await framed_writer.write_message(msg1)
        print("[Client] Sent handshake message 1")
        
        # XX handshake - initiator receives message 2
        msg2 = await framed_reader.read_message()
        payload2 = await handshake.read_message(msg2)
        print(f"[Client] Received handshake message 2 (payload: {len(payload2)} bytes)")
        
        # XX handshake - initiator sends message 3
        msg3 = await handshake.write_message(b"")
        await framed_writer.write_message(msg3)
        print("[Client] Sent handshake message 3")
        
        print("[Client] Handshake complete!")
        
        # Switch to transport mode
        transport = await handshake.to_transport()
        print("[Client] Switched to transport mode")
        
        # Send encrypted messages
        messages = [
            "Hello, async server!",
            "This is message 2",
            "And here's message 3",
        ]
        
        for i, msg in enumerate(messages, 1):
            # Encrypt and send
            ciphertext = await transport.send(msg.encode('utf-8'))
            await framed_writer.write_message(ciphertext)
            print(f"[Client] Sent message {i}: {msg}")
            
            # Receive echo
            echo_ciphertext = await framed_reader.read_message()
            echo_plaintext = await transport.receive(echo_ciphertext)
            print(f"[Client] Received echo {i}: {echo_plaintext.decode('utf-8')}")
            
            # Small delay between messages
            await asyncio.sleep(0.1)
        
        print("[Client] All messages sent and echoed!")
        
    except Exception as e:
        print(f"[Client] Error: {e}")
    finally:
        await framed_writer.close()


async def run_simple_example():
    """
    Simple example demonstrating async Noise usage without networking.
    """
    print("\n" + "="*60)
    print("Simple Async Example (In-Memory)")
    print("="*60)
    
    # Create handshakes
    initiator = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    responder = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    
    # Set roles and generate keys
    await initiator.set_as_initiator()
    await initiator.generate_static_keypair()
    await initiator.initialize()
    
    await responder.set_as_responder()
    await responder.generate_static_keypair()
    await responder.initialize()
    
    print("Performing XX handshake...")
    
    # Message 1: initiator -> responder
    msg1 = await initiator.write_message(b"")
    payload1 = await responder.read_message(msg1)
    
    # Message 2: responder -> initiator
    msg2 = await responder.write_message(b"")
    payload2 = await initiator.read_message(msg2)
    
    # Message 3: initiator -> responder
    msg3 = await initiator.write_message(b"")
    payload3 = await responder.read_message(msg3)
    
    print("Handshake complete!")
    
    # Get transports
    initiator_transport = await initiator.to_transport()
    responder_transport = await responder.to_transport()
    
    # Exchange encrypted messages
    print("\nExchanging encrypted messages...")
    
    # Initiator sends
    plaintext1 = b"Hello from initiator!"
    ciphertext1 = await initiator_transport.send(plaintext1)
    received1 = await responder_transport.receive(ciphertext1)
    print(f"Initiator -> Responder: {received1.decode('utf-8')}")
    assert received1 == plaintext1
    
    # Responder sends
    plaintext2 = b"Hello from responder!"
    ciphertext2 = await responder_transport.send(plaintext2)
    received2 = await initiator_transport.receive(ciphertext2)
    print(f"Responder -> Initiator: {received2.decode('utf-8')}")
    assert received2 == plaintext2
    
    print("\n✓ Async communication successful!")


async def main():
    """
    Main entry point - demonstrates all async examples.
    """
    print("="*60)
    print("NoiseFramework Async Examples")
    print("="*60)
    
    # Run simple in-memory example first
    await run_simple_example()
    
    # Ask user which example to run
    print("\n" + "="*60)
    print("TCP Client/Server Example")
    print("="*60)
    print("\nChoose an option:")
    print("1. Run server")
    print("2. Run client (requires server running)")
    print("3. Run both (server + client in separate tasks)")
    print("4. Exit")
    
    choice = input("\nYour choice (1-4): ").strip()
    
    if choice == "1":
        print("\nStarting server (press Ctrl+C to stop)...")
        await run_server()
    
    elif choice == "2":
        await run_client()
    
    elif choice == "3":
        print("\nStarting server and client...")
        # Start server in background
        server_task = asyncio.create_task(run_server())
        
        # Give server time to start
        await asyncio.sleep(0.5)
        
        # Run client
        await run_client()
        
        # Give time to see output
        await asyncio.sleep(0.5)
        
        # Cancel server
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        
        print("\n✓ Demo complete!")
    
    elif choice == "4":
        print("Exiting...")
    
    else:
        print("Invalid choice!")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
