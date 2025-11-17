"""
Basic client-server example using Noise_XX pattern.

This example demonstrates:
- Setting up client and server with XX pattern (mutual authentication)
- Performing handshake
- Sending encrypted messages after handshake

The XX pattern provides mutual authentication where both parties exchange
their static public keys during the handshake.
"""

from noiseframework import NoiseHandshake, NoiseTransport


def run_example():
    print("=" * 60)
    print("NoiseFramework - Basic Client/Server Example (XX Pattern)")
    print("=" * 60)
    print()

    # === Client Setup ===
    print("📱 Setting up client (initiator)...")
    client = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    client.set_as_initiator()

    # Generate and set client's static keypair
    client.generate_static_keypair()
    print(f"   Client public key: {client.static_public.hex()[:32]}...")

    # Initialize client handshake
    client.initialize()
    print("   ✓ Client initialized\n")

    # === Server Setup ===
    print("🖥️  Setting up server (responder)...")
    server = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    server.set_as_responder()

    # Generate and set server's static keypair
    server.generate_static_keypair()
    print(f"   Server public key: {server.static_public.hex()[:32]}...")

    # Initialize server handshake
    server.initialize()
    print("   ✓ Server initialized\n")

    # === Handshake Phase ===
    print("🤝 Performing handshake...")

    # Message 1: Client -> Server (e)
    print("   [1/3] Client sends ephemeral key...")
    msg1 = client.write_message(b"")
    server.read_message(msg1)
    print(f"         Sent {len(msg1)} bytes")

    # Message 2: Server -> Client (e, ee, s, es)
    print("   [2/3] Server sends ephemeral, static keys and performs DH...")
    msg2 = server.write_message(b"")
    client.read_message(msg2)
    print(f"         Sent {len(msg2)} bytes")

    # Message 3: Client -> Server (s, se)
    print("   [3/3] Client sends static key and completes handshake...")
    msg3 = client.write_message(b"")
    server.read_message(msg3)
    print(f"         Sent {len(msg3)} bytes")

    print("   ✓ Handshake complete!\n")

    # Verify handshake completed
    assert client.handshake_complete
    assert server.handshake_complete

    # Verify mutual authentication (both parties have each other's static keys)
    print("🔐 Verifying mutual authentication...")
    print(f"   Client received server key: {client.remote_static_public.hex()[:32]}...")
    print(f"   Server received client key: {server.remote_static_public.hex()[:32]}...")
    assert client.remote_static_public == server.static_public
    assert server.remote_static_public == client.static_public
    print("   ✓ Both parties authenticated!\n")

    # === Transport Phase ===
    print("🔒 Converting to transport mode...")
    client_send, client_recv = client.to_transport()
    server_send, server_recv = server.to_transport()
    
    # Create transport wrappers
    client_transport = NoiseTransport(client_send, client_recv)
    server_transport = NoiseTransport(server_send, server_recv)
    print("   ✓ Transport mode active\n")

    # === Encrypted Communication ===
    print("💬 Sending encrypted messages...")

    # Client -> Server
    message1 = b"Hello from client!"
    print(f"   Client: '{message1.decode()}'")
    ciphertext1 = client_transport.send(message1)
    print(f"          Encrypted: {ciphertext1.hex()[:40]}...")
    received1 = server_transport.receive(ciphertext1)
    print(f"          Server received: '{received1.decode()}'")
    assert received1 == message1

    print()

    # Server -> Client
    message2 = b"Hello from server!"
    print(f"   Server: '{message2.decode()}'")
    ciphertext2 = server_transport.send(message2)
    print(f"          Encrypted: {ciphertext2.hex()[:40]}...")
    received2 = client_transport.receive(ciphertext2)
    print(f"          Client received: '{received2.decode()}'")
    assert received2 == message2

    print()

    # Multiple messages
    print("   📨 Sending multiple messages...")
    for i in range(3):
        msg = f"Message {i+1}".encode()
        ct = client_transport.send(msg)
        pt = server_transport.receive(ct)
        print(f"      [{i+1}] Sent and received: '{pt.decode()}'")
        assert pt == msg

    print()
    print("=" * 60)
    print("✅ Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    run_example()
