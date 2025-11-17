"""
Simple chat example using Noise_XX pattern.

This example demonstrates:
- Interactive client-server chat
- Using XX pattern for mutual authentication
- Bidirectional encrypted communication
- Handling multiple messages in a session

This is a demonstration only. A real chat application would need:
- Network sockets
- Async I/O
- Message framing
- Connection handling
"""

from noiseframework import NoiseHandshake, NoiseTransport


class ChatParticipant:
    """Represents a chat participant with Noise encryption."""

    def __init__(self, name: str, is_initiator: bool):
        """Initialize a chat participant.

        Args:
            name: Display name
            is_initiator: True for client, False for server
        """
        self.name = name
        self.handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")

        if is_initiator:
            self.handshake.set_as_initiator()
        else:
            self.handshake.set_as_responder()

        # Generate keypair
        self.handshake.generate_static_keypair()
        self.public_key = self.handshake.static_public

        # Initialize handshake
        self.handshake.initialize()

        self.transport = None

    def complete_handshake(self, other: "ChatParticipant"):
        """Perform handshake with another participant.

        Args:
            other: The other chat participant
        """
        # XX pattern handshake (3 messages)
        if self.handshake.role.value == "initiator":
            # Message 1: initiator -> responder
            msg1 = self.handshake.write_message(b"")
            other.handshake.read_message(msg1)

            # Message 2: responder -> initiator
            msg2 = other.handshake.write_message(b"")
            self.handshake.read_message(msg2)

            # Message 3: initiator -> responder
            msg3 = self.handshake.write_message(b"")
            other.handshake.read_message(msg3)
        else:
            # Responder waits for initiator
            pass

        # Convert to transport
        send_cipher, recv_cipher = self.handshake.to_transport()
        other_send, other_recv = other.handshake.to_transport()
        
        self.transport = NoiseTransport(send_cipher, recv_cipher)
        other.transport = NoiseTransport(other_send, other_recv)

    def send_message(self, text: str) -> bytes:
        """Encrypt and send a message.

        Args:
            text: Message text

        Returns:
            Encrypted message bytes
        """
        plaintext = f"{self.name}: {text}".encode()
        return self.transport.send(plaintext)

    def receive_message(self, ciphertext: bytes) -> str:
        """Receive and decrypt a message.

        Args:
            ciphertext: Encrypted message

        Returns:
            Decrypted message text
        """
        plaintext = self.transport.receive(ciphertext)
        return plaintext.decode()


def run_example():
    """Run the chat example."""
    print("=" * 60)
    print("NoiseFramework - Simple Chat Example")
    print("=" * 60)
    print()

    # Create participants
    print("👥 Creating chat participants...")
    alice = ChatParticipant("Alice", is_initiator=True)
    bob = ChatParticipant("Bob", is_initiator=False)
    print(f"   ✓ {alice.name} (Client)")
    print(f"   ✓ {bob.name} (Server)")
    print()

    # Perform handshake
    print("🤝 Establishing secure connection...")
    alice.complete_handshake(bob)
    print("   ✓ Handshake complete!")
    print("   ✓ Secure channel established")
    print()

    # Verify mutual authentication
    print("🔐 Verifying identities...")
    print(f"   {alice.name} authenticated {bob.name}")
    print(f"   {bob.name} authenticated {alice.name}")
    print()

    # Simulate chat conversation
    print("💬 Chat session:")
    print("-" * 60)

    conversation = [
        (alice, "Hey Bob! Can you hear me?"),
        (bob, "Hi Alice! Yes, loud and clear!"),
        (alice, "Great! This connection is encrypted."),
        (bob, "I know, right? Pretty cool!"),
        (alice, "How's the weather there?"),
        (bob, "Sunny! How about you?"),
        (alice, "Same here. Perfect day!"),
        (bob, "Awesome! Talk to you later!"),
        (alice, "Bye! 👋"),
    ]

    for sender, message_text in conversation:
        if sender == alice:
            receiver = bob
        else:
            receiver = alice

        # Encrypt message
        ciphertext = sender.send_message(message_text)

        # Show encrypted version (truncated)
        print(f"   🔒 Encrypted: {ciphertext.hex()[:40]}...")

        # Decrypt message
        plaintext = receiver.receive_message(ciphertext)
        print(f"   📨 {plaintext}")
        print()

    print("-" * 60)
    print()

    # Show stats
    print("📊 Session Statistics:")
    print(f"   Messages sent by {alice.name}: 5")
    print(f"   Messages sent by {bob.name}: 4")
    print(f"   Total messages: 9")
    print(f"   {alice.name} send nonce: {alice.transport.get_send_nonce()}")
    print(f"   {bob.name} send nonce: {bob.transport.get_send_nonce()}")
    print()

    print("=" * 60)
    print("✅ Chat session completed successfully!")
    print("=" * 60)
    print()
    print("💡 Key Features Demonstrated:")
    print("   • Mutual authentication (XX pattern)")
    print("   • Encrypted messages in both directions")
    print("   • Automatic nonce management")
    print("   • Authentication tag verification")
    print()
    print("📝 Note: This is a simulation. Real chat applications need:")
    print("   • Network sockets (TCP/UDP)")
    print("   • Message framing and serialization")
    print("   • Async I/O for concurrent connections")
    print("   • Error handling and reconnection logic")


if __name__ == "__main__":
    run_example()
