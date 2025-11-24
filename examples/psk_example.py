"""
Pre-Shared Key (PSK) Examples for NoiseFramework

This module demonstrates how to use PSK patterns in Noise Protocol.
PSK patterns provide an additional layer of security and are useful for:
- Defense against quantum computing attacks (PSK can't be broken by quantum computers)
- Additional authentication layer
- IoT and embedded systems with pre-provisioned secrets
- Enterprise scenarios with pre-shared credentials

PSK modifiers:
- psk0: PSK mixed before first message
- psk1: PSK mixed after first message  
- psk2: PSK mixed after second message
- psk3: PSK mixed after third message
"""

import os
from noiseframework import NoiseHandshake, NoiseTransport


def nnpsk0_example():
    """
    Demonstrate Noise_NNpsk0 pattern.
    
    NNpsk0 is the simplest PSK pattern - anonymous with PSK mixed at the start.
    Both parties must share the same 32-byte PSK in advance.
    
    Pattern:
        <- psk (PSK mixed before any messages)
        -> e
        <- e, ee
    """
    print("=" * 60)
    print("Example 1: Noise_NNpsk0 (Anonymous + PSK at start)")
    print("=" * 60)
    
    # Generate a 32-byte pre-shared key (in practice, this would be pre-provisioned)
    psk = os.urandom(32)
    print(f"Pre-shared key: {psk.hex()[:32]}...")
    
    # === INITIATOR ===
    initiator = NoiseHandshake("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
    initiator.set_as_initiator()
    initiator.set_psk(psk)  # Set PSK before initialize
    initiator.initialize()
    
    # === RESPONDER ===
    responder = NoiseHandshake("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
    responder.set_as_responder()
    responder.set_psk(psk)  # Both parties must set the same PSK
    responder.initialize()
    
    # === HANDSHAKE ===
    print("\nPerforming handshake...")
    
    # Message 1: -> e
    msg1 = initiator.write_message(b"")
    responder.read_message(msg1)
    print(f"  Message 1: Initiator -> Responder ({len(msg1)} bytes)")
    
    # Message 2: <- e, ee
    msg2 = responder.write_message(b"")
    initiator.read_message(msg2)
    print(f"  Message 2: Responder -> Initiator ({len(msg2)} bytes)")
    
    print("✓ Handshake complete")
    
    # === TRANSPORT MODE ===
    init_send, init_recv = initiator.to_transport()
    resp_send, resp_recv = responder.to_transport()
    
    init_transport = NoiseTransport(init_send, init_recv)
    resp_transport = NoiseTransport(resp_send, resp_recv)
    
    # Send encrypted messages
    ciphertext = init_transport.send(b"Hello with PSK!")
    plaintext = resp_transport.receive(ciphertext)
    print(f"\nEncrypted message: {plaintext.decode()}")
    print("✓ NNpsk0 example complete\n")


def xxpsk3_example():
    """
    Demonstrate Noise_XXpsk3 pattern.
    
    XXpsk3 provides mutual authentication with static keys + PSK mixed after
    the third message. This is the most common PSK pattern.
    
    Pattern:
        -> e
        <- e, ee, s, es
        -> s, se, psk
    """
    print("=" * 60)
    print("Example 2: Noise_XXpsk3 (Mutual auth + PSK at end)")
    print("=" * 60)
    
    # Generate pre-shared key
    psk = os.urandom(32)
    print(f"Pre-shared key: {psk.hex()[:32]}...")
    
    # === INITIATOR ===
    initiator = NoiseHandshake("Noise_XXpsk3_25519_ChaChaPoly_SHA256")
    initiator.set_as_initiator()
    initiator.generate_static_keypair()  # XXpsk3 requires static keys
    initiator.set_psk(psk)
    initiator.initialize()
    
    init_pubkey = initiator.static_public
    print(f"Initiator public key: {init_pubkey.hex()[:32]}...")
    
    # === RESPONDER ===
    responder = NoiseHandshake("Noise_XXpsk3_25519_ChaChaPoly_SHA256")
    responder.set_as_responder()
    responder.generate_static_keypair()
    responder.set_psk(psk)
    responder.initialize()
    
    resp_pubkey = responder.static_public
    print(f"Responder public key: {resp_pubkey.hex()[:32]}...")
    
    # === HANDSHAKE ===
    print("\nPerforming handshake...")
    
    # Message 1: -> e
    msg1 = initiator.write_message(b"")
    responder.read_message(msg1)
    print(f"  Message 1: Initiator -> Responder ({len(msg1)} bytes)")
    
    # Message 2: <- e, ee, s, es
    msg2 = responder.write_message(b"")
    initiator.read_message(msg2)
    print(f"  Message 2: Responder -> Initiator ({len(msg2)} bytes)")
    
    # Message 3: -> s, se, psk
    msg3 = initiator.write_message(b"")
    responder.read_message(msg3)
    print(f"  Message 3: Initiator -> Responder ({len(msg3)} bytes, with PSK)")
    
    print("✓ Handshake complete")
    
    # Verify mutual authentication
    assert initiator.remote_static_public == resp_pubkey
    assert responder.remote_static_public == init_pubkey
    print("✓ Mutual authentication verified")
    
    # === TRANSPORT MODE ===
    init_send, init_recv = initiator.to_transport()
    resp_send, resp_recv = responder.to_transport()
    
    init_transport = NoiseTransport(init_send, init_recv)
    resp_transport = NoiseTransport(resp_send, resp_recv)
    
    # Send encrypted messages
    ciphertext = init_transport.send(b"Secure message with mutual auth + PSK!")
    plaintext = resp_transport.receive(ciphertext)
    print(f"\nEncrypted message: {plaintext.decode()}")
    print("✓ XXpsk3 example complete\n")


def ikpsk2_example():
    """
    Demonstrate Noise_IKpsk2 pattern.
    
    IKpsk2 provides initiator authentication + known responder identity + PSK
    mixed after the second message. Useful when responder's key is known.
    
    Pattern:
        <- s (responder's static key known)
        -> e, es, s, ss
        <- e, ee, se, psk
    """
    print("=" * 60)
    print("Example 3: Noise_IKpsk2 (Known responder + PSK)")
    print("=" * 60)
    
    # Generate pre-shared key
    psk = os.urandom(32)
    print(f"Pre-shared key: {psk.hex()[:32]}...")
    
    # === SETUP: Responder generates key pair in advance ===
    responder_static_private = os.urandom(32)
    responder_static_public = os.urandom(32)  # In real scenario, derive from private
    # For proper DH, we'd use: responder.generate_static_keypair()
    # But for demo, we'll use the handshake to generate proper keys
    
    temp_responder = NoiseHandshake("Noise_IKpsk2_25519_ChaChaPoly_SHA256")
    temp_responder.generate_static_keypair()
    responder_static_public = temp_responder.static_public
    responder_static_private = temp_responder.static_private
    
    print(f"Responder public key (known to initiator): {responder_static_public.hex()[:32]}...")
    
    # === INITIATOR (knows responder's public key) ===
    initiator = NoiseHandshake("Noise_IKpsk2_25519_ChaChaPoly_SHA256")
    initiator.set_as_initiator()
    initiator.generate_static_keypair()
    initiator.set_remote_static_public_key(responder_static_public)  # Known in advance
    initiator.set_psk(psk)
    initiator.initialize()
    
    # === RESPONDER ===
    responder = NoiseHandshake("Noise_IKpsk2_25519_ChaChaPoly_SHA256")
    responder.set_as_responder()
    responder.set_static_keypair(responder_static_private, responder_static_public)
    responder.set_psk(psk)
    responder.initialize()
    
    # === HANDSHAKE ===
    print("\nPerforming handshake...")
    
    # Message 1: -> e, es, s, ss
    msg1 = initiator.write_message(b"Hello server")
    payload1 = responder.read_message(msg1)
    print(f"  Message 1: Initiator -> Responder ({len(msg1)} bytes, payload: {payload1})")
    
    # Message 2: <- e, ee, se, psk
    msg2 = responder.write_message(b"Hello client")
    payload2 = initiator.read_message(msg2)
    print(f"  Message 2: Responder -> Initiator ({len(msg2)} bytes, payload: {payload2}, with PSK)")
    
    print("✓ Handshake complete")
    
    # Verify responder knows initiator's identity
    print(f"Responder received initiator's key: {responder.remote_static_public.hex()[:32]}...")
    print("✓ Initiator authenticated to responder")
    
    # === TRANSPORT MODE ===
    init_send, init_recv = initiator.to_transport()
    resp_send, resp_recv = responder.to_transport()
    
    init_transport = NoiseTransport(init_send, init_recv)
    resp_transport = NoiseTransport(resp_send, resp_recv)
    
    # Send encrypted messages
    ciphertext = init_transport.send(b"Protected by known key + PSK!")
    plaintext = resp_transport.receive(ciphertext)
    print(f"\nEncrypted message: {plaintext.decode()}")
    print("✓ IKpsk2 example complete\n")


def psk_security_benefits():
    """
    Explain the security benefits of using PSK patterns.
    """
    print("=" * 60)
    print("PSK Security Benefits")
    print("=" * 60)
    print("""
PSK (Pre-Shared Key) patterns provide several security advantages:

1. **Quantum Resistance**
   - PSKs are immune to quantum computer attacks on DH key exchange
   - Even if future quantum computers break the DH, the PSK keeps data secure
   - Provides "hybrid" security: classical DH + quantum-resistant PSK

2. **Additional Authentication**
   - PSK proves both parties share a secret
   - Protects against man-in-the-middle attacks
   - Useful when public key infrastructure is unavailable

3. **Forward Secrecy + Pre-Computation Resistance**
   - Combining ephemeral DH + PSK provides strong forward secrecy
   - PSK mixed into handshake hash prevents pre-computation attacks

4. **Use Cases**
   - IoT devices with pre-provisioned secrets
   - Enterprise VPNs with pre-shared credentials
   - Embedded systems without public key infrastructure
   - Defense applications requiring multi-factor security

5. **PSK Placement Trade-offs**
   - psk0: Earliest protection, but no forward secrecy yet
   - psk2/psk3: Better forward secrecy, delays quantum resistance slightly
   - Choose based on threat model and deployment scenario

**Best Practice**: Use XXpsk3 for general-purpose secure communications
with mutual authentication and PSK protection.
    """)


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("NoiseFramework PSK Examples")
    print("=" * 60 + "\n")
    
    try:
        # Run all examples
        nnpsk0_example()
        xxpsk3_example()
        ikpsk2_example()
        psk_security_benefits()
        
        print("\n" + "=" * 60)
        print("✓ All PSK examples completed successfully!")
        print("=" * 60 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
