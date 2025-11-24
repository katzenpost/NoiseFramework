"""
Fallback Pattern Support Example

This example demonstrates the Noise Pipes protocol (IK → XXfallback) where:
1. Alice attempts an IK handshake with Bob's static key
2. Bob cannot decrypt Alice's first message (wrong static key or outdated PSK)
3. Bob extracts Alice's ephemeral key and initiates fallback to XXfallback
4. Both parties complete the XXfallback handshake
5. They establish secure transport channels

This is useful for:
- Key rotation scenarios (responder's static key changed)
- PSK outdated/mismatched
- Graceful degradation when IK fails

Note: In production, Bob would catch a decryption exception and extract 
Alice's ephemeral key from the failed message. This example simulates that.
"""

import os
from noiseframework import NoiseHandshake


def demonstrate_fallback():
    """Demonstrate IK → XXfallback fallback scenario (Noise Pipes protocol)."""
    
    print("=== Noise Pipes Protocol: IK -> XXfallback ===\n")
    
    # 1. Setup: Bob generates his actual keys
    print("1. Bob generates his keys...")
    bob = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")  # Bob prepares for XXfallback
    bob.set_as_responder()
    bob.generate_static_keypair()
    bob_static_public_real = bob.static_public
    print(f"   Bob's real static public key: {bob_static_public_real.hex()[:32]}...")
    
    # 2. Alice attempts IK with WRONG Bob static key (simulates outdated key)
    print("\n2. Alice attempts IK handshake with outdated Bob key...")
    alice = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
    alice.set_as_initiator()
    alice.generate_static_keypair()
    
    # Alice has wrong/outdated Bob static key
    wrong_bob_key = os.urandom(32)
    alice.set_remote_static_public_key(wrong_bob_key)
    print(f"   Alice's (outdated) Bob key: {wrong_bob_key.hex()[:32]}...")
    print(f"   Keys mismatch: Alice's IK will fail!")
    
    alice.initialize()
    bob.initialize()
    
    # 3. Alice sends IK first message (e, es, s, ss)
    print("\n3. Alice sends IK first message...")
    ik_msg1 = alice.write_message(b"Hello Bob")
    print(f"   IK message length: {len(ik_msg1)} bytes")
    print(f"   Contains: Alice's ephemeral key + encrypted static key + payload")
    
    # 4. Bob tries to decrypt but fails (we simulate by extracting ephemeral)
    print("\n4. Bob cannot decrypt (wrong static key)...")
    print("   Bob extracts Alice's ephemeral key from failed message...")
    # In reality, Bob would catch InvalidTag and extract the ephemeral from the raw message
    # The first 32 bytes of IK message are Alice's ephemeral public key
    alice_ephemeral_from_msg = ik_msg1[:32]
    print(f"   Alice's ephemeral key: {alice_ephemeral_from_msg.hex()[:32]}...")
    
    # 5. Bob initiates fallback to XXfallback
    print("\n5. Bob initiates fallback to XXfallback...")
    bob.start_fallback(alice_ephemeral_from_msg)
    print("   * Fallback initiated")
    print("   * Alice's ephemeral key preserved")
    print("   * Pattern switched: XX -> XXfallback")
    print("   * Bob becomes effective initiator")
    
    # 6. Bob sends first XXfallback message
    print("\n6. Bob sends first XXfallback message...")
    fallback_msg1 = bob.write_message(b"Fallback initiated")
    print(f"   XXfallback message length: {len(fallback_msg1)} bytes")
    
    # 7. Alice realizes IK failed and switches to XXfallback
    print("\n7. Alice detects IK failure and switches to XXfallback...")
    alice_fallback = NoiseHandshake("Noise_XXfallback_25519_ChaChaPoly_SHA256")
    alice_fallback.set_as_initiator()
    alice_fallback.set_static_keypair(alice.static_private, alice.static_public)
    
    # In XXfallback, Alice's ephemeral key is a pre-message (must reuse it)
    alice_fallback.ephemeral_private = alice.ephemeral_private
    alice_fallback.ephemeral_public = alice.ephemeral_public
    alice_fallback.initialize()
    print("   * Alice switched to XXfallback")
    print("   * Reused ephemeral keys")
    
    # 8. Alice reads Bob's fallback message
    print("\n8. Alice reads Bob's fallback message...")
    payload1 = alice_fallback.read_message(fallback_msg1)
    print(f"   * Decrypted payload: {payload1.decode()}")
    
    # 9. Alice sends her static key (second XXfallback message)
    print("\n9. Alice sends her static key...")
    fallback_msg2 = alice_fallback.write_message(b"Acknowledged")
    print(f"   Message length: {len(fallback_msg2)} bytes")
    
    # 10. Bob reads Alice's response
    print("\n10. Bob reads Alice's response...")
    payload2 = bob.read_message(fallback_msg2)
    print(f"    * Decrypted payload: {payload2.decode()}")
    
    # 11. Handshake complete
    print("\n11. Handshake complete!")
    assert bob.handshake_complete
    assert alice_fallback.handshake_complete
    print("    * Bob handshake complete")
    print("    * Alice handshake complete")
    
    # 12. Convert to transport and exchange messages
    print("\n12. Establish transport channels...")
    bob_send, bob_recv = bob.to_transport()
    alice_send, alice_recv = alice_fallback.to_transport()
    print("    * Transport channels established")
    
    # 13. Test transport encryption
    print("\n13. Test transport encryption...")
    
    # Bob → Alice
    message1 = b"Welcome to the secure channel!"
    encrypted1 = bob_send.encrypt_with_ad(b"", message1)
    decrypted1 = alice_recv.decrypt_with_ad(b"", encrypted1)
    print(f"    Bob → Alice: {decrypted1.decode()}")
    assert decrypted1 == message1
    
    # Alice → Bob
    message2 = b"Thank you, fallback worked perfectly!"
    encrypted2 = alice_send.encrypt_with_ad(b"", message2)
    decrypted2 = bob_recv.decrypt_with_ad(b"", encrypted2)
    print(f"    Alice → Bob: {decrypted2.decode()}")
    assert decrypted2 == message2
    
    print("\n=== Fallback Handshake Successful ===")
    print("* IK failed due to wrong static key")
    print("* Bob extracted Alice's ephemeral key")
    print("* Bob initiated fallback to XXfallback")
    print("* Alice switched to XXfallback")
    print("* Handshake completed successfully")
    print("* Secure transport channels established")
    print("\nThis demonstrates the Noise Pipes protocol for graceful degradation.")


if __name__ == "__main__":
    demonstrate_fallback()
