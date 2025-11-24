"""
Error Handling Example for NoiseFramework.

This example demonstrates how to catch and handle the various custom exceptions
that NoiseFramework can raise, showing proper error handling patterns for
production code.
"""

import logging
from noiseframework import NoiseHandshake, NoiseTransport
from noiseframework.exceptions import (
    NoiseError,
    HandshakeError,
    RoleNotSetError,
    RoleAlreadySetError,
    WrongTurnError,
    HandshakeCompleteError,
    MissingKeyError,
    PatternError,
    UnsupportedPatternError,
    UnsupportedPrimitiveError,
    StateError,
    NoKeySetError,
    NonceOverflowError,
    InvalidKeySizeError,
    TransportError,
    AuthenticationError,
    CryptoError,
    ValidationError,
)

# Configure logging to see error messages in context
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
)


def example_1_pattern_validation():
    """Example 1: Handling pattern validation errors."""
    print("\n=== Example 1: Pattern Validation ===")
    
    # Invalid pattern string format
    try:
        hs = NoiseHandshake("Invalid_Pattern")
    except UnsupportedPatternError as e:
        print(f"[ERROR] Pattern error: {e}")
        print("   -> Use format: Noise_PATTERN_DH_CIPHER_HASH")
    
    # Unsupported DH function
    try:
        hs = NoiseHandshake("Noise_XX_InvalidDH_ChaChaPoly_SHA256")
    except UnsupportedPrimitiveError as e:
        print(f"[ERROR] Primitive error: {e}")
        print("   -> Supported DH: 25519, 448")
    
    # Unsupported cipher
    try:
        hs = NoiseHandshake("Noise_XX_25519_InvalidCipher_SHA256")
    except UnsupportedPrimitiveError as e:
        print(f"[ERROR] Primitive error: {e}")
        print("   -> Supported ciphers: ChaChaPoly, AESGCM")
    
    # Catch all pattern errors
    try:
        hs = NoiseHandshake("Noise_INVALID_25519_ChaChaPoly_SHA256")
    except PatternError as e:
        print(f"[ERROR] Pattern error: {e}")
        print("   -> Supported patterns: NN, NK, NX, KK, KN, KX, XK, XN, XX, IK, IN, IX")


def example_2_role_errors():
    """Example 2: Handling role configuration errors."""
    print("\n=== Example 2: Role Configuration ===")
    
    hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    
    # Trying to initialize without setting role
    try:
        hs.initialize()
    except RoleNotSetError as e:
        print(f"[ERROR] Role error: {e}")
        print("   -> Call set_as_initiator() or set_as_responder() first")
    
    # Set role properly
    hs.set_as_initiator()
    print("[OK] Role set to initiator")
    
    # Try to change role after it's set
    try:
        hs.set_as_responder()
    except RoleAlreadySetError as e:
        print(f"[ERROR] Role error: {e}")
        print("   -> Create a new NoiseHandshake instance to change roles")


def example_3_missing_keys():
    """Example 3: Handling missing key errors."""
    print("\n=== Example 3: Missing Keys ===")
    
    # IK pattern requires responder's static key to be known
    hs = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
    hs.set_as_initiator()
    
    # Try to initialize without setting remote static key
    try:
        hs.initialize()
    except MissingKeyError as e:
        print(f"[ERROR] Missing key: {e}")
        print("   -> For IK pattern, call set_remote_static_public_key() first")
    
    # Provide the required key
    remote_static = b"R" * 32  # In real code, this would be the responder's public key
    hs.set_remote_static_public_key(remote_static)
    print("[OK] Remote static key set")
    
    # Now initialization works
    hs.initialize()
    print("[OK] Handshake initialized")


def example_4_wrong_turn():
    """Example 4: Handling wrong turn errors."""
    print("\n=== Example 4: Wrong Turn ===")
    
    # Initiator
    init = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    init.set_as_initiator()
    init.generate_static_keypair()
    init.initialize()
    
    # Responder
    resp = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    resp.set_as_responder()
    resp.generate_static_keypair()
    resp.initialize()
    
    # Responder tries to write first (wrong - initiator should start)
    try:
        resp.write_message()
    except WrongTurnError as e:
        print(f"[ERROR] Wrong turn: {e}")
        print("   -> In XX pattern, initiator sends first message")
    
    # Correct order
    msg1 = init.write_message()
    print("[OK] Initiator sent message 1")
    
    resp.read_message(msg1)
    print("[OK] Responder received message 1")


def example_5_handshake_complete():
    """Example 5: Handling operations after handshake complete."""
    print("\n=== Example 5: Handshake Complete ===")
    
    # Complete a simple NN handshake
    init = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
    init.set_as_initiator()
    init.initialize()
    
    resp = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
    resp.set_as_responder()
    resp.initialize()
    
    # Exchange messages
    msg1 = init.write_message()
    resp.read_message(msg1)
    msg2 = resp.write_message()
    init.read_message(msg2)
    
    print("[OK] Handshake complete")
    
    # Try to send another handshake message
    try:
        init.write_message()
    except HandshakeCompleteError as e:
        print(f"[ERROR] Handshake complete: {e}")
        print("   -> Call to_transport() to switch to transport mode")
    
    # Correct approach
    init_send, init_recv = init.to_transport()
    resp_send, resp_recv = resp.to_transport()
    transport_init = NoiseTransport(init_send, init_recv)
    transport_resp = NoiseTransport(resp_send, resp_recv)
    print("[OK] Switched to transport mode")
    
    # Now can send encrypted messages
    ciphertext = transport_init.send(b"Hello!")
    plaintext = transport_resp.receive(ciphertext)
    print(f"[OK] Encrypted communication: {plaintext.decode()}")


def example_6_invalid_key_sizes():
    """Example 6: Handling invalid key size errors."""
    print("\n=== Example 6: Invalid Key Sizes ===")
    
    hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    
    # Try to set keypair with wrong size
    try:
        hs.set_static_keypair(b"short", b"also_short")
    except ValidationError as e:
        print(f"[ERROR] Validation error: {e}")
        print("   -> Curve25519 keys must be exactly 32 bytes")
    
    # Correct key sizes
    from noiseframework.crypto.dh import get_dh_function
    dh = get_dh_function("25519")
    private, public = dh.generate_keypair()
    hs.set_static_keypair(private, public)
    print(f"[OK] Valid keypair set (private={len(private)} bytes, public={len(public)} bytes)")


def example_7_authentication_failure():
    """Example 7: Handling authentication failures."""
    print("\n=== Example 7: Authentication Failure ===")
    
    # Create transport
    init = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
    init.set_as_initiator()
    init.initialize()
    
    resp = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
    resp.set_as_responder()
    resp.initialize()
    
    msg1 = init.write_message()
    resp.read_message(msg1)
    msg2 = resp.write_message()
    init.read_message(msg2)
    
    init_send, init_recv = init.to_transport()
    resp_send, resp_recv = resp.to_transport()
    transport_init = NoiseTransport(init_send, init_recv)
    transport_resp = NoiseTransport(resp_send, resp_recv)
    
    # Send valid message
    ciphertext = transport_init.send(b"Valid message")
    
    # Tamper with ciphertext
    tampered = ciphertext[:-1] + b"\x00"
    
    try:
        transport_resp.receive(tampered)
    except AuthenticationError as e:
        print(f"[ERROR] Authentication failed: {e}")
        print("   -> Message was tampered with or corrupted")
        print("   -> Do NOT process the message - discard it")


def example_8_comprehensive_error_handling():
    """Example 8: Comprehensive error handling in production code."""
    print("\n=== Example 8: Production Error Handling ===")
    
    def safe_handshake_initiator(pattern: str, remote_static: bytes = None) -> NoiseTransport:
        """
        Safely perform handshake as initiator with comprehensive error handling.
        
        Args:
            pattern: Noise pattern string
            remote_static: Remote static public key (required for some patterns)
        
        Returns:
            NoiseTransport instance ready for encrypted communication
        
        Raises:
            NoiseError: Base exception for all framework errors
        """
        try:
            # Create and configure handshake
            hs = NoiseHandshake(pattern)
            hs.set_as_initiator()
            
            # Generate or set keys
            if "K" in pattern or "X" in pattern:
                hs.generate_static_keypair()
            
            # Set remote static if required
            if remote_static:
                hs.set_remote_static_public_key(remote_static)
            
            # Initialize handshake
            hs.initialize()
            
            print(f"[OK] Handshake configured for pattern {pattern}")
            return hs
            
        except UnsupportedPatternError as e:
            print(f"[ERROR] Invalid pattern: {e}")
            raise
        except UnsupportedPrimitiveError as e:
            print(f"[ERROR] Unsupported primitive: {e}")
            raise
        except MissingKeyError as e:
            print(f"[ERROR] Missing required key: {e}")
            raise
        except ValidationError as e:
            print(f"[ERROR] Validation error: {e}")
            raise
        except NoiseError as e:
            # Catch any other NoiseFramework errors
            print(f"[ERROR] Unexpected error: {e}")
            raise
        except Exception as e:
            # Catch non-framework errors
            print(f"[ERROR] System error: {e}")
            raise
    
    # Test the function
    try:
        hs = safe_handshake_initiator("Noise_XX_25519_ChaChaPoly_SHA256")
        print("[OK] Handshake ready for message exchange")
    except NoiseError as e:
        print(f"Failed to create handshake: {e}")


def example_9_catching_all_errors():
    """Example 9: Catching all NoiseFramework errors."""
    print("\n=== Example 9: Catch All NoiseFramework Errors ===")
    
    def risky_operation():
        """Simulate various error conditions."""
        import random
        errors = [
            lambda: NoiseHandshake("Invalid"),
            lambda: NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256").initialize(),
            lambda: NoiseHandshake("Noise_XX_InvalidCipher_ChaChaPoly_SHA256"),
        ]
        random.choice(errors)()
    
    try:
        risky_operation()
    except NoiseError as e:
        # Catches ALL NoiseFramework exceptions
        print(f"[ERROR] NoiseFramework error: {type(e).__name__}")
        print(f"   Message: {e}")
        print("   -> All custom exceptions inherit from NoiseError")
        print("   -> Use this to catch any framework-specific error")
    except Exception as e:
        # Catches non-framework errors
        print(f"[ERROR] System error: {e}")


def main():
    """Run all examples."""
    print("=" * 60)
    print("NoiseFramework Error Handling Examples")
    print("=" * 60)
    
    example_1_pattern_validation()
    example_2_role_errors()
    example_3_missing_keys()
    example_4_wrong_turn()
    example_5_handshake_complete()
    example_6_invalid_key_sizes()
    example_7_authentication_failure()
    example_8_comprehensive_error_handling()
    example_9_catching_all_errors()
    
    print("\n" + "=" * 60)
    print("Key Takeaways:")
    print("=" * 60)
    print("1. All NoiseFramework exceptions inherit from NoiseError")
    print("2. Catch specific exceptions for targeted error handling")
    print("3. Catch NoiseError to handle all framework errors")
    print("4. Error messages include actionable suggestions")
    print("5. Use logging to see error context before exceptions")
    print("=" * 60)


if __name__ == "__main__":
    main()
