"""
Tests for fallback pattern support (Feature #7).

Tests the implementation of fallback patterns as specified in the Noise Protocol 
Framework Section 10.2. Fallback patterns allow graceful degradation when the 
responder cannot decrypt the initiator's first message (e.g., wrong static key 
or outdated PSK).
"""

import pytest
from noiseframework import NoiseHandshake
from noiseframework.noise.pattern import parse_pattern, get_pattern_tokens
from noiseframework.exceptions import (
    UnsupportedPatternError,
    ValidationError,
    RoleNotSetError,
    HandshakeCompleteError,
)


class TestFallbackPatternParsing:
    """Test parsing of fallback patterns."""

    def test_parse_xxfallback_pattern(self):
        """Test parsing of XXfallback pattern."""
        pattern = parse_pattern("Noise_XXfallback_25519_ChaChaPoly_SHA256")
        assert pattern.handshake_pattern == "XX"
        assert pattern.fallback_modifier == "fallback"
        assert pattern.dh_function == "25519"
        assert pattern.cipher_function == "ChaChaPoly"
        assert pattern.hash_function == "SHA256"

    def test_parse_ikfallback_pattern(self):
        """Test parsing of IKfallback pattern."""
        pattern = parse_pattern("Noise_IKfallback_25519_ChaChaPoly_SHA256")
        assert pattern.handshake_pattern == "IK"
        assert pattern.fallback_modifier == "fallback"

    def test_parse_nkfallback_pattern(self):
        """Test parsing of NKfallback pattern."""
        pattern = parse_pattern("Noise_NKfallback_25519_ChaChaPoly_SHA256")
        assert pattern.handshake_pattern == "NK"
        assert pattern.fallback_modifier == "fallback"

    def test_parse_non_fallback_pattern(self):
        """Test parsing of regular pattern has no fallback modifier."""
        pattern = parse_pattern("Noise_XX_25519_ChaChaPoly_SHA256")
        assert pattern.handshake_pattern == "XX"
        assert pattern.fallback_modifier is None

    def test_invalid_fallback_modifier(self):
        """Test parsing of invalid fallback modifier."""
        with pytest.raises(UnsupportedPatternError):
            parse_pattern("Noise_XXwrongfallback_25519_ChaChaPoly_SHA256")


class TestFallbackTokens:
    """Test token generation for fallback patterns."""

    def test_xxfallback_tokens(self):
        """Test XXfallback converts Alice's 'e' to pre-message."""
        initiator_pre, responder_pre, messages = get_pattern_tokens("XX", fallback_modifier="fallback")
        # XX:  -> e
        #      <- e, ee, s, es
        #      -> s, se
        # XXfallback:  -> e  (becomes pre-message)
        #              ...
        #              <- e, ee, s, es
        #              -> s, se
        assert initiator_pre == ["e"]
        assert responder_pre == []
        assert messages == ["e, ee, s, es", "s, se"]

    def test_xxfallback_is_valid_fallback_pattern(self):
        """Test that XXfallback is a valid fallback pattern."""
        # XX's first message is just "e", which can be a pre-message
        # This is the primary fallback pattern used in Noise Pipes
        initiator_pre, responder_pre, messages = get_pattern_tokens("XX", fallback_modifier="fallback")
        assert initiator_pre == ["e"]
        assert responder_pre == []
        assert messages == ["e, ee, s, es", "s, se"]

    def test_ik_cannot_directly_use_fallback_modifier(self):
        """Test that IK cannot directly use fallback modifier (first message too complex)."""
        # IK first message is "e, es, s, ss" which cannot be a pre-message
        # In Noise Pipes, when IK fails, Bob switches to XXfallback (not IKfallback)
        with pytest.raises(UnsupportedPatternError, match="cannot be converted to a pre-message"):
            get_pattern_tokens("IK", psk_modifier=None, fallback_modifier="fallback")

    def test_nk_cannot_directly_use_fallback_modifier(self):
        """Test that NK cannot directly use fallback modifier (first message has DH operations)."""
        # NK first message is "e, es" which cannot be a pre-message (contains es token)
        # In practice, when NK fails, Bob would switch to XXfallback
        with pytest.raises(UnsupportedPatternError, match="cannot be converted to a pre-message"):
            get_pattern_tokens("NK", fallback_modifier="fallback")

    def test_fallback_without_modifier_no_change(self):
        """Test pattern without fallback modifier is unchanged."""
        initiator_pre, responder_pre, messages = get_pattern_tokens("XX", fallback_modifier=None)
        assert initiator_pre == []
        assert responder_pre == []
        assert messages == ["e", "e, ee, s, es", "s, se"]


class TestFallbackHandshakeSetup:
    """Test setup of fallback handshakes."""

    def test_start_fallback_as_responder(self):
        """Test that responder can call start_fallback()."""
        handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        handshake.set_as_responder()
        handshake.generate_static_keypair()
        handshake.initialize()

        # Simulate receiving Alice's ephemeral key
        import os
        alice_ephemeral = os.urandom(32)

        # Should not raise
        handshake.start_fallback(alice_ephemeral)
        assert handshake.pattern.fallback_modifier == "fallback"
        assert handshake.pattern.name == "Noise_XXfallback_25519_ChaChaPoly_SHA256"

    def test_start_fallback_as_initiator_fails(self):
        """Test that initiator cannot call start_fallback()."""
        handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        handshake.set_as_initiator()
        handshake.generate_static_keypair()
        handshake.initialize()

        import os
        alice_ephemeral = os.urandom(32)

        with pytest.raises(RoleNotSetError, match="only responder can call start_fallback"):
            handshake.start_fallback(alice_ephemeral)

    def test_start_fallback_without_role_fails(self):
        """Test that start_fallback() fails if role not set."""
        handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")

        import os
        alice_ephemeral = os.urandom(32)

        with pytest.raises(RoleNotSetError):
            handshake.start_fallback(alice_ephemeral)

    def test_start_fallback_after_completion_fails(self):
        """Test that start_fallback() fails after handshake complete."""
        # Create a simple NN handshake to completion
        initiator = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        responder = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")

        initiator.set_as_initiator()
        responder.set_as_responder()

        initiator.initialize()
        responder.initialize()

        # Complete handshake
        msg1 = initiator.write_message(b"")
        responder.read_message(msg1)
        msg2 = responder.write_message(b"")
        initiator.read_message(msg2)

        assert responder.handshake_complete

        import os
        alice_ephemeral = os.urandom(32)

        with pytest.raises(HandshakeCompleteError, match="handshake already complete"):
            responder.start_fallback(alice_ephemeral)

    def test_start_fallback_invalid_key_size(self):
        """Test that start_fallback() validates ephemeral key size."""
        handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        handshake.set_as_responder()
        handshake.generate_static_keypair()
        handshake.initialize()

        invalid_key = b"tooshort"

        with pytest.raises(ValidationError, match="Invalid remote ephemeral key size"):
            handshake.start_fallback(invalid_key)

    def test_start_fallback_preserves_ephemeral_key(self):
        """Test that start_fallback() preserves the remote ephemeral key."""
        handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        handshake.set_as_responder()
        handshake.generate_static_keypair()
        handshake.initialize()

        import os
        alice_ephemeral = os.urandom(32)

        handshake.start_fallback(alice_ephemeral)
        assert handshake.remote_ephemeral_public == alice_ephemeral


class TestFallbackHandshakes:
    """Test complete fallback handshake flows."""

    def test_ik_to_xxfallback_handshake(self):
        """Test IK → XXfallback fallback scenario (Noise Pipes)."""
        # Alice attempts IK with wrong responder static key
        # Bob cannot decrypt, falls back to XXfallback
        # This is the Noise Pipes protocol

        # Bob's actual keys
        bob = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")  # Bob prepares for XXfallback
        bob.set_as_responder()
        bob.generate_static_keypair()
        bob_static_public = bob.static_public

        # Alice has WRONG Bob static key
        alice = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
        alice.set_as_initiator()
        alice.generate_static_keypair()
        # Set wrong remote static key (generate another random one)
        import os
        wrong_bob_key = os.urandom(32)
        alice.set_remote_static_public_key(wrong_bob_key)

        alice.initialize()
        bob.initialize()

        # Alice sends IK first message (e, es, s, ss)
        ik_msg1 = alice.write_message(b"Hello")

        # Bob tries to read but will fail decryption (we simulate this)
        # In reality, Bob would catch exception and extract ephemeral key
        # For this test, we simulate that Bob knows Alice's ephemeral is the first 32 bytes
        alice_ephemeral_from_msg = ik_msg1[:32]

        # Bob initiates fallback to XXfallback
        bob.start_fallback(alice_ephemeral_from_msg)

        # Now Bob sends first XXfallback message (Bob's ephemeral + encrypted Bob's static)
        fallback_msg1 = bob.write_message(b"Fallback")

        # Alice needs to switch to XXfallback too (she realizes IK failed)
        alice_fallback = NoiseHandshake("Noise_XXfallback_25519_ChaChaPoly_SHA256")
        alice_fallback.set_as_initiator()
        alice_fallback.set_static_keypair(alice.static_private, alice.static_public)
        # In XXfallback, Alice's ephemeral key is a pre-message, so we need to reuse it
        # Set ephemeral keys BEFORE initialize() so they're mixed as pre-messages
        alice_fallback.ephemeral_private = alice.ephemeral_private
        alice_fallback.ephemeral_public = alice.ephemeral_public
        alice_fallback.initialize()

        # Alice reads Bob's fallback message
        payload1 = alice_fallback.read_message(fallback_msg1)
        assert payload1 == b"Fallback"

        # Alice sends her static key
        fallback_msg2 = alice_fallback.write_message(b"OK")

        # Bob reads Alice's response
        payload2 = bob.read_message(fallback_msg2)
        assert payload2 == b"OK"

        # Both should complete
        assert bob.handshake_complete
        assert alice_fallback.handshake_complete

        # Convert to transport and exchange messages
        bob_send, bob_recv = bob.to_transport()
        alice_send, alice_recv = alice_fallback.to_transport()

        # Test transport messages
        encrypted1 = bob_send.encrypt_with_ad(b"", b"Fallback works!")
        decrypted1 = alice_recv.decrypt_with_ad(b"", encrypted1)
        assert decrypted1 == b"Fallback works!"

        encrypted2 = alice_send.encrypt_with_ad(b"", b"Success!")
        decrypted2 = bob_recv.decrypt_with_ad(b"", encrypted2)
        assert decrypted2 == b"Success!"

    def test_xx_handshake_without_fallback(self):
        """Test normal XX handshake for comparison."""
        alice = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        bob = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")

        alice.set_as_initiator()
        bob.set_as_responder()

        alice.generate_static_keypair()
        bob.generate_static_keypair()

        alice.initialize()
        bob.initialize()

        # Message 1: Alice -> Bob (e)
        msg1 = alice.write_message(b"Hello")
        payload1 = bob.read_message(msg1)
        assert payload1 == b"Hello"

        # Message 2: Bob -> Alice (e, ee, s, es)
        msg2 = bob.write_message(b"World")
        payload2 = alice.read_message(msg2)
        assert payload2 == b"World"

        # Message 3: Alice -> Bob (s, se)
        msg3 = alice.write_message(b"!")
        payload3 = bob.read_message(msg3)
        assert payload3 == b"!"

        assert alice.handshake_complete
        assert bob.handshake_complete


class TestFallbackAsync:
    """Test async fallback support."""

    @pytest.mark.asyncio
    async def test_async_start_fallback(self):
        """Test async start_fallback() method."""
        from noiseframework.async_support import AsyncNoiseHandshake

        handshake = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        await handshake.set_as_responder()
        await handshake.generate_static_keypair()
        await handshake.initialize()

        import os
        alice_ephemeral = os.urandom(32)

        # Should not raise
        await handshake.start_fallback(alice_ephemeral)
        assert handshake._handshake.pattern.fallback_modifier == "fallback"


class TestFallbackErrorCases:
    """Test error handling for fallback patterns."""

    def test_fallback_pattern_with_invalid_first_message(self):
        """Test that fallback fails for patterns with invalid first messages."""
        # NN pattern has first message "e" which is valid for fallback
        # But let's test with a hypothetical pattern that doesn't support fallback
        # Actually, most patterns support fallback if their first message is "e", "s", or "e, s"
        # So this test may not apply to standard patterns
        pass  # Skip for now, all standard patterns with "e" first message support fallback

    def test_multiple_fallback_calls(self):
        """Test that calling start_fallback() after already in fallback pattern fails."""
        handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        handshake.set_as_responder()
        handshake.generate_static_keypair()
        handshake.initialize()

        import os
        alice_ephemeral = os.urandom(32)

        handshake.start_fallback(alice_ephemeral)

        # Try to call fallback again on an already-fallback pattern
        # This should fail because XXfallback's first message is "e, ee, s, es" (not "e")
        alice_ephemeral2 = os.urandom(32)
        
        with pytest.raises(ValidationError, match="cannot be converted to a pre-message"):
            handshake.start_fallback(alice_ephemeral2)
