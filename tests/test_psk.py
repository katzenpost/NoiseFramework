"""
Tests for Pre-Shared Key (PSK) patterns.

Tests PSK pattern parsing, PSK setting, PSK mixing, and complete PSK handshakes.
"""

import pytest
import os
from noiseframework import NoiseHandshake, NoiseTransport
from noiseframework.noise.pattern import parse_pattern, get_pattern_tokens
from noiseframework.exceptions import ValidationError, MissingKeyError, UnsupportedPatternError


class TestPSKPatternParsing:
    """Test PSK pattern string parsing."""
    
    def test_parse_xxpsk3_pattern(self):
        """Test parsing XXpsk3 pattern."""
        pattern = parse_pattern("Noise_XXpsk3_25519_ChaChaPoly_SHA256")
        assert pattern.handshake_pattern == "XX"
        assert pattern.psk_modifier == "psk3"
        assert pattern.dh_function == "25519"
        assert pattern.cipher_function == "ChaChaPoly"
        assert pattern.hash_function == "SHA256"
    
    def test_parse_nnpsk0_pattern(self):
        """Test parsing NNpsk0 pattern."""
        pattern = parse_pattern("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        assert pattern.handshake_pattern == "NN"
        assert pattern.psk_modifier == "psk0"
    
    def test_parse_ikpsk2_pattern(self):
        """Test parsing IKpsk2 pattern."""
        pattern = parse_pattern("Noise_IKpsk2_448_AESGCM_BLAKE2b")
        assert pattern.handshake_pattern == "IK"
        assert pattern.psk_modifier == "psk2"
        assert pattern.dh_function == "448"
        assert pattern.cipher_function == "AESGCM"
        assert pattern.hash_function == "BLAKE2b"
    
    def test_parse_non_psk_pattern(self):
        """Test that non-PSK patterns have None psk_modifier."""
        pattern = parse_pattern("Noise_XX_25519_ChaChaPoly_SHA256")
        assert pattern.handshake_pattern == "XX"
        assert pattern.psk_modifier is None
    
    def test_parse_all_psk_modifiers(self):
        """Test all supported PSK modifiers."""
        for psk_num in range(5):  # psk0 through psk4
            pattern = parse_pattern(f"Noise_XXpsk{psk_num}_25519_ChaChaPoly_SHA256")
            assert pattern.psk_modifier == f"psk{psk_num}"
    
    def test_parse_invalid_psk_modifier(self):
        """Test that invalid PSK modifiers are rejected."""
        with pytest.raises(UnsupportedPatternError) as exc_info:
            parse_pattern("Noise_XXpsk5_25519_ChaChaPoly_SHA256")
        assert "Unsupported PSK modifier" in str(exc_info.value) or "Invalid pattern string format" in str(exc_info.value)


class TestPSKTokens:
    """Test PSK token insertion in message patterns."""
    
    def test_psk0_token_placement(self):
        """Test that psk0 adds PSK token at start of first message."""
        init_pre, resp_pre, messages = get_pattern_tokens("NN", "psk0")
        assert "psk" in messages[0]
        # psk should be at the beginning
        assert messages[0].startswith("psk")
    
    def test_psk2_token_placement(self):
        """Test that psk2 adds PSK token at end of second message."""
        init_pre, resp_pre, messages = get_pattern_tokens("XX", "psk2")
        assert "psk" in messages[1]
        # psk should be at the end
        assert messages[1].endswith("psk")
    
    def test_psk3_token_placement(self):
        """Test that psk3 adds PSK token at end of third message."""
        init_pre, resp_pre, messages = get_pattern_tokens("XX", "psk3")
        assert "psk" in messages[2]
        assert messages[2].endswith("psk")
    
    def test_no_psk_without_modifier(self):
        """Test that no PSK token is added without PSK modifier."""
        init_pre, resp_pre, messages = get_pattern_tokens("XX", None)
        for message in messages:
            assert "psk" not in message


class TestPSKHandshakeSetup:
    """Test PSK handshake initialization and validation."""
    
    def test_set_psk_valid(self):
        """Test setting a valid PSK."""
        hs = NoiseHandshake("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        psk = os.urandom(32)
        hs.set_psk(psk)  # Should not raise
        assert hs.psk == psk
    
    def test_set_psk_invalid_size(self):
        """Test that PSK must be exactly 32 bytes."""
        hs = NoiseHandshake("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        
        # Too short
        with pytest.raises(ValidationError) as exc_info:
            hs.set_psk(b"short")
        assert "32 bytes" in str(exc_info.value)
        
        # Too long
        with pytest.raises(ValidationError) as exc_info:
            hs.set_psk(os.urandom(64))
        assert "32 bytes" in str(exc_info.value)
    
    def test_set_psk_on_non_psk_pattern(self):
        """Test that setting PSK on non-PSK pattern fails."""
        hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        
        with pytest.raises(ValidationError) as exc_info:
            hs.set_psk(os.urandom(32))
        assert "does not use a PSK modifier" in str(exc_info.value)
    
    def test_initialize_without_psk_fails(self):
        """Test that initializing PSK pattern without PSK fails."""
        hs = NoiseHandshake("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        hs.set_as_initiator()
        
        with pytest.raises(MissingKeyError) as exc_info:
            hs.initialize()
        assert "pre-shared key" in str(exc_info.value).lower()
    
    def test_initialize_with_psk_succeeds(self):
        """Test that initializing PSK pattern with PSK succeeds."""
        hs = NoiseHandshake("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        hs.set_as_initiator()
        hs.set_psk(os.urandom(32))
        hs.initialize()  # Should not raise


class TestPSKHandshakes:
    """Test complete PSK handshakes."""
    
    def test_nnpsk0_handshake(self):
        """Test complete NNpsk0 handshake."""
        psk = os.urandom(32)
        
        # Initiator
        initiator = NoiseHandshake("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        initiator.set_as_initiator()
        initiator.set_psk(psk)
        initiator.initialize()
        
        # Responder
        responder = NoiseHandshake("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        responder.set_as_responder()
        responder.set_psk(psk)
        responder.initialize()
        
        # Handshake
        msg1 = initiator.write_message(b"")
        responder.read_message(msg1)
        
        msg2 = responder.write_message(b"")
        initiator.read_message(msg2)
        
        assert initiator.handshake_complete
        assert responder.handshake_complete
    
    def test_xxpsk3_handshake(self):
        """Test complete XXpsk3 handshake with mutual authentication."""
        psk = os.urandom(32)
        
        # Initiator
        initiator = NoiseHandshake("Noise_XXpsk3_25519_ChaChaPoly_SHA256")
        initiator.set_as_initiator()
        initiator.generate_static_keypair()
        initiator.set_psk(psk)
        initiator.initialize()
        
        # Responder
        responder = NoiseHandshake("Noise_XXpsk3_25519_ChaChaPoly_SHA256")
        responder.set_as_responder()
        responder.generate_static_keypair()
        responder.set_psk(psk)
        responder.initialize()
        
        # Handshake
        msg1 = initiator.write_message(b"")
        responder.read_message(msg1)
        
        msg2 = responder.write_message(b"")
        initiator.read_message(msg2)
        
        msg3 = initiator.write_message(b"")
        responder.read_message(msg3)
        
        assert initiator.handshake_complete
        assert responder.handshake_complete
        
        # Verify mutual authentication
        assert initiator.remote_static_public == responder.static_public
        assert responder.remote_static_public == initiator.static_public
    
    def test_ikpsk2_handshake(self):
        """Test complete IKpsk2 handshake with known responder."""
        psk = os.urandom(32)
        
        # Responder generates keys first
        temp = NoiseHandshake("Noise_IKpsk2_25519_ChaChaPoly_SHA256")
        temp.generate_static_keypair()
        resp_private = temp.static_private
        resp_public = temp.static_public
        
        # Initiator
        initiator = NoiseHandshake("Noise_IKpsk2_25519_ChaChaPoly_SHA256")
        initiator.set_as_initiator()
        initiator.generate_static_keypair()
        initiator.set_remote_static_public_key(resp_public)
        initiator.set_psk(psk)
        initiator.initialize()
        
        # Responder
        responder = NoiseHandshake("Noise_IKpsk2_25519_ChaChaPoly_SHA256")
        responder.set_as_responder()
        responder.set_static_keypair(resp_private, resp_public)
        responder.set_psk(psk)
        responder.initialize()
        
        # Handshake
        msg1 = initiator.write_message(b"Hello")
        payload1 = responder.read_message(msg1)
        assert payload1 == b"Hello"
        
        msg2 = responder.write_message(b"World")
        payload2 = initiator.read_message(msg2)
        assert payload2 == b"World"
        
        assert initiator.handshake_complete
        assert responder.handshake_complete
    
    def test_psk_mismatch_fails(self):
        """Test that mismatched PSKs cause authentication failure."""
        psk1 = os.urandom(32)
        psk2 = os.urandom(32)
        
        # Initiator with PSK1
        initiator = NoiseHandshake("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        initiator.set_as_initiator()
        initiator.set_psk(psk1)
        initiator.initialize()
        
        # Responder with PSK2 (different!)
        responder = NoiseHandshake("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        responder.set_as_responder()
        responder.set_psk(psk2)
        responder.initialize()
        
        # Handshake should fail on second message
        msg1 = initiator.write_message(b"")
        responder.read_message(msg1)
        
        msg2 = responder.write_message(b"")
        
        # Authentication should fail when initiator tries to read
        with pytest.raises(Exception):  # AuthenticationError or similar
            initiator.read_message(msg2)


class TestPSKTransport:
    """Test transport mode after PSK handshake."""
    
    def test_transport_encryption_after_psk(self):
        """Test encrypted transport after PSK handshake."""
        psk = os.urandom(32)
        
        # Complete handshake
        initiator = NoiseHandshake("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        initiator.set_as_initiator()
        initiator.set_psk(psk)
        initiator.initialize()
        
        responder = NoiseHandshake("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        responder.set_as_responder()
        responder.set_psk(psk)
        responder.initialize()
        
        msg1 = initiator.write_message(b"")
        responder.read_message(msg1)
        
        msg2 = responder.write_message(b"")
        initiator.read_message(msg2)
        
        # Create transports
        init_send, init_recv = initiator.to_transport()
        resp_send, resp_recv = responder.to_transport()
        
        init_transport = NoiseTransport(init_send, init_recv)
        resp_transport = NoiseTransport(resp_send, resp_recv)
        
        # Test encryption
        plaintext = b"Secret message after PSK handshake"
        ciphertext = init_transport.send(plaintext)
        received = resp_transport.receive(ciphertext)
        assert received == plaintext
        
        # Test reverse direction
        plaintext2 = b"Reply message"
        ciphertext2 = resp_transport.send(plaintext2)
        received2 = init_transport.receive(ciphertext2)
        assert received2 == plaintext2
    
    def test_multiple_messages_after_psk(self):
        """Test multiple message exchange after PSK handshake."""
        psk = os.urandom(32)
        
        # Complete handshake
        initiator = NoiseHandshake("Noise_XXpsk3_25519_ChaChaPoly_SHA256")
        initiator.set_as_initiator()
        initiator.generate_static_keypair()
        initiator.set_psk(psk)
        initiator.initialize()
        
        responder = NoiseHandshake("Noise_XXpsk3_25519_ChaChaPoly_SHA256")
        responder.set_as_responder()
        responder.generate_static_keypair()
        responder.set_psk(psk)
        responder.initialize()
        
        # Handshake
        msg1 = initiator.write_message(b"")
        responder.read_message(msg1)
        msg2 = responder.write_message(b"")
        initiator.read_message(msg2)
        msg3 = initiator.write_message(b"")
        responder.read_message(msg3)
        
        # Create transports
        init_send, init_recv = initiator.to_transport()
        resp_send, resp_recv = responder.to_transport()
        
        init_transport = NoiseTransport(init_send, init_recv)
        resp_transport = NoiseTransport(resp_send, resp_recv)
        
        # Send multiple messages
        for i in range(10):
            msg = f"Message {i}".encode()
            ct = init_transport.send(msg)
            pt = resp_transport.receive(ct)
            assert pt == msg


class TestPSKPayloads:
    """Test payloads in PSK handshake messages."""
    
    def test_payload_in_psk_handshake(self):
        """Test sending payloads during PSK handshake."""
        psk = os.urandom(32)
        
        # Initiator
        initiator = NoiseHandshake("Noise_XXpsk3_25519_ChaChaPoly_SHA256")
        initiator.set_as_initiator()
        initiator.generate_static_keypair()
        initiator.set_psk(psk)
        initiator.initialize()
        
        # Responder
        responder = NoiseHandshake("Noise_XXpsk3_25519_ChaChaPoly_SHA256")
        responder.set_as_responder()
        responder.generate_static_keypair()
        responder.set_psk(psk)
        responder.initialize()
        
        # Handshake with payloads
        msg1 = initiator.write_message(b"Init payload")
        payload1 = responder.read_message(msg1)
        assert payload1 == b"Init payload"
        
        msg2 = responder.write_message(b"Resp payload")
        payload2 = initiator.read_message(msg2)
        assert payload2 == b"Resp payload"
        
        msg3 = initiator.write_message(b"Final payload")
        payload3 = responder.read_message(msg3)
        assert payload3 == b"Final payload"
        
        assert initiator.handshake_complete
        assert responder.handshake_complete
