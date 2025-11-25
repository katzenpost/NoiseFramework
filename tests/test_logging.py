"""
Tests for logging functionality in NoiseFramework.

Verifies that appropriate log messages are generated at correct levels
for handshake and transport operations.
"""

import logging
from unittest.mock import Mock, call
import pytest
from noiseframework.exceptions import (
    AuthenticationError, CryptoError, InvalidKeySizeError,
    UnsupportedPrimitiveError, UnsupportedPatternError,
    ValidationError, RoleNotSetError, RoleAlreadySetError,
    WrongTurnError, HandshakeCompleteError, MissingKeyError,
    NoKeySetError, NonceOverflowError
)

from noiseframework import NoiseHandshake, NoiseTransport
from noiseframework.noise.state import CipherState, SymmetricState
from noiseframework.crypto.cipher import ChaChaPoly
from noiseframework.crypto.hash import SHA256


class TestHandshakeLogging:
    """Test logging in NoiseHandshake class."""

    def test_default_logger_creation(self):
        """Test that default logger is created correctly."""
        handshake = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        assert handshake.logger is not None
        assert handshake.logger.name == "noiseframework.noise.handshake.NoiseHandshake"

    def test_custom_logger(self):
        """Test that custom logger is used when provided."""
        custom_logger = logging.getLogger("test.custom")
        handshake = NoiseHandshake(
            "Noise_NN_25519_ChaChaPoly_SHA256",
            logger=custom_logger
        )
        assert handshake.logger is custom_logger

    def test_role_setting_logs(self, caplog):
        """Test that role setting generates appropriate logs."""
        handshake = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        
        with caplog.at_level(logging.INFO):
            handshake.set_as_initiator()
        
        assert "Role set as INITIATOR" in caplog.text
        
        caplog.clear()
        
        # Test error when trying to set role again
        with caplog.at_level(logging.ERROR):
            with pytest.raises((RoleNotSetError, RoleAlreadySetError, WrongTurnError, HandshakeCompleteError, ValidationError, UnsupportedPatternError, MissingKeyError, NoKeySetError, InvalidKeySizeError)):
                handshake.set_as_responder()
        
        assert "Attempted to set role as RESPONDER when already set" in caplog.text

    def test_key_generation_logs(self, caplog):
        """Test that key generation logs at appropriate levels."""
        handshake = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        handshake.set_as_initiator()
        
        with caplog.at_level(logging.DEBUG):
            handshake.generate_static_keypair()
        
        assert "Generating static keypair" in caplog.text
        assert "Static keypair generated" in caplog.text

    def test_initialization_logs(self, caplog):
        """Test that initialization generates appropriate logs."""
        handshake = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        handshake.set_as_initiator()
        
        with caplog.at_level(logging.DEBUG):
            handshake.initialize()
        
        assert "Handshake initialized" in caplog.text

    def test_write_message_logs(self, caplog):
        """Test that write_message generates appropriate logs."""
        initiator = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        initiator.set_as_initiator()
        initiator.initialize()
        
        with caplog.at_level(logging.DEBUG):
            msg = initiator.write_message(b"test")
        
        assert "Writing handshake message" in caplog.text
        assert "Sent handshake message" in caplog.text
        assert "Processing tokens" in caplog.text

    def test_read_message_logs(self, caplog):
        """Test that read_message generates appropriate logs."""
        initiator = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        responder = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        
        initiator.set_as_initiator()
        responder.set_as_responder()
        
        initiator.initialize()
        responder.initialize()
        
        msg = initiator.write_message(b"test")
        
        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            responder.read_message(msg)
        
        assert "Reading handshake message" in caplog.text
        assert "Received handshake message" in caplog.text
        assert "Processing tokens" in caplog.text

    def test_handshake_complete_log(self, caplog):
        """Test that handshake completion is logged."""
        initiator = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        responder = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        
        initiator.set_as_initiator()
        responder.set_as_responder()
        
        initiator.initialize()
        responder.initialize()
        
        msg1 = initiator.write_message(b"")
        responder.read_message(msg1)
        
        caplog.clear()
        with caplog.at_level(logging.INFO):
            msg2 = responder.write_message(b"")
        
        assert "Handshake complete" in caplog.text

    def test_to_transport_logs(self, caplog):
        """Test that transport creation logs appropriately."""
        initiator = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        responder = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        
        initiator.set_as_initiator()
        responder.set_as_responder()
        
        initiator.initialize()
        responder.initialize()
        
        msg1 = initiator.write_message(b"")
        responder.read_message(msg1)
        
        msg2 = responder.write_message(b"")
        initiator.read_message(msg2)
        
        caplog.clear()
        with caplog.at_level(logging.INFO):
            initiator.to_transport()
        
        assert "Created transport ciphers" in caplog.text
        assert "initiator" in caplog.text

    def test_error_logs(self, caplog):
        """Test that errors are logged appropriately."""
        handshake = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        
        # Test writing without role
        with caplog.at_level(logging.ERROR):
            with pytest.raises((RoleNotSetError, RoleAlreadySetError, WrongTurnError, HandshakeCompleteError, ValidationError, UnsupportedPatternError, MissingKeyError, NoKeySetError, InvalidKeySizeError)):
                handshake.write_message(b"test")
        
        assert "Attempted to write message without setting role" in caplog.text
        
        caplog.clear()
        
        # Test to_transport before completion
        handshake.set_as_initiator()
        handshake.initialize()
        
        with caplog.at_level(logging.ERROR):
            with pytest.raises((RoleNotSetError, RoleAlreadySetError, WrongTurnError, HandshakeCompleteError, ValidationError, UnsupportedPatternError, MissingKeyError, NoKeySetError, InvalidKeySizeError)):
                handshake.to_transport()
        
        assert "Attempted to call to_transport before handshake completion" in caplog.text


class TestTransportLogging:
    """Test logging in NoiseTransport class."""

    def test_default_logger_creation(self):
        """Test that default logger is created correctly."""
        cipher = ChaChaPoly()
        send = CipherState(cipher)
        recv = CipherState(cipher)
        send.initialize_key(b"0" * 32)
        recv.initialize_key(b"1" * 32)
        
        transport = NoiseTransport(send, recv)
        assert transport.logger is not None
        assert transport.logger.name == "noiseframework.transport.transport.NoiseTransport"

    def test_custom_logger(self):
        """Test that custom logger is used when provided."""
        cipher = ChaChaPoly()
        send = CipherState(cipher)
        recv = CipherState(cipher)
        send.initialize_key(b"0" * 32)
        recv.initialize_key(b"1" * 32)
        
        custom_logger = logging.getLogger("test.custom")
        transport = NoiseTransport(send, recv, logger=custom_logger)
        assert transport.logger is custom_logger

    def test_send_logs(self, caplog):
        """Test that send operation generates appropriate logs."""
        cipher = ChaChaPoly()
        send = CipherState(cipher)
        recv = CipherState(cipher)
        send.initialize_key(b"0" * 32)
        recv.initialize_key(b"1" * 32)
        
        transport = NoiseTransport(send, recv)
        
        with caplog.at_level(logging.DEBUG):
            transport.send(b"Hello, World!")
        
        assert "Encrypting message" in caplog.text
        assert "Sent encrypted message" in caplog.text
        assert "nonce=" in caplog.text

    def test_receive_logs(self, caplog):
        """Test that receive operation generates appropriate logs."""
        cipher = ChaChaPoly()
        send = CipherState(cipher)
        recv = CipherState(cipher)
        send.initialize_key(b"0" * 32)
        recv.initialize_key(b"0" * 32)  # Same key for testing
        
        transport = NoiseTransport(send, recv)
        encrypted = transport.send(b"Test message")
        
        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            transport.receive(encrypted)
        
        assert "Decrypting message" in caplog.text
        assert "Received decrypted message" in caplog.text

    def test_nonce_warning(self, caplog):
        """Test that high nonce values trigger warnings."""
        cipher = ChaChaPoly()
        send = CipherState(cipher)
        recv = CipherState(cipher)
        send.initialize_key(b"0" * 32)
        recv.initialize_key(b"1" * 32)
        
        # Manually set high nonce
        send.nonce = 2**63
        
        transport = NoiseTransport(send, recv)
        
        with caplog.at_level(logging.WARNING):
            transport.send(b"test")
        
        assert "nonce high" in caplog.text
        assert "approaching 2^64 limit" in caplog.text


class TestStateLogging:
    """Test logging in state classes."""

    def test_cipher_state_logger(self):
        """Test CipherState logger creation."""
        cipher = ChaChaPoly()
        state = CipherState(cipher)
        assert state.logger is not None
        assert state.logger.name == "noiseframework.noise.state.CipherState"

    def test_symmetric_state_logger(self):
        """Test SymmetricState logger creation."""
        hash_func = SHA256()
        cipher = ChaChaPoly()
        state = SymmetricState(hash_func, cipher)
        assert state.logger is not None
        assert state.logger.name == "noiseframework.noise.state.SymmetricState"

    def test_key_mixing_logs(self, caplog):
        """Test that key mixing is logged."""
        hash_func = SHA256()
        cipher = ChaChaPoly()
        state = SymmetricState(hash_func, cipher)
        state.initialize_symmetric(b"test")
        
        with caplog.at_level(logging.DEBUG):
            state.mix_key(b"key_material" * 3)
        
        assert "Mixing key material" in caplog.text


class TestLogLevels:
    """Test that appropriate log levels are used."""

    def test_debug_level_detail(self, caplog):
        """Test that DEBUG level provides detailed information."""
        handshake = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        handshake.set_as_initiator()
        handshake.initialize()
        
        with caplog.at_level(logging.DEBUG):
            handshake.write_message(b"test")
        
        # DEBUG should include token details
        assert "Processing tokens" in caplog.text

    def test_info_level_operations(self, caplog):
        """Test that INFO level logs major operations."""
        handshake = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        
        with caplog.at_level(logging.INFO):
            handshake.set_as_initiator()
            handshake.initialize()
        
        assert "Role set" in caplog.text
        assert "Handshake initialized" in caplog.text

    def test_error_level_failures(self, caplog):
        """Test that ERROR level logs failures."""
        handshake = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        
        with caplog.at_level(logging.ERROR):
            with pytest.raises((RoleNotSetError, RoleAlreadySetError, WrongTurnError, HandshakeCompleteError, ValidationError, UnsupportedPatternError, MissingKeyError, NoKeySetError, InvalidKeySizeError)):
                handshake.initialize()  # No role set
        
        assert "ERROR" in caplog.text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
