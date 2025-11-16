"""Tests for Noise handshake state machine."""

import pytest
from py_noise.noise.handshake import NoiseHandshake, Role


class TestNoiseHandshakeInit:
    """Test NoiseHandshake initialization."""

    def test_init_valid_pattern(self) -> None:
        """Test initialization with valid pattern."""
        hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")

        assert hs.pattern.handshake_pattern == "XX"
        assert hs.pattern.dh_function == "25519"
        assert hs.pattern.cipher_function == "ChaChaPoly"
        assert hs.pattern.hash_function == "SHA256"
        assert hs.role is None
        assert not hs.handshake_complete
        assert hs.message_index == 0

    def test_init_invalid_pattern(self) -> None:
        """Test that invalid pattern raises error."""
        with pytest.raises(ValueError):
            NoiseHandshake("Invalid_Pattern")

    def test_set_as_initiator(self) -> None:
        """Test setting role as initiator."""
        hs = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        hs.set_as_initiator()

        assert hs.role == Role.INITIATOR

    def test_set_as_responder(self) -> None:
        """Test setting role as responder."""
        hs = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        hs.set_as_responder()

        assert hs.role == Role.RESPONDER

    def test_cannot_set_role_twice(self) -> None:
        """Test that role cannot be changed once set."""
        hs = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        hs.set_as_initiator()

        with pytest.raises(ValueError, match="Role already set"):
            hs.set_as_responder()

    def test_generate_static_keypair(self) -> None:
        """Test static key pair generation."""
        hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        hs.generate_static_keypair()

        assert hs.static_private is not None
        assert hs.static_public is not None
        assert len(hs.static_private) == 32
        assert len(hs.static_public) == 32

    def test_set_static_keypair(self) -> None:
        """Test setting static key pair."""
        hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        private = b"p" * 32
        public = b"P" * 32

        hs.set_static_keypair(private, public)

        assert hs.static_private == private
        assert hs.static_public == public

    def test_set_static_keypair_invalid_size(self) -> None:
        """Test that invalid key sizes raise error."""
        hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")

        with pytest.raises(ValueError, match="Private key must be 32 bytes"):
            hs.set_static_keypair(b"short", b"P" * 32)

        with pytest.raises(ValueError, match="Public key must be 32 bytes"):
            hs.set_static_keypair(b"p" * 32, b"short")

    def test_set_remote_static_public_key(self) -> None:
        """Test setting remote static public key."""
        hs = NoiseHandshake("Noise_NK_25519_ChaChaPoly_SHA256")
        remote_pub = b"R" * 32

        hs.set_remote_static_public_key(remote_pub)

        assert hs.remote_static_public == remote_pub

    def test_set_remote_static_invalid_size(self) -> None:
        """Test that invalid remote key size raises error."""
        hs = NoiseHandshake("Noise_NK_25519_ChaChaPoly_SHA256")

        with pytest.raises(ValueError, match="Public key must be 32 bytes"):
            hs.set_remote_static_public_key(b"short")


class TestNoiseHandshakeNN:
    """Test NN pattern (simplest: no static keys)."""

    def test_nn_handshake_complete(self) -> None:
        """Test complete NN handshake."""
        # Initiator
        init = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        init.set_as_initiator()
        init.initialize()

        # Responder
        resp = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        resp.set_as_responder()
        resp.initialize()

        # Message 1: -> e
        msg1 = init.write_message(b"init payload 1")
        assert len(msg1) > 32  # At least ephemeral key
        payload1 = resp.read_message(msg1)
        assert payload1 == b"init payload 1"

        # Message 2: <- e, ee
        msg2 = resp.write_message(b"resp payload 2")
        payload2 = init.read_message(msg2)
        assert payload2 == b"resp payload 2"

        # Both should have completed handshake
        assert init.handshake_complete
        assert resp.handshake_complete

    def test_nn_transport_encryption(self) -> None:
        """Test transport encryption after NN handshake."""
        # Complete handshake
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

        # Get transport ciphers
        init_send, init_recv = init.to_transport()
        resp_send, resp_recv = resp.to_transport()

        # Test encryption: initiator -> responder
        plaintext = b"Hello from initiator"
        ciphertext = init_send.encrypt_with_ad(b"", plaintext)
        decrypted = resp_recv.decrypt_with_ad(b"", ciphertext)
        assert decrypted == plaintext

        # Test encryption: responder -> initiator
        plaintext2 = b"Hello from responder"
        ciphertext2 = resp_send.encrypt_with_ad(b"", plaintext2)
        decrypted2 = init_recv.decrypt_with_ad(b"", ciphertext2)
        assert decrypted2 == plaintext2


class TestNoiseHandshakeXX:
    """Test XX pattern (mutual authentication)."""

    def test_xx_handshake_complete(self) -> None:
        """Test complete XX handshake."""
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

        # Message 1: -> e
        msg1 = init.write_message()
        resp.read_message(msg1)

        # Message 2: <- e, ee, s, es
        msg2 = resp.write_message()
        init.read_message(msg2)

        # Message 3: -> s, se
        msg3 = init.write_message()
        resp.read_message(msg3)

        # Both should have completed
        assert init.handshake_complete
        assert resp.handshake_complete

        # Both should have each other's static keys
        assert init.remote_static_public == resp.static_public
        assert resp.remote_static_public == init.static_public

    def test_xx_with_payloads(self) -> None:
        """Test XX handshake with payloads."""
        init = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        init.set_as_initiator()
        init.generate_static_keypair()
        init.initialize()

        resp = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        resp.set_as_responder()
        resp.generate_static_keypair()
        resp.initialize()

        # Exchange with payloads
        msg1 = init.write_message(b"Hello")
        p1 = resp.read_message(msg1)
        assert p1 == b"Hello"

        msg2 = resp.write_message(b"World")
        p2 = init.read_message(msg2)
        assert p2 == b"World"

        msg3 = init.write_message(b"Done")
        p3 = resp.read_message(msg3)
        assert p3 == b"Done"

        assert init.handshake_complete
        assert resp.handshake_complete


class TestNoiseHandshakeNK:
    """Test NK pattern (responder has known static key)."""

    def test_nk_handshake_complete(self) -> None:
        """Test complete NK handshake."""
        # Setup responder
        resp = NoiseHandshake("Noise_NK_25519_ChaChaPoly_SHA256")
        resp.set_as_responder()
        resp.generate_static_keypair()

        # Initiator knows responder's static key
        init = NoiseHandshake("Noise_NK_25519_ChaChaPoly_SHA256")
        init.set_as_initiator()
        init.set_remote_static_public_key(resp.static_public)  # type: ignore
        init.initialize()

        # Initialize responder
        resp.initialize()

        # Message 1: -> e, es
        msg1 = init.write_message()
        resp.read_message(msg1)

        # Message 2: <- e, ee
        msg2 = resp.write_message()
        init.read_message(msg2)

        assert init.handshake_complete
        assert resp.handshake_complete


class TestNoiseHandshakeIK:
    """Test IK pattern (responder known, initiator identity hidden)."""

    def test_ik_handshake_complete(self) -> None:
        """Test complete IK handshake."""
        # Setup responder with static key
        resp = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
        resp.set_as_responder()
        resp.generate_static_keypair()

        # Setup initiator with static key and knowing responder's key
        init = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
        init.set_as_initiator()
        init.generate_static_keypair()
        init.set_remote_static_public_key(resp.static_public)  # type: ignore
        init.initialize()

        # Initialize responder
        resp.initialize()

        # Message 1: -> e, es, s, ss
        msg1 = init.write_message()
        resp.read_message(msg1)

        # Message 2: <- e, ee, se
        msg2 = resp.write_message()
        init.read_message(msg2)

        assert init.handshake_complete
        assert resp.handshake_complete

        # Both should have each other's static keys
        assert init.remote_static_public == resp.static_public
        assert resp.remote_static_public == init.static_public


class TestNoiseHandshakeErrors:
    """Test error conditions."""

    def test_write_before_role_set(self) -> None:
        """Test that writing without role raises error."""
        hs = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")

        with pytest.raises(ValueError, match="Role not set"):
            hs.write_message()

    def test_read_before_role_set(self) -> None:
        """Test that reading without role raises error."""
        hs = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")

        with pytest.raises(ValueError, match="Role not set"):
            hs.read_message(b"test")

    def test_write_when_not_our_turn(self) -> None:
        """Test that writing out of turn raises error."""
        init = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        init.set_as_initiator()
        init.initialize()

        resp = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        resp.set_as_responder()
        resp.initialize()

        # Responder tries to send first
        with pytest.raises(ValueError, match="Not our turn"):
            resp.write_message()

    def test_read_when_not_our_turn(self) -> None:
        """Test that reading out of turn raises error."""
        init = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        init.set_as_initiator()
        init.initialize()

        # Initiator tries to read first
        with pytest.raises(ValueError, match="Not our turn"):
            init.read_message(b"test")

    def test_write_after_complete(self) -> None:
        """Test that writing after handshake complete raises error."""
        init = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        init.set_as_initiator()
        init.initialize()

        resp = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        resp.set_as_responder()
        resp.initialize()

        # Complete handshake
        msg1 = init.write_message()
        resp.read_message(msg1)
        msg2 = resp.write_message()
        init.read_message(msg2)

        # Try to write after complete
        with pytest.raises(ValueError, match="already complete"):
            init.write_message()

    def test_to_transport_before_complete(self) -> None:
        """Test that to_transport before complete raises error."""
        hs = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        hs.set_as_initiator()
        hs.initialize()

        with pytest.raises(ValueError, match="not yet complete"):
            hs.to_transport()

    def test_get_handshake_hash_before_complete(self) -> None:
        """Test that getting hash before complete raises error."""
        hs = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        hs.set_as_initiator()
        hs.initialize()

        with pytest.raises(ValueError, match="not yet complete"):
            hs.get_handshake_hash()

    def test_handshake_hash_same_both_sides(self) -> None:
        """Test that handshake hash matches on both sides."""
        init = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        init.set_as_initiator()
        init.generate_static_keypair()
        init.initialize()

        resp = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        resp.set_as_responder()
        resp.generate_static_keypair()
        resp.initialize()

        # Complete handshake
        msg1 = init.write_message()
        resp.read_message(msg1)
        msg2 = resp.write_message()
        init.read_message(msg2)
        msg3 = init.write_message()
        resp.read_message(msg3)

        # Handshake hashes should match
        init_hash = init.get_handshake_hash()
        resp_hash = resp.get_handshake_hash()
        assert init_hash == resp_hash


class TestMultiplePatterns:
    """Test various handshake patterns."""

    def test_kk_pattern(self) -> None:
        """Test KK pattern (both parties have known static keys)."""
        # Both generate keys and exchange beforehand
        init = NoiseHandshake("Noise_KK_25519_ChaChaPoly_SHA256")
        init.set_as_initiator()
        init.generate_static_keypair()

        resp = NoiseHandshake("Noise_KK_25519_ChaChaPoly_SHA256")
        resp.set_as_responder()
        resp.generate_static_keypair()

        # They know each other's static keys
        init.set_remote_static_public_key(resp.static_public)  # type: ignore
        resp.set_remote_static_public_key(init.static_public)  # type: ignore

        init.initialize()
        resp.initialize()

        # Perform handshake
        msg1 = init.write_message()
        resp.read_message(msg1)

        msg2 = resp.write_message()
        init.read_message(msg2)

        assert init.handshake_complete
        assert resp.handshake_complete

    def test_xk_pattern(self) -> None:
        """Test XK pattern."""
        # Responder with known static key
        resp = NoiseHandshake("Noise_XK_25519_ChaChaPoly_SHA256")
        resp.set_as_responder()
        resp.generate_static_keypair()

        # Initiator with static key, knows responder's key
        init = NoiseHandshake("Noise_XK_25519_ChaChaPoly_SHA256")
        init.set_as_initiator()
        init.generate_static_keypair()
        init.set_remote_static_public_key(resp.static_public)  # type: ignore

        init.initialize()
        resp.initialize()

        # Three-message handshake
        msg1 = init.write_message()
        resp.read_message(msg1)

        msg2 = resp.write_message()
        init.read_message(msg2)

        msg3 = init.write_message()
        resp.read_message(msg3)

        assert init.handshake_complete
        assert resp.handshake_complete
