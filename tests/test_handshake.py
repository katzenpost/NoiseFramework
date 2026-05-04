"""Tests for Noise handshake state machine."""

import pytest
from noiseframework.exceptions import (
    AuthenticationError, CryptoError, InvalidKeySizeError,
    UnsupportedPrimitiveError, UnsupportedPatternError,
    ValidationError, RoleNotSetError, RoleAlreadySetError,
    WrongTurnError, HandshakeCompleteError, MissingKeyError,
    NoKeySetError, NonceOverflowError
)
from noiseframework.noise.handshake import NoiseHandshake, Role


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
        with pytest.raises((RoleNotSetError, RoleAlreadySetError, WrongTurnError, HandshakeCompleteError, ValidationError, UnsupportedPatternError, MissingKeyError, NoKeySetError, InvalidKeySizeError)):
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

        with pytest.raises(RoleAlreadySetError):
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

        with pytest.raises(ValidationError):
            hs.set_static_keypair(b"short", b"P" * 32)

        with pytest.raises(ValidationError):
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

        with pytest.raises(ValidationError):
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


class TestNoiseHandshakeNK1:
    """Test NK1 deferred pattern.

    NK1 is the deferred variant of NK: the responder's static-key DH
    (``es``) is moved out of the initiator's first message and into
    the responder's reply. This avoids the 0-RTT replay caveat of NK
    at the cost of one round trip for the static authentication.
    """

    def test_nk1_handshake_complete(self) -> None:
        """Run a full NK1 handshake to completion."""
        resp = NoiseHandshake("Noise_NK1_25519_ChaChaPoly_SHA256")
        resp.set_as_responder()
        resp.generate_static_keypair()

        init = NoiseHandshake("Noise_NK1_25519_ChaChaPoly_SHA256")
        init.set_as_initiator()
        init.set_remote_static_public_key(resp.static_public)  # type: ignore
        init.initialize()
        resp.initialize()

        # Message 1: -> e   (deferred: no static-key DH yet)
        msg1 = init.write_message()
        resp.read_message(msg1)

        # Message 2: <- e, ee, es
        msg2 = resp.write_message()
        init.read_message(msg2)

        assert init.handshake_complete
        assert resp.handshake_complete

    def test_nk1_first_message_shorter_than_nk(self) -> None:
        """Pin the deferred-message structure on the wire.

        The initiator's first message in NK1 carries only the raw
        ephemeral key (32 bytes for X25519). NK's first message also
        carries an encrypted-and-tagged payload (16 bytes of AEAD tag
        even for an empty payload), so NK's first message is longer.
        """
        # NK1 first message
        resp1 = NoiseHandshake("Noise_NK1_25519_ChaChaPoly_SHA256")
        resp1.set_as_responder()
        resp1.generate_static_keypair()
        init1 = NoiseHandshake("Noise_NK1_25519_ChaChaPoly_SHA256")
        init1.set_as_initiator()
        init1.set_remote_static_public_key(resp1.static_public)  # type: ignore
        init1.initialize()
        nk1_msg1 = init1.write_message()

        # NK first message
        resp = NoiseHandshake("Noise_NK_25519_ChaChaPoly_SHA256")
        resp.set_as_responder()
        resp.generate_static_keypair()
        init = NoiseHandshake("Noise_NK_25519_ChaChaPoly_SHA256")
        init.set_as_initiator()
        init.set_remote_static_public_key(resp.static_public)  # type: ignore
        init.initialize()
        nk_msg1 = init.write_message()

        assert len(nk1_msg1) == 32  # raw ephemeral, no encrypted payload yet
        assert len(nk_msg1) == 32 + 16  # ephemeral plus AEAD tag for empty payload
        assert len(nk1_msg1) < len(nk_msg1)

    def test_nk1_payload_round_trip(self) -> None:
        """Confirm payloads round-trip through both NK1 messages."""
        resp = NoiseHandshake("Noise_NK1_25519_ChaChaPoly_SHA256")
        resp.set_as_responder()
        resp.generate_static_keypair()
        init = NoiseHandshake("Noise_NK1_25519_ChaChaPoly_SHA256")
        init.set_as_initiator()
        init.set_remote_static_public_key(resp.static_public)  # type: ignore
        init.initialize()
        resp.initialize()

        # First message has no key yet (the responder's static is
        # known but the ``es`` happens in message 2), so the payload
        # is sent in the clear. Pass empty for clarity.
        msg1 = init.write_message(b"")
        assert resp.read_message(msg1) == b""

        # Second message rides under the just-derived transport-grade
        # key, so payloads are encrypted.
        msg2 = resp.write_message(b"hello from responder")
        assert init.read_message(msg2) == b"hello from responder"


class TestNoiseHandshakeNK1Hybrid:
    """Test the target Pigeonhole-over-Reticulum protocol.

    Exercises ``Noise_NK1_Hybrid25519CTIDH1024_ChaChaPoly_BLAKE2s``:
    NK1 deferred handshake over the X25519 + CTIDH1024 hybrid NIKE,
    ChaCha20-Poly1305 AEAD, BLAKE2s hash.
    """

    PROTOCOL = "Noise_NK1_Hybrid25519CTIDH1024_ChaChaPoly_BLAKE2s"

    def test_handshake_complete(self) -> None:
        """Run the full target handshake to completion."""
        resp = NoiseHandshake(self.PROTOCOL)
        resp.set_as_responder()
        resp.generate_static_keypair()

        init = NoiseHandshake(self.PROTOCOL)
        init.set_as_initiator()
        init.set_remote_static_public_key(resp.static_public)  # type: ignore
        init.initialize()
        resp.initialize()

        # Message 1: -> e   (160 B raw hybrid ephemeral pubkey)
        msg1 = init.write_message()
        assert len(msg1) == 160
        resp.read_message(msg1)

        # Message 2: <- e, ee, es
        msg2 = resp.write_message()
        init.read_message(msg2)

        assert init.handshake_complete
        assert resp.handshake_complete

    def test_transport_round_trip(self) -> None:
        """Confirm transport ciphers established by the handshake work."""
        resp = NoiseHandshake(self.PROTOCOL)
        resp.set_as_responder()
        resp.generate_static_keypair()
        init = NoiseHandshake(self.PROTOCOL)
        init.set_as_initiator()
        init.set_remote_static_public_key(resp.static_public)  # type: ignore
        init.initialize()
        resp.initialize()

        # Drive the two-message NK1 handshake to completion.
        resp.read_message(init.write_message(b""))
        init.read_message(resp.write_message(b""))

        init_send, init_recv = init.to_transport()
        resp_send, resp_recv = resp.to_transport()

        # Initiator -> responder
        ct = init_send.encrypt_with_ad(b"", b"hello, sir")
        assert resp_recv.decrypt_with_ad(b"", ct) == b"hello, sir"

        # Responder -> initiator
        ct2 = resp_send.encrypt_with_ad(b"", b"good evening")
        assert init_recv.decrypt_with_ad(b"", ct2) == b"good evening"


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

        with pytest.raises(RoleNotSetError):
            hs.write_message()

    def test_read_before_role_set(self) -> None:
        """Test that reading without role raises error."""
        hs = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")

        with pytest.raises(RoleNotSetError):
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
        with pytest.raises(WrongTurnError):
            resp.write_message()

    def test_read_when_not_our_turn(self) -> None:
        """Test that reading out of turn raises error."""
        init = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        init.set_as_initiator()
        init.initialize()

        # Initiator tries to read first
        with pytest.raises(WrongTurnError):
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
        with pytest.raises(HandshakeCompleteError):
            init.write_message()

    def test_to_transport_before_complete(self) -> None:
        """Test that to_transport before complete raises error."""
        hs = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        hs.set_as_initiator()
        hs.initialize()

        with pytest.raises(HandshakeCompleteError):
            hs.to_transport()

    def test_get_handshake_hash_before_complete(self) -> None:
        """Test that getting hash before complete raises error."""
        hs = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        hs.set_as_initiator()
        hs.initialize()

        with pytest.raises(HandshakeCompleteError):
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


