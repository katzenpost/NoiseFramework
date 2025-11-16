"""Tests for transport layer."""

import pytest
from noiseframework.noise.handshake import NoiseHandshake
from noiseframework.transport.transport import NoiseTransport


class TestNoiseTransport:
    """Test NoiseTransport functionality."""

    def setup_method(self) -> None:
        """Set up a completed handshake for transport testing."""
        # Complete NN handshake
        self.init = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        self.init.set_as_initiator()
        self.init.initialize()

        self.resp = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
        self.resp.set_as_responder()
        self.resp.initialize()

        # Exchange handshake messages
        msg1 = self.init.write_message()
        self.resp.read_message(msg1)

        msg2 = self.resp.write_message()
        self.init.read_message(msg2)

        # Get transport ciphers
        init_send, init_recv = self.init.to_transport()
        resp_send, resp_recv = self.resp.to_transport()

        # Create transport objects
        self.init_transport = NoiseTransport(init_send, init_recv)
        self.resp_transport = NoiseTransport(resp_send, resp_recv)

    def test_transport_init(self) -> None:
        """Test transport initialization."""
        assert self.init_transport.send_cipher is not None
        assert self.init_transport.receive_cipher is not None
        assert self.resp_transport.send_cipher is not None
        assert self.resp_transport.receive_cipher is not None

    def test_send_receive_initiator_to_responder(self) -> None:
        """Test sending from initiator to responder."""
        plaintext = b"Hello from initiator"

        ciphertext = self.init_transport.send(plaintext)
        decrypted = self.resp_transport.receive(ciphertext)

        assert decrypted == plaintext

    def test_send_receive_responder_to_initiator(self) -> None:
        """Test sending from responder to initiator."""
        plaintext = b"Hello from responder"

        ciphertext = self.resp_transport.send(plaintext)
        decrypted = self.init_transport.receive(ciphertext)

        assert decrypted == plaintext

    def test_bidirectional_communication(self) -> None:
        """Test bidirectional message exchange."""
        # Initiator -> Responder
        msg1 = b"Message 1"
        ct1 = self.init_transport.send(msg1)
        pt1 = self.resp_transport.receive(ct1)
        assert pt1 == msg1

        # Responder -> Initiator
        msg2 = b"Message 2"
        ct2 = self.resp_transport.send(msg2)
        pt2 = self.init_transport.receive(ct2)
        assert pt2 == msg2

        # Initiator -> Responder again
        msg3 = b"Message 3"
        ct3 = self.init_transport.send(msg3)
        pt3 = self.resp_transport.receive(ct3)
        assert pt3 == msg3

    def test_send_with_associated_data(self) -> None:
        """Test sending with associated data."""
        plaintext = b"secret message"
        ad = b"metadata"

        ciphertext = self.init_transport.send(plaintext, ad)
        decrypted = self.resp_transport.receive(ciphertext, ad)

        assert decrypted == plaintext

    def test_wrong_associated_data_fails(self) -> None:
        """Test that wrong associated data fails authentication."""
        plaintext = b"secret message"
        ad = b"correct metadata"

        ciphertext = self.init_transport.send(plaintext, ad)

        # Try to decrypt with wrong AD
        with pytest.raises(ValueError, match="Decryption failed"):
            self.resp_transport.receive(ciphertext, b"wrong metadata")

    def test_tampered_ciphertext_fails(self) -> None:
        """Test that tampered ciphertext fails authentication."""
        plaintext = b"original message"

        ciphertext = self.init_transport.send(plaintext)

        # Tamper with ciphertext
        tampered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

        with pytest.raises(ValueError, match="Decryption failed"):
            self.resp_transport.receive(tampered)

    def test_nonce_increments(self) -> None:
        """Test that nonces increment with each message."""
        assert self.init_transport.get_send_nonce() == 0
        assert self.resp_transport.get_receive_nonce() == 0

        # Send first message
        self.init_transport.send(b"msg1")
        assert self.init_transport.get_send_nonce() == 1

        # Send second message
        self.init_transport.send(b"msg2")
        assert self.init_transport.get_send_nonce() == 2

    def test_multiple_messages(self) -> None:
        """Test sending multiple messages in sequence."""
        messages = [b"Message 1", b"Message 2", b"Message 3", b"Message 4", b"Message 5"]

        for msg in messages:
            ct = self.init_transport.send(msg)
            pt = self.resp_transport.receive(ct)
            assert pt == msg

    def test_large_message(self) -> None:
        """Test sending a large message."""
        plaintext = b"X" * 10000

        ciphertext = self.init_transport.send(plaintext)
        decrypted = self.resp_transport.receive(ciphertext)

        assert decrypted == plaintext

    def test_empty_message(self) -> None:
        """Test sending an empty message."""
        plaintext = b""

        ciphertext = self.init_transport.send(plaintext)
        decrypted = self.resp_transport.receive(ciphertext)

        assert decrypted == plaintext


class TestTransportFromXXHandshake:
    """Test transport from XX handshake (with authentication)."""

    def test_xx_transport(self) -> None:
        """Test transport after XX handshake."""
        # Complete XX handshake
        init = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        init.set_as_initiator()
        init.generate_static_keypair()
        init.initialize()

        resp = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        resp.set_as_responder()
        resp.generate_static_keypair()
        resp.initialize()

        # Exchange handshake messages
        msg1 = init.write_message()
        resp.read_message(msg1)
        msg2 = resp.write_message()
        init.read_message(msg2)
        msg3 = init.write_message()
        resp.read_message(msg3)

        # Create transports
        init_send, init_recv = init.to_transport()
        resp_send, resp_recv = resp.to_transport()

        init_transport = NoiseTransport(init_send, init_recv)
        resp_transport = NoiseTransport(resp_send, resp_recv)

        # Test transport encryption
        plaintext = b"Authenticated transport message"
        ciphertext = init_transport.send(plaintext)
        decrypted = resp_transport.receive(ciphertext)

        assert decrypted == plaintext
