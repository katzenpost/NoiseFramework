"""Tests for symmetric state and cipher state."""

import pytest
from noiseframework.exceptions import (
    AuthenticationError, CryptoError, InvalidKeySizeError,
    UnsupportedPrimitiveError, UnsupportedPatternError,
    ValidationError, RoleNotSetError, RoleAlreadySetError,
    WrongTurnError, HandshakeCompleteError, MissingKeyError,
    NoKeySetError, NonceOverflowError
)
from noiseframework.noise.state import CipherState, SymmetricState
from noiseframework.crypto.cipher import ChaChaPoly
from noiseframework.crypto.hash import SHA256


class TestCipherState:
    """Test CipherState functionality."""

    def test_init(self) -> None:
        """Test CipherState initialization."""
        cipher = ChaChaPoly()
        cs = CipherState(cipher)

        assert cs.cipher is cipher
        assert cs.key is None
        assert cs.nonce == 0
        assert not cs.has_key()

    def test_initialize_key(self) -> None:
        """Test setting encryption key."""
        cs = CipherState(ChaChaPoly())
        key = b"0" * 32

        cs.initialize_key(key)

        assert cs.key == key
        assert cs.nonce == 0
        assert cs.has_key()

    def test_initialize_key_invalid_size(self) -> None:
        """Test that invalid key size raises error."""
        cs = CipherState(ChaChaPoly())

        with pytest.raises(InvalidKeySizeError):
            cs.initialize_key(b"short")

    def test_encrypt_decrypt_round_trip(self) -> None:
        """Test encryption and decryption."""
        cs_enc = CipherState(ChaChaPoly())
        cs_dec = CipherState(ChaChaPoly())

        key = b"1" * 32
        cs_enc.initialize_key(key)
        cs_dec.initialize_key(key)

        plaintext = b"test message"
        ad = b"associated data"

        ciphertext = cs_enc.encrypt_with_ad(ad, plaintext)
        decrypted = cs_dec.decrypt_with_ad(ad, ciphertext)

        assert decrypted == plaintext

    def test_nonce_increments(self) -> None:
        """Test that nonce increments after each operation."""
        cs = CipherState(ChaChaPoly())
        cs.initialize_key(b"2" * 32)

        assert cs.nonce == 0

        cs.encrypt_with_ad(b"", b"msg1")
        assert cs.nonce == 1

        cs.encrypt_with_ad(b"", b"msg2")
        assert cs.nonce == 2

    def test_encrypt_without_key_raises_error(self) -> None:
        """Test that encrypting without a key raises error."""
        cs = CipherState(ChaChaPoly())

        with pytest.raises(NoKeySetError):
            cs.encrypt_with_ad(b"", b"data")

    def test_decrypt_without_key_raises_error(self) -> None:
        """Test that decrypting without a key raises error."""
        cs = CipherState(ChaChaPoly())

        with pytest.raises(NoKeySetError):
            cs.decrypt_with_ad(b"", b"data")

    def test_rekey_not_implemented(self) -> None:
        """Test that rekey raises NotImplementedError."""
        cs = CipherState(ChaChaPoly())
        cs.initialize_key(b"3" * 32)

        with pytest.raises(NotImplementedError):
            cs.rekey()


class TestSymmetricState:
    """Test SymmetricState functionality."""

    def test_init(self) -> None:
        """Test SymmetricState initialization."""
        hash_func = SHA256()
        cipher = ChaChaPoly()
        ss = SymmetricState(hash_func, cipher)

        assert ss.hash_func is hash_func
        assert ss.cipher_state.cipher is cipher
        assert ss.chaining_key == b""
        assert ss.h == b""

    def test_initialize_symmetric_short_name(self) -> None:
        """Test initialization with short protocol name."""
        ss = SymmetricState(SHA256(), ChaChaPoly())
        protocol_name = b"Noise"

        ss.initialize_symmetric(protocol_name)

        # Should be padded to hashlen (32 for SHA256)
        assert len(ss.h) == 32
        assert ss.h.startswith(protocol_name)
        assert ss.chaining_key == ss.h

    def test_initialize_symmetric_long_name(self) -> None:
        """Test initialization with long protocol name."""
        ss = SymmetricState(SHA256(), ChaChaPoly())
        protocol_name = b"Very_Long_Protocol_Name_That_Exceeds_Hash_Length"

        ss.initialize_symmetric(protocol_name)

        # Should be hashed
        assert len(ss.h) == 32
        assert ss.chaining_key == ss.h

    def test_mix_hash(self) -> None:
        """Test mixing data into hash."""
        ss = SymmetricState(SHA256(), ChaChaPoly())
        ss.initialize_symmetric(b"Noise")

        initial_h = ss.h
        ss.mix_hash(b"test data")

        assert ss.h != initial_h
        assert len(ss.h) == 32

    def test_mix_key(self) -> None:
        """Test mixing key material."""
        ss = SymmetricState(SHA256(), ChaChaPoly())
        ss.initialize_symmetric(b"Noise")

        initial_ck = ss.chaining_key
        assert not ss.cipher_state.has_key()

        ss.mix_key(b"key material" * 3)

        assert ss.chaining_key != initial_ck
        assert ss.cipher_state.has_key()

    def test_mix_key_and_hash(self) -> None:
        """Test mixing key into both chaining key and hash."""
        ss = SymmetricState(SHA256(), ChaChaPoly())
        ss.initialize_symmetric(b"Noise")

        initial_ck = ss.chaining_key
        initial_h = ss.h

        ss.mix_key_and_hash(b"psk material" * 3)

        assert ss.chaining_key != initial_ck
        assert ss.h != initial_h
        assert ss.cipher_state.has_key()

    def test_get_handshake_hash(self) -> None:
        """Test getting handshake hash."""
        ss = SymmetricState(SHA256(), ChaChaPoly())
        ss.initialize_symmetric(b"Noise")

        h = ss.get_handshake_hash()
        assert h == ss.h
        assert len(h) == 32

    def test_encrypt_and_hash_without_key(self) -> None:
        """Test encrypt_and_hash returns plaintext when no key is set."""
        ss = SymmetricState(SHA256(), ChaChaPoly())
        ss.initialize_symmetric(b"Noise")

        plaintext = b"test message"
        initial_h = ss.h

        result = ss.encrypt_and_hash(plaintext)

        # Should return plaintext unchanged
        assert result == plaintext
        # Hash should be updated
        assert ss.h != initial_h

    def test_encrypt_and_hash_with_key(self) -> None:
        """Test encrypt_and_hash encrypts when key is set."""
        ss = SymmetricState(SHA256(), ChaChaPoly())
        ss.initialize_symmetric(b"Noise")
        ss.mix_key(b"key material" * 3)

        plaintext = b"secret message"

        ciphertext = ss.encrypt_and_hash(plaintext)

        # Should be encrypted (different from plaintext)
        assert ciphertext != plaintext
        # Should include tag (16 bytes)
        assert len(ciphertext) == len(plaintext) + 16

    def test_decrypt_and_hash_without_key(self) -> None:
        """Test decrypt_and_hash returns ciphertext when no key is set."""
        ss = SymmetricState(SHA256(), ChaChaPoly())
        ss.initialize_symmetric(b"Noise")

        data = b"test message"

        result = ss.decrypt_and_hash(data)

        # Should return data unchanged
        assert result == data

    def test_decrypt_and_hash_with_key(self) -> None:
        """Test decrypt_and_hash decrypts when key is set."""
        # Encrypt with one state
        ss_enc = SymmetricState(SHA256(), ChaChaPoly())
        ss_enc.initialize_symmetric(b"Noise")
        ss_enc.mix_key(b"shared key" * 3)

        plaintext = b"secret message"
        ciphertext = ss_enc.encrypt_and_hash(plaintext)

        # Decrypt with another state (same setup)
        ss_dec = SymmetricState(SHA256(), ChaChaPoly())
        ss_dec.initialize_symmetric(b"Noise")
        ss_dec.mix_key(b"shared key" * 3)

        decrypted = ss_dec.decrypt_and_hash(ciphertext)

        assert decrypted == plaintext

    def test_split(self) -> None:
        """Test splitting into transport cipher states."""
        ss = SymmetricState(SHA256(), ChaChaPoly())
        ss.initialize_symmetric(b"Noise")
        ss.mix_key(b"final key material" * 3)

        c1, c2 = ss.split()

        assert c1.has_key()
        assert c2.has_key()
        assert c1.key != c2.key
        assert c1.nonce == 0
        assert c2.nonce == 0

    def test_split_transport_encryption(self) -> None:
        """Test that split ciphers can encrypt/decrypt."""
        ss1 = SymmetricState(SHA256(), ChaChaPoly())
        ss1.initialize_symmetric(b"Noise")
        ss1.mix_key(b"shared secret" * 3)

        ss2 = SymmetricState(SHA256(), ChaChaPoly())
        ss2.initialize_symmetric(b"Noise")
        ss2.mix_key(b"shared secret" * 3)

        # Split both states - note: in Noise, initiator and responder swap c1/c2
        # Initiator uses c1 for sending, c2 for receiving
        # Responder uses c2 for sending, c1 for receiving
        c1_init, c2_init = ss1.split()
        c1_resp, c2_resp = ss2.split()

        # Initiator sends with c1, responder receives with c1
        plaintext = b"transport message"
        ciphertext = c1_init.encrypt_with_ad(b"", plaintext)
        decrypted = c1_resp.decrypt_with_ad(b"", ciphertext)
        assert decrypted == plaintext

        # Responder sends with c2, initiator receives with c2
        plaintext2 = b"response message"
        ciphertext2 = c2_resp.encrypt_with_ad(b"", plaintext2)
        decrypted2 = c2_init.decrypt_with_ad(b"", ciphertext2)
        assert decrypted2 == plaintext2


class TestSymmetricStateIntegration:
    """Integration tests for SymmetricState."""

    def test_full_handshake_flow(self) -> None:
        """Test a simplified handshake flow."""
        # Initialize both sides
        initiator = SymmetricState(SHA256(), ChaChaPoly())
        responder = SymmetricState(SHA256(), ChaChaPoly())

        protocol = b"Noise_XX_25519_ChaChaPoly_SHA256"
        initiator.initialize_symmetric(protocol)
        responder.initialize_symmetric(protocol)

        # Message 1: e
        dh_output1 = b"dh_result_1" * 3
        initiator.mix_hash(b"ephemeral_public_key")
        responder.mix_hash(b"ephemeral_public_key")

        # Message 2: e, ee
        dh_output2 = b"dh_result_2" * 3
        responder.mix_hash(b"responder_ephemeral")
        initiator.mix_hash(b"responder_ephemeral")

        responder.mix_key(dh_output2)
        initiator.mix_key(dh_output2)

        # Both should have same state
        assert initiator.h == responder.h
        assert initiator.chaining_key == responder.chaining_key

        # Split for transport - both sides get same c1, c2
        c1_init, c2_init = initiator.split()
        c1_resp, c2_resp = responder.split()

        # Test transport encryption: initiator sends with c1, responder receives with c1
        msg = b"Hello, Noise!"
        ct = c1_init.encrypt_with_ad(b"", msg)
        pt = c1_resp.decrypt_with_ad(b"", ct)
        assert pt == msg
