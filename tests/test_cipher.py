"""Tests for AEAD cipher functions."""

import pytest
from noiseframework.crypto.cipher import ChaChaPoly, AESGCMCipher, get_cipher_function
from noiseframework.exceptions import AuthenticationError, CryptoError, InvalidKeySizeError, UnsupportedPrimitiveError


class TestChaChaPoly:
    """Test ChaCha20-Poly1305 cipher."""

    def test_init(self) -> None:
        """Test ChaChaPoly initialization."""
        cipher = ChaChaPoly()
        assert cipher.name == "ChaChaPoly"

    def test_encrypt_decrypt_round_trip(self) -> None:
        """Test encryption and decryption round trip."""
        cipher = ChaChaPoly()
        key = b"0" * 32
        nonce = 0
        ad = b"associated data"
        plaintext = b"Hello, Noise Protocol!"

        ciphertext = cipher.encrypt(key, nonce, ad, plaintext)
        decrypted = cipher.decrypt(key, nonce, ad, ciphertext)

        assert decrypted == plaintext

    def test_ciphertext_has_tag(self) -> None:
        """Test that ciphertext includes authentication tag."""
        cipher = ChaChaPoly()
        key = b"1" * 32
        nonce = 42
        plaintext = b"test"

        ciphertext = cipher.encrypt(key, nonce, b"", plaintext)

        # Ciphertext should be plaintext + 16 byte tag
        assert len(ciphertext) == len(plaintext) + 16

    def test_different_nonces_produce_different_ciphertexts(self) -> None:
        """Test that different nonces produce different ciphertexts."""
        cipher = ChaChaPoly()
        key = b"2" * 32
        plaintext = b"secret message"

        ct1 = cipher.encrypt(key, 0, b"", plaintext)
        ct2 = cipher.encrypt(key, 1, b"", plaintext)

        assert ct1 != ct2

    def test_authentication_with_ad(self) -> None:
        """Test authentication with associated data."""
        cipher = ChaChaPoly()
        key = b"3" * 32
        nonce = 100
        ad = b"metadata"
        plaintext = b"payload"

        ciphertext = cipher.encrypt(key, nonce, ad, plaintext)

        # Correct AD should decrypt successfully
        decrypted = cipher.decrypt(key, nonce, ad, ciphertext)
        assert decrypted == plaintext

        # Wrong AD should fail authentication
        with pytest.raises(AuthenticationError):
            cipher.decrypt(key, nonce, b"wrong", ciphertext)

    def test_tampered_ciphertext_fails(self) -> None:
        """Test that tampered ciphertext fails authentication."""
        cipher = ChaChaPoly()
        key = b"4" * 32
        nonce = 5

        ciphertext = cipher.encrypt(key, nonce, b"", b"original")

        # Tamper with ciphertext
        tampered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

        with pytest.raises(AuthenticationError):
            cipher.decrypt(key, nonce, b"", tampered)

    def test_invalid_key_size(self) -> None:
        """Test that invalid key size raises error."""
        cipher = ChaChaPoly()

        with pytest.raises(InvalidKeySizeError):
            cipher.encrypt(b"short", 0, b"", b"data")

        with pytest.raises(InvalidKeySizeError):
            cipher.decrypt(b"short", 0, b"", b"data")

    def test_invalid_nonce_range(self) -> None:
        """Test that invalid nonce range raises error."""
        cipher = ChaChaPoly()
        key = b"5" * 32

        with pytest.raises(CryptoError):
            cipher.encrypt(key, -1, b"", b"data")

        with pytest.raises(CryptoError):
            cipher.encrypt(key, 2**64, b"", b"data")


class TestAESGCM:
    """Test AES-256-GCM cipher."""

    def test_init(self) -> None:
        """Test AESGCM initialization."""
        cipher = AESGCMCipher()
        assert cipher.name == "AESGCM"

    def test_encrypt_decrypt_round_trip(self) -> None:
        """Test encryption and decryption round trip."""
        cipher = AESGCMCipher()
        key = b"a" * 32
        nonce = 0
        ad = b"associated data"
        plaintext = b"Hello, Noise Protocol!"

        ciphertext = cipher.encrypt(key, nonce, ad, plaintext)
        decrypted = cipher.decrypt(key, nonce, ad, ciphertext)

        assert decrypted == plaintext

    def test_ciphertext_has_tag(self) -> None:
        """Test that ciphertext includes authentication tag."""
        cipher = AESGCMCipher()
        key = b"b" * 32
        nonce = 42
        plaintext = b"test"

        ciphertext = cipher.encrypt(key, nonce, b"", plaintext)

        # Ciphertext should be plaintext + 16 byte tag
        assert len(ciphertext) == len(plaintext) + 16

    def test_different_nonces_produce_different_ciphertexts(self) -> None:
        """Test that different nonces produce different ciphertexts."""
        cipher = AESGCMCipher()
        key = b"c" * 32
        plaintext = b"secret message"

        ct1 = cipher.encrypt(key, 0, b"", plaintext)
        ct2 = cipher.encrypt(key, 1, b"", plaintext)

        assert ct1 != ct2

    def test_authentication_with_ad(self) -> None:
        """Test authentication with associated data."""
        cipher = AESGCMCipher()
        key = b"d" * 32
        nonce = 100
        ad = b"metadata"
        plaintext = b"payload"

        ciphertext = cipher.encrypt(key, nonce, ad, plaintext)

        # Correct AD should decrypt successfully
        decrypted = cipher.decrypt(key, nonce, ad, ciphertext)
        assert decrypted == plaintext

        # Wrong AD should fail authentication
        with pytest.raises(AuthenticationError):
            cipher.decrypt(key, nonce, b"wrong", ciphertext)

    def test_tampered_ciphertext_fails(self) -> None:
        """Test that tampered ciphertext fails authentication."""
        cipher = AESGCMCipher()
        key = b"e" * 32
        nonce = 5

        ciphertext = cipher.encrypt(key, nonce, b"", b"original")

        # Tamper with ciphertext
        tampered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

        with pytest.raises(AuthenticationError):
            cipher.decrypt(key, nonce, b"", tampered)

    def test_invalid_key_size(self) -> None:
        """Test that invalid key size raises error."""
        cipher = AESGCMCipher()

        with pytest.raises(InvalidKeySizeError):
            cipher.encrypt(b"short", 0, b"", b"data")

        with pytest.raises(InvalidKeySizeError):
            cipher.decrypt(b"short", 0, b"", b"data")

    def test_invalid_nonce_range(self) -> None:
        """Test that invalid nonce range raises error."""
        cipher = AESGCMCipher()
        key = b"f" * 32

        with pytest.raises(CryptoError):
            cipher.encrypt(key, -1, b"", b"data")

        with pytest.raises(CryptoError):
            cipher.encrypt(key, 2**64, b"", b"data")


class TestGetCipherFunction:
    """Test cipher function factory."""

    def test_get_chachapoly(self) -> None:
        """Test getting ChaCha20-Poly1305."""
        cipher = get_cipher_function("ChaChaPoly")
        assert isinstance(cipher, ChaChaPoly)
        assert cipher.name == "ChaChaPoly"

    def test_get_aesgcm(self) -> None:
        """Test getting AES-256-GCM."""
        cipher = get_cipher_function("AESGCM")
        assert isinstance(cipher, AESGCMCipher)
        assert cipher.name == "AESGCM"

    def test_unknown_cipher_function(self) -> None:
        """Test unknown cipher function raises error."""
        with pytest.raises(UnsupportedPrimitiveError):
            get_cipher_function("unknown")


class TestCipherCompatibility:
    """Test that both ciphers work correctly."""

    def test_both_ciphers_work(self) -> None:
        """Test that both ChaCha20-Poly1305 and AES-256-GCM work correctly."""
        key = b"x" * 32
        nonce = 12345
        ad = b"test ad"
        plaintext = b"test plaintext data"

        for cipher in [ChaChaPoly(), AESGCMCipher()]:
            ciphertext = cipher.encrypt(key, nonce, ad, plaintext)
            decrypted = cipher.decrypt(key, nonce, ad, ciphertext)
            assert decrypted == plaintext

