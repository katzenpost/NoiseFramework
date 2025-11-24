"""Tests for Noise pattern parsing."""

import pytest
from noiseframework.exceptions import (
    AuthenticationError, CryptoError, InvalidKeySizeError,
    UnsupportedPrimitiveError, UnsupportedPatternError,
    ValidationError, RoleNotSetError, RoleAlreadySetError,
    WrongTurnError, HandshakeCompleteError, MissingKeyError,
    NoKeySetError, NonceOverflowError
)
from noiseframework.noise.pattern import (
    parse_pattern,
    get_pattern_tokens,
    validate_pattern_string,
    NoisePattern,
)


class TestParsePattern:
    """Test pattern string parsing."""

    def test_parse_valid_pattern(self) -> None:
        """Test parsing a valid pattern string."""
        pattern = parse_pattern("Noise_XX_25519_ChaChaPoly_SHA256")

        assert pattern.name == "Noise_XX_25519_ChaChaPoly_SHA256"
        assert pattern.handshake_pattern == "XX"
        assert pattern.dh_function == "25519"
        assert pattern.cipher_function == "ChaChaPoly"
        assert pattern.hash_function == "SHA256"

    def test_parse_all_combinations(self) -> None:
        """Test parsing various valid combinations."""
        test_cases = [
            ("Noise_NN_25519_AESGCM_SHA512", "NN", "25519", "AESGCM", "SHA512"),
            ("Noise_IK_448_ChaChaPoly_BLAKE2s", "IK", "448", "ChaChaPoly", "BLAKE2s"),
            ("Noise_KK_25519_AESGCM_BLAKE2b", "KK", "25519", "AESGCM", "BLAKE2b"),
        ]

        for pattern_str, expected_hp, expected_dh, expected_cipher, expected_hash in test_cases:
            pattern = parse_pattern(pattern_str)
            assert pattern.handshake_pattern == expected_hp
            assert pattern.dh_function == expected_dh
            assert pattern.cipher_function == expected_cipher
            assert pattern.hash_function == expected_hash

    def test_parse_invalid_format(self) -> None:
        """Test that invalid format raises error."""
        invalid_patterns = [
            "NoiseXX_25519_ChaChaPoly_SHA256",  # Missing underscore
            "Noise_XX_25519_ChaChaPoly",  # Missing hash
            "XX_25519_ChaChaPoly_SHA256",  # Missing Noise_ prefix
            "Noise_XX-25519-ChaChaPoly-SHA256",  # Wrong separator
            "",  # Empty string
        ]

        for invalid in invalid_patterns:
            with pytest.raises(UnsupportedPatternError):
                parse_pattern(invalid)

    def test_parse_unsupported_handshake(self) -> None:
        """Test that unsupported handshake pattern raises error."""
        with pytest.raises(UnsupportedPatternError):
            parse_pattern("Noise_ZZ_25519_ChaChaPoly_SHA256")

    def test_parse_unsupported_dh(self) -> None:
        """Test that unsupported DH function raises error."""
        with pytest.raises(UnsupportedPrimitiveError):
            parse_pattern("Noise_XX_secp256k1_ChaChaPoly_SHA256")

    def test_parse_unsupported_cipher(self) -> None:
        """Test that unsupported cipher raises error."""
        with pytest.raises(UnsupportedPrimitiveError):
            parse_pattern("Noise_XX_25519_AES_SHA256")

    def test_parse_unsupported_hash(self) -> None:
        """Test that unsupported hash function raises error."""
        with pytest.raises(UnsupportedPrimitiveError):
            parse_pattern("Noise_XX_25519_ChaChaPoly_MD5")


class TestGetPatternTokens:
    """Test handshake pattern token sequences."""

    def test_nn_pattern(self) -> None:
        """Test NN pattern tokens."""
        init_pre, resp_pre, messages = get_pattern_tokens("NN")
        assert init_pre == []
        assert resp_pre == []
        assert messages == ["e", "e, ee"]

    def test_xx_pattern(self) -> None:
        """Test XX pattern tokens."""
        init_pre, resp_pre, messages = get_pattern_tokens("XX")
        assert init_pre == []
        assert resp_pre == []
        assert messages == ["e", "e, ee, s, es", "s, se"]

    def test_ik_pattern(self) -> None:
        """Test IK pattern tokens."""
        init_pre, resp_pre, messages = get_pattern_tokens("IK")
        assert init_pre == []
        assert resp_pre == ["s"]
        assert messages == ["e, es, s, ss", "e, ee, se"]

    def test_kk_pattern(self) -> None:
        """Test KK pattern tokens."""
        init_pre, resp_pre, messages = get_pattern_tokens("KK")
        assert init_pre == ["s"]
        assert resp_pre == ["s"]
        assert messages == ["e, es, ss", "e, ee, se"]

    def test_nk_pattern(self) -> None:
        """Test NK pattern tokens."""
        init_pre, resp_pre, messages = get_pattern_tokens("NK")
        assert init_pre == []
        assert resp_pre == ["s"]
        assert messages == ["e, es", "e, ee"]

    def test_xk_pattern(self) -> None:
        """Test XK pattern tokens."""
        init_pre, resp_pre, messages = get_pattern_tokens("XK")
        assert init_pre == []
        assert resp_pre == ["s"]
        assert messages == ["e, es", "e, ee", "s, se"]

    def test_all_supported_patterns(self) -> None:
        """Test that all supported patterns have token sequences."""
        patterns = ["NN", "NK", "NX", "KN", "KK", "KX", "XN", "XK", "XX", "IN", "IK", "IX"]

        for pattern in patterns:
            init_pre, resp_pre, messages = get_pattern_tokens(pattern)
            assert isinstance(init_pre, list)
            assert isinstance(resp_pre, list)
            assert isinstance(messages, list)
            assert len(messages) >= 2  # At least two messages in a handshake

    def test_unknown_pattern(self) -> None:
        """Test that unknown pattern raises error."""
        with pytest.raises(UnsupportedPatternError):
            get_pattern_tokens("UNKNOWN")


class TestValidatePatternString:
    """Test pattern string validation."""

    def test_valid_patterns(self) -> None:
        """Test that valid patterns return True."""
        valid_patterns = [
            "Noise_XX_25519_ChaChaPoly_SHA256",
            "Noise_NN_448_AESGCM_BLAKE2b",
            "Noise_IK_25519_ChaChaPoly_SHA512",
        ]

        for pattern in valid_patterns:
            assert validate_pattern_string(pattern) is True

    def test_invalid_patterns(self) -> None:
        """Test that invalid patterns return False."""
        invalid_patterns = [
            "Invalid",
            "Noise_ZZ_25519_ChaChaPoly_SHA256",
            "Noise_XX_invalid_ChaChaPoly_SHA256",
            "",
        ]

        for pattern in invalid_patterns:
            assert validate_pattern_string(pattern) is False


class TestNoisePattern:
    """Test NoisePattern dataclass."""

    def test_pattern_attributes(self) -> None:
        """Test that pattern attributes are accessible."""
        pattern = NoisePattern(
            name="Noise_XX_25519_ChaChaPoly_SHA256",
            handshake_pattern="XX",
            dh_function="25519",
            cipher_function="ChaChaPoly",
            hash_function="SHA256",
        )

        assert pattern.name == "Noise_XX_25519_ChaChaPoly_SHA256"
        assert pattern.handshake_pattern == "XX"
        assert pattern.dh_function == "25519"
        assert pattern.cipher_function == "ChaChaPoly"
        assert pattern.hash_function == "SHA256"
