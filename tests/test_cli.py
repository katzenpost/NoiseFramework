"""Tests for CLI functionality."""

import pytest
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from noiseframework.cli.main import main, generate_keypair, validate_pattern, show_info


class TestCLIGenerateKeypair:
    """Test keypair generation command."""

    def test_generate_keypair_25519(self, tmp_path: Path) -> None:
        """Test generating Curve25519 keypair."""
        output_prefix = str(tmp_path / "test_key")
        
        with patch("sys.argv", ["noiseframework", "generate-keypair", "--dh", "25519", "-o", output_prefix]):
            result = main()
        
        assert result == 0
        assert (tmp_path / "test_key_private.key").exists()
        assert (tmp_path / "test_key_public.key").exists()
        
        private = (tmp_path / "test_key_private.key").read_bytes()
        public = (tmp_path / "test_key_public.key").read_bytes()
        
        assert len(private) == 32
        assert len(public) == 32

    def test_generate_keypair_448(self, tmp_path: Path) -> None:
        """Test generating Curve448 keypair."""
        output_prefix = str(tmp_path / "test_key")
        
        with patch("sys.argv", ["noiseframework", "generate-keypair", "--dh", "448", "-o", output_prefix]):
            result = main()
        
        assert result == 0
        assert (tmp_path / "test_key_private.key").exists()
        assert (tmp_path / "test_key_public.key").exists()
        
        private = (tmp_path / "test_key_private.key").read_bytes()
        public = (tmp_path / "test_key_public.key").read_bytes()
        
        assert len(private) == 56
        assert len(public) == 56

    def test_generate_keypair_default_output(self, tmp_path: Path, monkeypatch) -> None:
        """Test generating keypair with default output prefix."""
        monkeypatch.chdir(tmp_path)
        
        with patch("sys.argv", ["noiseframework", "generate-keypair"]):
            result = main()
        
        assert result == 0
        assert (tmp_path / "noise_key_private.key").exists()
        assert (tmp_path / "noise_key_public.key").exists()


class TestCLIValidatePattern:
    """Test pattern validation command."""

    def test_validate_valid_pattern(self) -> None:
        """Test validating a valid pattern."""
        with patch("sys.argv", ["noiseframework", "validate-pattern", "Noise_XX_25519_ChaChaPoly_SHA256"]):
            result = main()
        
        assert result == 0

    def test_validate_invalid_pattern(self) -> None:
        """Test validating an invalid pattern."""
        with patch("sys.argv", ["noiseframework", "validate-pattern", "Invalid_Pattern"]):
            with patch("sys.stderr", new_callable=StringIO):
                result = main()
        
        assert result == 1

    def test_validate_all_supported_patterns(self) -> None:
        """Test validating all supported patterns."""
        patterns = [
            "Noise_NN_25519_ChaChaPoly_SHA256",
            "Noise_NK_25519_ChaChaPoly_SHA256",
            "Noise_NX_25519_ChaChaPoly_SHA256",
            "Noise_XX_25519_ChaChaPoly_SHA256",
            "Noise_IK_25519_ChaChaPoly_SHA256",
            "Noise_KK_25519_ChaChaPoly_SHA256",
        ]
        
        for pattern in patterns:
            with patch("sys.argv", ["noiseframework", "validate-pattern", pattern]):
                result = main()
                assert result == 0, f"Pattern {pattern} should be valid"


class TestCLIInfo:
    """Test info command."""

    def test_show_info(self) -> None:
        """Test showing noiseframework information."""
        with patch("sys.argv", ["noiseframework", "info"]):
            result = main()
        
        assert result == 0

    def test_info_output_contains_key_information(self) -> None:
        """Test that info output contains expected information."""
        with patch("sys.argv", ["noiseframework", "info"]):
            with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
                result = main()
                output = mock_stdout.getvalue()
        
        assert result == 0
        assert "25519" in output
        assert "ChaChaPoly" in output
        assert "SHA256" in output
        assert "XX" in output


class TestCLIHelp:
    """Test help output."""

    def test_no_command_shows_help(self) -> None:
        """Test that running without command shows help."""
        with patch("sys.argv", ["noiseframework"]):
            result = main()
        
        assert result == 0

    def test_help_flag(self) -> None:
        """Test --help flag."""
        with patch("sys.argv", ["noiseframework", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
        
        assert exc_info.value.code == 0

    def test_version_flag(self) -> None:
        """Test --version flag."""
        with patch("sys.argv", ["noiseframework", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
        
        assert exc_info.value.code == 0


class TestCLIAliases:
    """Test command aliases."""

    def test_genkey_alias(self, tmp_path: Path) -> None:
        """Test genkey alias for generate-keypair."""
        output_prefix = str(tmp_path / "alias_key")
        
        with patch("sys.argv", ["noiseframework", "genkey", "-o", output_prefix]):
            result = main()
        
        assert result == 0
        assert (tmp_path / "alias_key_private.key").exists()

    def test_validate_alias(self) -> None:
        """Test validate alias for validate-pattern."""
        with patch("sys.argv", ["noiseframework", "validate", "Noise_XX_25519_ChaChaPoly_SHA256"]):
            result = main()
        
        assert result == 0


class TestCLIEncryptDecrypt:
    """Test encrypt/decrypt commands."""

    def test_encrypt_requires_input(self) -> None:
        """Test that encrypt requires input file."""
        with patch("sys.argv", ["noiseframework", "encrypt"]):
            with pytest.raises(SystemExit):
                main()

    def test_encrypt_nonexistent_file(self) -> None:
        """Test encrypting nonexistent file."""
        with patch("sys.argv", ["noiseframework", "encrypt", "-i", "nonexistent.txt"]):
            with patch("sys.stderr", new_callable=StringIO):
                result = main()
        
        assert result == 1

    def test_decrypt_requires_input(self) -> None:
        """Test that decrypt requires input file."""
        with patch("sys.argv", ["noiseframework", "decrypt"]):
            with pytest.raises(SystemExit):
                main()
