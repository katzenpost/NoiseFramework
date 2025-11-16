"""Tests for hash functions."""

import pytest
from py_noise.crypto.hash import SHA256, SHA512, BLAKE2s, BLAKE2b, get_hash_function


class TestSHA256:
    """Test SHA-256 hash function."""

    def test_init(self) -> None:
        """Test SHA-256 initialization."""
        h = SHA256()
        assert h.name == "SHA256"
        assert h.hashlen == 32
        assert h.blocklen == 64

    def test_hash(self) -> None:
        """Test hashing produces correct output size."""
        h = SHA256()
        digest = h.hash(b"test data")
        assert len(digest) == 32
        assert isinstance(digest, bytes)

    def test_hash_deterministic(self) -> None:
        """Test that hashing is deterministic."""
        h = SHA256()
        data = b"deterministic test"
        digest1 = h.hash(data)
        digest2 = h.hash(data)
        assert digest1 == digest2

    def test_hash_different_inputs(self) -> None:
        """Test that different inputs produce different hashes."""
        h = SHA256()
        hash1 = h.hash(b"input1")
        hash2 = h.hash(b"input2")
        assert hash1 != hash2

    def test_hmac_hash(self) -> None:
        """Test HMAC produces correct output size."""
        h = SHA256()
        key = b"secret key"
        data = b"message"
        hmac = h.hmac_hash(key, data)
        assert len(hmac) == 32
        assert isinstance(hmac, bytes)

    def test_hmac_deterministic(self) -> None:
        """Test that HMAC is deterministic."""
        h = SHA256()
        key = b"key"
        data = b"data"
        hmac1 = h.hmac_hash(key, data)
        hmac2 = h.hmac_hash(key, data)
        assert hmac1 == hmac2

    def test_hkdf_two_outputs(self) -> None:
        """Test HKDF with two outputs."""
        h = SHA256()
        ck = b"chaining key" + b"\x00" * 20
        ikm = b"input key material"
        
        output1, output2 = h.hkdf(ck, ikm, 2)
        
        assert len(output1) == 32
        assert len(output2) == 32
        assert output1 != output2

    def test_hkdf_three_outputs(self) -> None:
        """Test HKDF with three outputs."""
        h = SHA256()
        ck = b"chaining key" + b"\x00" * 20
        ikm = b"input key material"
        
        output1, output2, output3 = h.hkdf(ck, ikm, 3)
        
        assert len(output1) == 32
        assert len(output2) == 32
        assert len(output3) == 32
        assert len({output1, output2, output3}) == 3  # All unique

    def test_hkdf_invalid_num_outputs(self) -> None:
        """Test HKDF with invalid number of outputs."""
        h = SHA256()
        ck = b"x" * 32
        ikm = b"y" * 32
        
        with pytest.raises(ValueError, match="num_outputs must be 2 or 3"):
            h.hkdf(ck, ikm, 1)
        
        with pytest.raises(ValueError, match="num_outputs must be 2 or 3"):
            h.hkdf(ck, ikm, 4)


class TestSHA512:
    """Test SHA-512 hash function."""

    def test_init(self) -> None:
        """Test SHA-512 initialization."""
        h = SHA512()
        assert h.name == "SHA512"
        assert h.hashlen == 64
        assert h.blocklen == 128

    def test_hash(self) -> None:
        """Test hashing produces correct output size."""
        h = SHA512()
        digest = h.hash(b"test data")
        assert len(digest) == 64

    def test_hmac_hash(self) -> None:
        """Test HMAC produces correct output size."""
        h = SHA512()
        hmac = h.hmac_hash(b"key", b"data")
        assert len(hmac) == 64

    def test_hkdf(self) -> None:
        """Test HKDF produces correct output sizes."""
        h = SHA512()
        ck = b"x" * 64
        ikm = b"y" * 64
        
        output1, output2 = h.hkdf(ck, ikm, 2)
        assert len(output1) == 64
        assert len(output2) == 64


class TestBLAKE2s:
    """Test BLAKE2s hash function."""

    def test_init(self) -> None:
        """Test BLAKE2s initialization."""
        h = BLAKE2s()
        assert h.name == "BLAKE2s"
        assert h.hashlen == 32
        assert h.blocklen == 64

    def test_hash(self) -> None:
        """Test hashing produces correct output size."""
        h = BLAKE2s()
        digest = h.hash(b"test data")
        assert len(digest) == 32

    def test_hmac_hash(self) -> None:
        """Test HMAC produces correct output size."""
        h = BLAKE2s()
        hmac = h.hmac_hash(b"key", b"data")
        assert len(hmac) == 32

    def test_hkdf(self) -> None:
        """Test HKDF produces correct output sizes."""
        h = BLAKE2s()
        ck = b"x" * 32
        ikm = b"y" * 32
        
        output1, output2, output3 = h.hkdf(ck, ikm, 3)
        assert len(output1) == 32
        assert len(output2) == 32
        assert len(output3) == 32


class TestBLAKE2b:
    """Test BLAKE2b hash function."""

    def test_init(self) -> None:
        """Test BLAKE2b initialization."""
        h = BLAKE2b()
        assert h.name == "BLAKE2b"
        assert h.hashlen == 64
        assert h.blocklen == 128

    def test_hash(self) -> None:
        """Test hashing produces correct output size."""
        h = BLAKE2b()
        digest = h.hash(b"test data")
        assert len(digest) == 64

    def test_hmac_hash(self) -> None:
        """Test HMAC produces correct output size."""
        h = BLAKE2b()
        hmac = h.hmac_hash(b"key", b"data")
        assert len(hmac) == 64

    def test_hkdf(self) -> None:
        """Test HKDF produces correct output sizes."""
        h = BLAKE2b()
        ck = b"x" * 64
        ikm = b"y" * 64
        
        output1, output2 = h.hkdf(ck, ikm, 2)
        assert len(output1) == 64
        assert len(output2) == 64


class TestGetHashFunction:
    """Test hash function factory."""

    def test_get_sha256(self) -> None:
        """Test getting SHA-256."""
        h = get_hash_function("SHA256")
        assert isinstance(h, SHA256)
        assert h.name == "SHA256"

    def test_get_sha512(self) -> None:
        """Test getting SHA-512."""
        h = get_hash_function("SHA512")
        assert isinstance(h, SHA512)
        assert h.name == "SHA512"

    def test_get_blake2s(self) -> None:
        """Test getting BLAKE2s."""
        h = get_hash_function("BLAKE2s")
        assert isinstance(h, BLAKE2s)
        assert h.name == "BLAKE2s"

    def test_get_blake2b(self) -> None:
        """Test getting BLAKE2b."""
        h = get_hash_function("BLAKE2b")
        assert isinstance(h, BLAKE2b)
        assert h.name == "BLAKE2b"

    def test_unknown_hash_function(self) -> None:
        """Test unknown hash function raises error."""
        with pytest.raises(ValueError, match="Unknown hash function"):
            get_hash_function("unknown")


class TestAllHashFunctions:
    """Test that all hash functions work correctly."""

    def test_all_hash_functions_work(self) -> None:
        """Test that all supported hash functions produce output."""
        data = b"test data for all hash functions"
        
        for hash_func in [SHA256(), SHA512(), BLAKE2s(), BLAKE2b()]:
            # Test basic hashing
            digest = hash_func.hash(data)
            assert len(digest) == hash_func.hashlen
            
            # Test HMAC
            hmac = hash_func.hmac_hash(b"key", data)
            assert len(hmac) == hash_func.hashlen
            
            # Test HKDF
            ck = b"x" * hash_func.hashlen
            ikm = b"y" * hash_func.hashlen
            outputs = hash_func.hkdf(ck, ikm, 2)
            assert len(outputs) == 2
            assert all(len(o) == hash_func.hashlen for o in outputs)
