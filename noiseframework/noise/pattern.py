"""
Noise Protocol pattern parsing and validation.

Parses and validates Noise protocol pattern strings like:
- Noise_XX_25519_ChaChaPoly_SHA256
- Noise_IK_448_AESGCM_BLAKE2b
"""

import re
from typing import List, Tuple
from dataclasses import dataclass


@dataclass
class NoisePattern:
    """Parsed Noise protocol pattern."""

    name: str  # Full pattern name (e.g., "Noise_XX_25519_ChaChaPoly_SHA256")
    handshake_pattern: str  # Handshake pattern (e.g., "XX", "IK")
    dh_function: str  # DH function name (e.g., "25519", "448")
    cipher_function: str  # Cipher function name (e.g., "ChaChaPoly", "AESGCM")
    hash_function: str  # Hash function name (e.g., "SHA256", "BLAKE2b")


# Supported handshake patterns (fundamental and interactive)
SUPPORTED_PATTERNS = {
    "NN",
    "NK",
    "NX",
    "KN",
    "KK",
    "KX",
    "XN",
    "XK",
    "XX",
    "IN",
    "IK",
    "IX",
}

# Supported DH functions
SUPPORTED_DH = {"25519", "448"}

# Supported cipher functions
SUPPORTED_CIPHERS = {"ChaChaPoly", "AESGCM"}

# Supported hash functions
SUPPORTED_HASHES = {"SHA256", "SHA512", "BLAKE2s", "BLAKE2b"}


def parse_pattern(pattern_string: str) -> NoisePattern:
    """
    Parse a Noise protocol pattern string.

    Args:
        pattern_string: Pattern string (e.g., "Noise_XX_25519_ChaChaPoly_SHA256")

    Returns:
        Parsed NoisePattern

    Raises:
        ValueError: If pattern string is invalid or contains unsupported primitives
    """
    # Pattern format: Noise_PATTERN_DH_CIPHER_HASH
    pattern_regex = r"^Noise_([A-Z]{2})_(\w+)_(\w+)_(\w+)$"
    match = re.match(pattern_regex, pattern_string)

    if not match:
        raise ValueError(
            f"Invalid pattern string format: {pattern_string}. "
            f"Expected format: Noise_PATTERN_DH_CIPHER_HASH"
        )

    handshake, dh, cipher, hash_func = match.groups()

    # Validate handshake pattern
    if handshake not in SUPPORTED_PATTERNS:
        raise ValueError(
            f"Unsupported handshake pattern: {handshake}. "
            f"Supported patterns: {', '.join(sorted(SUPPORTED_PATTERNS))}"
        )

    # Validate DH function
    if dh not in SUPPORTED_DH:
        raise ValueError(
            f"Unsupported DH function: {dh}. "
            f"Supported DH functions: {', '.join(sorted(SUPPORTED_DH))}"
        )

    # Validate cipher function
    if cipher not in SUPPORTED_CIPHERS:
        raise ValueError(
            f"Unsupported cipher function: {cipher}. "
            f"Supported ciphers: {', '.join(sorted(SUPPORTED_CIPHERS))}"
        )

    # Validate hash function
    if hash_func not in SUPPORTED_HASHES:
        raise ValueError(
            f"Unsupported hash function: {hash_func}. "
            f"Supported hash functions: {', '.join(sorted(SUPPORTED_HASHES))}"
        )

    return NoisePattern(
        name=pattern_string,
        handshake_pattern=handshake,
        dh_function=dh,
        cipher_function=cipher,
        hash_function=hash_func,
    )


def get_pattern_tokens(handshake_pattern: str) -> Tuple[List[str], List[str], List[str]]:
    """
    Get the message token sequence for a handshake pattern.

    Args:
        handshake_pattern: Handshake pattern name (e.g., "XX", "IK")

    Returns:
        Tuple of (pre_messages_initiator, pre_messages_responder, message_patterns)
        where message_patterns is a list of token strings for each message

    Raises:
        ValueError: If handshake pattern is not supported
    """
    # Pattern definitions from Noise spec
    # Format: (initiator_pre, responder_pre, message_tokens)
    patterns = {
        "NN": ([], [], ["e", "e, ee"]),
        "NK": ([], ["s"], ["e, es", "e, ee"]),
        "NX": ([], [], ["e", "e, ee, s, es"]),
        "KN": (["s"], [], ["e", "e, ee, se"]),
        "KK": (["s"], ["s"], ["e, es, ss", "e, ee, se"]),
        "KX": (["s"], [], ["e", "e, ee, se, s, es"]),
        "XN": ([], [], ["e", "e, ee", "s, se"]),
        "XK": ([], ["s"], ["e, es", "e, ee", "s, se"]),
        "XX": ([], [], ["e", "e, ee, s, es", "s, se"]),
        "IN": ([], [], ["e, s", "e, ee, se"]),
        "IK": ([], ["s"], ["e, es, s, ss", "e, ee, se"]),
        "IX": ([], [], ["e, s", "e, ee, se, s, es"]),
    }

    if handshake_pattern not in patterns:
        raise ValueError(f"Unknown handshake pattern: {handshake_pattern}")

    initiator_pre, responder_pre, messages = patterns[handshake_pattern]
    return initiator_pre, responder_pre, messages


def validate_pattern_string(pattern_string: str) -> bool:
    """
    Check if a pattern string is valid.

    Args:
        pattern_string: Pattern string to validate

    Returns:
        True if valid, False otherwise
    """
    try:
        parse_pattern(pattern_string)
        return True
    except ValueError:
        return False
