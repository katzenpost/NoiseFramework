"""
Noise Protocol pattern parsing and validation.

Parses and validates Noise protocol pattern strings like:
- Noise_XX_25519_ChaChaPoly_SHA256
- Noise_IK_448_AESGCM_BLAKE2b
"""

import re
from typing import List, Tuple, Optional
from dataclasses import dataclass
from noiseframework.exceptions import UnsupportedPatternError, UnsupportedPrimitiveError


@dataclass
class NoisePattern:
    """Parsed Noise protocol pattern."""

    name: str  # Full pattern name (e.g., "Noise_XX_25519_ChaChaPoly_SHA256")
    handshake_pattern: str  # Handshake pattern (e.g., "XX", "IK")
    dh_function: str  # DH function name (e.g., "25519", "448")
    cipher_function: str  # Cipher function name (e.g., "ChaChaPoly", "AESGCM")
    hash_function: str  # Hash function name (e.g., "SHA256", "BLAKE2b")
    psk_modifier: Optional[str] = None  # PSK modifier (e.g., "psk0", "psk2", "psk3")


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

# Supported PSK modifiers
SUPPORTED_PSK_MODIFIERS = {"psk0", "psk1", "psk2", "psk3", "psk4"}


def parse_pattern(pattern_string: str) -> NoisePattern:
    """
    Parse a Noise protocol pattern string.

    Args:
        pattern_string: Pattern string (e.g., "Noise_XX_25519_ChaChaPoly_SHA256" or "Noise_XXpsk3_25519_ChaChaPoly_SHA256")

    Returns:
        Parsed NoisePattern

    Raises:
        ValueError: If pattern string is invalid or contains unsupported primitives
    """
    # Pattern format: Noise_PATTERN[pskN]_DH_CIPHER_HASH
    # where [pskN] is optional and N is 0-4
    pattern_regex = r"^Noise_([A-Z]{2}(?:psk[0-4])?)_(\w+)_(\w+)_(\w+)$"
    match = re.match(pattern_regex, pattern_string)

    if not match:
        raise UnsupportedPatternError(
            f"Invalid pattern string format: '{pattern_string}'. "
            f"Expected format: Noise_PATTERN[pskN]_DH_CIPHER_HASH (e.g., Noise_XX_25519_ChaChaPoly_SHA256 or Noise_XXpsk3_25519_ChaChaPoly_SHA256)"
        )

    handshake_full, dh, cipher, hash_func = match.groups()
    
    # Split handshake pattern and PSK modifier
    psk_modifier = None
    if "psk" in handshake_full:
        # Extract base pattern and PSK modifier (e.g., "XXpsk3" -> "XX", "psk3")
        handshake = handshake_full[:2]  # First two characters (XX, IK, NN, etc.)
        psk_modifier = handshake_full[2:]  # Remaining part (psk0, psk2, etc.)
    else:
        handshake = handshake_full

    # Validate handshake pattern
    if handshake not in SUPPORTED_PATTERNS:
        supported = ', '.join(sorted(SUPPORTED_PATTERNS))
        raise UnsupportedPatternError(
            f"Unsupported handshake pattern: '{handshake}' in pattern '{pattern_string}'. "
            f"Supported patterns: {supported}. "
            f"Check for typos in your pattern name."
        )
    
    # Validate PSK modifier if present
    if psk_modifier is not None:
        if psk_modifier not in SUPPORTED_PSK_MODIFIERS:
            supported = ', '.join(sorted(SUPPORTED_PSK_MODIFIERS))
            raise UnsupportedPatternError(
                f"Unsupported PSK modifier: '{psk_modifier}' in pattern '{pattern_string}'. "
                f"Supported PSK modifiers: {supported}. "
                f"PSK modifier indicates when the pre-shared key is mixed into the handshake."
            )

    # Validate DH function
    if dh not in SUPPORTED_DH:
        supported = ', '.join(sorted(SUPPORTED_DH))
        raise UnsupportedPrimitiveError(
            f"Unsupported DH function: '{dh}' in pattern '{pattern_string}'. "
            f"Supported DH functions: {supported}. "
            f"Currently supporting Curve25519 (25519) and Curve448 (448)."
        )

    # Validate cipher function
    if cipher not in SUPPORTED_CIPHERS:
        supported = ', '.join(sorted(SUPPORTED_CIPHERS))
        raise UnsupportedPrimitiveError(
            f"Unsupported cipher function: '{cipher}' in pattern '{pattern_string}'. "
            f"Supported ciphers: {supported}. "
            f"Currently supporting ChaCha20-Poly1305 (ChaChaPoly) and AES-256-GCM (AESGCM)."
        )

    # Validate hash function
    if hash_func not in SUPPORTED_HASHES:
        supported = ', '.join(sorted(SUPPORTED_HASHES))
        raise UnsupportedPrimitiveError(
            f"Unsupported hash function: '{hash_func}' in pattern '{pattern_string}'. "
            f"Supported hash functions: {supported}."
        )

    return NoisePattern(
        name=pattern_string,
        handshake_pattern=handshake,
        dh_function=dh,
        cipher_function=cipher,
        hash_function=hash_func,
        psk_modifier=psk_modifier,
    )


def get_pattern_tokens(handshake_pattern: str, psk_modifier: Optional[str] = None) -> Tuple[List[str], List[str], List[str]]:
    """
    Get the message token sequence for a handshake pattern.

    Args:
        handshake_pattern: Handshake pattern name (e.g., "XX", "IK")
        psk_modifier: Optional PSK modifier (e.g., "psk0", "psk2", "psk3")

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
        supported = ', '.join(sorted(patterns.keys()))
        raise UnsupportedPatternError(
            f"Unknown handshake pattern: '{handshake_pattern}'. "
            f"Supported patterns: {supported}."
        )

    initiator_pre, responder_pre, messages = patterns[handshake_pattern]
    
    # Insert PSK token if PSK modifier is present
    if psk_modifier:
        # Extract PSK position (e.g., "psk2" -> 2)
        psk_position = int(psk_modifier[3])  # Get the number from "pskN"
        
        # Make a copy of messages list
        messages = list(messages)
        
        # PSK token is added at the specified position
        # psk0 means before first message, psk1 after first message, etc.
        if psk_position == 0:
            # Add "psk" token to the beginning of first message
            if messages:
                messages[0] = "psk, " + messages[0]
        elif psk_position <= len(messages):
            # Add "psk" token to the end of specified message
            messages[psk_position - 1] = messages[psk_position - 1] + ", psk"
        else:
            # psk position is beyond the number of messages
            # This shouldn't happen with valid patterns, but handle gracefully
            pass
    
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
    except (UnsupportedPatternError, UnsupportedPrimitiveError):
        return False
