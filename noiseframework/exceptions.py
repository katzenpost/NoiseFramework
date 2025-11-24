"""
Custom exception classes for NoiseFramework.

This module provides a hierarchy of exception classes with clear, actionable
error messages to help developers debug issues quickly.
"""


class NoiseError(Exception):
    """
    Base exception for all NoiseFramework errors.
    
    All custom exceptions in NoiseFramework inherit from this class,
    making it easy to catch any framework-specific error.
    """
    pass


class HandshakeError(NoiseError):
    """
    Exception raised during Noise handshake operations.
    
    This includes errors related to:
    - Invalid handshake state transitions
    - Missing required keys
    - Wrong message ordering
    - Role configuration issues
    """
    pass


class RoleNotSetError(HandshakeError):
    """Handshake role (initiator/responder) has not been set."""
    pass


class RoleAlreadySetError(HandshakeError):
    """Handshake role has already been set and cannot be changed."""
    pass


class WrongTurnError(HandshakeError):
    """Attempted to send/receive message out of turn in handshake."""
    pass


class HandshakeCompleteError(HandshakeError):
    """Attempted handshake operation after handshake is complete."""
    pass


class MissingKeyError(HandshakeError):
    """Required cryptographic key is missing for handshake operation."""
    pass


class PatternError(NoiseError):
    """
    Exception raised for invalid Noise pattern specifications.
    
    This includes errors related to:
    - Invalid pattern string format
    - Unsupported handshake patterns
    - Unsupported cryptographic primitives
    """
    pass


class UnsupportedPatternError(PatternError):
    """Noise pattern is not supported by this implementation."""
    pass


class UnsupportedPrimitiveError(PatternError):
    """Cryptographic primitive (DH, cipher, or hash) is not supported."""
    pass


class StateError(NoiseError):
    """
    Exception raised for invalid cipher or symmetric state operations.
    
    This includes errors related to:
    - Operating on uninitialized state
    - Nonce overflow conditions
    - Invalid key sizes
    """
    pass


class NoKeySetError(StateError):
    """Attempted cipher operation with no key set."""
    pass


class NonceOverflowError(StateError):
    """Nonce has overflowed; no more messages can be encrypted/decrypted."""
    pass


class InvalidKeySizeError(StateError):
    """Cryptographic key has invalid size for the cipher."""
    pass


class TransportError(NoiseError):
    """
    Exception raised during Noise transport operations.
    
    This includes errors related to:
    - Authentication failures
    - Nonce limit warnings
    - Transport state issues
    """
    pass


class AuthenticationError(TransportError):
    """Message authentication failed during decryption."""
    pass


class CryptoError(NoiseError):
    """
    Exception raised for cryptographic operation failures.
    
    This includes errors related to:
    - Invalid DH operations
    - Invalid key sizes for primitives
    - Failed cryptographic operations
    """
    pass


class ValidationError(NoiseError):
    """
    Exception raised for input validation failures.
    
    This includes errors related to:
    - Invalid parameter values
    - Out-of-range values
    - Type mismatches
    """
    pass


# FramingError is already defined in framing.py
# We'll keep it there to avoid circular imports, but document it here
# class FramingError(NoiseError):
#     """Exception raised for framing protocol errors."""
#     pass
