"""
Tests for custom exception hierarchy in noiseframework.exceptions.

This module tests that all custom exceptions are properly defined,
inherit from the correct base classes, and can be caught appropriately.
"""

import pytest
from noiseframework.exceptions import (
    NoiseError,
    HandshakeError,
    RoleNotSetError,
    RoleAlreadySetError,
    WrongTurnError,
    HandshakeCompleteError,
    MissingKeyError,
    PatternError,
    UnsupportedPatternError,
    UnsupportedPrimitiveError,
    StateError,
    NoKeySetError,
    NonceOverflowError,
    InvalidKeySizeError,
    TransportError,
    AuthenticationError,
    CryptoError,
    ValidationError,
)


class TestExceptionHierarchy:
    """Test exception inheritance hierarchy."""

    def test_all_exceptions_inherit_from_noise_error(self) -> None:
        """Test that all custom exceptions inherit from NoiseError."""
        exceptions = [
            HandshakeError,
            RoleNotSetError,
            RoleAlreadySetError,
            WrongTurnError,
            HandshakeCompleteError,
            MissingKeyError,
            PatternError,
            UnsupportedPatternError,
            UnsupportedPrimitiveError,
            StateError,
            NoKeySetError,
            NonceOverflowError,
            InvalidKeySizeError,
            TransportError,
            AuthenticationError,
            CryptoError,
            ValidationError,
        ]

        for exc_class in exceptions:
            assert issubclass(exc_class, NoiseError), f"{exc_class.__name__} should inherit from NoiseError"

    def test_handshake_exceptions_inherit_from_handshake_error(self) -> None:
        """Test handshake exception hierarchy."""
        handshake_exceptions = [
            RoleNotSetError,
            RoleAlreadySetError,
            WrongTurnError,
            HandshakeCompleteError,
            MissingKeyError,
        ]

        for exc_class in handshake_exceptions:
            assert issubclass(exc_class, HandshakeError), f"{exc_class.__name__} should inherit from HandshakeError"
            assert issubclass(exc_class, NoiseError), f"{exc_class.__name__} should inherit from NoiseError"

    def test_pattern_exceptions_inherit_from_pattern_error(self) -> None:
        """Test pattern exception hierarchy."""
        pattern_exceptions = [
            UnsupportedPatternError,
            UnsupportedPrimitiveError,
        ]

        for exc_class in pattern_exceptions:
            assert issubclass(exc_class, PatternError), f"{exc_class.__name__} should inherit from PatternError"
            assert issubclass(exc_class, NoiseError), f"{exc_class.__name__} should inherit from NoiseError"

    def test_state_exceptions_inherit_from_state_error(self) -> None:
        """Test state exception hierarchy."""
        state_exceptions = [
            NoKeySetError,
            NonceOverflowError,
            InvalidKeySizeError,
        ]

        for exc_class in state_exceptions:
            assert issubclass(exc_class, StateError), f"{exc_class.__name__} should inherit from StateError"
            assert issubclass(exc_class, NoiseError), f"{exc_class.__name__} should inherit from NoiseError"

    def test_transport_exceptions_inherit_from_transport_error(self) -> None:
        """Test transport exception hierarchy."""
        transport_exceptions = [
            AuthenticationError,
        ]

        for exc_class in transport_exceptions:
            assert issubclass(exc_class, TransportError), f"{exc_class.__name__} should inherit from TransportError"
            assert issubclass(exc_class, NoiseError), f"{exc_class.__name__} should inherit from NoiseError"


class TestExceptionCatching:
    """Test that exceptions can be caught at different levels."""

    def test_catch_specific_exception(self) -> None:
        """Test catching specific exception type."""
        with pytest.raises(RoleNotSetError):
            raise RoleNotSetError("Test error")

    def test_catch_handshake_error_base(self) -> None:
        """Test catching HandshakeError catches specific handshake exceptions."""
        with pytest.raises(HandshakeError):
            raise RoleNotSetError("Test error")

        with pytest.raises(HandshakeError):
            raise WrongTurnError("Test error")

    def test_catch_pattern_error_base(self) -> None:
        """Test catching PatternError catches specific pattern exceptions."""
        with pytest.raises(PatternError):
            raise UnsupportedPatternError("Test error")

        with pytest.raises(PatternError):
            raise UnsupportedPrimitiveError("Test error")

    def test_catch_state_error_base(self) -> None:
        """Test catching StateError catches specific state exceptions."""
        with pytest.raises(StateError):
            raise NoKeySetError("Test error")

        with pytest.raises(StateError):
            raise NonceOverflowError("Test error")

    def test_catch_noise_error_base(self) -> None:
        """Test catching NoiseError catches all custom exceptions."""
        exceptions_to_test = [
            RoleNotSetError("Test"),
            UnsupportedPatternError("Test"),
            NoKeySetError("Test"),
            AuthenticationError("Test"),
            CryptoError("Test"),
            ValidationError("Test"),
        ]

        for exc in exceptions_to_test:
            with pytest.raises(NoiseError):
                raise exc


class TestExceptionInstantiation:
    """Test that exceptions can be instantiated with messages."""

    def test_exceptions_accept_messages(self) -> None:
        """Test that all exceptions accept and store error messages."""
        test_message = "Test error message"

        exceptions = [
            NoiseError(test_message),
            HandshakeError(test_message),
            RoleNotSetError(test_message),
            RoleAlreadySetError(test_message),
            WrongTurnError(test_message),
            HandshakeCompleteError(test_message),
            MissingKeyError(test_message),
            PatternError(test_message),
            UnsupportedPatternError(test_message),
            UnsupportedPrimitiveError(test_message),
            StateError(test_message),
            NoKeySetError(test_message),
            NonceOverflowError(test_message),
            InvalidKeySizeError(test_message),
            TransportError(test_message),
            AuthenticationError(test_message),
            CryptoError(test_message),
            ValidationError(test_message),
        ]

        for exc in exceptions:
            assert str(exc) == test_message, f"{type(exc).__name__} should store error message"


class TestExceptionDocstrings:
    """Test that exceptions have helpful docstrings."""

    def test_base_exceptions_have_docstrings(self) -> None:
        """Test that base exception classes have docstrings."""
        base_exceptions = [
            NoiseError,
            HandshakeError,
            PatternError,
            StateError,
            TransportError,
        ]

        for exc_class in base_exceptions:
            assert exc_class.__doc__ is not None, f"{exc_class.__name__} should have a docstring"
            assert len(exc_class.__doc__.strip()) > 20, f"{exc_class.__name__} docstring should be descriptive"

    def test_specific_exceptions_have_docstrings(self) -> None:
        """Test that specific exception classes have docstrings."""
        specific_exceptions = [
            RoleNotSetError,
            RoleAlreadySetError,
            WrongTurnError,
            HandshakeCompleteError,
            MissingKeyError,
            UnsupportedPatternError,
            UnsupportedPrimitiveError,
            NoKeySetError,
            NonceOverflowError,
            InvalidKeySizeError,
            AuthenticationError,
            CryptoError,
            ValidationError,
        ]

        for exc_class in specific_exceptions:
            assert exc_class.__doc__ is not None, f"{exc_class.__name__} should have a docstring"
            assert len(exc_class.__doc__.strip()) > 10, f"{exc_class.__name__} docstring should be descriptive"


class TestExceptionExport:
    """Test that exceptions are properly exported."""

    def test_exceptions_importable_from_main_package(self) -> None:
        """Test that exceptions can be imported from main noiseframework package."""
        # This test succeeds if the imports at the top of this file work
        # We verify by checking that the imported classes are actually the exception classes
        assert NoiseError.__bases__ == (Exception,)
        assert HandshakeError.__bases__ == (NoiseError,)
        assert PatternError.__bases__ == (NoiseError,)
        assert StateError.__bases__ == (NoiseError,)
        assert TransportError.__bases__ == (NoiseError,)

    def test_exception_count(self) -> None:
        """Test that we have the expected number of exception classes."""
        from noiseframework import exceptions as exc_module

        exception_classes = [
            name for name in dir(exc_module)
            if not name.startswith('_')
            and isinstance(getattr(exc_module, name), type)
            and issubclass(getattr(exc_module, name), Exception)
        ]

        # We should have 18 exception classes (including base classes)
        # NoiseError + 4 category bases + 13 specific exceptions
        assert len(exception_classes) >= 18, f"Expected at least 18 exception classes, found {len(exception_classes)}"
