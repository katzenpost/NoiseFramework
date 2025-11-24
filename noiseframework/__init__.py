"""
NoiseFramework: A professional implementation of the Noise Protocol Framework in Python.

This package provides cryptographically sound, specification-compliant implementations
of Noise handshake patterns for building secure communication channels.
"""

__version__ = "1.2.0"
__author__ = "Julius Pleunes"
__license__ = "MIT"

# Public API exports
from noiseframework.noise.handshake import NoiseHandshake
from noiseframework.transport.transport import NoiseTransport
from noiseframework.framing import (
    FramedReader,
    FramedWriter,
    FramingError,
    read_framed_message,
    write_framed_message,
)

__all__ = [
    "__version__",
    "NoiseHandshake",
    "NoiseTransport",
    "FramedReader",
    "FramedWriter",
    "FramingError",
    "read_framed_message",
    "write_framed_message",
]
