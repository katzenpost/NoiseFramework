"""
NoiseFramework: A professional implementation of the Noise Protocol Framework in Python.

This package provides cryptographically sound, specification-compliant implementations
of Noise handshake patterns for building secure communication channels.
"""

__version__ = "0.1.0"
__author__ = "Julius Pleunes"
__license__ = "MIT"

# Public API exports
from py_noise.noise.handshake import NoiseHandshake

__all__ = [
    "__version__",
    "NoiseHandshake",
]
