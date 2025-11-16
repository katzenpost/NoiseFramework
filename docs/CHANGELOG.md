# Changelog

All notable changes to Py-Noise will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure and configuration
- Professional README with comprehensive documentation and badges
- MIT License
- Python package configuration with pyproject.toml
- Development dependencies (pytest, black, mypy, ruff, hypothesis)
- requirements.txt for core dependencies
- Complete cryptographic primitives layer:
  - Diffie-Hellman: Curve25519 (X25519) and Curve448 (X448)
  - AEAD ciphers: ChaCha20-Poly1305 and AES-256-GCM
  - Hash functions: SHA-256, SHA-512, BLAKE2s, BLAKE2b with HKDF
- Noise protocol pattern parser and validator
  - Supports all 12 fundamental and interactive patterns
  - Pattern string validation and parsing
  - Token sequence generation for handshake patterns
- Symmetric state and cipher state implementation
  - CipherState for AEAD encryption/decryption
  - SymmetricState for handshake state management
  - Key derivation and mixing operations
  - Split operation for transport encryption
- NoiseHandshake class for managing complete handshake protocol
  - Role management (initiator/responder)
  - All DH token operations (e, s, ee, es, se, ss)
  - write_message() and read_message() for handshake steps
  - to_transport() for converting to post-handshake cipher states
  - Support for multiple patterns (NN, XX, NK, IK, KK, XK)
- NoiseTransport class for post-handshake encrypted communication
  - send() and receive() methods with associated data support
  - Nonce tracking methods (get_send_nonce(), get_receive_nonce())
  - Bidirectional encrypted communication wrapper
- Command-line interface (py-noise CLI)
  - generate-keypair command for creating static keypairs
  - validate-pattern command for validating Noise pattern strings
  - info command for displaying supported primitives and patterns
  - Command aliases (genkey, validate)
  - Full argparse-based CLI with help and version flags
- Public API exports in py_noise.__init__.py
- CLI script entry point in pyproject.toml
- Comprehensive documentation in README.md
  - Detailed Python API examples (XX, NN, IK patterns)
  - Complete CLI documentation with usage examples
  - Error handling examples
  - Performance benchmarking guide
  - FAQ section
- Comprehensive test suite with 156 tests and 92% coverage
- CLI module structure
- Transport layer module structure
- Comprehensive .gitignore for Python projects

### Changed
- Nothing yet

### Fixed
- Nothing yet

## [0.1.0] - TBD

- Initial release (not yet published)
