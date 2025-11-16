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
- Comprehensive test suite with 102 tests and 99% coverage
- CLI module structure
- Transport layer module structure
- Comprehensive .gitignore for Python projects

### Changed
- Nothing yet

### Fixed
- Nothing yet

## [0.1.0] - TBD

- Initial release (not yet published)
