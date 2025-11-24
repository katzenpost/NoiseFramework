# Changelog

All notable changes to NoiseFramework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive logging support throughout the framework:
  - Added optional `logger` parameter to `NoiseHandshake`, `NoiseTransport`, `CipherState`, and `SymmetricState` classes
  - Default logger uses module + class name pattern (e.g., `noiseframework.noise.handshake.NoiseHandshake`)
  - DEBUG-level logging for detailed operations (message sizes, tokens, nonces, key material)
  - INFO-level logging for major events (role setting, handshake completion, message exchange)
  - ERROR-level logging for validation failures and error conditions
  - WARNING-level logging for approaching nonce limits in transport mode
- `examples/logging_example.py` demonstrating logging configuration and usage
- `tests/test_logging.py` with 21 comprehensive logging tests (100% pass rate)

## [1.2.1] - 2025-11-18

### Added
- `benchmark.py` script in repository root for comprehensive performance testing
- `docs/BENCHMARKS.md` with real-world performance measurements and detailed analysis:
  - Handshake performance across different patterns (XX, NN, IK) and cipher suites
  - Transport encryption/decryption throughput for message sizes from 64 bytes to 64 KB
  - Key generation performance for Curve25519 and Curve448
  - Performance recommendations for different use cases (low-latency, high-throughput, embedded, maximum security)
  - Optimization tips and best practices
  - Comparison methodology and reproducibility instructions

### Changed
- Updated README.md performance section with actual benchmark results:
  - Complete XX handshake: 558-642 µs (1,500-1,800 handshakes/sec)
  - Transport encryption: 3+ GB/s for large messages, <3 µs latency for small messages
  - Key generation: ~32,000 keypairs/sec for Curve25519
  - Added quick benchmark results table
  - Added instructions for running benchmarks yourself
  - Added link to comprehensive BENCHMARKS.md documentation

## [1.2.0] - 2025-11-17

### Added
- Exported `NoiseTransport` from main `noiseframework` package for cleaner imports
- Exported `NoiseTransport` from `noiseframework.transport` module
- Support for three import styles: `from noiseframework import NoiseTransport`, `from noiseframework.transport import NoiseTransport`, or `from noiseframework.transport.transport import NoiseTransport`

### Changed
- Updated all code examples in README.md to use cleaner imports (`from noiseframework import NoiseHandshake, NoiseTransport`)
- Updated all code examples in API.md to use cleaner imports
- Improved examples/basic_client_server.py to use `NoiseTransport` wrapper class instead of raw cipher states
- Improved examples/simple_chat.py to use `NoiseTransport` wrapper class and simplified internal state management
- Updated all documentation examples to explicitly pass `b""` to `write_message()` where appropriate for clarity

### Fixed
- README.md: Corrected all import statements from `py_noise` to `noiseframework` (Quick Start, all pattern examples, performance section)
- README.md: Fixed Architecture section to show correct package structure (`noiseframework/` instead of `py_noise/`)
- README.md: Fixed test coverage command from `pytest --cov=py_noise` to `pytest --cov=noiseframework`
- README.md: Added missing `b""` parameter to all `write_message()` calls for consistency
- API.md: Fixed malformed code block (missing closing triple backticks after `initialize()` example)
- API.md: Removed version-specific reference ("v1.1.0") in favor of generic version documentation
- API.md: Updated all examples to use cleaner imports with `NoiseTransport`
- API.md: Updated `write_message()` example to show default empty bytes parameter
- API.md: Updated `to_transport()` example to demonstrate recommended `NoiseTransport` wrapper usage with alternative showing raw cipher state approach
- ARCHITECTURE.md: Updated all file path references from `py_noise/` to `noiseframework/` (8 occurrences)
- CONTRIBUTING.md: Updated all command examples from `py_noise/` to `noiseframework/` in formatting, type checking, and linting commands
- CONTRIBUTING.md: Updated project structure diagram from `py_noise/` to `noiseframework/`
- examples/basic_client_server.py: Now uses `NoiseTransport` wrapper instead of directly calling cipher state methods
- examples/simple_chat.py: Refactored to use `NoiseTransport` wrapper and simplified from separate cipher states to single transport instance

## [1.1.0] - 2025-11-16

### Added
- SECURITY.md with vulnerability reporting process and security considerations
- CONTRIBUTING.md with comprehensive contribution guidelines
- CODE_OF_CONDUCT.md based on Contributor Covenant 2.0
- API.md with complete API reference documentation covering all public interfaces
- GitHub issue templates (bug report, feature request) and PR template
- Examples directory with basic_client_server.py, file_encryption.py, and simple_chat.py
- ARCHITECTURE.md documenting internal design and component interactions
- FAQ.md with common questions, troubleshooting, and best practices

### Changed
- **BREAKING**: Renamed internal package from `py_noise` to `noiseframework` for consistency
  - Old: `from py_noise import NoiseHandshake`
  - New: `from noiseframework import NoiseHandshake`

### Fixed
- Package finder in pyproject.toml now correctly looks for `noiseframework*` instead of `py_noise*`
- CLI entry point (`noiseframework` command) now correctly imports the renamed module

## [0.1.0] - 2025-11-16

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
- Command-line interface (noiseframework CLI)
  - generate-keypair command for creating static keypairs
  - validate-pattern command for validating Noise pattern strings
  - info command for displaying supported primitives and patterns
  - Command aliases (genkey, validate)
  - Full argparse-based CLI with help and version flags
- Public API exports in noiseframework.__init__.py
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