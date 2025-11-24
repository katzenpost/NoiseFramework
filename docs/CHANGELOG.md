# Changelog

All notable changes to NoiseFramework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Fallback Pattern Support for graceful handshake degradation**:
  - Implements Noise Protocol Framework Section 10.2 fallback patterns
  - Extended pattern parser to support `fallback` modifier: `Noise_XXfallback_25519_ChaChaPoly_SHA256`
  - Added `NoiseHandshake.start_fallback(remote_ephemeral_public_key: bytes)` method
  - Responder-only operation: triggered when initiator's first message cannot be decrypted
  - Preserves initiator's ephemeral key, switches pattern, re-initializes symmetric state
  - Fallback transformation: moves initiator's first message to pre-message (e.g., XX → XXfallback)
  - Fallback validation: first message must be "e", "s", or "e, s" (no DH operations)
  - Role reversal: responder becomes effective initiator in fallback pattern (sends first)
  - Custom turn-checking logic for fallback patterns (`is_fallback` flag)
  - Extended `_process_pre_messages()` to handle ephemeral ("e") pre-messages
  - **Noise Pipes protocol**: IK → XXfallback (when wrong static key or outdated PSK)
  - Async fallback support: `AsyncNoiseHandshake.start_fallback(remote_ephemeral_public_key: bytes)`
  - Error handling: validates responder role, handshake not complete, key size matching
- `examples/fallback_example.py` demonstrating Noise Pipes protocol:
  - Alice attempts IK handshake with wrong/outdated Bob static key
  - Bob detects decryption failure and extracts Alice's ephemeral key
  - Bob initiates fallback to XXfallback using `start_fallback()`
  - Alice switches to XXfallback and reuses ephemeral keys
  - Both complete XXfallback handshake and establish transport channels
  - Educational comments explaining fallback mechanics and use cases
- `tests/test_fallback.py` with 21 comprehensive tests (100% pass rate):
  - Fallback pattern parsing: XXfallback, IKfallback, NKfallback, invalid modifiers (5 tests)
  - Token transformation: XX → XXfallback, validation that IK/NK cannot directly use fallback (5 tests)
  - Handshake setup: responder-only, completion checks, key validation, ephemeral preservation (6 tests)
  - Full handshakes: IK→XXfallback (Noise Pipes), normal XX comparison (2 tests)
  - Async support: async start_fallback() (1 test)
  - Error cases: invalid patterns, multiple fallback calls (2 tests)
- **Pre-Shared Key (PSK) support for quantum-resistant patterns**:
  - Extended pattern parser to support PSK modifiers: `psk0`, `psk1`, `psk2`, `psk3`, `psk4`
  - PSK patterns format: `Noise_XXpsk3_25519_ChaChaPoly_SHA256` (base pattern + PSK modifier)
  - Added `NoiseHandshake.set_psk(psk: bytes)` method to configure 32-byte pre-shared keys
  - PSK validation: ensures pattern uses PSK modifier and key is exactly 32 bytes
  - PSK token processing integrated into handshake message flow (automatic mixing via MixKeyAndHash)
  - PSK mixing positions: `psk0` before first message, `psk1-4` after specified message
  - Async PSK support: `AsyncNoiseHandshake.set_psk(psk: bytes)` with async/await compatibility
  - Security benefits: quantum resistance, additional authentication layer, pre-computation resistance
  - All PSK patterns work with existing transport and framing infrastructure
- `examples/psk_example.py` with 3 comprehensive PSK demonstrations:
  - **NNpsk0**: Anonymous pattern with PSK mixed before first message (2-message handshake)
  - **XXpsk3**: Mutual authentication with PSK after third message (most common PSK pattern)
  - **IKpsk2**: Known responder identity with PSK after second message
  - Educational section explaining quantum resistance and PSK security benefits
  - Use cases: IoT devices, enterprise VPNs, defense systems, embedded systems
- `tests/test_psk.py` with 22 comprehensive tests (100% pass rate):
  - PSK pattern parsing tests (valid patterns, all modifiers, invalid modifiers)
  - PSK token placement verification (psk0-4 positions)
  - PSK validation tests (size requirements, pattern requirements)
  - Complete handshake tests for NNpsk0, XXpsk3, IKpsk2 patterns
  - PSK mismatch authentication failure test
  - Transport encryption after PSK handshake
  - Multiple message exchange tests
  - Payload handling in PSK handshakes
- **High-level connection/session manager API**:
  - Created `noiseframework/connection.py` module (~654 lines)
  - `NoiseConnection` class for synchronous high-level connections
  - `AsyncNoiseConnection` class for asynchronous connections with async/await
  - Automatic handshake execution (no manual `write_message()`/`read_message()` calls)
  - Automatic transition from handshake to transport mode
  - Built-in length-prefixed message framing
  - Connection lifecycle: `connect()`, `accept()`, `send()`, `receive()`, `close()`
  - Context manager support for automatic cleanup (`with` and `async with` statements)
  - Properties for connection state and remote identity: `is_connected`, `remote_static_public_key`, `local_static_public_key`
  - Support for custom pre-generated keys (persistent identity)
  - Clear error handling with ValidationError, HandshakeError, and TransportError
  - Configurable maximum message size (default 16 MB)
  - Optional logging support
- `examples/connection_example.py` with 3 comprehensive examples:
  - Synchronous client/server example using `NoiseConnection`
  - Asynchronous client/server example using `AsyncNoiseConnection` with `asyncio`
  - Advanced example demonstrating custom keys and identity verification
- `tests/test_connection.py` with 25 comprehensive tests (100% pass rate):
  - Connection initialization and role validation
  - Error handling (invalid role, not connected, wrong methods for role)
  - Context managers (sync and async)
  - Full communication (handshake + message exchange)
  - Multiple message exchange
  - Remote static key access
  - Large message handling (100 KB+)
  - Both synchronous and asynchronous versions
- Exported `NoiseConnection` and `AsyncNoiseConnection` from main package
- **Better error messages with custom exception hierarchy**:
  - Created `noiseframework/exceptions.py` with 14 custom exception classes
  - `NoiseError` base class for all framework exceptions (enables catching all with single except clause)
  - Handshake exceptions: `RoleNotSetError`, `RoleAlreadySetError`, `WrongTurnError`, `HandshakeCompleteError`, `MissingKeyError`
  - Pattern validation exceptions: `UnsupportedPatternError`, `UnsupportedPrimitiveError`
  - State management exceptions: `NoKeySetError`, `NonceOverflowError`, `InvalidKeySizeError`
  - Transport exception: `AuthenticationError`
  - Generic exceptions: `CryptoError`, `ValidationError`
  - All exceptions include helpful context: current state, expected vs actual values, actionable suggestions
  - Error messages explain what went wrong and how to fix it (e.g., "Call generate_static_keypair() first")
  - Pattern-specific hints for common mistakes (IK/NK/XK/KK patterns requiring pre-message keys)
  - Cryptographic errors provide security-relevant context (nonce overflow, authentication failure)
- Replaced all generic `ValueError` and `RuntimeError` exceptions throughout codebase
- Updated all modules with specific custom exceptions and helpful error messages:
  - `handshake.py`: 15+ error types with state-aware messages
  - `state.py`: Key initialization and nonce overflow errors
  - `pattern.py`: Pattern validation with supported options listed
  - `crypto/cipher.py`: Key size and authentication errors with cipher context
  - `crypto/dh.py`: DH key size errors with curve-specific messages
  - `crypto/hash.py`: HKDF and hash function errors
  - `framing.py`: Message size validation errors
  - `async_support.py`: Async framing validation errors
- All custom exceptions exported from main `noiseframework` package
- `FramingError` now inherits from `NoiseError` for consistency
- `examples/error_handling_example.py` with 9 comprehensive error handling examples (~380 lines)
- `tests/test_exceptions.py` with 15 dedicated exception tests validating hierarchy, catching patterns, and exports
- Async/await support for modern Python asyncio applications:
  - `AsyncNoiseHandshake` class wrapping `NoiseHandshake` with async methods
  - `AsyncNoiseTransport` class wrapping `NoiseTransport` for async encrypted communication
  - `AsyncFramedReader` for reading framed messages from `asyncio.StreamReader`
  - `AsyncFramedWriter` for writing framed messages to `asyncio.StreamWriter`
  - Async convenience functions: `async_read_framed_message()` and `async_write_framed_message()`
  - All async operations use `asyncio.run_in_executor()` to avoid blocking event loop
  - Compatible with asyncio streams (`StreamReader`, `StreamWriter`)
  - Same security guarantees as synchronous version
- `noiseframework/async_support.py` module (~450 lines) with complete async implementation
- `examples/async_tcp_example.py` demonstrating async TCP server/client with Noise XX handshake
- `tests/test_async.py` with 21 comprehensive async tests (100% pass rate)
- Exported 6 async utilities from main package: `AsyncNoiseHandshake`, `AsyncNoiseTransport`, `AsyncFramedReader`, `AsyncFramedWriter`, `async_read_framed_message`, `async_write_framed_message`
- Complete async API documentation in `docs/API.md` with usage examples
- Async usage section in `README.md` with TCP server/client examples
- Comprehensive logging support throughout the framework:
  - Added optional `logger` parameter to `NoiseHandshake`, `NoiseTransport`, `CipherState`, and `SymmetricState` classes
  - Default logger uses module + class name pattern (e.g., `noiseframework.noise.handshake.NoiseHandshake`)
  - DEBUG-level logging for detailed operations (message sizes, tokens, nonces, key material)
  - INFO-level logging for major events (role setting, handshake completion, message exchange)
  - ERROR-level logging for validation failures and error conditions
  - WARNING-level logging for approaching nonce limits in transport mode
- `examples/logging_example.py` demonstrating logging configuration and usage
- `tests/test_logging.py` with 21 comprehensive logging tests (100% pass rate)
- Message framing utilities for stream-based transports:
  - `FramedReader` class for reading length-prefixed messages with automatic partial read handling
  - `FramedWriter` class for writing length-prefixed messages
  - `FramingError` exception for framing-related errors (oversized messages, truncated frames)
  - Helper functions `read_framed_message()` and `write_framed_message()` for single-message operations
  - 4-byte big-endian length prefix format (supports messages up to 2^32-1 bytes)
  - Default 16 MB maximum message size (configurable)
  - Message counters (`messages_sent`, `messages_received`) for debugging
  - Optional logging support in framing classes
- `examples/framed_tcp_example.py` demonstrating TCP communication with Noise + framing
- `tests/test_framing.py` with 30 comprehensive framing tests (100% pass rate)
- Exported framing utilities from main package: `FramedReader`, `FramedWriter`, `FramingError`, `read_framed_message`, `write_framed_message`

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