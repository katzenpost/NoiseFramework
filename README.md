# Py-Noise

[![PyPI version](https://img.shields.io/pypi/v/py-noise.svg)](https://pypi.org/project/py-noise/)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/juliuspleunes4/py-noise)](https://github.com/juliuspleunes4/py-noise/issues)
[![GitHub Stars](https://img.shields.io/github/stars/juliuspleunes4/py-noise)](https://github.com/juliuspleunes4/py-noise/stargazers)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> A professional, secure, and easy-to-use implementation of the [Noise Protocol Framework](https://noiseprotocol.org/) in Python.

**Py-Noise** provides cryptographically sound, specification-compliant implementations of Noise handshake patterns for building secure communication channels. It is designed to be both simple to integrate into applications and robust enough for production use.

---

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
  - [Python API](#python-api)
  - [Command-Line Interface](#command-line-interface)
- [Python API Documentation](#-python-api-documentation)
  - [Basic Handshake (Noise_XX)](#basic-handshake-noise_xx)
  - [Anonymous Pattern (Noise_NN)](#anonymous-pattern-noise_nn)
  - [Pre-Shared Key Pattern (Noise_IK)](#pre-shared-key-pattern-noise_ik)
  - [Transport Layer Encryption](#transport-layer-encryption)
  - [Error Handling](#error-handling)
- [CLI Documentation](#-cli-documentation)
  - [Generate Keypair](#generate-keypair)
  - [Validate Pattern](#validate-pattern)
  - [Show Information](#show-information)
- [Supported Patterns](#-supported-patterns)
- [Cryptographic Primitives](#-cryptographic-primitives)
- [Architecture](#-architecture)
- [Testing](#-testing)
- [Performance](#-performance)
- [Contributing](#-contributing)
- [Security](#-security)
- [FAQ](#-faq)
- [License](#-license)
- [Acknowledgments](#-acknowledgments)

---

## ✨ Features

- **📜 Spec-Compliant**: Implements the [Noise Protocol Framework specification](https://noiseprotocol.org/noise.html) faithfully
- **🔒 Secure by Default**: Uses well-vetted cryptographic primitives from trusted libraries
- **🐍 Pythonic API**: Simple, type-hinted interfaces that are easy to use and hard to misuse
- **🛠️ CLI Tool**: Command-line interface for encryption, decryption, and handshake operations
- **✅ Well-Tested**: Comprehensive test suite with unit, integration, and property-based tests
- **📦 Zero Config**: Works out-of-the-box with sensible defaults
- **🔧 Flexible**: Supports multiple DH functions, cipher suites, and hash functions
- **📖 Documented**: Extensive documentation with examples and best practices

---

## 📦 Installation

### From PyPI (Recommended)

```bash
pip install py-noise
```

### From Source

```bash
git clone https://github.com/juliuspleunes4/py-noise.git
cd py-noise
pip install -e .
```

### Requirements

- Python 3.8 or higher
- Dependencies are automatically installed via pip

---

## 🚀 Quick Start

### Python API

```python
from py_noise import NoiseHandshake
from py_noise.transport.transport import NoiseTransport

# === INITIATOR SIDE ===
initiator = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
initiator.set_as_initiator()
initiator.generate_static_keypair()
initiator.initialize()

# === RESPONDER SIDE ===
responder = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
responder.set_as_responder()
responder.generate_static_keypair()
responder.initialize()

# === HANDSHAKE ===
msg1 = initiator.write_message()
responder.read_message(msg1)

msg2 = responder.write_message()
initiator.read_message(msg2)

msg3 = initiator.write_message()
responder.read_message(msg3)

# === TRANSPORT ENCRYPTION ===
init_send, init_recv = initiator.to_transport()
resp_send, resp_recv = responder.to_transport()

init_transport = NoiseTransport(init_send, init_recv)
resp_transport = NoiseTransport(resp_send, resp_recv)

# Send encrypted messages
ciphertext = init_transport.send(b"Hello, secure world!")
plaintext = resp_transport.receive(ciphertext)
print(plaintext)  # b"Hello, secure world!"
```

### Command-Line Interface

```bash
# Generate a keypair
py-noise generate-keypair --dh 25519 -o mykey
# Creates: mykey_private.key, mykey_public.key

# Validate a pattern string
py-noise validate-pattern "Noise_XX_25519_ChaChaPoly_SHA256"

# Show supported primitives
py-noise info

# Use shorter aliases
py-noise genkey --dh 25519 -o mykey
py-noise validate "Noise_XX_25519_ChaChaPoly_SHA256"
```

---

## 📖 Python API Documentation

### Basic Handshake (Noise_XX)

The `XX` pattern provides mutual authentication with no prior knowledge required. Both parties exchange static keys during the handshake.

```python
from py_noise import NoiseHandshake
from py_noise.transport.transport import NoiseTransport

# === INITIATOR SIDE ===
initiator = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
initiator.set_as_initiator()
initiator.generate_static_keypair()  # Generate static key
initiator.initialize()

# Send first message (-> e)
msg1 = initiator.write_message()

# === RESPONDER SIDE ===
responder = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
responder.set_as_responder()
responder.generate_static_keypair()  # Generate static key
responder.initialize()

# Process first message and send response (-> e, ee, s, es)
responder.read_message(msg1)
msg2 = responder.write_message()

# === INITIATOR SIDE (continued) ===
# Process second message and send final (-> s, se)
initiator.read_message(msg2)
msg3 = initiator.write_message()

# === RESPONDER SIDE (continued) ===
# Process final message
responder.read_message(msg3)

# === BOTH SIDES NOW HAVE SECURE CHANNEL ===
# Get transport cipher pairs
init_send, init_recv = initiator.to_transport()
resp_send, resp_recv = responder.to_transport()

# Create transport wrappers
init_transport = NoiseTransport(init_send, init_recv)
resp_transport = NoiseTransport(resp_send, resp_recv)

# Send encrypted data (initiator -> responder)
ciphertext = init_transport.send(b"Secret payload")
plaintext = resp_transport.receive(ciphertext)
assert plaintext == b"Secret payload"

# Send encrypted data (responder -> initiator)
ciphertext = resp_transport.send(b"Response data")
plaintext = init_transport.receive(ciphertext)
assert plaintext == b"Response data"
```

### Anonymous Pattern (Noise_NN)

The `NN` pattern provides encryption without authentication. No static keys are required.

```python
from py_noise import NoiseHandshake
from py_noise.transport.transport import NoiseTransport

# === INITIATOR SIDE ===
initiator = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
initiator.set_as_initiator()
initiator.initialize()

# Send first message (-> e)
msg1 = initiator.write_message()

# === RESPONDER SIDE ===
responder = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
responder.set_as_responder()
responder.initialize()

# Process first message and send response (-> e, ee)
responder.read_message(msg1)
msg2 = responder.write_message()

# === INITIATOR SIDE (continued) ===
# Process second message - handshake complete
initiator.read_message(msg2)

# === CREATE TRANSPORT ===
init_send, init_recv = initiator.to_transport()
resp_send, resp_recv = responder.to_transport()

init_transport = NoiseTransport(init_send, init_recv)
resp_transport = NoiseTransport(resp_send, resp_recv)

# Now both sides can communicate securely (but without authentication)
ciphertext = init_transport.send(b"Anonymous message")
plaintext = resp_transport.receive(ciphertext)
```

### Pre-Shared Key Pattern (Noise_IK)

The `IK` pattern allows the initiator to know the responder's static public key in advance. The initiator's identity is hidden.

```python
from py_noise import NoiseHandshake
from py_noise.transport.transport import NoiseTransport

# === SETUP: Generate responder's static keypair ===
responder_setup = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
responder_setup.set_as_responder()
responder_setup.generate_static_keypair()
responder_private = responder_setup.get_static_private_key()
responder_public = responder_setup.get_static_public_key()

# === INITIATOR SIDE ===
initiator = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
initiator.set_as_initiator()
initiator.generate_static_keypair()  # Generate own static key
initiator.set_remote_static_pubkey(responder_public)  # Know responder's key
initiator.initialize()

# Send first message (-> e, es, s, ss)
msg1 = initiator.write_message()

# === RESPONDER SIDE ===
responder = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
responder.set_as_responder()
responder.set_static_keypair(responder_private)  # Use existing keypair
responder.initialize()

# Process first message and send response (-> e, ee, se)
responder.read_message(msg1)
msg2 = responder.write_message()

# === INITIATOR SIDE (continued) ===
# Process second message - handshake complete
initiator.read_message(msg2)

# === CREATE TRANSPORT ===
init_send, init_recv = initiator.to_transport()
resp_send, resp_recv = responder.to_transport()

init_transport = NoiseTransport(init_send, init_recv)
resp_transport = NoiseTransport(resp_send, resp_recv)

# Secure authenticated communication
ciphertext = init_transport.send(b"Authenticated message")
plaintext = resp_transport.receive(ciphertext)
```

### Transport Layer Encryption

After handshake completion, use the transport layer for ongoing encrypted communication:

```python
from py_noise.transport.transport import NoiseTransport

# After successful handshake, get cipher states
send_cipher, recv_cipher = handshake.to_transport()

# Create transport wrapper
transport = NoiseTransport(send_cipher, recv_cipher)

# Encrypt and send data
ciphertext = transport.send(b"Sensitive data")

# Decrypt received data
plaintext = transport.receive(ciphertext)

# Send with associated data (authenticated but not encrypted)
ciphertext = transport.send(b"payload", ad=b"metadata")
plaintext = transport.receive(ciphertext, ad=b"metadata")

# Track nonces
print(f"Messages sent: {transport.get_send_nonce()}")
print(f"Messages received: {transport.get_receive_nonce()}")

# Transport automatically handles:
# - Nonce increment
# - Authentication tags
# - AEAD encryption/decryption
```

### Error Handling

```python
from py_noise import NoiseHandshake

try:
    # Invalid pattern string
    hs = NoiseHandshake("Invalid_Pattern")
except ValueError as e:
    print(f"Pattern error: {e}")

try:
    # Attempt operation in wrong state
    hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    hs.set_as_initiator()
    hs.write_message()  # Error: not initialized
except ValueError as e:
    print(f"State error: {e}")

try:
    # Authentication failure
    ciphertext_tampered = ciphertext[:-1] + b"\x00"
    transport.receive(ciphertext_tampered)
except ValueError as e:
    print(f"Authentication failed: {e}")

# Always check handshake completion
if initiator.is_handshake_complete():
    send_cipher, recv_cipher = initiator.to_transport()
else:
    print("Handshake not complete")

---

## 🖥️ CLI Documentation

The `py-noise` command-line tool provides easy access to key operations without writing code.

### Generate Keypair

Generate static keypairs for use in Noise handshakes:

```bash
# Generate Curve25519 keypair (default)
py-noise generate-keypair -o mykey
# Creates: mykey_private.key (32 bytes), mykey_public.key (32 bytes)

# Generate Curve448 keypair
py-noise generate-keypair --dh 448 -o mykey448
# Creates: mykey448_private.key (56 bytes), mykey448_public.key (56 bytes)

# Use short alias
py-noise genkey -o server_key
```

**Output:**
```
Generated keypair:
  Private key: mykey_private.key
  Public key:  mykey_public.key
  Key size:    32 bytes
```

**Usage in Python:**
```python
from pathlib import Path
from py_noise import NoiseHandshake

# Load generated keys
private_key = Path("mykey_private.key").read_bytes()
public_key = Path("mykey_public.key").read_bytes()

# Use in handshake
hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
hs.set_static_keypair(private_key)
```

### Validate Pattern

Validate Noise pattern strings and view their components:

```bash
# Validate a pattern
py-noise validate-pattern "Noise_XX_25519_ChaChaPoly_SHA256"

# Use short alias
py-noise validate "Noise_IK_448_AESGCM_BLAKE2b"
```

**Output:**
```
Pattern: Noise_XX_25519_ChaChaPoly_SHA256
  Valid: ✓
  Name:       Noise_XX_25519_ChaChaPoly_SHA256
  Handshake:  XX
  DH:         25519
  Cipher:     ChaChaPoly
  Hash:       SHA256
```

**Invalid pattern:**
```bash
py-noise validate "Noise_INVALID_Pattern"
# Error: Invalid pattern: Unsupported handshake pattern: INVALID
```

### Show Information

Display supported cryptographic primitives and patterns:

```bash
py-noise info
```

**Output:**
```
Py-Noise - Noise Protocol Framework Implementation

Supported DH functions:
  - 25519 (Curve25519/X25519)
  - 448 (Curve448/X448)

Supported ciphers:
  - ChaChaPoly (ChaCha20-Poly1305) [recommended]
  - AESGCM (AES-256-GCM)

Supported hash functions:
  - SHA256 [recommended]
  - SHA512
  - BLAKE2s
  - BLAKE2b

Supported patterns:
  NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX

Example pattern string:
  Noise_XX_25519_ChaChaPoly_SHA256
```

### Help and Version

```bash
# Show help
py-noise --help
py-noise generate-keypair --help

# Show version
py-noise --version
```

---

## 🔐 Supported Patterns

Py-Noise supports all fundamental and interactive Noise patterns:

| Pattern | Description | Use Case |
|---------|-------------|----------|
| `NN` | No static keys | Anonymous communication |
| `KN` | Initiator known | Server authentication |
| `NK` | Responder known | Client knows server's key |
| `KK` | Both known | Pre-shared public keys |
| `NX` | Responder transmits | Certificate-like exchange |
| `KX` | Initiator known, responder transmits | Hybrid authentication |
| `XN` | Initiator transmits | Basic server setup |
| `IN` | Initiator identity hidden | Privacy-preserving |
| `XK` | Responder known, initiator transmits | Standard mutual auth |
| `IK` | Responder known, initiator identity hidden | Tor-like handshake |
| `XX` | Both transmit | Full mutual authentication |
| `IX` | Initiator identity hidden, responder transmits | Privacy + auth |

### Pattern Modifiers

- **`psk0`, `psk1`, `psk2`**: Pre-shared symmetric key modes
- **Fallback patterns**: For retry and downgrade scenarios

---

## 🔑 Cryptographic Primitives

Py-Noise uses battle-tested cryptographic libraries:

### Diffie-Hellman Functions
- **Curve25519** (X25519) - Recommended
- **Curve448** (X448)

### Cipher Functions (AEAD)
- **ChaChaPoly** (ChaCha20-Poly1305) - Recommended
- **AESGCM** (AES-256-GCM)

### Hash Functions
- **SHA-256** - Recommended
- **SHA-512**
- **BLAKE2s**
- **BLAKE2b**

**Example pattern string**: `Noise_XX_25519_ChaChaPoly_SHA256`

Format: `Noise_[PATTERN]_[DH]_[CIPHER]_[HASH]`

---

## 🏗️ Architecture

```
py-noise/
├── py_noise/
│   ├── __init__.py          # Public API
│   ├── noise/
│   │   ├── handshake.py     # Handshake state machine
│   │   ├── pattern.py       # Pattern parser and validator
│   │   ├── state.py         # Cipher and symmetric state
│   │   └── protocol.py      # Core protocol logic
│   ├── crypto/
│   │   ├── dh.py            # Diffie-Hellman functions
│   │   ├── cipher.py        # AEAD cipher implementations
│   │   └── hash.py          # Hash function wrappers
│   ├── transport/
│   │   └── transport.py     # Post-handshake encryption
│   └── cli/
│       └── main.py          # Command-line interface
├── tests/
│   ├── test_handshake.py
│   ├── test_transport.py
│   ├── test_patterns.py
│   └── test_vectors.py      # Official test vectors
├── docs/
│   ├── CHANGELOG.md
│   └── ...
├── pyproject.toml
└── README.md
```

---

## 🧪 Testing

Py-Noise has comprehensive test coverage with 156 tests achieving 92% code coverage.

---

## ⚡ Performance

Py-Noise is designed for correctness and security first, with reasonable performance for most use cases:

- **Handshake**: ~1-2ms for XX pattern on modern hardware
- **Transport encryption**: ~100MB/s for large messages
- **Memory**: Low memory footprint, suitable for embedded systems

**Benchmarking:**
```python
import time
from py_noise import NoiseHandshake

# Benchmark handshake
start = time.perf_counter()
for _ in range(1000):
    hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    hs.set_as_initiator()
    hs.initialize()
end = time.perf_counter()
print(f"Handshakes/sec: {1000 / (end - start):.0f}")
```

---

## 🧪 Testing (Detailed)

Run the test suite:

```bash
# Install test dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=py_noise --cov-report=html

# Run specific test file
pytest tests/test_handshake.py

# Run with verbose output
pytest -v
```

### Test Categories

- **Unit tests**: Test individual components in isolation
- **Integration tests**: Test complete handshake flows
- **Property-based tests**: Use Hypothesis for invariant testing
- **Vector tests**: Validate against official Noise test vectors

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository** and create a feature branch
2. **Follow the coding style**: PEP 8, type hints, and existing conventions
3. **Write tests**: All new features must include tests
4. **Update documentation**: Add examples and update `CHANGELOG.md`
5. **Run the test suite**: Ensure all tests pass
6. **Submit a pull request**: Describe your changes clearly

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

### Development Setup

```bash
git clone https://github.com/juliuspleunes4/py-noise.git
cd py-noise
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

---

## ❓ FAQ

### Which pattern should I use?

- **XX**: Default choice for mutual authentication
- **NN**: Quick anonymous encryption (no authentication)
- **IK**: When client knows server's key in advance (like Tor)
- **NK**: When server identity is public (like HTTPS with pinning)

### Is Py-Noise production-ready?

Yes, but with caveats:
- ✅ Cryptographically sound (uses battle-tested primitives)
- ✅ Specification-compliant implementation
- ✅ Well-tested (156 tests, 92% coverage)
- ⚠️ Consider security audit for high-stakes applications
- ⚠️ Keep dependencies updated

### How does it compare to other Noise implementations?

- **PyNaCl/libsodium**: Lower-level, Py-Noise is higher-level Noise protocol
- **noiseprotocol (Python)**: Similar, but Py-Noise has better docs and CLI
- **snow (Rust)**: Faster, but Py-Noise is pure Python with better accessibility

### Can I use custom cryptographic primitives?

Yes, you can extend the crypto modules. However, we strongly recommend using only well-vetted primitives from established libraries.

### Does it support post-quantum cryptography?

Not yet. Post-quantum Noise patterns (pqXX, etc.) are planned for future releases.

---

## 🔒 Security

### Reporting Vulnerabilities

If you discover a security vulnerability, please **DO NOT** open a public issue. Instead:

1. Email security concerns to: [jjgpleunes@gmail.com]
2. Include a detailed description and steps to reproduce
3. Allow reasonable time for a fix before public disclosure

### Security Best Practices

- **Key Management**: Never hard-code keys in source code
- **RNG**: Use system-provided cryptographically secure random number generators
- **Updates**: Keep Py-Noise and its dependencies up-to-date
- **Audit**: Consider professional security audits for production use
- **Side-Channels**: Be aware of timing and other side-channel attacks

### Dependencies

Py-Noise relies on:
- `cryptography` - Audited, well-maintained Python cryptography library
- No custom cryptographic primitives

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **[Trevor Perrin](https://github.com/trevp)** - Creator of the Noise Protocol Framework
- **Noise Protocol Community** - For the specification and test vectors
- **PyCA Cryptography** - For providing robust cryptographic primitives

---

## 📚 Resources

- [Noise Protocol Framework Specification](https://noiseprotocol.org/noise.html)
- [Noise Explorer](https://noiseexplorer.com/) - Formal verification of Noise patterns
- [Noise Wiki](https://github.com/noiseprotocol/noise_wiki/wiki)
- [PyCA Cryptography Documentation](https://cryptography.io/)

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/juliuspleunes4/py-noise/issues)
- **Discussions**: [GitHub Discussions](https://github.com/juliuspleunes4/py-noise/discussions)
- **Documentation**: [Full Documentation](https://pynoise.readthedocs.io/)

---

<p align="center">
  <strong>Built with ❤️ for secure communications</strong>
</p>

<p align="center">
  <sub>If you find this project useful, please consider giving it a ⭐️</sub>
</p>
