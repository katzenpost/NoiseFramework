# Py-Noise

[![PyPI version](https://img.shields.io/pypi/v/py-noise.svg)](https://pypi.org/project/py-noise/)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/juliuspleunes4/pynoise)](https://github.com/juliuspleunes4/pynoise/issues)
[![GitHub Stars](https://img.shields.io/github/stars/juliuspleunes4/pynoise)](https://github.com/juliuspleunes4/pynoise/stargazers)
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
- [Usage Examples](#-usage-examples)
  - [Basic Handshake (Noise_XX)](#basic-handshake-noise_xx)
  - [Pre-Shared Key Pattern (Noise_IK)](#pre-shared-key-pattern-noise_ik)
  - [Transport Layer Encryption](#transport-layer-encryption)
- [Supported Patterns](#-supported-patterns)
- [Cryptographic Primitives](#-cryptographic-primitives)
- [Architecture](#-architecture)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [Security](#-security)
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
git clone https://github.com/juliuspleunes4/pynoise.git
cd pynoise
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

# Initialize a Noise handshake with the XX pattern
handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")

# Perform handshake steps
# ... (see detailed examples below)

# Create a transport channel for encrypted communication
transport = handshake.to_transport()

# Send encrypted messages
transport.send(b"Hello, secure world!")

# Receive encrypted messages
message = transport.receive()
```

### Command-Line Interface

```bash
# Perform a handshake
py-noise handshake --pattern Noise_XX_25519_ChaChaPoly_SHA256

# Encrypt a file
py-noise encrypt --in message.txt --out message.enc

# Decrypt a file
py-noise decrypt --in message.enc --out message.txt

# Generate key pairs
py-noise keygen --type 25519 --out keypair.json
```

---

## 💡 Usage Examples

### Basic Handshake (Noise_XX)

The `XX` pattern provides mutual authentication with no prior knowledge required:

```python
from py_noise import NoiseHandshake

# === INITIATOR SIDE ===
initiator = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
initiator.set_as_initiator()

# Generate ephemeral key pair
initiator.initialize()

# Send first message (-> e)
msg1 = initiator.write_message(b"")

# === RESPONDER SIDE ===
responder = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
responder.set_as_responder()

# Process first message
responder.read_message(msg1)

# Send second message (-> e, ee, s, es)
msg2 = responder.write_message(b"")

# === INITIATOR SIDE (continued) ===
# Process second message
initiator.read_message(msg2)

# Send third message (-> s, se)
msg3 = initiator.write_message(b"")

# === RESPONDER SIDE (continued) ===
# Process third message
responder.read_message(msg3)

# Both sides now have a secure channel
initiator_transport = initiator.to_transport()
responder_transport = responder.to_transport()

# Send encrypted data
ciphertext = initiator_transport.send(b"Secret payload")
plaintext = responder_transport.receive(ciphertext)
```

### Pre-Shared Key Pattern (Noise_IK)

The `IK` pattern allows the initiator to know the responder's static public key in advance:

```python
from py_noise import NoiseHandshake

# Generate or load responder's static key pair
responder_static_public = b"..." # 32 bytes

# === INITIATOR SIDE ===
initiator = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
initiator.set_as_initiator()
initiator.set_remote_static_public_key(responder_static_public)
initiator.initialize()

# Perform handshake
msg1 = initiator.write_message(b"Hello")

# === RESPONDER SIDE ===
responder = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
responder.set_as_responder()
responder.set_static_keypair(private_key, public_key)
responder.initialize()

payload = responder.read_message(msg1)
msg2 = responder.write_message(b"Welcome")

# Continue handshake...
```

### Transport Layer Encryption

After handshake completion, use the transport layer for ongoing encrypted communication:

```python
# After successful handshake
transport = handshake.to_transport()

# Encrypt and send data
ciphertext = transport.send(b"Sensitive data")

# Decrypt received data
plaintext = transport.receive(ciphertext)

# Transport automatically handles nonces and authentication
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
git clone https://github.com/juliuspleunes4/pynoise.git
cd pynoise
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

---

## 🔒 Security

### Reporting Vulnerabilities

If you discover a security vulnerability, please **DO NOT** open a public issue. Instead:

1. Email security concerns to: [security@example.com]
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
- All contributors who have helped improve this project

---

## 📚 Resources

- [Noise Protocol Framework Specification](https://noiseprotocol.org/noise.html)
- [Noise Explorer](https://noiseexplorer.com/) - Formal verification of Noise patterns
- [Noise Wiki](https://github.com/noiseprotocol/noise_wiki/wiki)
- [PyCA Cryptography Documentation](https://cryptography.io/)

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/juliuspleunes4/pynoise/issues)
- **Discussions**: [GitHub Discussions](https://github.com/juliuspleunes4/pynoise/discussions)
- **Documentation**: [Full Documentation](https://pynoise.readthedocs.io/)

---

<p align="center">
  <strong>Built with ❤️ for secure communications</strong>
</p>

<p align="center">
  <sub>If you find this project useful, please consider giving it a ⭐️</sub>
</p>
