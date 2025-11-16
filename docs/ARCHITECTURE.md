# Architecture

This document describes the internal architecture and design of NoiseFramework.

## Table of Contents

- [Overview](#overview)
- [Design Principles](#design-principles)
- [Component Architecture](#component-architecture)
- [Data Flow](#data-flow)
- [State Management](#state-management)
- [Cryptographic Layer](#cryptographic-layer)
- [Extension Points](#extension-points)

---

## Overview

NoiseFramework is structured in three main layers:

```
┌─────────────────────────────────────────────┐
│           High-Level API                    │
│    (NoiseHandshake, NoiseTransport)        │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│         Protocol Implementation             │
│  (Pattern, SymmetricState, CipherState)    │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│       Cryptographic Primitives              │
│      (DH, Cipher, Hash functions)          │
└─────────────────────────────────────────────┘
```

Each layer has clear responsibilities and minimal coupling, making the codebase maintainable and testable.

---

## Design Principles

### 1. Separation of Concerns

Each component has a single, well-defined responsibility:

- **Crypto primitives** only perform cryptographic operations
- **Protocol layer** manages state machines and Noise specification compliance
- **High-level API** provides user-friendly interfaces

### 2. Fail-Fast Validation

Invalid inputs are rejected immediately at public API boundaries:

```python
def set_static_keypair(self, private_key: bytes, public_key: bytes) -> None:
    if len(private_key) != self.dh.dhlen:
        raise ValueError(f"Private key must be {self.dh.dhlen} bytes")
    # ... proceed with valid input
```

### 3. Type Safety

Comprehensive type hints throughout the codebase enable:
- Static analysis with mypy
- Better IDE support
- Self-documenting interfaces

### 4. No Magic

- Explicit is better than implicit
- No hidden state changes
- Clear error messages

### 5. Specification Compliance

The implementation strictly follows the [Noise Protocol Framework specification](https://noiseprotocol.org/noise.html), with references to specific sections in comments.

---

## Component Architecture

### High-Level API (`py_noise/__init__.py`, `py_noise/noise/handshake.py`)

**Purpose:** User-facing interfaces for performing handshakes and encrypted communication.

**Key Components:**

#### `NoiseHandshake`
- **Responsibility:** Orchestrate complete handshake flow
- **State:** Tracks handshake progress, keys, role
- **Methods:** `start()`, `write_message()`, `read_message()`, `to_transport()`
- **Dependencies:** Pattern parser, SymmetricState, DH functions

```python
class NoiseHandshake:
    pattern: NoisePattern
    dh: DHFunction
    cipher: CipherFunction
    hash: HashFunction
    symmetric: SymmetricState
    role: Optional[Role]
    message_index: int
    # ... keys and state
```

#### `NoiseTransport` (`py_noise/transport/transport.py`)
- **Responsibility:** Post-handshake encrypted communication
- **State:** Two CipherState instances (send/receive)
- **Methods:** `send()`, `receive()`
- **Simple wrapper:** Minimal abstraction over CipherState

---

### Protocol Layer

#### Pattern Parser (`py_noise/noise/pattern.py`)

**Purpose:** Parse and validate Noise pattern strings.

```python
parse_pattern("Noise_XX_25519_ChaChaPoly_SHA256")
# → NoisePattern(
#     handshake_pattern="XX",
#     dh_function="25519",
#     cipher_function="ChaChaPoly",
#     hash_function="SHA256"
#   )
```

**Key Functions:**
- `parse_pattern()`: Parse pattern string
- `get_pattern_tokens()`: Extract pre-message and message patterns
- Validates against known patterns

**Pattern Token Sequences:**

```python
HANDSHAKE_PATTERNS = {
    "XX": {
        "initiator_pre": [],
        "responder_pre": [],
        "messages": [
            ["e"],           # → e
            ["e", "ee", "s", "es"],  # ← e, ee, s, es
            ["s", "se"],     # → s, se
        ],
    },
    # ... more patterns
}
```

#### SymmetricState (`py_noise/noise/state.py`)

**Purpose:** Manage handshake cryptographic state per Noise spec.

**State Variables:**
- `ck`: Chaining key (for key derivation)
- `h`: Handshake hash (transcript)
- `cipher_state`: For encrypted handshake messages

**Key Operations:**

```python
class SymmetricState:
    def mix_key(self, input_key_material: bytes) -> None:
        """Mix key material into chaining key."""
        self.ck, temp_k = self.hash_fn.hkdf(self.ck, input_key_material, 2)
        self.cipher_state.initialize_key(temp_k)
    
    def mix_hash(self, data: bytes) -> None:
        """Mix data into handshake hash."""
        self.h = self.hash_fn.hash(self.h + data)
    
    def split(self) -> tuple[CipherState, CipherState]:
        """Split into two CipherStates for transport mode."""
        temp_k1, temp_k2 = self.hash_fn.hkdf(self.ck, b"", 2)
        # ... return initialized CipherStates
```

#### CipherState (`py_noise/noise/state.py`)

**Purpose:** Manage AEAD encryption with automatic nonce handling.

**State:**
- `k`: Encryption key (or None if unkeyed)
- `nonce`: 64-bit counter

**Key Methods:**

```python
class CipherState:
    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if not self.has_key():
            return plaintext  # Cleartext fallback
        ciphertext = self.cipher_fn.encrypt(self.k, self.nonce, ad, plaintext)
        self.nonce += 1
        if self.nonce >= 2**64:
            raise ValueError("Nonce overflow")
        return ciphertext
```

---

### Cryptographic Layer

All cryptographic operations are delegated to the `cryptography` library.

#### DH Functions (`py_noise/crypto/dh.py`)

**Interface:**

```python
class DHFunction:
    name: str
    dhlen: int  # Key length in bytes
    
    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate (private_key, public_key)."""
    
    def dh(self, private_key: bytes, public_key: bytes) -> bytes:
        """Compute shared secret."""
```

**Implementations:**
- `Curve25519`: X25519, 32-byte keys
- `Curve448`: X448, 56-byte keys

#### Cipher Functions (`py_noise/crypto/cipher.py`)

**Interface:**

```python
class CipherFunction:
    name: str
    
    def encrypt(self, key: bytes, nonce: int, ad: bytes, plaintext: bytes) -> bytes:
        """AEAD encryption."""
    
    def decrypt(self, key: bytes, nonce: int, ad: bytes, ciphertext: bytes) -> bytes:
        """AEAD decryption and verification."""
```

**Implementations:**
- `ChaChaPoly`: ChaCha20-Poly1305
- `AESGCM`: AES-256-GCM

**Nonce Encoding:**
```python
# Noise uses 8-byte little-endian + 4 zero bytes
nonce_bytes = nonce.to_bytes(8, "little") + b"\x00\x00\x00\x00"
```

#### Hash Functions (`py_noise/crypto/hash.py`)

**Interface:**

```python
class HashFunction:
    name: str
    hashlen: int   # Output length
    blocklen: int  # Block size
    
    def hash(self, data: bytes) -> bytes:
        """Cryptographic hash."""
    
    def hmac_hash(self, key: bytes, data: bytes) -> bytes:
        """HMAC-HASH."""
    
    def hkdf(self, chaining_key: bytes, input_key_material: bytes, 
             num_outputs: int) -> tuple:
        """HKDF key derivation (Noise variant)."""
```

**Implementations:**
- `SHA256`, `SHA512`
- `BLAKE2s`, `BLAKE2b`

---

## Data Flow

### Handshake Flow (XX Pattern)

```
Initiator                           Responder
─────────                           ─────────

1. Generate ephemeral
2. write_message(b"")
   → e
   → MixHash(e.public_key)
                              ──────────────→
                                        3. read_message(msg1)
                                           → MixHash(re.public_key)
                                        
                                        4. Generate ephemeral
                                        5. DH(e, re) → ee
                                        6. write_message(b"")
                                           → e, ee, s, es
                              ←──────────────
7. read_message(msg2)
   → Parse e, s
   → DH(e, re) → ee
   → DH(e, rs) → es

8. write_message(b"")
   → s, se
   → DH(s, re) → se
                              ──────────────→
                                        9. read_message(msg3)
                                           → Parse s
                                           → DH(re, s) → se

10. handshake_finished = True       11. handshake_finished = True
11. to_transport()                   12. to_transport()
```

### Key Derivation (HKDF Chain)

```
Initial State:
  ck = HASHLEN zeros
  h = Hash(protocol_name)

After MixKey(dh_output):
  ck, temp_k = HKDF(ck, dh_output, 2)
  cipher.key ← temp_k

At Split:
  temp_k1, temp_k2 = HKDF(ck, b"", 2)
  send_cipher.key ← temp_k1
  recv_cipher.key ← temp_k2
```

### Message Format

**Unencrypted handshake message:**
```
[ephemeral_key (0 or dhlen bytes)]
[static_key (0 or dhlen bytes, possibly encrypted)]
[payload (0+ bytes, possibly encrypted)]
```

**Encrypted transport message:**
```
[ciphertext (len(plaintext) bytes)]
[authentication_tag (16 bytes)]
```

---

## State Management

### Handshake State Machine

```
[Created] 
    ↓ start()
[Started]
    ↓ write_message() / read_message()
[In Progress] ← (loop for pattern length)
    ↓ final message processed
[Finished]
    ↓ to_transport()
[Transport Mode]
```

**State Transitions:**
- Invalid transitions raise `ValueError`
- State is tracked via `message_index` and `handshake_finished`

### Error States

```python
# Common error conditions:
if not self.role:
    raise ValueError("Role not set - call set_as_initiator/responder")

if self.handshake_complete:
    raise ValueError("Handshake already complete")

if self.message_index >= len(self.message_patterns):
    raise ValueError("Handshake already finished")
```

---

## Cryptographic Layer

### Key Hierarchy

```
Static Keys (long-term)
    ├─ Initiator static (s)
    └─ Responder static (rs)

Ephemeral Keys (per-session)
    ├─ Initiator ephemeral (e)
    └─ Responder ephemeral (re)

Derived Keys
    ├─ Chaining Key (ck) ─→ HKDF ─→ temp_k
    └─ Handshake Hash (h) ─→ Transcript

Transport Keys (post-handshake)
    ├─ Send cipher key (temp_k1)
    └─ Receive cipher key (temp_k2)
```

### Token Processing

Each token in a message pattern triggers specific operations:

| Token | Operation |
|-------|-----------|
| `e` | Send/receive ephemeral public key, MixHash(e) |
| `s` | Send/receive static public key (encrypted), MixHash(s) |
| `ee` | MixKey(DH(e, re)) |
| `es` | MixKey(DH(e, rs)) or MixKey(DH(s, re)) |
| `se` | MixKey(DH(s, re)) or MixKey(DH(e, rs)) |
| `ss` | MixKey(DH(s, rs)) |

**Implementation:**

```python
def process_token(self, token: str, sending: bool):
    if token == "e":
        if sending:
            self.symmetric.mix_hash(self.ephemeral_public)
        else:
            self.symmetric.mix_hash(remote_ephemeral)
    elif token == "ee":
        shared = self.dh.dh(self.ephemeral_private, self.remote_ephemeral_public)
        self.symmetric.mix_key(shared)
    # ... etc
```

---

## Extension Points

### Adding New Patterns

1. Add pattern definition to `HANDSHAKE_PATTERNS` in `pattern.py`:

```python
HANDSHAKE_PATTERNS = {
    "CustomPattern": {
        "initiator_pre": [...],
        "responder_pre": [...],
        "messages": [
            [...],  # Message 1 tokens
            [...],  # Message 2 tokens
        ],
    },
}
```

2. Update tests in `tests/test_pattern.py`

### Adding New Crypto Primitives

#### New DH Function

1. Implement `DHFunction` interface in `crypto/dh.py`
2. Add to `DH_FUNCTIONS` dictionary
3. Update `get_dh_function()`
4. Add tests

#### New Cipher

1. Implement `CipherFunction` interface in `crypto/cipher.py`
2. Add to `CIPHER_FUNCTIONS` dictionary
3. Update `get_cipher_function()`
4. Add tests

#### New Hash

1. Implement `HashFunction` interface in `crypto/hash.py`
2. Add to `HASH_FUNCTIONS` dictionary
3. Update `get_hash_function()`
4. Add tests

### Custom Transport Layer

Extend `NoiseTransport` for specific needs:

```python
class CustomTransport(NoiseTransport):
    def send_with_framing(self, plaintext: bytes) -> bytes:
        """Add length prefix."""
        ciphertext = self.send(plaintext)
        return len(ciphertext).to_bytes(4, 'big') + ciphertext
    
    def receive_with_framing(self, data: bytes) -> bytes:
        """Parse length prefix."""
        length = int.from_bytes(data[:4], 'big')
        ciphertext = data[4:4+length]
        return self.receive(ciphertext)
```

---

## Testing Strategy

### Unit Tests
- Each component tested independently
- Mock external dependencies
- Cover success and error paths

### Integration Tests
- Full handshake flows
- Multiple patterns tested
- Cross-role communication

### Property-Based Tests (Hypothesis)
- Pattern parsing with random inputs
- Cryptographic primitive properties
- State machine invariants

### Test Structure

```
tests/
├── test_dh.py          # DH functions
├── test_cipher.py      # Cipher functions
├── test_hash.py        # Hash functions
├── test_pattern.py     # Pattern parsing
├── test_state.py       # SymmetricState, CipherState
├── test_handshake.py   # NoiseHandshake
├── test_transport.py   # NoiseTransport
└── test_cli.py         # CLI tool
```

---

## Performance Considerations

### Hot Paths

1. **Encryption/Decryption**: Called for every transport message
   - Use hardware acceleration when available (AES-NI)
   - Consider ChaCha20 for software-only implementations

2. **DH Operations**: Called multiple times during handshake
   - Already optimized in `cryptography` library
   - Profile if extending to new curves

3. **Hashing**: Called frequently for MixHash operations
   - BLAKE2 variants often faster than SHA-2
   - Hardware acceleration available for SHA-256

### Memory Management

- Keys stored as bytes (immutable)
- No unnecessary copies in hot paths
- Nonce stored as integer (not bytes)

### Benchmarking

```bash
python -m pytest tests/ --benchmark-only
```

---

## Security Architecture

### Defense in Depth

1. **Input Validation**: All public APIs validate inputs
2. **Type Safety**: Type hints catch errors early
3. **Fail-Fast**: Invalid state transitions raise immediately
4. **Vetted Crypto**: All primitives from `cryptography` library
5. **Specification Compliance**: Follow Noise spec precisely

### Attack Surface

**Minimal public API:**
- `NoiseHandshake`: Handshake orchestration
- `NoiseTransport`: Post-handshake encryption
- Pattern parser: String validation only

**No exposure of:**
- Raw cryptographic operations
- Internal state management
- Key derivation details

### Side Channels

**Current status:** Not constant-time

**Considerations:**
- Python not ideal for timing-resistant code
- Rely on `cryptography` library primitives
- Future: Consider timing analysis of high-level logic

---

## Future Enhancements

### Planned Features
- PSK (pre-shared key) variants
- Fallback patterns
- Rekey support
- Async I/O support

### Extension Ideas
- Protocol composition (noise over noise)
- Custom token support
- Hardware security module (HSM) integration
- Performance profiling tools

---

## References

- **Noise Protocol Specification**: https://noiseprotocol.org/noise.html
- **pyca/cryptography**: https://cryptography.io/
- **Test Vectors**: https://github.com/noiseprotocol/noise_wiki/wiki

---

For questions about the architecture, open a discussion on [GitHub](https://github.com/juliuspleunes4/noiseframework/discussions).
