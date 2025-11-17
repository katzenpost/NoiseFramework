# API Reference

Complete API documentation for NoiseFramework.

## Table of Contents

- [High-Level API](#high-level-api)
  - [NoiseHandshake](#noisehandshake)
  - [NoiseTransport](#noisetransport)
- [Pattern System](#pattern-system)
  - [Pattern Parser](#pattern-parser)
  - [Supported Patterns](#supported-patterns)
- [Cryptographic Primitives](#cryptographic-primitives)
  - [Diffie-Hellman Functions](#diffie-hellman-functions)
  - [AEAD Ciphers](#aead-ciphers)
  - [Hash Functions](#hash-functions)
- [Low-Level Components](#low-level-components)
  - [SymmetricState](#symmetricstate)
  - [CipherState](#cipherstate)

---

## High-Level API

The high-level API provides simple interfaces for performing Noise handshakes and encrypted communication.

### NoiseHandshake

Main class for orchestrating Noise Protocol handshakes.

#### Import

```python
from noiseframework import NoiseHandshake
```

#### Constructor

```python
NoiseHandshake(pattern_string: str) -> NoiseHandshake
```

Initialize a Noise handshake with a pattern string.

**Parameters:**
- `pattern_string` (str): Noise pattern in format `Noise_PATTERN_DH_CIPHER_HASH`
  - Example: `"Noise_XX_25519_ChaChaPoly_SHA256"`

**Raises:**
- `ValueError`: If pattern string is invalid or uses unsupported algorithms

**Example:**
```python
handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
```

#### Methods

##### `set_as_initiator()`

```python
set_as_initiator() -> None
```

Configure this handshake instance as the initiator (client).

**Raises:**
- `ValueError`: If role is already set

**Example:**
```python
handshake.set_as_initiator()
```

##### `set_as_responder()`

```python
set_as_responder() -> None
```

Configure this handshake instance as the responder (server).

**Raises:**
- `ValueError`: If role is already set

**Example:**
```python
handshake.set_as_responder()
```

##### `set_static_keypair(private_key, public_key)`

```python
set_static_keypair(private_key: bytes, public_key: bytes) -> None
```

Set the static (long-term) key pair for this handshake.

**Parameters:**
- `private_key` (bytes): Private key (length depends on DH function)
- `public_key` (bytes): Public key (length depends on DH function)

**Raises:**
- `ValueError`: If key sizes are incorrect

**Example:**
```python
# Generate and set in one step
handshake.generate_static_keypair()

# Or set explicitly
private_key = b'\x00' * 32  # Your key material
public_key = b'\x00' * 32
handshake.set_static_keypair(private_key, public_key)
```

##### `set_remote_static_public_key(public_key)`

```python
set_remote_static_public_key(public_key: bytes) -> None
```

Set the remote peer's known static public key (for patterns like IK, IKpsk).

**Parameters:**
- `public_key` (bytes): Remote static public key

**Raises:**
- `ValueError`: If key size is incorrect

**Example:**
```python
# IK pattern where initiator knows responder's public key
handshake.set_remote_static_public_key(server_public_key)
```

##### `initialize()`

```python
initialize() -> None
```

Initialize the handshake state and begin the protocol.

**Raises:**
- `ValueError`: If role is not set
- `ValueError`: If required keys are missing for the pattern

**Note:** The protocol name from the pattern string is automatically used to initialize the handshake hash.

**Example:**
```python
handshake.initialize()
```

##### `write_message(payload)`

```python
write_message(payload: bytes) -> bytes
```

Write the next handshake message.

**Parameters:**
- `payload` (bytes): Application payload to include in this message (can be empty)

**Returns:**
- `bytes`: Handshake message to send to peer

**Raises:**
- `ValueError`: If handshake is not started or already complete
- `ValueError`: If not this party's turn to send

**Example:**
```python
# First message (usually no payload)
msg1 = initiator.write_message()

# Later message with payload
msg2 = initiator.write_message(b"Hello")
```

##### `read_message(message)`

```python
read_message(message: bytes) -> bytes
```

Read and process a handshake message from the peer.

**Parameters:**
- `message` (bytes): Handshake message received from peer

**Returns:**
- `bytes`: Application payload extracted from message (may be empty)

**Raises:**
- `ValueError`: If handshake is not started
- `ValueError`: If message is malformed or authentication fails
- `ValueError`: If not this party's turn to receive

**Example:**
```python
payload = responder.read_message(msg1)
```

##### `generate_static_keypair()`

```python
generate_static_keypair() -> None
```

Generate a new static key pair using the configured DH function and set it automatically.

**Note:** This method generates and internally sets the static keypair. Keys are not returned.

**Example:**
```python
handshake.generate_static_keypair()
# Keys are now set internally and ready to use
```

##### `to_transport()`

```python
to_transport() -> Tuple[CipherState, CipherState]
```

Convert completed handshake to transport mode for ongoing communication.

**Returns:**
- `Tuple[CipherState, CipherState]`: (send_cipher, receive_cipher)
  - Initiator: sends with first cipher, receives with second
  - Responder: sends with second cipher, receives with first

**Raises:**
- `ValueError`: If handshake is not complete

**Example:**
```python
send_cipher, receive_cipher = handshake.to_transport()

# Send encrypted message
ciphertext = send_cipher.encrypt_with_ad(b"", plaintext)

# Receive encrypted message
plaintext = receive_cipher.decrypt_with_ad(b"", ciphertext)
```

#### Properties

##### `handshake_complete`

```python
handshake_complete: bool
```

Whether the handshake has completed successfully.

**Example:**
```python
if handshake.handshake_complete:
    print("Handshake complete!")
```

##### `role`

```python
role: Optional[Role]
```

Current role (`Role.INITIATOR`, `Role.RESPONDER`, or `None`).

---

### NoiseTransport

Transport layer for encrypted communication after handshake completion.

#### Import

```python
from noiseframework import NoiseTransport
# OR
from noiseframework.transport import NoiseTransport
# OR (explicit)
from noiseframework.transport.transport import NoiseTransport
```

#### Constructor

Typically created via `NoiseHandshake.to_transport()`, not directly.

#### Methods

##### `send(plaintext, ad)`

```python
send(plaintext: bytes, ad: bytes = b"") -> bytes
```

Encrypt and send a message.

**Parameters:**
- `plaintext` (bytes): Data to encrypt
- `ad` (bytes, optional): Associated data (authenticated but not encrypted). Default: `b""`

**Returns:**
- `bytes`: Ciphertext with authentication tag

**Raises:**
- `ValueError`: If encryption fails or nonce overflow occurs

**Example:**
```python
ciphertext = transport.send(b"Hello, world!")
```

##### `receive(ciphertext, ad)`

```python
receive(ciphertext: bytes, ad: bytes = b"") -> bytes
```

Receive and decrypt a message.

**Parameters:**
- `ciphertext` (bytes): Encrypted data with authentication tag
- `ad` (bytes, optional): Associated data (must match what sender used). Default: `b""`

**Returns:**
- `bytes`: Plaintext

**Raises:**
- `ValueError`: If decryption or authentication fails

**Example:**
```python
plaintext = transport.receive(ciphertext)
```

##### `get_send_nonce()`

```python
get_send_nonce() -> int
```

Get the current send nonce value (for monitoring/debugging).

**Returns:**
- `int`: Current nonce

##### `get_receive_nonce()`

```python
get_receive_nonce() -> int
```

Get the current receive nonce value (for monitoring/debugging).

**Returns:**
- `int`: Current nonce

---

## Pattern System

### Pattern Parser

#### `parse_pattern(pattern_string)`

```python
from noiseframework.noise.pattern import parse_pattern

parse_pattern(pattern_string: str) -> NoisePattern
```

Parse a Noise pattern string into its components.

**Parameters:**
- `pattern_string` (str): Pattern in format `Noise_PATTERN_DH_CIPHER_HASH`

**Returns:**
- `NoisePattern`: Named tuple with fields:
  - `handshake_pattern` (str): Pattern name (e.g., "XX", "IK")
  - `dh_function` (str): DH algorithm ("25519" or "448")
  - `cipher_function` (str): Cipher ("ChaChaPoly" or "AESGCM")
  - `hash_function` (str): Hash ("SHA256", "SHA512", "BLAKE2s", or "BLAKE2b")

**Raises:**
- `ValueError`: If pattern string is invalid

**Example:**
```python
pattern = parse_pattern("Noise_XX_25519_ChaChaPoly_SHA256")
print(pattern.handshake_pattern)  # "XX"
print(pattern.dh_function)         # "25519"
```

### Supported Patterns

NoiseFramework supports all 12 fundamental interactive patterns:

#### One-way patterns (no authentication)
- **NN**: No static keys, ephemeral-only
- **NK**: Responder has known static key
- **NX**: Responder transmits static key

#### Interactive patterns with initiator authentication
- **KN**: Initiator has known static key
- **KK**: Both have known static keys
- **KX**: Initiator known, responder transmits

#### Interactive patterns (most common)
- **XN**: Initiator transmits static key
- **XK**: Initiator transmits, responder known
- **XX**: Both parties transmit static keys (mutual authentication)

#### Interactive patterns with immediate initiator authentication
- **IN**: Initiator immediately authenticated
- **IK**: Initiator authenticated, responder known
- **IX**: Initiator authenticated, responder transmits

**Pattern Selection Guide:**

| Use Case | Recommended Pattern |
|----------|-------------------|
| Mutual authentication, no pre-shared keys | `XX` |
| Client knows server's key | `IK` or `XK` |
| Server knows client's key | `KK` |
| One-way encryption (no auth) | `NN` (not for production!) |
| Anonymous client, authenticated server | `XK` or `NK` |

---

## Cryptographic Primitives

### Diffie-Hellman Functions

#### `get_dh_function(name)`

```python
from noiseframework.crypto.dh import get_dh_function

get_dh_function(name: str) -> DHFunction
```

Get a DH function instance by name.

**Parameters:**
- `name` (str): `"25519"` or `"448"`

**Returns:**
- `DHFunction`: Curve25519 or Curve448 instance

**Raises:**
- `ValueError`: If name is unsupported

#### DHFunction Interface

##### `generate_keypair()`

```python
generate_keypair() -> Tuple[bytes, bytes]
```

Generate a new key pair.

**Returns:**
- `Tuple[bytes, bytes]`: (private_key, public_key)

##### `dh(private_key, public_key)`

```python
dh(private_key: bytes, public_key: bytes) -> bytes
```

Perform Diffie-Hellman key agreement.

**Parameters:**
- `private_key` (bytes): Our private key
- `public_key` (bytes): Their public key

**Returns:**
- `bytes`: Shared secret

**Raises:**
- `ValueError`: If key sizes are invalid

#### Supported DH Functions

| Name | Algorithm | Key Length | Security Level |
|------|-----------|-----------|----------------|
| `25519` | Curve25519 (X25519) | 32 bytes | ~128-bit |
| `448` | Curve448 (X448) | 56 bytes | ~224-bit |

---

### AEAD Ciphers

#### `get_cipher_function(name)`

```python
from noiseframework.crypto.cipher import get_cipher_function

get_cipher_function(name: str) -> CipherFunction
```

Get a cipher function instance by name.

**Parameters:**
- `name` (str): `"ChaChaPoly"` or `"AESGCM"`

**Returns:**
- `CipherFunction`: Cipher instance

**Raises:**
- `ValueError`: If name is unsupported

#### CipherFunction Interface

##### `encrypt(key, nonce, ad, plaintext)`

```python
encrypt(key: bytes, nonce: int, ad: bytes, plaintext: bytes) -> bytes
```

Encrypt with authenticated encryption.

**Parameters:**
- `key` (bytes): 32-byte encryption key
- `nonce` (int): 64-bit nonce (unsigned integer)
- `ad` (bytes): Associated data
- `plaintext` (bytes): Data to encrypt

**Returns:**
- `bytes`: Ciphertext with 16-byte authentication tag appended

##### `decrypt(key, nonce, ad, ciphertext)`

```python
decrypt(key: bytes, nonce: int, ad: bytes, ciphertext: bytes) -> bytes
```

Decrypt and verify authentication.

**Parameters:**
- `key` (bytes): 32-byte encryption key
- `nonce` (int): 64-bit nonce (must match encryption)
- `ad` (bytes): Associated data (must match encryption)
- `ciphertext` (bytes): Data with authentication tag

**Returns:**
- `bytes`: Plaintext

**Raises:**
- `ValueError`: If authentication fails

#### Supported Ciphers

| Name | Algorithm | Key Length | Nonce | Tag Length |
|------|-----------|-----------|-------|-----------|
| `ChaChaPoly` | ChaCha20-Poly1305 | 32 bytes | 64-bit | 16 bytes |
| `AESGCM` | AES-256-GCM | 32 bytes | 64-bit | 16 bytes |

**Recommendation:** Use `ChaChaPoly` (ChaCha20-Poly1305) unless you have specific requirements for AES-GCM.

---

### Hash Functions

#### `get_hash_function(name)`

```python
from noiseframework.crypto.hash import get_hash_function

get_hash_function(name: str) -> HashFunction
```

Get a hash function instance by name.

**Parameters:**
- `name` (str): `"SHA256"`, `"SHA512"`, `"BLAKE2s"`, or `"BLAKE2b"`

**Returns:**
- `HashFunction`: Hash function instance

**Raises:**
- `ValueError`: If name is unsupported

#### HashFunction Interface

##### `hash(data)`

```python
hash(data: bytes) -> bytes
```

Compute cryptographic hash.

**Parameters:**
- `data` (bytes): Data to hash

**Returns:**
- `bytes`: Hash output

##### `hmac_hash(key, data)`

```python
hmac_hash(key: bytes, data: bytes) -> bytes
```

Compute HMAC.

**Parameters:**
- `key` (bytes): HMAC key
- `data` (bytes): Data to authenticate

**Returns:**
- `bytes`: HMAC output

##### `hkdf(chaining_key, input_key_material, num_outputs)`

```python
hkdf(chaining_key: bytes, input_key_material: bytes, num_outputs: int) -> tuple
```

HKDF key derivation function (Noise variant).

**Parameters:**
- `chaining_key` (bytes): Chaining key (HKDF salt)
- `input_key_material` (bytes): Input key material
- `num_outputs` (int): Number of outputs (2 or 3)

**Returns:**
- `tuple`: 2 or 3 derived keys

**Raises:**
- `ValueError`: If `num_outputs` is not 2 or 3

#### Supported Hash Functions

| Name | Algorithm | Output Length | Block Size |
|------|-----------|--------------|-----------|
| `SHA256` | SHA-256 | 32 bytes | 64 bytes |
| `SHA512` | SHA-512 | 64 bytes | 128 bytes |
| `BLAKE2s` | BLAKE2s | 32 bytes | 64 bytes |
| `BLAKE2b` | BLAKE2b | 64 bytes | 128 bytes |

**Recommendation:** Use `SHA256` for general use or `BLAKE2s` for higher performance.

---

## Low-Level Components

### SymmetricState

Internal state management for handshake cryptographic operations.

**Note:** Rarely used directly; `NoiseHandshake` provides a higher-level interface.

#### Constructor

```python
from noiseframework.noise.state import SymmetricState

SymmetricState(hash_fn: HashFunction, cipher_fn: CipherFunction) -> SymmetricState
```

#### Methods

- `initialize_symmetric(protocol_name)`: Initialize with protocol name
- `mix_key(input_key_material)`: Mix key material into chaining key
- `mix_hash(data)`: Mix data into handshake hash
- `mix_key_and_hash(input_key_material)`: Mix into both key and hash
- `encrypt_and_hash(plaintext)`: Encrypt and update hash
- `decrypt_and_hash(ciphertext)`: Decrypt and update hash
- `split()`: Split into two CipherStates for transport mode

---

### CipherState

Manages AEAD encryption with automatic nonce handling.

**Note:** Created by `SymmetricState.split()` or `NoiseHandshake.to_transport()`.

#### Constructor

```python
from noiseframework.noise.state import CipherState

CipherState(cipher_fn: CipherFunction) -> CipherState
```

#### Methods

- `initialize_key(key)`: Set encryption key
- `has_key()`: Check if key is set
- `encrypt_with_ad(ad, plaintext)`: Encrypt with AD
- `decrypt_with_ad(ad, ciphertext)`: Decrypt with AD

---

## Complete Examples

### XX Pattern (Mutual Authentication)

```python
from noiseframework import NoiseHandshake, NoiseTransport

# === Setup ===
# Initiator (client)
initiator = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
initiator.set_as_initiator()
initiator.generate_static_keypair()
initiator.initialize()

# Responder (server)
responder = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
responder.set_as_responder()
responder.generate_static_keypair()
responder.initialize()

# === Handshake ===
# -> e
msg1 = initiator.write_message(b"")
responder.read_message(msg1)

# <- e, ee, s, es
msg2 = responder.write_message(b"")
initiator.read_message(msg2)

# -> s, se
msg3 = initiator.write_message(b"")
responder.read_message(msg3)

# === Transport ===
i_send, i_recv = initiator.to_transport()
r_send, r_recv = responder.to_transport()

i_transport = NoiseTransport(i_send, i_recv)
r_transport = NoiseTransport(r_send, r_recv)

# Send encrypted messages
ciphertext = i_transport.send(b"Hello, server!")
plaintext = r_transport.receive(ciphertext)
assert plaintext == b"Hello, server!"
```

### IK Pattern (Known Responder)

```python
from noiseframework import NoiseHandshake, NoiseTransport

# === Setup ===
# Generate server's static keypair (done once, published)
server_setup = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
server_setup.set_as_responder()
server_setup.generate_static_keypair()
s_priv = server_setup.static_private
s_pub = server_setup.static_public

# Client knows server's public key
client = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
client.set_as_initiator()
client.generate_static_keypair()
client.set_remote_static_public_key(s_pub)  # Known server key
client.initialize()

# Server
server = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
server.set_as_responder()
server.set_static_keypair(s_priv, s_pub)
server.initialize()

# === Handshake ===
# -> e, es, s, ss
msg1 = client.write_message(b"")
server.read_message(msg1)

# <- e, ee
msg2 = server.write_message(b"")
client.read_message(msg2)

# === Transport ===
c_send, c_recv = client.to_transport()
s_send, s_recv = server.to_transport()

c_transport = NoiseTransport(c_send, c_recv)
s_transport = NoiseTransport(s_send, s_recv)
```

---

## Error Handling

All functions raise `ValueError` for invalid inputs or cryptographic failures:

```python
try:
    handshake = NoiseHandshake("Noise_InvalidPattern_25519_ChaChaPoly_SHA256")
except ValueError as e:
    print(f"Invalid pattern: {e}")

try:
    payload = responder.read_message(tampered_message)
except ValueError as e:
    print(f"Authentication failed: {e}")
```

---

## Type Hints

NoiseFramework uses comprehensive type hints:

```python
from typing import Optional, Tuple
from noiseframework import NoiseHandshake, NoiseTransport

def setup_client(pattern: str) -> NoiseHandshake:
    handshake: NoiseHandshake = NoiseHandshake(pattern)
    handshake.set_as_initiator()
    handshake.generate_static_keypair()
    handshake.initialize()
    return handshake
```

---

## Performance Considerations

- **ChaCha20-Poly1305** is typically faster than AES-GCM on systems without AES-NI
- **Curve25519** is faster than Curve448 but provides lower security margin
- **SHA-256** and **BLAKE2s** are faster than their 512-bit counterparts
- Nonce overflow occurs after 2^64 messages (practically impossible)
- Handshake state can be reused for multiple sessions with same peer

---

## Security Notes

1. **Never reuse static keys across different protocols** without re-initialization
2. **Validate peer identity** after handshake completion (application's responsibility)
3. **Use strong random number generation** (handled automatically by `cryptography` library)
4. **Protect private keys** in memory and storage
5. **Choose appropriate patterns** for your threat model (see pattern selection guide)
6. **Monitor nonces** to detect replay attacks at the application layer

---

## Version

This API documentation is maintained for the current version of NoiseFramework.

For version-specific changes and updates, see the [CHANGELOG](CHANGELOG.md).
