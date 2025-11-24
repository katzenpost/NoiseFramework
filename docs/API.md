# API Reference

Complete API documentation for NoiseFramework.

## Table of Contents

- [High-Level API](#high-level-api)
  - [NoiseHandshake](#noisehandshake)
  - [NoiseTransport](#noisetransport)
- [Logging](#logging)
  - [Logger Parameters](#logger-parameters)
  - [Log Levels](#log-levels)
  - [Logger Names](#logger-names)
  - [Usage Examples](#usage-examples)
- [Framing](#framing)
  - [FramedWriter](#framedwriter)
  - [FramedReader](#framedreader)
  - [Convenience Functions](#convenience-functions)
  - [FramingError](#framingerror)
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
NoiseHandshake(pattern_string: str, logger: Optional[logging.Logger] = None) -> NoiseHandshake
```

Initialize a Noise handshake with a pattern string.

**Parameters:**
- `pattern_string` (str): Noise pattern in format `Noise_PATTERN_DH_CIPHER_HASH`
  - Example: `"Noise_XX_25519_ChaChaPoly_SHA256"`
- `logger` (Optional[logging.Logger]): Custom logger instance for handshake operations. If None, creates a default logger with name `noiseframework.noise.handshake.NoiseHandshake`.

**Raises:**
- `ValueError`: If pattern string is invalid or uses unsupported algorithms

**Examples:**
```python
# Basic usage with default logger
handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")

# With custom logger
import logging
custom_logger = logging.getLogger("myapp.noise")
handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256", logger=custom_logger)
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
from noiseframework import NoiseTransport

send_cipher, receive_cipher = handshake.to_transport()

# Create transport wrapper (recommended)
transport = NoiseTransport(send_cipher, receive_cipher)

# Send encrypted message
ciphertext = transport.send(b"Hello, world!")

# Receive encrypted message
plaintext = transport.receive(ciphertext)
```

**Alternative (using raw cipher states):**
```python
# Direct cipher state usage (lower-level)
send_cipher, receive_cipher = handshake.to_transport()
ciphertext = send_cipher.encrypt_with_ad(b"", plaintext)
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

```python
NoiseTransport(send_cipher: CipherState, receive_cipher: CipherState, logger: Optional[logging.Logger] = None) -> NoiseTransport
```

Typically created via `NoiseHandshake.to_transport()`, but can be instantiated directly if needed.

**Parameters:**
- `send_cipher` (CipherState): CipherState for sending messages
- `receive_cipher` (CipherState): CipherState for receiving messages  
- `logger` (Optional[logging.Logger]): Custom logger instance for transport operations. If None, creates a default logger with name `noiseframework.transport.transport.NoiseTransport`.

**Example:**
```python
# Via handshake (recommended)
send_cipher, recv_cipher = handshake.to_transport()
transport = NoiseTransport(send_cipher, recv_cipher)

# With custom logger
import logging
custom_logger = logging.getLogger("myapp.transport")
transport = NoiseTransport(send_cipher, recv_cipher, logger=custom_logger)
```

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

## Logging

NoiseFramework provides comprehensive logging support for debugging and monitoring. All major classes accept an optional `logger` parameter.

### Logger Parameters

All main classes support an optional `logger` parameter in their constructors:

- **NoiseHandshake**: `NoiseHandshake(pattern_string: str, logger: Optional[logging.Logger] = None)`
- **NoiseTransport**: `NoiseTransport(send_cipher, receive_cipher, logger: Optional[logging.Logger] = None)`
- **SymmetricState**: `SymmetricState(hash_func, cipher, logger: Optional[logging.Logger] = None)`
- **CipherState**: `CipherState(cipher, logger: Optional[logging.Logger] = None)`

If `logger` is `None`, each class creates a default logger using the pattern `logging.getLogger(f"{__name__}.ClassName")`.

### Log Levels

NoiseFramework logs at four standard levels:

#### DEBUG

Detailed operational information:
- Message sizes and nonce values
- Token processing during handshakes (`['e', 'es', 'ss']`)
- Key material mixing operations
- Cipher initialization details

**Example:**
```
DEBUG: Writing handshake message 1 (payload=0 bytes)
DEBUG: Processing tokens: ['e']
DEBUG: Encrypting message (plaintext=13 bytes, ad=0 bytes, nonce=0)
DEBUG: Mixing key material (32 bytes)
```

#### INFO

Major operational events:
- Role setting (initiator/responder)
- Handshake initialization and completion
- Message send/receive operations
- Transport cipher creation

**Example:**
```
INFO: Role set as INITIATOR
INFO: Generated static keypair
INFO: Handshake initialized
INFO: Sent handshake message 1 (ciphertext=32 bytes)
INFO: Handshake complete - ready for transport mode
INFO: Created transport ciphers (initiator: send=c1, receive=c2)
INFO: Sent encrypted message (ciphertext=29 bytes)
```

#### WARNING

Potential issues that don't prevent operation:
- Nonce approaching limit (`>= 2^63`, warns about `2^64` overflow)

**Example:**
```
WARNING: Send cipher nonce high: 9223372036854775808 (approaching 2^64 limit - consider rekeying)
```

#### ERROR

Error conditions (always logged before raising exceptions):
- Invalid state transitions
- Validation failures (wrong role, missing keys)
- Authentication failures
- Nonce overflow

**Example:**
```
ERROR: Attempted to write message without setting role
ERROR: Attempted to set role when already set
ERROR: Attempted to create transport ciphers before handshake completion
ERROR: Decryption failed: Authentication tag verification failed
```

### Logger Names

Default logger names follow the pattern `module.path.ClassName`:

- `noiseframework.noise.handshake.NoiseHandshake`
- `noiseframework.transport.transport.NoiseTransport`
- `noiseframework.noise.state.SymmetricState`
- `noiseframework.noise.state.CipherState`

These names allow fine-grained control over logging output.

### Usage Examples

#### Basic Setup

```python
import logging
from noiseframework import NoiseHandshake

# Configure logging globally
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
)

# Use NoiseFramework - logging happens automatically
handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
handshake.set_as_initiator()  # Logs: "Role set as INITIATOR"
```

#### Custom Logger

```python
import logging
from noiseframework import NoiseHandshake, NoiseTransport

# Create custom logger
custom_logger = logging.getLogger("myapp.noise")
custom_logger.setLevel(logging.DEBUG)

# Add custom handler
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
custom_logger.addHandler(handler)

# Pass to NoiseFramework components
handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256", logger=custom_logger)
send_cipher, recv_cipher = handshake.to_transport()
transport = NoiseTransport(send_cipher, recv_cipher, logger=custom_logger)
```

#### Per-Module Configuration

```python
import logging

# Configure different levels for different modules
logging.getLogger("noiseframework.noise.handshake").setLevel(logging.INFO)
logging.getLogger("noiseframework.transport.transport").setLevel(logging.DEBUG)
logging.getLogger("noiseframework.noise.state").setLevel(logging.WARNING)

# Or disable all NoiseFramework logging
logging.getLogger("noiseframework").setLevel(logging.CRITICAL)
```

#### Filtering to Specific Operations

```python
import logging

# Only log handshake operations
handshake_logger = logging.getLogger("noiseframework.noise.handshake")
handshake_logger.setLevel(logging.DEBUG)

handler = logging.FileHandler("handshake_debug.log")
handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
handshake_logger.addHandler(handler)

# NoiseTransport logs won't appear unless configured separately
```

#### Production Configuration

```python
import logging

# Minimal logging in production
logging.basicConfig(
    level=logging.WARNING,  # Only warnings and errors
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("/var/log/myapp/noise.log"),
        logging.StreamHandler()
    ]
)

# Use NoiseFramework normally
handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
# Only WARNINGs and ERRORs will be logged
```

#### Complete Example with Output

```python
import logging
from noiseframework import NoiseHandshake

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
)

# Create and use handshake
handshake = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
handshake.set_as_initiator()
handshake.initialize()
msg = handshake.write_message(b"hello")
```

**Output:**
```
2025-11-24 15:30:01 [DEBUG   ] noiseframework.noise.handshake.NoiseHandshake: Initializing NoiseHandshake with pattern: Noise_NN_25519_ChaChaPoly_SHA256
2025-11-24 15:30:01 [DEBUG   ] noiseframework.noise.handshake.NoiseHandshake: Pattern parsed: NN, DH=25519, Cipher=ChaChaPoly, Hash=SHA256
2025-11-24 15:30:01 [INFO    ] noiseframework.noise.handshake.NoiseHandshake: Role set as INITIATOR
2025-11-24 15:30:01 [DEBUG   ] noiseframework.noise.handshake.NoiseHandshake: Initializing handshake (pattern=Noise_NN_25519_ChaChaPoly_SHA256)
2025-11-24 15:30:01 [INFO    ] noiseframework.noise.handshake.NoiseHandshake: Handshake initialized
2025-11-24 15:30:01 [DEBUG   ] noiseframework.noise.handshake.NoiseHandshake: Writing handshake message 1 (payload=5 bytes)
2025-11-24 15:30:01 [DEBUG   ] noiseframework.noise.handshake.NoiseHandshake: Processing tokens: ['e']
2025-11-24 15:30:01 [INFO    ] noiseframework.noise.handshake.NoiseHandshake: Sent handshake message 1 (ciphertext=37 bytes)
```

See [`examples/logging_example.py`](../examples/logging_example.py) for more comprehensive examples.

---

## Framing

Length-prefixed message framing utilities for stream-based transports (TCP, pipes, etc.). Solves the message boundary problem when using Noise over byte streams.

### Frame Format

NoiseFramework uses a simple 4-byte big-endian length prefix:

```
┌──────────────┬────────────────────┐
│ Length (4B)  │  Message Data      │
│ big-endian   │  (0 to 2^32-1 B)   │
└──────────────┴────────────────────┘
```

- **Header**: 4 bytes, big-endian unsigned integer (`struct.pack("!I", length)`)
- **Max Size**: Default 16 MB, configurable up to 4 GB (2^32-1 bytes)
- **Data**: Raw message bytes (0 to max_message_size bytes)

### FramedWriter

Writes length-prefixed messages to a stream.

#### Import

```python
from noiseframework import FramedWriter
```

#### Constructor

```python
FramedWriter(
    stream,
    max_message_size: int = 16 * 1024 * 1024,  # 16 MB
    logger: Optional[logging.Logger] = None
) -> FramedWriter
```

**Parameters:**
- `stream`: Writable byte stream (e.g., `socket.makefile('wb')`, `open('file', 'wb')`, `io.BytesIO()`)
- `max_message_size` (int, optional): Maximum allowed message size in bytes. Default: 16 MB (16777216). Must be > 0 and < 2^32.
- `logger` (logging.Logger, optional): Custom logger. Default: `logging.getLogger("noiseframework.framing.FramedWriter")`

**Raises:**
- `ValueError`: If `max_message_size` is ≤ 0 or ≥ 2^32

#### Methods

##### `write_message(message: bytes) -> None`

Write a length-prefixed message to the stream.

**Parameters:**
- `message` (bytes): Message data to write

**Raises:**
- `FramingError`: If message size exceeds `max_message_size`
- `IOError`: If underlying stream write fails

**Example:**
```python
writer = FramedWriter(sock.makefile('wb'))
writer.write_message(b"Hello, World!")
writer.write_message(ciphertext)
```

##### `close() -> None`

Close the underlying stream.

**Example:**
```python
writer.close()
```

#### Properties

##### `messages_sent: int`

Number of messages successfully written. Useful for debugging and monitoring.

**Example:**
```python
print(f"Sent {writer.messages_sent} messages")
```

### FramedReader

Reads length-prefixed messages from a stream.

#### Import

```python
from noiseframework import FramedReader
```

#### Constructor

```python
FramedReader(
    stream,
    max_message_size: int = 16 * 1024 * 1024,  # 16 MB
    logger: Optional[logging.Logger] = None
) -> FramedReader
```

**Parameters:**
- `stream`: Readable byte stream (e.g., `socket.makefile('rb')`, `open('file', 'rb')`, `io.BytesIO()`)
- `max_message_size` (int, optional): Maximum allowed message size in bytes. Default: 16 MB (16777216). Must be > 0 and < 2^32.
- `logger` (logging.Logger, optional): Custom logger. Default: `logging.getLogger("noiseframework.framing.FramedReader")`

**Raises:**
- `ValueError`: If `max_message_size` is ≤ 0 or ≥ 2^32

#### Methods

##### `read_message() -> bytes`

Read a length-prefixed message from the stream.

Automatically handles partial reads by accumulating data until the complete message is received.

**Returns:**
- `bytes`: The message data (without the length header)

**Raises:**
- `FramingError`: If message length exceeds `max_message_size`, header is truncated, or message data is truncated
- `IOError`: If underlying stream read fails

**Example:**
```python
reader = FramedReader(sock.makefile('rb'))
message = reader.read_message()
print(f"Received: {message}")
```

##### `close() -> None`

Close the underlying stream.

**Example:**
```python
reader.close()
```

#### Properties

##### `messages_received: int`

Number of messages successfully read. Useful for debugging and monitoring.

**Example:**
```python
print(f"Received {reader.messages_received} messages")
```

### Convenience Functions

For single-message operations without maintaining reader/writer objects.

#### `write_framed_message(stream, message: bytes, max_message_size: int = ...) -> None`

Write a single framed message.

**Parameters:**
- `stream`: Writable byte stream
- `message` (bytes): Message to write
- `max_message_size` (int, optional): Maximum allowed size. Default: 16 MB

**Example:**
```python
from noiseframework import write_framed_message

with open('data.bin', 'wb') as f:
    write_framed_message(f, b"Hello")
    write_framed_message(f, b"World")
```

#### `read_framed_message(stream, max_message_size: int = ...) -> bytes`

Read a single framed message.

**Parameters:**
- `stream`: Readable byte stream
- `max_message_size` (int, optional): Maximum allowed size. Default: 16 MB

**Returns:**
- `bytes`: The message data

**Example:**
```python
from noiseframework import read_framed_message

with open('data.bin', 'rb') as f:
    msg1 = read_framed_message(f)
    msg2 = read_framed_message(f)
```

### FramingError

Exception raised for framing-related errors.

#### Import

```python
from noiseframework import FramingError
```

#### Usage

```python
try:
    message = reader.read_message()
except FramingError as e:
    if "exceeds maximum" in str(e):
        print("Message too large")
    elif "Connection closed" in str(e):
        print("Connection terminated")
    else:
        print(f"Framing error: {e}")
```

#### Common Error Messages

- `"Frame length {size} exceeds maximum allowed size {max}"` - Message header indicates size > max_message_size
- `"Message size {size} exceeds maximum allowed size {max}"` - Attempted to write oversized message
- `"Connection closed while reading frame header: expected 4 bytes, got {n}"` - Header truncated
- `"Connection closed: expected {size} bytes, got {n}"` - Message data truncated

### Complete TCP Example

```python
import socket
from noiseframework import NoiseHandshake, FramedWriter, FramedReader

# Server
def server():
    with socket.socket() as sock:
        sock.bind(('localhost', 8000))
        sock.listen(1)
        conn, _ = sock.accept()
        
        # Noise handshake
        hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        hs.set_as_responder()
        hs.generate_static_keypair()
        hs.initialize()
        
        # Framed communication
        reader = FramedReader(conn.makefile('rb'))
        writer = FramedWriter(conn.makefile('wb'))
        
        # Handshake messages (3 messages for XX)
        msg1 = reader.read_message()
        msg2 = hs.read_message(msg1)
        msg2_out = hs.write_message(msg2)
        writer.write_message(msg2_out)
        
        msg3 = reader.read_message()
        hs.read_message(msg3)
        
        # Transport mode
        transport = hs.to_transport()
        
        # Receive encrypted message
        ciphertext = reader.read_message()
        plaintext = transport.receive(ciphertext)
        print(f"Received: {plaintext}")
        
        # Send encrypted response
        response = transport.send(b"Hello, Client!")
        writer.write_message(response)

# Client
def client():
    with socket.socket() as sock:
        sock.connect(('localhost', 8000))
        
        # Noise handshake
        hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        hs.set_as_initiator()
        hs.generate_static_keypair()
        hs.initialize()
        
        # Framed communication
        reader = FramedReader(sock.makefile('rb'))
        writer = FramedWriter(sock.makefile('wb'))
        
        # Handshake messages (3 messages for XX)
        msg1 = hs.write_message(b"")
        writer.write_message(msg1)
        
        msg2 = reader.read_message()
        msg3_payload = hs.read_message(msg2)
        msg3 = hs.write_message(msg3_payload)
        writer.write_message(msg3)
        
        # Transport mode
        transport = hs.to_transport()
        
        # Send encrypted message
        ciphertext = transport.send(b"Hello, Server!")
        writer.write_message(ciphertext)
        
        # Receive encrypted response
        response_ciphertext = reader.read_message()
        response = transport.receive(response_ciphertext)
        print(f"Received: {response}")
```

### Best Practices

1. **Always use framing over TCP/streams**: Noise encryption doesn't preserve message boundaries
2. **Set appropriate max_message_size**: Prevents DoS via memory exhaustion
3. **Enable logging in development**: Helps debug connection issues
4. **Handle FramingError**: Connection may close unexpectedly
5. **Use context managers**: Ensure streams are properly closed
6. **Thread safety**: FramedReader and FramedWriter are thread-safe for concurrent read/write on different threads

See [`examples/framed_tcp_example.py`](../examples/framed_tcp_example.py) for a complete working example.

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
