# NoiseFramework

[![Official Website](https://img.shields.io/badge/🌐%20Official%20Website-www.noiseframework.com-4A90E2?style=for-the-badge&logo=globe&logoColor=white)](https://www.noiseframework.com)
<br>

<br>

[![PyPI version](https://img.shields.io/pypi/v/noiseframework.svg)](https://pypi.org/project/noiseframework/)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/juliuspleunes4/noiseframework)](https://github.com/juliuspleunes4/noiseframework/issues)
[![GitHub Stars](https://img.shields.io/github/stars/juliuspleunes4/noiseframework)](https://github.com/juliuspleunes4/noiseframework/stargazers)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> A professional, secure, and easy-to-use implementation of the [Noise Protocol Framework](https://noiseprotocol.org/) in Python.

**NoiseFramework** provides cryptographically sound, specification-compliant implementations of Noise handshake patterns for building secure communication channels. It is designed to be both simple to integrate into applications and robust enough for production use.

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
  - [Logging](#logging)
  - [Message Framing](#message-framing)
  - [Async/Await Support](#asyncawait-support)
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
pip install noiseframework
```

### From Source

```bash
git clone https://github.com/juliuspleunes4/noiseframework.git
cd noiseframework
pip install -e .
```

### Requirements

- Python 3.8 or higher
- Dependencies are automatically installed via pip

---

## 🚀 Quick Start

### Python API

```python
from noiseframework import NoiseHandshake, NoiseTransport

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
msg1 = initiator.write_message(b"")
responder.read_message(msg1)

msg2 = responder.write_message(b"")
initiator.read_message(msg2)

msg3 = initiator.write_message(b"")
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
noiseframework generate-keypair --dh 25519 -o mykey
# Creates: mykey_private.key, mykey_public.key

# Validate a pattern string
noiseframework validate-pattern "Noise_XX_25519_ChaChaPoly_SHA256"

# Show supported primitives
noiseframework info

# Use shorter aliases
noiseframework genkey --dh 25519 -o mykey
noiseframework validate "Noise_XX_25519_ChaChaPoly_SHA256"
```

---

## 📖 Python API Documentation

### Basic Handshake (Noise_XX)

The `XX` pattern provides mutual authentication with no prior knowledge required. Both parties exchange static keys during the handshake.

```python
from noiseframework import NoiseHandshake, NoiseTransport

# === INITIATOR SIDE ===
initiator = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
initiator.set_as_initiator()
initiator.generate_static_keypair()  # Generate static key
initiator.initialize()

# Send first message (-> e)
msg1 = initiator.write_message(b"")

# === RESPONDER SIDE ===
responder = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
responder.set_as_responder()
responder.generate_static_keypair()  # Generate static key
responder.initialize()

# Process first message and send response (-> e, ee, s, es)
responder.read_message(msg1)
msg2 = responder.write_message(b"")

# === INITIATOR SIDE (continued) ===
# Process second message and send final (-> s, se)
initiator.read_message(msg2)
msg3 = initiator.write_message(b"")

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
from noiseframework import NoiseHandshake, NoiseTransport

# === INITIATOR SIDE ===
initiator = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
initiator.set_as_initiator()
initiator.initialize()

# Send first message (-> e)
msg1 = initiator.write_message(b"")

# === RESPONDER SIDE ===
responder = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
responder.set_as_responder()
responder.initialize()

# Process first message and send response (-> e, ee)
responder.read_message(msg1)
msg2 = responder.write_message(b"")

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
from noiseframework import NoiseHandshake, NoiseTransport

# === SETUP: Generate responder's static keypair ===
responder_setup = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
responder_setup.set_as_responder()
responder_setup.generate_static_keypair()
responder_private = responder_setup.static_private
responder_public = responder_setup.static_public

# === INITIATOR SIDE ===
initiator = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
initiator.set_as_initiator()
initiator.generate_static_keypair()  # Generate own static key
initiator.set_remote_static_public_key(responder_public)  # Know responder's key
initiator.initialize()

# Send first message (-> e, es, s, ss)
msg1 = initiator.write_message(b"")

# === RESPONDER SIDE ===
responder = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
responder.set_as_responder()
responder.set_static_keypair(responder_private, responder_public)  # Use existing keypair
responder.initialize()

# Process first message and send response (-> e, ee, se)
responder.read_message(msg1)
msg2 = responder.write_message(b"")

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
from noiseframework import NoiseTransport

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
from noiseframework import NoiseHandshake

try:
    # Invalid pattern string
    hs = NoiseHandshake("Invalid_Pattern")
except ValueError as e:
    print(f"Pattern error: {e}")

try:
    # Attempt operation in wrong state
    hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    # Not setting role - will fail
    hs.write_message()  # Error: role not set
except ValueError as e:
    print(f"State error: {e}")

try:
    # Authentication failure
    ciphertext_tampered = ciphertext[:-1] + b"\x00"
    transport.receive(ciphertext_tampered)
except ValueError as e:
    print(f"Authentication failed: {e}")

# Always check handshake completion
if initiator.handshake_complete:
    send_cipher, recv_cipher = initiator.to_transport()
else:
    print("Handshake not complete")
```

---

### Logging

NoiseFramework includes comprehensive logging support for debugging and monitoring. All major operations are logged at appropriate levels.

#### Basic Logging Setup

```python
import logging
from noiseframework import NoiseHandshake, NoiseTransport

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
)

# Use NoiseFramework normally - logging happens automatically
handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
handshake.set_as_initiator()  # Logs: "Role set as INITIATOR"
handshake.generate_static_keypair()  # Logs: "Generated static keypair"
handshake.initialize()  # Logs: "Handshake initialized"

msg = handshake.write_message(b"")  # Logs: "Sent handshake message 1"
```

#### Log Levels

- **DEBUG**: Detailed operations (message sizes, nonces, token processing, key operations)
- **INFO**: Major events (role changes, handshake completion, message send/receive)
- **WARNING**: Potential issues (nonce approaching limit)
- **ERROR**: Failures (validation errors, authentication failures)

#### Custom Logger

```python
# Create custom logger with specific configuration
custom_logger = logging.getLogger("myapp.noise")
custom_logger.setLevel(logging.DEBUG)

# Add custom handler
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
custom_logger.addHandler(handler)

# Pass custom logger to NoiseHandshake
handshake = NoiseHandshake(
    "Noise_XX_25519_ChaChaPoly_SHA256",
    logger=custom_logger
)

# Pass custom logger to NoiseTransport
transport = NoiseTransport(send_cipher, recv_cipher, logger=custom_logger)
```

#### Filtering Logs by Module

```python
# Only show INFO+ logs from handshake module
logging.getLogger("noiseframework.noise.handshake").setLevel(logging.INFO)

# Show DEBUG logs from transport module
logging.getLogger("noiseframework.transport.transport").setLevel(logging.DEBUG)

# Disable logs from state module
logging.getLogger("noiseframework.noise.state").setLevel(logging.WARNING)
```

#### Example Log Output

```
2025-11-24 15:30:01 [INFO    ] noiseframework.noise.handshake.NoiseHandshake: Role set as INITIATOR
2025-11-24 15:30:01 [DEBUG   ] noiseframework.noise.handshake.NoiseHandshake: Generating static keypair (Curve25519)
2025-11-24 15:30:01 [INFO    ] noiseframework.noise.handshake.NoiseHandshake: Generated static keypair
2025-11-24 15:30:01 [INFO    ] noiseframework.noise.handshake.NoiseHandshake: Handshake initialized
2025-11-24 15:30:01 [DEBUG   ] noiseframework.noise.handshake.NoiseHandshake: Writing handshake message 1 (payload=0 bytes)
2025-11-24 15:30:01 [INFO    ] noiseframework.noise.handshake.NoiseHandshake: Sent handshake message 1 (ciphertext=32 bytes)
2025-11-24 15:30:02 [INFO    ] noiseframework.noise.handshake.NoiseHandshake: Handshake complete - ready for transport mode
2025-11-24 15:30:02 [INFO    ] noiseframework.noise.handshake.NoiseHandshake: Created transport ciphers (initiator: send=c1, receive=c2)
2025-11-24 15:30:03 [INFO    ] noiseframework.transport.transport.NoiseTransport: Sent encrypted message (ciphertext=29 bytes)
2025-11-24 15:30:03 [WARNING ] noiseframework.transport.transport.NoiseTransport: Send cipher nonce high: 9223372036854775808 (approaching 2^64 limit - consider rekeying)
```

See [`examples/logging_example.py`](examples/logging_example.py) for more detailed examples.

### Message Framing

When using Noise over stream-based transports (TCP, pipes, etc.), you need a way to preserve message boundaries. NoiseFramework provides length-prefixed framing utilities for this purpose.

#### Basic Usage

```python
import socket
from noiseframework import NoiseHandshake, FramedWriter, FramedReader

# After handshake completes...
transport = handshake.to_transport()

# Wrap socket for framed communication
writer = FramedWriter(sock.makefile('wb'))
reader = FramedReader(sock.makefile('rb'))

# Send framed encrypted messages
ciphertext = transport.send(b"Hello, World!")
writer.write_message(ciphertext)

# Receive framed encrypted messages
framed_message = reader.read_message()
plaintext = transport.receive(framed_message)
```

#### Frame Format

NoiseFramework uses a simple 4-byte big-endian length prefix:

```
┌──────────────┬────────────────────┐
│ Length (4B)  │  Message Data      │
│ big-endian   │  (0 to 2^32-1 B)   │
└──────────────┴────────────────────┘
```

#### Configuration

```python
# Default maximum message size is 16 MB
reader = FramedReader(stream)  # max_message_size=16*1024*1024

# Set custom maximum
reader = FramedReader(stream, max_message_size=1024*1024)  # 1 MB limit

# Add logging
import logging
logger = logging.getLogger("myapp.framing")
reader = FramedReader(stream, logger=logger)
writer = FramedWriter(stream, logger=logger)
```

#### TCP Example

```python
import socket
from noiseframework import NoiseHandshake, FramedWriter, FramedReader

# Server
def server(port):
    with socket.socket() as sock:
        sock.bind(('localhost', port))
        sock.listen(1)
        conn, _ = sock.accept()
        
        # Noise handshake (responder)
        hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        hs.set_as_responder()
        hs.generate_static_keypair()
        hs.initialize()
        
        reader = FramedReader(conn.makefile('rb'))
        writer = FramedWriter(conn.makefile('wb'))
        
        # Handshake messages with framing
        msg1 = reader.read_message()
        msg2 = hs.read_message(msg1)
        msg2_out = hs.write_message(msg2)
        writer.write_message(msg2_out)
        
        msg3 = reader.read_message()
        hs.read_message(msg3)
        
        # Transport mode
        transport = hs.to_transport()
        encrypted = reader.read_message()
        plaintext = transport.receive(encrypted)
        print(f"Server received: {plaintext}")

# Client
def client(port):
    with socket.socket() as sock:
        sock.connect(('localhost', port))
        
        # Noise handshake (initiator)
        hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
        hs.set_as_initiator()
        hs.generate_static_keypair()
        hs.initialize()
        
        reader = FramedReader(sock.makefile('rb'))
        writer = FramedWriter(sock.makefile('wb'))
        
        # Handshake messages with framing
        msg1 = hs.write_message(b"")
        writer.write_message(msg1)
        
        msg2 = reader.read_message()
        msg3_payload = hs.read_message(msg2)
        msg3 = hs.write_message(msg3_payload)
        writer.write_message(msg3)
        
        # Transport mode
        transport = hs.to_transport()
        ciphertext = transport.send(b"Hello, Server!")
        writer.write_message(ciphertext)
```

#### Convenience Functions

For single-message operations:

```python
from noiseframework import write_framed_message, read_framed_message

# Write single framed message
write_framed_message(stream, b"Hello")

# Read single framed message
message = read_framed_message(stream)

# With custom max size
message = read_framed_message(stream, max_message_size=1024*1024)
```

#### Error Handling

```python
from noiseframework import FramingError

try:
    message = reader.read_message()
except FramingError as e:
    # Connection closed, oversized message, or invalid frame
    print(f"Framing error: {e}")
except IOError as e:
    # Underlying stream error
    print(f"IO error: {e}")
```

**Key Points:**
- Automatic handling of partial reads
- Protection against oversized messages (configurable limit)
- Message counters for debugging (`messages_sent`, `messages_received`)
- Thread-safe for concurrent read/write on different threads
- Works with any byte stream (sockets, files, pipes, etc.)

See [`examples/framed_tcp_example.py`](examples/framed_tcp_example.py) for a complete working example.

### Async/Await Support

NoiseFramework provides full `asyncio` support for modern async Python applications. All async classes wrap the synchronous implementation using `run_in_executor`, making them safe for use in async contexts without blocking the event loop.

#### Basic Async Usage

```python
import asyncio
from noiseframework import AsyncNoiseHandshake, AsyncNoiseTransport

async def async_handshake():
    # Create async handshake
    handshake = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    await handshake.set_as_initiator()
    await handshake.generate_static_keypair()
    await handshake.initialize()
    
    # Perform handshake (async)
    msg1 = await handshake.write_message(b"")
    # ... exchange messages over network ...
    
    # Convert to async transport
    transport = await handshake.to_transport()
    
    # Send/receive encrypted messages (async)
    ciphertext = await transport.send(b"Hello, async world!")
    plaintext = await transport.receive(ciphertext)

# Run the async function
asyncio.run(async_handshake())
```

#### Async TCP Server Example

```python
import asyncio
from noiseframework import (
    AsyncNoiseHandshake,
    AsyncFramedReader,
    AsyncFramedWriter,
)

async def handle_client(reader, writer):
    """Handle incoming client connection."""
    # Create responder handshake
    handshake = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    await handshake.set_as_responder()
    await handshake.generate_static_keypair()
    await handshake.initialize()
    
    # Wrap streams with framing
    framed_reader = AsyncFramedReader(reader)
    framed_writer = AsyncFramedWriter(writer)
    
    # Perform XX handshake
    msg1 = await framed_reader.read_message()
    await handshake.read_message(msg1)
    
    msg2 = await handshake.write_message(b"")
    await framed_writer.write_message(msg2)
    
    msg3 = await framed_reader.read_message()
    await handshake.read_message(msg3)
    
    # Switch to transport mode
    transport = await handshake.to_transport()
    
    # Receive and process encrypted messages
    while True:
        try:
            ciphertext = await framed_reader.read_message()
            plaintext = await transport.receive(ciphertext)
            print(f"Received: {plaintext.decode()}")
            
            # Send encrypted response
            response = await transport.send(b"Message received!")
            await framed_writer.write_message(response)
        except:
            break
    
    await framed_writer.close()

async def main():
    server = await asyncio.start_server(
        handle_client, '127.0.0.1', 9999
    )
    async with server:
        await server.serve_forever()

asyncio.run(main())
```

#### Async TCP Client Example

```python
async def async_client():
    # Connect to server
    reader, writer = await asyncio.open_connection('127.0.0.1', 9999)
    
    # Create initiator handshake
    handshake = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    await handshake.set_as_initiator()
    await handshake.generate_static_keypair()
    await handshake.initialize()
    
    # Wrap streams with framing
    framed_reader = AsyncFramedReader(reader)
    framed_writer = AsyncFramedWriter(writer)
    
    # Perform XX handshake (3 messages)
    msg1 = await handshake.write_message(b"")
    await framed_writer.write_message(msg1)
    
    msg2 = await framed_reader.read_message()
    await handshake.read_message(msg2)
    
    msg3 = await handshake.write_message(b"")
    await framed_writer.write_message(msg3)
    
    # Switch to transport mode
    transport = await handshake.to_transport()
    
    # Send encrypted messages
    for i in range(3):
        message = f"Message {i+1}".encode()
        ciphertext = await transport.send(message)
        await framed_writer.write_message(ciphertext)
        
        response_ct = await framed_reader.read_message()
        response = await transport.receive(response_ct)
        print(f"Server response: {response.decode()}")
    
    await framed_writer.close()

asyncio.run(async_client())
```

#### Async Framing

For asyncio streams, use `AsyncFramedReader` and `AsyncFramedWriter`:

```python
from noiseframework import AsyncFramedReader, AsyncFramedWriter

async def async_framed_communication(reader, writer):
    framed_writer = AsyncFramedWriter(writer)
    framed_reader = AsyncFramedReader(reader)
    
    # Write framed message
    await framed_writer.write_message(b"Hello, async!")
    
    # Read framed message
    message = await framed_reader.read_message()
    
    # Close when done
    await framed_writer.close()
```

#### Async Convenience Functions

```python
from noiseframework import (
    async_write_framed_message,
    async_read_framed_message,
)

# Write single message
await async_write_framed_message(writer, b"Hello")

# Read single message
message = await async_read_framed_message(reader)
```

#### Async API Classes

**AsyncNoiseHandshake**: Async wrapper for `NoiseHandshake`
- `await set_as_initiator()` - Set role as initiator
- `await set_as_responder()` - Set role as responder
- `await generate_static_keypair()` - Generate static keys
- `await set_static_keypair(private, public)` - Set existing keys
- `await set_remote_static_public_key(public)` - Set remote's public key
- `await initialize()` - Initialize handshake state
- `await write_message(payload)` - Write handshake message
- `await read_message(message)` - Read handshake message
- `await to_transport()` - Get AsyncNoiseTransport after completion
- `await get_handshake_hash()` - Get handshake hash
- `.is_complete` - Check if handshake is complete (property)

**AsyncNoiseTransport**: Async wrapper for `NoiseTransport`
- `await send(plaintext, ad=b"")` - Encrypt and send message
- `await receive(ciphertext, ad=b"")` - Decrypt and receive message
- `.send_nonce` - Current send nonce (property)
- `.receive_nonce` - Current receive nonce (property)

**AsyncFramedReader**: Async framed message reader
- `await read_message()` - Read length-prefixed message
- `await close()` - Close reader
- `.messages_received` - Message counter (property)

**AsyncFramedWriter**: Async framed message writer
- `await write_message(message)` - Write length-prefixed message
- `await close()` - Close writer and wait for completion
- `.messages_sent` - Message counter (property)

**Key Points:**
- All async operations use `run_in_executor` internally
- No blocking calls in the async event loop
- Compatible with `asyncio.StreamReader` and `asyncio.StreamWriter`
- Same security guarantees as synchronous version
- Logging support in all async classes

See [`examples/async_tcp_example.py`](examples/async_tcp_example.py) for a complete working example with server and client.

---

## 🖥️ CLI Documentation

The `NoiseFramework` command-line tool provides easy access to key operations without writing code.

### Generate Keypair

Generate static keypairs for use in Noise handshakes:

```bash
# Generate Curve25519 keypair (default)
noiseframework generate-keypair -o mykey
# Creates: mykey_private.key (32 bytes), mykey_public.key (32 bytes)

# Generate Curve448 keypair
noiseframework generate-keypair --dh 448 -o mykey448
# Creates: mykey448_private.key (56 bytes), mykey448_public.key (56 bytes)

# Use short alias
noiseframework genkey -o server_key
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
from noiseframework import NoiseHandshake

# Load generated keys
private_key = Path("mykey_private.key").read_bytes()
public_key = Path("mykey_public.key").read_bytes()

# Use in handshake
hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
hs.set_static_keypair(private_key, public_key)
```

### Validate Pattern

Validate Noise pattern strings and view their components:

```bash
# Validate a pattern
noiseframework validate-pattern "Noise_XX_25519_ChaChaPoly_SHA256"

# Use short alias
noiseframework validate "Noise_IK_448_AESGCM_BLAKE2b"
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
noiseframework validate "Noise_INVALID_Pattern"
# Error: Invalid pattern: Unsupported handshake pattern: INVALID
```

### Show Information

Display supported cryptographic primitives and patterns:

```bash
noiseframework info
```

**Output:**
```
NoiseFramework - Noise Protocol Framework Implementation

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
noiseframework --help
noiseframework generate-keypair --help

# Show version
noiseframework --version
```

---

## 🔐 Supported Patterns

NoiseFramework supports all fundamental and interactive Noise patterns:

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

NoiseFramework uses battle-tested cryptographic libraries:

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
noiseframework/
├── noiseframework/
│   ├── __init__.py          # Public API
│   ├── noise/
│   │   ├── handshake.py     # Handshake state machine
│   │   ├── pattern.py       # Pattern parser and validator
│   │   └── state.py         # Cipher and symmetric state
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
│   └── test_cipher.py
├── examples/
│   ├── basic_client_server.py
│   ├── simple_chat.py
│   └── file_encryption.py
├── docs/
│   ├── API.md
│   ├── CHANGELOG.md
│   └── ...
├── pyproject.toml
└── README.md
```

---

## 🧪 Testing

NoiseFramework has comprehensive test coverage with 156 tests achieving 92% code coverage.

---

## ⚡ Performance

NoiseFramework delivers production-ready performance with real-world benchmarks:

- **Handshakes**: ~1,500-1,800 complete handshakes/sec (XX pattern)
- **Transport encryption**: **3+ GB/s** throughput for large messages
- **Key generation**: ~32,000 keypairs/sec (Curve25519)
- **Latency**: <3 µs per small message encryption

### Quick Benchmark Results

| Operation | Performance |
|-----------|-------------|
| Complete XX handshake | 558-642 µs |
| Encrypt 64 KB message | 18.5 µs (3.29 GB/s) |
| Encrypt 1 KB message | 2.4 µs (403 MB/s) |
| Generate Curve25519 keypair | 31 µs |

**See [BENCHMARKS.md](docs/BENCHMARKS.md) for comprehensive performance analysis, methodology, and optimization tips.**

### Run Benchmarks Yourself

```bash
# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# or
.\.venv\Scripts\Activate.ps1  # Windows PowerShell

# Run benchmark script
python benchmark.py
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
pytest --cov=noiseframework --cov-report=html

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

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for detailed guidelines.

### Development Setup

```bash
git clone https://github.com/juliuspleunes4/noiseframework.git
cd noiseframework
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

### Is NoiseFramework production-ready?

Yes, but with caveats:
- ✅ Cryptographically sound (uses battle-tested primitives)
- ✅ Specification-compliant implementation
- ✅ Well-tested (156 tests, 92% coverage)
- ⚠️ Consider security audit for high-stakes applications
- ⚠️ Keep dependencies updated

### How does it compare to other Noise implementations?

- **PyNaCl/libsodium**: Lower-level, NoiseFramework is higher-level Noise protocol
- **noiseprotocol (Python)**: Similar, but NoiseFramework has better docs and CLI
- **snow (Rust)**: Faster, but NoiseFramework is pure Python with better accessibility

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
- **Updates**: Keep NoiseFramework and its dependencies up-to-date
- **Audit**: Consider professional security audits for production use
- **Side-Channels**: Be aware of timing and other side-channel attacks

### Dependencies

NoiseFramework relies on:
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

- **Issues**: [GitHub Issues](https://github.com/juliuspleunes4/noiseframework/issues)
- **Discussions**: [GitHub Discussions](https://github.com/juliuspleunes4/noiseframework/discussions)
- **Documentation**: [Full Documentation](https://noiseframework.readthedocs.io/)

---

<p align="center">
  <strong>Built with ❤️ for secure communications</strong>
</p>

<p align="center">
  <sub>If you find this project useful, please consider giving it a ⭐️</sub>
</p>
