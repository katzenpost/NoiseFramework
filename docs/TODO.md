# NoiseFramework TODO List

This document tracks implementation tasks for NoiseFramework enhancements (version 1.3.0 - Production Readiness).

**Progress**: 6/7 complete (86%)

---

## 📋 **IMPORTANT: Usage Instructions**

**When completing a TODO:**

1. ✅ Mark the item as `[DONE]`
2. 📝 Add implementation details in the **"Implementation Notes"** section
3. 📚 Document any API changes, new imports, or usage examples
4. ⚠️ Note any breaking changes or deprecations
5. 🔗 Reference the files modified

**Why?** This ensures when we update README.md, API.md, and other documentation at the end, we have accurate information about what was actually implemented, preventing documentation-code mismatches.

---

## 🎯 HIGH PRIORITY - Production Readiness

### 1. ✅ **Async/Await Support** [DONE]

**Goal**: Add async support for modern Python applications using asyncio.

**Tasks**:
- [x] Create `noiseframework/async_support.py` module
- [x] Implement `AsyncNoiseHandshake` class wrapping sync operations
- [x] Implement `AsyncNoiseTransport` class
- [x] Add async examples
- [x] Add tests for async functionality
- [x] Update documentation

**Target Files**:
- New: `noiseframework/async_support.py` (~450 lines)
- New: `examples/async_tcp_example.py` (~300 lines)
- New: `tests/test_async.py` (21 tests, 100% pass rate)
- Modified: `noiseframework/__init__.py` (added 6 async exports)
- Updated: `README.md` (async section added)
- Updated: `docs/API.md` (complete async API documentation)

**Implementation Strategy**:
- Uses `asyncio.run_in_executor()` to wrap synchronous operations
- No blocking calls in event loop
- Compatible with `asyncio.StreamReader` and `asyncio.StreamWriter`
- Same security guarantees as synchronous version

**Implementation Notes**:

**Import Statements**:
```python
# Main async classes
from noiseframework import AsyncNoiseHandshake, AsyncNoiseTransport

# Async framing utilities
from noiseframework import AsyncFramedReader, AsyncFramedWriter

# Async convenience functions
from noiseframework import async_read_framed_message, async_write_framed_message
```

**AsyncNoiseHandshake API**:
```python
# Constructor (same as sync, but methods are async)
handshake = AsyncNoiseHandshake(pattern: str, logger: Optional[logging.Logger] = None)

# Async methods (all require await)
await handshake.set_as_initiator()
await handshake.set_as_responder()
await handshake.generate_static_keypair()
await handshake.set_static_keypair(private_key: bytes, public_key: bytes)
await handshake.set_remote_static_public_key(public_key: bytes)
await handshake.initialize()
msg = await handshake.write_message(payload: bytes = b"")
payload = await handshake.read_message(message: bytes)
transport = await handshake.to_transport()  # Returns AsyncNoiseTransport
h = await handshake.get_handshake_hash()

# Properties (sync access, no await needed)
is_complete = handshake.is_complete  # bool
pattern = handshake.pattern  # NoisePattern object
```

**AsyncNoiseTransport API**:
```python
# Created from AsyncNoiseHandshake.to_transport()
transport = await handshake.to_transport()

# Async methods
ciphertext = await transport.send(plaintext: bytes, associated_data: bytes = b"")
plaintext = await transport.receive(ciphertext: bytes, associated_data: bytes = b"")

# Properties (sync access, no await)
send_nonce = transport.send_nonce  # int
receive_nonce = transport.receive_nonce  # int
```

**AsyncFramedReader API**:
```python
# Constructor
reader = AsyncFramedReader(
    reader: asyncio.StreamReader,
    max_message_size: int = 16*1024*1024,  # 16 MB default
    logger: Optional[logging.Logger] = None
)

# Async methods
message = await reader.read_message()  # Returns bytes
await reader.close()

# Properties
messages_received = reader.messages_received  # int
```

**AsyncFramedWriter API**:
```python
# Constructor
writer = AsyncFramedWriter(
    writer: asyncio.StreamWriter,
    max_message_size: int = 16*1024*1024,  # 16 MB default
    logger: Optional[logging.Logger] = None
)

# Async methods
await writer.write_message(message: bytes)
await writer.close()

# Properties
messages_sent = writer.messages_sent  # int
```

**Complete Working Example**:
```python
import asyncio
from noiseframework import AsyncNoiseHandshake, AsyncFramedReader, AsyncFramedWriter

async def handle_client(reader, writer):
    """Server side (responder)."""
    # Create handshake
    hs = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    await hs.set_as_responder()
    await hs.generate_static_keypair()
    await hs.initialize()
    
    # Create framing
    framed_reader = AsyncFramedReader(reader)
    framed_writer = AsyncFramedWriter(writer)
    
    # Perform handshake (XX pattern: <- e, <- e, ee, -> s, se, <- s, es)
    msg1 = await framed_reader.read_message()
    await hs.read_message(msg1)
    
    msg2 = await hs.write_message(b"")
    await framed_writer.write_message(msg2)
    
    msg3 = await framed_reader.read_message()
    await hs.read_message(msg3)
    
    # Switch to transport mode
    transport = await hs.to_transport()
    
    # Receive encrypted message
    ciphertext = await framed_reader.read_message()
    plaintext = await transport.receive(ciphertext)
    print(f"Server received: {plaintext.decode()}")
    
    await framed_writer.close()

async def client():
    """Client side (initiator)."""
    reader, writer = await asyncio.open_connection('localhost', 9999)
    
    # Create handshake
    hs = AsyncNoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    await hs.set_as_initiator()
    await hs.generate_static_keypair()
    await hs.initialize()
    
    # Create framing
    framed_reader = AsyncFramedReader(reader)
    framed_writer = AsyncFramedWriter(writer)
    
    # Perform handshake
    msg1 = await hs.write_message(b"")
    await framed_writer.write_message(msg1)
    
    msg2 = await framed_reader.read_message()
    await hs.read_message(msg2)
    
    msg3 = await hs.write_message(b"")
    await framed_writer.write_message(msg3)
    
    # Switch to transport mode
    transport = await hs.to_transport()
    
    # Send encrypted message
    ciphertext = await transport.send(b"Hello, async server!")
    await framed_writer.write_message(ciphertext)
    
    await framed_writer.close()

# Run server
async def main():
    server = await asyncio.start_server(handle_client, 'localhost', 9999)
    async with server:
        await server.serve_forever()

asyncio.run(main())
```

**Performance Characteristics**:
- All async operations use `run_in_executor()` to avoid blocking event loop
- Minimal overhead (microseconds) compared to synchronous version
- No native async cryptography (wraps sync primitives)
- Suitable for I/O-bound applications where concurrency is beneficial
- Not faster than sync version for single operations, but allows concurrent handshakes

**Limitations and Caveats**:
- Underlying crypto operations still run synchronously (via executor)
- No performance gain for CPU-bound workloads
- Best for I/O-bound scenarios (network communication, multiple concurrent connections)
- Memory usage slightly higher due to executor threads

**Testing**:
- 21 async tests covering all async classes and methods
- Tests complete in <1 second (no blocking)
- In-memory tests for speed (no real TCP connections)
- Total test count: 228 tests (207 original + 21 async)

**Documentation**:
- Complete async section in `README.md` with usage examples
- Full async API reference in `docs/API.md`
- Working example in `examples/async_tcp_example.py`
- See `docs/CHANGELOG.md` for detailed changes

---

### 2. ✅ **Logging Support** [DONE]

**Goal**: Add comprehensive logging throughout the library for debugging and monitoring.

**Tasks**:
- [x] Add logging to `NoiseHandshake` class
- [x] Add logging to `NoiseTransport` class
- [x] Add logging to crypto operations (optional, debug level)
- [x] Add logging configuration examples
- [x] Document logging levels and what they show
- [x] Add tests that verify logging output

**Target Files**:
- Modified: `noiseframework/noise/handshake.py`
- Modified: `noiseframework/transport/transport.py`
- Modified: `noiseframework/noise/state.py`
- New: `examples/logging_example.py`
- New: `tests/test_logging.py`
- Update: `docs/API.md` (pending)

**Logging Levels Implemented**:
- `DEBUG`: Detailed protocol steps, message sizes, nonces, tokens, key operations
- `INFO`: Role setting, handshake completion, transport creation, message send/receive
- `WARNING`: Approaching nonce limits (2^63+)
- `ERROR`: Authentication failures, invalid states, validation errors

**Implementation Notes**:

**Logger Parameters** (added to all main classes):
```python
# NoiseHandshake
NoiseHandshake(pattern: str, logger: Optional[logging.Logger] = None)
# Default logger: logging.getLogger("noiseframework.noise.handshake.NoiseHandshake")

# NoiseTransport
NoiseTransport(send_cipher, receive_cipher, logger: Optional[logging.Logger] = None)
# Default logger: logging.getLogger("noiseframework.transport.transport.NoiseTransport")

# SymmetricState
SymmetricState(hash_func, cipher, logger: Optional[logging.Logger] = None)
# Default logger: logging.getLogger("noiseframework.noise.state.SymmetricState")

# CipherState
CipherState(cipher, logger: Optional[logging.Logger] = None)
# Default logger: logging.getLogger("noiseframework.noise.state.CipherState")
```

**Basic Usage**:
```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
)

# Use NoiseFramework normally - logging happens automatically
handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
handshake.set_as_initiator()  # Logs: "Set role to INITIATOR"
handshake.initialize()        # Logs: "Handshake initialized"
```

**Custom Logger**:
```python
# Create custom logger
custom_logger = logging.getLogger("myapp.noise")
custom_logger.setLevel(logging.DEBUG)

# Pass to NoiseHandshake
handshake = NoiseHandshake(pattern, logger=custom_logger)
```

**What Gets Logged**:

- **DEBUG Level**: Token processing, message sizes, nonce values, key operations, state initialization
- **INFO Level**: Role changes, handshake completion, transport creation, successful message operations
- **WARNING Level**: Nonce approaching limit (>= 2^63, warns about 2^64 overflow)
- **ERROR Level**: Invalid state transitions, validation failures (always logged before raising exceptions)

**Example Log Output**:
```
2025-11-24 15:30:01 [INFO    ] noiseframework.noise.handshake.NoiseHandshake: Set role to INITIATOR
2025-11-24 15:30:01 [DEBUG   ] noiseframework.noise.handshake.NoiseHandshake: Generating static keypair (Curve25519)
2025-11-24 15:30:01 [INFO    ] noiseframework.noise.handshake.NoiseHandshake: Generated static keypair
2025-11-24 15:30:01 [DEBUG   ] noiseframework.noise.handshake.NoiseHandshake: Initializing handshake (pattern=Noise_XX_25519_ChaChaPoly_SHA256)
2025-11-24 15:30:01 [INFO    ] noiseframework.noise.handshake.NoiseHandshake: Handshake initialized
2025-11-24 15:30:01 [DEBUG   ] noiseframework.noise.handshake.NoiseHandshake: Writing handshake message 1 (payload=0 bytes)
2025-11-24 15:30:01 [DEBUG   ] noiseframework.noise.handshake.NoiseHandshake: Processing tokens: ['e']
2025-11-24 15:30:01 [INFO    ] noiseframework.noise.handshake.NoiseHandshake: Sent handshake message 1 (ciphertext=32 bytes)
```

**Performance Impact**: Minimal - logging is only performed when handlers are configured. Default Python logging has negligible overhead when no handlers are attached.

**Test Coverage**: 21 new tests in `tests/test_logging.py` covering all log levels, custom loggers, and different scenarios.

---

### 3. ✅ **Message Framing Helper** [DONE]

**Goal**: Provide built-in message framing for network communication.

**Tasks**:
- [x] Create `noiseframework/framing.py` module
- [x] Implement length-prefixed framing
- [x] Add chunked reading support (partial reads)
- [x] Add examples with real sockets
- [x] Add tests for edge cases (partial reads, large messages)

**Target Files**:
- New: `noiseframework/framing.py`
- New: `examples/framed_tcp_example.py`
- New: `tests/test_framing.py`
- Update: `noiseframework/__init__.py` (added to exports)

**Frame Format**:
```
┌──────────────┬────────────────────┐
│ Length (4B)  │  Message Data      │
│ big-endian   │  (0 to 2^32-1 B)   │
└──────────────┴────────────────────┘
```
- Header: 4 bytes, big-endian unsigned int (`struct.pack("!I", length)`)
- Max message size: 16 MB default (configurable, must be < 2^32)

**Implementation Notes**:

**Classes and API**:
```python
# Exception
class FramingError(Exception):
    """Raised for framing-related errors (oversized messages, truncated frames, etc.)"""

# Writer
class FramedWriter:
    def __init__(self, stream, max_message_size=16*1024*1024, logger=None)
    def write_message(self, message: bytes) -> None
        """Write length-prefixed message. Raises FramingError if message > max_message_size."""
    def close(self) -> None
    @property messages_sent: int  # Counter for debugging

# Reader
class FramedReader:
    def __init__(self, stream, max_message_size=16*1024*1024, logger=None)
    def read_message(self) -> bytes
        """Read length-prefixed message. Raises FramingError if oversized or truncated."""
    def close(self) -> None
    @property messages_received: int  # Counter for debugging
    
    # Internal helper
    def _read_exactly(self, num_bytes: int) -> bytes
        """Handles partial reads automatically, accumulating until num_bytes received."""

# Convenience functions
def write_framed_message(stream, message: bytes, max_message_size=...) -> None
def read_framed_message(stream, max_message_size=...) -> bytes
```

**Usage Example**:
```python
from noiseframework import NoiseHandshake, FramedWriter, FramedReader
import socket

# After handshake completes
transport = handshake.to_transport()

# Wrap socket streams
writer = FramedWriter(sock.makefile('wb'))
reader = FramedReader(sock.makefile('rb'))

# Send/receive with automatic framing
ciphertext = transport.send(b"Hello!")
writer.write_message(ciphertext)

framed_msg = reader.read_message()
plaintext = transport.receive(framed_msg)
```

**Error Handling**:
- `FramingError`: Oversized message (> max_message_size), truncated header/data, connection closed
- `IOError`: Underlying stream errors or struct.unpack failures
- `ValueError`: Invalid max_message_size (≤ 0 or ≥ 2^32)

**Features**:
- Automatic handling of partial reads (no manual buffering needed)
- Size validation before reading (prevents memory exhaustion)
- Logging support (INFO for messages, DEBUG for sizes, ERROR for failures)
- Message counters for debugging
- Works with any byte stream (sockets, files, pipes, BytesIO, etc.)
- Thread-safe for concurrent read/write

**Performance Characteristics**:
- Zero-copy for small messages (direct write/read)
- Buffering for partial reads (accumulates chunks efficiently)
- Minimal overhead: 4 bytes per message + validation
- No async support yet (sync only)

**Test Coverage**: 30 tests in `tests/test_framing.py` covering:
- Normal read/write operations
- Empty messages, large messages (1 MB+)
- Oversized messages (> max_message_size)
- Truncated headers and data
- Partial reads simulation
- Round-trip preservation
- Convenience functions
- Logging output
- Counter functionality

---

### 4. ✅ **Connection/Session Manager** [DONE]

**Goal**: High-level API that combines handshake and transport in one object.

**Tasks**:
- [x] Create `noiseframework/connection.py` module
- [x] Implement `NoiseConnection` class (sync)
- [x] Implement `AsyncNoiseConnection` class (async)
- [x] Auto-transition from handshake to transport
- [x] Add convenience methods for common patterns
- [x] Support both sync and async
- [x] Add examples
- [x] Add comprehensive tests

**Target Files**:
- New: `noiseframework/connection.py` (~654 lines)
- New: `examples/connection_example.py` (~290 lines)
- New: `tests/test_connection.py` (25 tests, 100% pass rate)
- Modified: `noiseframework/__init__.py` (added 2 exports)
- Updated: `README.md` (connection section added)
- Updated: `docs/API.md` (complete connection API documentation)

**Implementation Notes**:

**Import Statements**:
```python
# Synchronous connection
from noiseframework import NoiseConnection

# Asynchronous connection
from noiseframework import AsyncNoiseConnection
```

**NoiseConnection API** (Synchronous):
```python
# Constructor
conn = NoiseConnection(
    pattern: str,                              # e.g., "Noise_XX_25519_ChaChaPoly_SHA256"
    role: str,                                 # "initiator" or "responder"
    static_private_key: Optional[bytes] = None,  # Pre-generated keys (optional)
    static_public_key: Optional[bytes] = None,
    remote_static_public_key: Optional[bytes] = None,  # Known remote key (for IK, NK)
    max_message_size: int = 16*1024*1024,      # 16 MB default
    logger: Optional[logging.Logger] = None
)

# Connection methods
conn.connect(address: Tuple[str, int])  # Initiator: connect and perform handshake
conn.accept(client_socket: socket.socket)  # Responder: accept and perform handshake
conn.send(plaintext: bytes)  # Send encrypted message
plaintext = conn.receive()  # Receive and decrypt message (returns bytes)
conn.close()  # Close connection

# Properties (sync access, no await needed)
is_connected = conn.is_connected  # bool
remote_key = conn.remote_static_public_key  # Optional[bytes]
local_key = conn.local_static_public_key  # Optional[bytes]

# Context manager support
with NoiseConnection(pattern, role) as conn:
    conn.connect(address)
    conn.send(b"data")
    response = conn.receive()
# Automatically closes on exit
```

**AsyncNoiseConnection API** (Asynchronous):
```python
# Constructor (same as sync)
conn = AsyncNoiseConnection(
    pattern: str,
    role: str,
    static_private_key: Optional[bytes] = None,
    static_public_key: Optional[bytes] = None,
    remote_static_public_key: Optional[bytes] = None,
    max_message_size: int = 16*1024*1024,
    logger: Optional[logging.Logger] = None
)

# Async connection methods (all require await)
await conn.connect(address: Tuple[str, int])  # Initiator
await conn.accept_streams(reader: StreamReader, writer: StreamWriter)  # Responder
await conn.send(plaintext: bytes)
plaintext = await conn.receive()  # Returns bytes
await conn.close()

# Properties (sync access, no await)
is_connected = conn.is_connected  # bool
remote_key = conn.remote_static_public_key  # Optional[bytes]
local_key = conn.local_static_public_key  # Optional[bytes]

# Async context manager support
async with AsyncNoiseConnection(pattern, role) as conn:
    await conn.connect(address)
    await conn.send(b"data")
    response = await conn.receive()
# Automatically closes on exit
```

**Complete Working Example (Sync)**:
```python
from noiseframework import NoiseConnection
import socket
import threading

def server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("localhost", 9999))
    server_sock.listen(1)
    client_sock, _ = server_sock.accept()
    
    with NoiseConnection("Noise_XX_25519_ChaChaPoly_SHA256", "responder") as conn:
        conn.accept(client_sock)  # Automatic handshake
        data = conn.receive()
        conn.send(b"Echo: " + data)
    
    server_sock.close()

# Start server in background
threading.Thread(target=server, daemon=True).start()

# Client
with NoiseConnection("Noise_XX_25519_ChaChaPoly_SHA256", "initiator") as conn:
    conn.connect(("localhost", 9999))  # Automatic handshake
    conn.send(b"Hello!")
    response = conn.receive()
    print(response)  # b"Echo: Hello!"
```

**Complete Working Example (Async)**:
```python
import asyncio
from noiseframework import AsyncNoiseConnection

async def handle_client(reader, writer):
    async with AsyncNoiseConnection("Noise_XX_25519_ChaChaPoly_SHA256", "responder") as conn:
        await conn.accept_streams(reader, writer)  # Automatic handshake
        data = await conn.receive()
        await conn.send(b"Echo: " + data)

async def main():
    # Start server
    server = await asyncio.start_server(handle_client, "localhost", 9999)
    
    # Client
    async with AsyncNoiseConnection("Noise_XX_25519_ChaChaPoly_SHA256", "initiator") as conn:
        await conn.connect(("localhost", 9999))  # Automatic handshake
        await conn.send(b"Hello!")
        response = await conn.receive()
        print(response)  # b"Echo: Hello!"
    
    server.close()
    await server.wait_closed()

asyncio.run(main())
```

**Key Features**:
- **Automatic Handshake**: No manual `write_message()`/`read_message()` calls
- **Automatic Transport Transition**: Seamlessly switches after handshake
- **Automatic Framing**: Built-in length-prefixed message framing
- **Connection Lifecycle**: `connect()`, `accept()`, `send()`, `receive()`, `close()`
- **Context Manager**: Automatic cleanup with `with` statement
- **Error Handling**: Clear exceptions (ValidationError, HandshakeError, TransportError)
- **Identity Management**: Access to local and remote static public keys
- **Custom Keys**: Support for pre-generated keypairs (persistent identity)
- **Both Sync & Async**: Identical APIs, choose based on application needs

**When to Use**:
- **Use NoiseConnection when**: You want simple, high-level API for complete connections
- **Use NoiseHandshake + NoiseTransport when**: You need fine control over handshake steps or custom message handling
- **Use Framing separately when**: You're implementing custom protocols on top of Noise

**Thread Safety**:
- Each connection instance is **not** thread-safe
- Use separate connections per thread
- Or protect with locks if sharing across threads

**Performance Characteristics**:
- Automatic handshake detection: O(1) per message
- Message overhead: 4 bytes (framing) + 16 bytes (AEAD tag)
- Zero-copy for transport operations
- Async version uses executor for crypto operations (non-blocking I/O)

**Test Coverage**: 25 tests in `tests/test_connection.py` covering:
- Connection initialization (initiator/responder, custom keys)
- Error handling (invalid role, not connected, wrong methods)
- Context managers (sync and async)
- Full communication (handshake + multiple messages)
- Remote key access
- Large messages (100 KB+)
- Both sync and async versions

**Documentation**:
- Complete connection section in `README.md` with usage examples
- Full API reference in `docs/API.md`
- Working examples in `examples/connection_example.py` (sync, async, advanced)
- See `docs/CHANGELOG.md` for detailed changes

---

---

### 5. ✅ **Better Error Messages** [DONE]

**Goal**: Improve error messages to be more helpful and actionable.

**Tasks**:
- [x] Audit all `ValueError` and `RuntimeError` exceptions
- [x] Rewrite error messages with context and solutions
- [x] Add custom exception classes where appropriate
- [x] Document all exception types
- [x] Add error handling examples

**Target Files**:
- New: `noiseframework/exceptions.py` (~150 lines with 14 custom exception classes)
- Modified: `noiseframework/noise/handshake.py` (15+ error types with context-aware messages)
- Modified: `noiseframework/noise/pattern.py` (pattern validation with suggestions)
- Modified: `noiseframework/noise/state.py` (key and nonce errors)
- Modified: `noiseframework/crypto/cipher.py` (authentication and key size errors)
- Modified: `noiseframework/crypto/dh.py` (DH key size errors)
- Modified: `noiseframework/crypto/hash.py` (HKDF and hash function errors)
- Modified: `noiseframework/framing.py` (message size validation)
- Modified: `noiseframework/async_support.py` (async validation)
- Modified: `noiseframework/cli/main.py` (CLI error handling)
- Modified: `noiseframework/__init__.py` (exported 14 exception classes)
- New: `examples/error_handling_example.py` (~380 lines with 9 comprehensive examples)
- Updated: `docs/API.md` (exception documentation - pending complete update)
- Updated: `tests/*.py` (all 10 test files updated, 228 tests passing)

**Custom Exception Hierarchy** (14 classes):
```python
NoiseError (base)
├── HandshakeError
│   ├── RoleNotSetError
│   ├── RoleAlreadySetError
│   ├── WrongTurnError
│   ├── HandshakeCompleteError
│   └── MissingKeyError
├── PatternError
│   ├── UnsupportedPatternError
│   └── UnsupportedPrimitiveError
├── StateError
│   ├── NoKeySetError
│   ├── NonceOverflowError
│   └── InvalidKeySizeError
├── TransportError
│   └── AuthenticationError
├── CryptoError
├── ValidationError
└── FramingError (already existed, now inherits from NoiseError)
```

**Implementation Notes**:

All `ValueError` and `RuntimeError` exceptions replaced with specific custom exceptions throughout the entire codebase (11 production files modified). Every exception now includes:

1. **Current state context**: Role, pattern, message number, nonce value, etc.
2. **Expected vs actual values**: "Expected 32 bytes, got 5 bytes"
3. **Actionable suggestions**: "Call generate_static_keypair() first"
4. **Pattern-specific hints**: For IK/NK/XK/KK patterns requiring pre-message keys

**Example Error Messages**:

Before: `ValueError: Role not set`
After: `RoleNotSetError: Cannot write handshake message: role not set. Call set_as_initiator() or set_as_responder() first.`

Before: `ValueError: Handshake already complete`
After: `HandshakeCompleteError: Handshake already complete for pattern XX. Call to_transport() to create transport ciphers.`

Before: `ValueError: Keys not available for es`
After: `MissingKeyError: Cannot perform 'es' operation: remote static public key not available. For IK pattern, call set_remote_static_public_key() before initialize().`

Before: `ValueError: Decryption failed`
After: `AuthenticationError: ChaCha20-Poly1305 decryption failed: authentication tag verification failed. This indicates message tampering, corruption, or wrong keys.`

**Error Handling Best Practices**:
```python
# Catch specific exceptions for targeted handling
try:
    hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    hs.initialize()
except RoleNotSetError as e:
    print(f"Set role first: {e}")
except MissingKeyError as e:
    print(f"Missing key: {e}")

# Catch all NoiseFramework exceptions
try:
    # ... noise operations ...
except NoiseError as e:
    print(f"Framework error: {e}")

# Catch all pattern/validation errors
try:
    hs = NoiseHandshake(pattern_string)
except PatternError as e:
    print(f"Invalid pattern: {e}")
```

**Examples**: `examples/error_handling_example.py` contains 9 comprehensive examples:
1. Pattern validation errors (format, unsupported DH/cipher/hash)
2. Role configuration errors (not set, already set)
3. Missing key errors (IK pattern requiring remote static key)
4. Wrong turn errors (responder trying to send first)
5. Handshake complete errors (trying to send after completion)
6. Invalid key size errors (wrong byte length for curve)
7. Authentication failures (tampered ciphertext)
8. Production error handling pattern (comprehensive try/except)
9. Catching all NoiseFramework errors (using base class)

**Test Coverage**: 243 tests passing (100% pass rate)
- All 10 test files updated to expect custom exceptions
- Tests verify correct exception types are raised
- Tests verify error messages are helpful
- Added `tests/test_exceptions.py` with 15 dedicated tests:
  - Exception hierarchy validation (all inherit from NoiseError)
  - Category-based exception catching (HandshakeError, PatternError, StateError, TransportError)
  - Exception instantiation with messages
  - Docstring completeness verification
  - Proper export from main package

**Documentation**:
- See `docs/CHANGELOG.md` for detailed feature description
- Complete example in `examples/error_handling_example.py`
- API.md needs comprehensive exception documentation update (see task #7)

---

### 6. ✅ **PSK (Pre-Shared Key) Support** [DONE]

**Goal**: Add support for PSK patterns for quantum-resistant authentication.

**Tasks**:
- [x] Extend pattern parser to recognize PSK modifiers
- [x] Add PSK token processing (uses existing `MixKeyAndHash`)
- [x] Add `set_psk()` method to `NoiseHandshake`
- [x] Add async PSK support (`AsyncNoiseHandshake.set_psk()`)
- [x] Update pattern validation
- [x] Add PSK examples
- [x] Add comprehensive tests for PSK patterns

**Target Files**:
- Modified: `noiseframework/noise/pattern.py` (added `psk_modifier` field, PSK regex, token insertion)
- Modified: `noiseframework/noise/handshake.py` (added PSK storage, validation, token processing)
- Modified: `noiseframework/async_support.py` (added async `set_psk()` method)
- New: `examples/psk_example.py` (~290 lines, 3 complete examples)
- New: `tests/test_psk.py` (22 tests, 100% pass rate)
- Updated: `docs/CHANGELOG.md` (PSK feature documented)

**Supported PSK Modifiers**:
- `psk0`: PSK mixed before first message
- `psk1`: PSK mixed after first message
- `psk2`: PSK mixed after second message
- `psk3`: PSK mixed after third message
- `psk4`: PSK mixed after fourth message

**All Base Patterns Work With PSK**:
- NNpsk0, NNpsk2, XXpsk0, XXpsk3, IKpsk0, IKpsk2, KKpsk0, KKpsk2, NKpsk0, NKpsk2, XKpsk1, etc.
- Format: `Noise_<BASE><PSK>_<DH>_<CIPHER>_<HASH>` (e.g., `Noise_XXpsk3_25519_ChaChaPoly_SHA256`)

**Implementation Notes**:

**Pattern String Format**:
```python
# PSK patterns combine base pattern with PSK modifier
"Noise_XXpsk3_25519_ChaChaPoly_SHA256"  # XX with PSK after third message
"Noise_NNpsk0_25519_ChaChaPoly_SHA256"  # NN with PSK before first message
"Noise_IKpsk2_448_AESGCM_BLAKE2b"       # IK with PSK after second message
```

**Import Statements**:
```python
# PSK support works with existing classes
from noiseframework import NoiseHandshake, AsyncNoiseHandshake
```

**NoiseHandshake.set_psk() API**:
```python
def set_psk(self, psk: bytes) -> None:
    """
    Set pre-shared key for PSK patterns.
    
    Args:
        psk: 32-byte pre-shared key
        
    Raises:
        ValidationError: If pattern doesn't use PSK modifier or PSK is not 32 bytes
    """
```

**AsyncNoiseHandshake.set_psk() API**:
```python
async def set_psk(self, psk: bytes) -> None:
    """Async version of set_psk()."""
```

**PSK Mixing Positions**:
- **psk0**: Mixed immediately before first handshake message (most quantum-resistant)
- **psk1**: Mixed after first message is processed
- **psk2**: Mixed after second message is processed (common for IK patterns)
- **psk3**: Mixed after third message is processed (most common - XXpsk3)
- **psk4**: Mixed after fourth message is processed (rare)

**Complete Working Examples**:

**Example 1: NNpsk0 (Anonymous + Early PSK)**:
```python
import os
from noiseframework import NoiseHandshake, NoiseTransport

# Generate shared secret (32 bytes)
psk = os.urandom(32)

# Initiator
initiator = NoiseHandshake("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
initiator.set_as_initiator()
initiator.set_psk(psk)  # Set PSK before initialize
initiator.initialize()

# Responder
responder = NoiseHandshake("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
responder.set_as_responder()
responder.set_psk(psk)  # Must use same PSK
responder.initialize()

# Handshake (2 messages: -> e psk, <- e ee)
msg1 = initiator.write_message(b"")
responder.read_message(msg1)

msg2 = responder.write_message(b"")
initiator.read_message(msg2)

# Create transport
init_send, init_recv = initiator.to_transport()
resp_send, resp_recv = responder.to_transport()

init_transport = NoiseTransport(init_send, init_recv)
resp_transport = NoiseTransport(resp_send, resp_recv)

# Secure communication
ct = init_transport.send(b"Quantum-resistant message!")
pt = resp_transport.receive(ct)
```

**Example 2: XXpsk3 (Mutual Auth + Late PSK, Most Common)**:
```python
psk = os.urandom(32)

# Initiator
initiator = NoiseHandshake("Noise_XXpsk3_25519_ChaChaPoly_SHA256")
initiator.set_as_initiator()
initiator.generate_static_keypair()  # XX requires static keys
initiator.set_psk(psk)
initiator.initialize()

# Responder
responder = NoiseHandshake("Noise_XXpsk3_25519_ChaChaPoly_SHA256")
responder.set_as_responder()
responder.generate_static_keypair()  # XX requires static keys
responder.set_psk(psk)
responder.initialize()

# Handshake (3 messages: -> e, <- e ee s es, -> s se psk)
msg1 = initiator.write_message(b"")
responder.read_message(msg1)

msg2 = responder.write_message(b"")
initiator.read_message(msg2)

msg3 = initiator.write_message(b"")  # PSK mixed here
responder.read_message(msg3)

# Both parties authenticated, PSK provides quantum resistance
# Create transport and communicate...
```

**Example 3: IKpsk2 (Known Responder + Mid PSK)**:
```python
psk = os.urandom(32)

# Responder generates keys first
temp = NoiseHandshake("Noise_IKpsk2_25519_ChaChaPoly_SHA256")
temp.generate_static_keypair()
resp_public = temp.static_public

# Initiator (knows responder's public key)
initiator = NoiseHandshake("Noise_IKpsk2_25519_ChaChaPoly_SHA256")
initiator.set_as_initiator()
initiator.generate_static_keypair()
initiator.set_remote_static_public_key(resp_public)  # Known in advance
initiator.set_psk(psk)
initiator.initialize()

# Responder
responder = NoiseHandshake("Noise_IKpsk2_25519_ChaChaPoly_SHA256")
responder.set_as_responder()
responder.set_static_keypair(temp.static_private, temp.static_public)
responder.set_psk(psk)
responder.initialize()

# Handshake (2 messages: -> e es s ss, <- e ee se psk)
msg1 = initiator.write_message(b"Hello")
payload1 = responder.read_message(msg1)  # "Hello"

msg2 = responder.write_message(b"World")  # PSK mixed here
payload2 = initiator.read_message(msg2)  # "World"

# Initiator authenticated to responder, PSK provides additional security
```

**Security Considerations**:
- **Quantum Resistance**: PSK immune to quantum computer attacks (unlike DH)
- **Additional Authentication**: PSK provides extra authentication layer beyond public keys
- **Pre-computation Resistance**: Attackers can't pre-compute attacks on PSK
- **PSK Management**: PSKs must be exchanged securely out-of-band (like passwords)
- **PSK Reuse**: Same PSK can be reused for multiple sessions safely (mixed into unique handshake state)
- **Placement Trade-offs**:
  - Early PSK (psk0): Maximum quantum resistance, protects entire handshake
  - Late PSK (psk3): Allows public key exchange first, then adds PSK protection
- **Use Cases**: IoT devices, enterprise VPNs, defense systems, embedded systems, any scenario requiring quantum resistance

**Test Coverage**:
- 22 comprehensive tests covering all PSK scenarios
- Pattern parsing (valid/invalid PSK modifiers)
- PSK token placement verification
- PSK validation (size, pattern requirements)
- Complete handshakes (NNpsk0, XXpsk3, IKpsk2)
- PSK mismatch authentication failure
- Transport encryption after PSK handshake
- Multiple message exchange
- Payload handling

---

### 7. ⏳ **Fallback Pattern Support** [TODO]

**Goal**: Add support for fallback patterns (XXfallback, etc.)

**Tasks**:
- [ ] Implement fallback pattern parsing
- [ ] Add fallback handshake logic
- [ ] Add `start_fallback()` method or similar
- [ ] Add examples showing fallback scenarios
- [ ] Add tests for fallback transitions

**Target Files**:
- Modify: `noiseframework/noise/pattern.py`
- Modify: `noiseframework/noise/handshake.py`
- New: `examples/fallback_example.py`
- New: `tests/test_fallback.py`
- Update: `docs/API.md`

**Fallback Scenarios**:
- IK → XXfallback (when responder key is wrong)
- NK → XXfallback (when authentication fails)

**Implementation Notes**:
```
[When completed, document here:]
- How to trigger fallback
- Which patterns support fallback
- API for fallback handling
- Example usage
- Security implications
```

---

## 📊 **Progress Tracking**

**Completed**: 1 / 7 (14%)
**In Progress**: 0
**Not Started**: 6

**Latest Completion**: Logging Support (November 24, 2025)
**Estimated Release**: TBD

---

## 🔄 **Update Checklist** (After All TODOs Complete)

When all items are `[DONE]`, update these files using implementation notes above:

- [ ] `README.md` - Add new features, update examples
- [ ] `docs/API.md` - Document all new classes, methods, exceptions
- [ ] `docs/CHANGELOG.md` - Create entry for version 1.3.0
- [ ] `pyproject.toml` - Update version to 1.3.0
- [ ] `noiseframework/__init__.py` - Update version string, exports
- [ ] `docs/FAQ.md` - Add Q&A for new features
- [ ] `examples/README.md` - Document new examples
- [ ] Website - Update content (if applicable)

---

## 📝 **Notes**

- All features should maintain backward compatibility where possible
- Breaking changes must be clearly documented
- All new code must have tests (minimum 90% coverage)
- All public APIs must have type hints
- All public APIs must have docstrings
- Follow existing code style (PEP 8, Black formatted)

---

**Last Updated**: November 24, 2025
**Target Version**: 1.3.0 - Production Readiness
**Branch**: feat/enhancements
