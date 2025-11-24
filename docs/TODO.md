# NoiseFramework TODO List

This document tracks implementation tasks for NoiseFramework enhancements (version 1.3.0 - Production Readiness).

**Progress**: 3/7 complete (43%)

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

### 4. ⏳ **Connection/Session Manager** [TODO]

**Goal**: High-level API that combines handshake and transport in one object.

**Tasks**:
- [ ] Create `noiseframework/session.py` module
- [ ] Implement `NoiseSession` class
- [ ] Auto-transition from handshake to transport
- [ ] Add convenience methods for common patterns
- [ ] Support both sync and async
- [ ] Add examples
- [ ] Add comprehensive tests

**Target Files**:
- New: `noiseframework/session.py`
- New: `examples/session_example.py`
- New: `tests/test_session.py`
- Update: `noiseframework/__init__.py` (add to exports)

**API Design**:
```python
class NoiseSession:
    def __init__(self, pattern: str, role: str, **kwargs)
    def send(self, data: bytes) -> bytes
    def receive(self, data: bytes) -> Optional[bytes]
    @property
    def is_handshake_complete(self) -> bool
    @property
    def remote_static_key(self) -> Optional[bytes]
```

**Implementation Notes**:
```
[When completed, document here:]
- Complete class signature
- All methods and their exact signatures
- Usage examples for common scenarios
- How it differs from NoiseHandshake + NoiseTransport
- When to use Session vs low-level API
- Thread safety considerations
```

---

### 5. ⏳ **Better Error Messages** [TODO]

**Goal**: Improve error messages to be more helpful and actionable.

**Tasks**:
- [ ] Audit all `ValueError` and `RuntimeError` exceptions
- [ ] Rewrite error messages with context and solutions
- [ ] Add custom exception classes where appropriate
- [ ] Document all exception types
- [ ] Add error handling examples

**Target Files**:
- Modify: `noiseframework/noise/handshake.py`
- Modify: `noiseframework/noise/pattern.py`
- Modify: `noiseframework/noise/state.py`
- Modify: `noiseframework/transport/transport.py`
- New: `noiseframework/exceptions.py` (if creating custom exceptions)
- Update: `docs/API.md`

**Error Messages to Improve**:
- "Keys not available for es" → "IK pattern requires responder's static public key. Call set_remote_static_public_key() before initialize()"
- "Handshake already complete" → "Handshake completed after message 3. Use to_transport() to get transport ciphers for encrypted communication"
- "Invalid pattern string" → Include format example and valid options

**Implementation Notes**:
```
[When completed, document here:]
- List of all custom exception classes (if created)
- List of improved error messages (before/after)
- Error handling best practices
- How to catch specific errors
```

---

### 6. ⏳ **PSK (Pre-Shared Key) Support** [TODO]

**Goal**: Add support for PSK patterns (NNpsk2, XXpsk3, etc.)

**Tasks**:
- [ ] Extend pattern parser to recognize PSK modifiers
- [ ] Add PSK mixing to `SymmetricState`
- [ ] Add `set_psk()` method to `NoiseHandshake`
- [ ] Update pattern validation
- [ ] Add PSK examples
- [ ] Add comprehensive tests for PSK patterns

**Target Files**:
- Modify: `noiseframework/noise/pattern.py`
- Modify: `noiseframework/noise/state.py`
- Modify: `noiseframework/noise/handshake.py`
- New: `examples/psk_example.py`
- New: `tests/test_psk.py`
- Update: `docs/API.md`

**PSK Patterns to Support**:
- NNpsk0, NNpsk2
- XXpsk0, XXpsk3
- IKpsk0, IKpsk2
- (And others from Noise spec)

**Implementation Notes**:
```
[When completed, document here:]
- Exact pattern string format (e.g., "Noise_NNpsk2_25519_ChaChaPoly_SHA256")
- set_psk() method signature
- Where PSK is mixed in different patterns
- Example usage for each PSK pattern
- Security considerations
```

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
