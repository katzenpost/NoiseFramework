# NoiseFramework TODO List

This document tracks implementation tasks for NoiseFramework enhancements (version 1.3.0 - Production Readiness).

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

### 1. ⏳ **Async/Await Support** [TODO]

**Goal**: Add async support for modern Python applications using asyncio.

**Tasks**:
- [ ] Create `noiseframework/async_support.py` module
- [ ] Implement `AsyncNoiseHandshake` class wrapping sync operations
- [ ] Implement `AsyncNoiseTransport` class
- [ ] Add async examples
- [ ] Add tests for async functionality
- [ ] Update documentation

**Target Files**:
- New: `noiseframework/async_support.py`
- New: `examples/async_tcp_server.py`
- New: `tests/test_async.py`

**Implementation Notes**:
```
[When completed, document here:]
- Exact class names and signatures
- Import statements users need
- Example code that works
- Any limitations or caveats
- Performance characteristics
```

---

### 2. ⏳ **Logging Support** [TODO]

**Goal**: Add comprehensive logging throughout the library for debugging and monitoring.

**Tasks**:
- [ ] Add logging to `NoiseHandshake` class
- [ ] Add logging to `NoiseTransport` class
- [ ] Add logging to crypto operations (optional, debug level)
- [ ] Add logging configuration examples
- [ ] Document logging levels and what they show
- [ ] Add tests that verify logging output

**Target Files**:
- Modify: `noiseframework/noise/handshake.py`
- Modify: `noiseframework/transport/transport.py`
- Modify: `noiseframework/noise/state.py`
- New: `examples/logging_example.py`
- Update: `docs/API.md`

**Logging Levels to Implement**:
- `DEBUG`: Detailed protocol steps, message sizes, nonces
- `INFO`: Handshake completion, transport creation
- `WARNING`: Approaching nonce limits, deprecated usage
- `ERROR`: Authentication failures, invalid states

**Implementation Notes**:
```
[When completed, document here:]
- How to enable logging (example code)
- What each log level shows
- Default logger names
- How to configure per-class logging
- Example log output
```

---

### 3. ⏳ **Message Framing Helper** [TODO]

**Goal**: Provide built-in message framing for network communication.

**Tasks**:
- [ ] Create `noiseframework/framing.py` module
- [ ] Implement length-prefixed framing
- [ ] Support both sync and async I/O
- [ ] Add chunked reading support
- [ ] Add examples with real sockets
- [ ] Add tests for edge cases (partial reads, large messages)

**Target Files**:
- New: `noiseframework/framing.py`
- New: `examples/framed_tcp_example.py`
- New: `tests/test_framing.py`
- Update: `noiseframework/__init__.py` (add to exports)

**Design Decisions to Make**:
- Frame format: `[4-byte length][data]` (big-endian)
- Max message size: 16 MB default (configurable)
- Error handling: raise `FramingError` on invalid frames

**Implementation Notes**:
```
[When completed, document here:]
- Complete API (class names, methods, signatures)
- Frame format specification
- Maximum message size
- Error types and when they're raised
- Example usage with sockets
- Example usage with asyncio streams
- Performance characteristics
```

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

**Completed**: 0 / 7
**In Progress**: 0
**Not Started**: 7

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
