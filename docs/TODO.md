# NoiseFramework TODO List

This document tracks planned future enhancements for NoiseFramework beyond v1.3.0.

**Status**: Planning phase for v1.4.0 and beyond

---

## 🎯 Planned Features for v1.4.0

### 1. ⏳ **Rekey Support** [PLANNED]

**Goal**: Implement rekeying to prevent nonce exhaustion and extend connection lifetime indefinitely.

**Why Important**:
- Prevents nonce overflow after 2^64 messages
- Essential for long-lived connections (IoT, persistent servers, VPNs)
- Part of official Noise Protocol Framework specification (Section 11.3)
- Enables truly persistent secure channels

**Planned API**:
```python
# Manual rekeying
transport.rekey()  # Rekey send cipher
transport.rekey_receive()  # Rekey receive cipher

# Automatic rekeying (opt-in)
transport = NoiseTransport(
    send_cipher, 
    receive_cipher,
    auto_rekey=True,  # NEW: Enable automatic rekeying
    rekey_interval=2**63  # NEW: Rekey at half nonce space (default)
)

# Async support
await async_transport.rekey()
await async_transport.rekey_receive()
```

**Tasks**:
- [ ] Implement `CipherState.rekey()` method
- [ ] Add `NoiseTransport.rekey()` and `NoiseTransport.rekey_receive()` methods
- [ ] Implement automatic rekey with configurable threshold
- [ ] Add nonce monitoring and warnings before overflow
- [ ] Add async support in `AsyncNoiseTransport`
- [ ] Create examples showing manual and automatic rekeying
- [ ] Add comprehensive tests for rekey functionality
- [ ] Update documentation (README, API.md)

**Target Files**:
- Modify: `noiseframework/noise/state.py` (CipherState.rekey)
- Modify: `noiseframework/transport/transport.py` (rekey methods, auto-rekey)
- Modify: `noiseframework/async_support.py` (async rekey)
- New: `examples/rekey_example.py`
- New: `tests/test_rekey.py`
- Update: `README.md`, `docs/API.md`

**Use Cases**:
- IoT devices maintaining permanent connections
- VPN servers with long-lived tunnels
- WebSocket servers requiring persistent encryption
- Any application sending >2^63 messages per session

---

### 2. ⏳ **Deferred Patterns** [PLANNED]

**Goal**: Support deferred patterns where responder identity is unknown initially.

**Why Important**:
- Allows responder to defer revealing static key until second message
- Useful for server-side optimization (wait for client authentication)
- Part of official Noise spec (Section 10.4)
- Enables more flexible handshake patterns

**Planned Patterns**:
- `NX` - Responder static key in second message (deferred)
- `KX` - Initiator knows responder identity, but responder defers
- `IX` - Initiator sends identity first, responder defers

**Tasks**:
- [ ] Extend pattern parser to support deferred patterns
- [ ] Implement deferred token processing in handshake
- [ ] Add tests for NX, KX, IX patterns
- [ ] Update pattern documentation
- [ ] Add examples

**Target Files**:
- Modify: `noiseframework/noise/pattern.py`
- Modify: `noiseframework/noise/handshake.py`
- New: `examples/deferred_patterns_example.py`
- New: `tests/test_deferred_patterns.py`

---

### 3. ⏳ **Channel Binding** [PLANNED]

**Goal**: Bind Noise session to application-layer context.

**Why Important**:
- Links transport channel to application context (TLS session ticket, etc.)
- Prevents session confusion attacks
- Part of Noise spec (Section 11.2)
- Required for some compliance scenarios

**Planned API**:
```python
# Get channel binding value after handshake
binding = handshake.get_channel_binding()

# Verify binding in application layer
app.verify_binding(binding, expected_context)
```

**Tasks**:
- [ ] Implement `get_channel_binding()` in NoiseHandshake
- [ ] Document channel binding usage patterns
- [ ] Add tests and examples
- [ ] Update security documentation

---

## 🔮 Future Considerations (v1.5.0+)

### 4. 💡 **Out-of-Order Transport**

**Goal**: Support UDP and other unreliable transports with explicit nonce handling.

**Challenges**:
- Requires tracking nonce windows
- Replay protection needed
- Packet loss handling
- More complex than current stream-based transport

**Use Cases**:
- UDP-based applications (gaming, VoIP, IoT)
- QUIC integration
- Low-latency scenarios

---

### 5. 💡 **Compound Protocols**

**Goal**: Support for compound Noise protocols (multiple sub-protocols).

**Use Cases**:
- Protocol negotiation and version fallback
- Multi-party protocols
- Complex handshake orchestration

---

### 6. 💡 **Hardware Security Module (HSM) Support**

**Goal**: Allow key operations to be performed on HSM/TPM devices.

**Benefits**:
- Enhanced key security
- Compliance requirements (FIPS, etc.)
- Enterprise deployments

**Challenges**:
- Platform-specific APIs
- Performance considerations
- Testing complexity

---

### 7. 💡 **Post-Quantum Cryptography**

**Goal**: Support for post-quantum DH functions.

**Status**: 
- Waiting for NIST PQC standardization finalization
- Experimental support for hybrid classical/PQ schemes

**Options**:
- Kyber (KEM)
- Hybrid X25519+Kyber
- NewHope

---

### 8. 💡 **Additional Cipher Suites**

**Goal**: Expand supported cryptographic primitives.

**Candidates**:
- **DH**: X448 (already supported), secp256k1
- **Cipher**: XChaCha20-Poly1305, AES-SIV
- **Hash**: SHA3-256, SHA3-512

---

### 9. 💡 **Performance Optimizations**

**Ideas**:
- Zero-copy message processing where possible
- SIMD optimizations (via cryptography library)
- Batch processing for multiple messages
- Memory pooling for frequent allocations

---

### 10. 💡 **Protocol Plugins/Extensions**

**Goal**: Allow custom protocol extensions without modifying core.

**Use Cases**:
- Custom authentication mechanisms
- Application-specific handshake payloads
- Protocol versioning and negotiation

---

## 📊 Progress Tracking

**v1.3.0**: ✅ Complete (7/7 features)
- Async/Await Support
- Message Framing  
- Better Error Messages
- High-Level Connection API
- Logging Support
- PSK Support
- Fallback Pattern Support

**v1.4.0**: 🔄 Planning (0/3 features)
- Rekey Support
- Deferred Patterns
- Channel Binding

**v1.5.0+**: 💡 Ideas (7 concepts)

---

## 🔄 Update Process

**When starting a new feature:**

1. Move it from [PLANNED] to [IN PROGRESS]
2. Create a feature branch: `feat/feature-name`
3. Implement following the project's coding standards
4. Add comprehensive tests (target: 100% pass rate)
5. Update all documentation (README, API.md, CHANGELOG)
6. Create examples demonstrating real usage
7. Mark as [DONE] and document implementation details

**Quality Standards:**
- All features must have tests (minimum 90% coverage)
- All public APIs must have type hints
- All public APIs must have docstrings
- Follow existing code style (PEP 8, Black formatted)
- Maintain backward compatibility where possible
- Document any breaking changes clearly

---

## 📝 Contributing

Want to implement one of these features? See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Priority Order** (recommended):
1. **Rekey Support** - Most impactful for production deployments
2. **Deferred Patterns** - Expands pattern coverage
3. **Channel Binding** - Security enhancement

---

## 📚 References

- [Noise Protocol Framework Specification](https://noiseprotocol.org/noise.html)
  - Section 11.3: Rekey
  - Section 10.4: Deferred patterns
  - Section 11.2: Channel binding
- [Noise Explorer](https://noiseexplorer.com/) - Formal verification
- [Noise Wiki](https://github.com/noiseprotocol/noise_wiki/wiki) - Community resources

---

**Last Updated**: November 25, 2025  
**Current Version**: 1.3.0  
**Next Target Version**: 1.4.0
