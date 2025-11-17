# Frequently Asked Questions (FAQ)

Common questions and troubleshooting for NoiseFramework.

## Table of Contents

- [General Questions](#general-questions)
- [Pattern Selection](#pattern-selection)
- [Cryptography Questions](#cryptography-questions)
- [Implementation Questions](#implementation-questions)
- [Troubleshooting](#troubleshooting)
- [Performance](#performance)
- [Security](#security)

---

## General Questions

### What is the Noise Protocol Framework?

The Noise Protocol Framework is a specification for building cryptographic protocols based on Diffie-Hellman key agreement. It provides a flexible system for combining handshake patterns with various cryptographic primitives to create secure communication channels.

**Key features:**
- Simple, easy-to-analyze security model
- Flexible pattern system
- Modern cryptographic primitives
- Forward secrecy
- Mutual or one-way authentication

**Used by:** WireGuard, WhatsApp, Lightning Network, and many others.

### Why use NoiseFramework instead of TLS?

| NoiseFramework (Noise) | TLS |
|------------------------|-----|
| Simpler specification (~50 pages) | Complex specification (1000+ pages) |
| Fewer round trips | More round trips |
| Modern crypto only | Legacy crypto support |
| Flexible patterns | Fixed handshake |
| Forward secrecy by default | Optional forward secrecy |
| Easier to implement correctly | Complex state machine |

**Use Noise when:**
- Building custom protocols
- Need minimal handshake overhead
- Want simple, auditable security
- Working with IoT/embedded systems

**Use TLS when:**
- Need web browser support
- Require certificate infrastructure
- Need established ecosystem

### Is NoiseFramework production-ready?

**Status:** Beta / Production-ready for non-critical applications

**Strengths:**
- Spec-compliant implementation
- Well-tested (156 tests, 92% coverage)
- Uses vetted `cryptography` library
- Simple, auditable codebase

**Limitations:**
- No formal security audit
- Not optimized for timing attacks
- Young project (v0.1.0)

**Recommendation:** Suitable for production use in non-critical applications. For high-security environments, consider additional review and testing.

### What Python versions are supported?

**Supported:** Python 3.8+

Tested on:
- Python 3.8, 3.9, 3.10, 3.11, 3.12
- Windows, Linux, macOS

---

## Pattern Selection

### Which pattern should I use?

**For most cases:** `XX` (mutual authentication, no pre-shared keys)

**Pattern selection guide:**

| Scenario | Pattern | Why |
|----------|---------|-----|
| Client-server, no pre-shared keys | `XX` | Mutual authentication, most common |
| Client knows server's public key | `IK` or `XK` | Faster, server authenticated first |
| Server knows client's public key | `KK` | Pre-authenticated client |
| Anonymous client | `XK` or `NK` | Server authenticated, client anonymous |
| Testing/demo only | `NN` | No authentication (INSECURE!) |
| One-way communication | `N` patterns | Initiator sends to responder only |

**Example:**
```python
# Most common: XX pattern
handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
```

### What's the difference between XX and IK?

**XX Pattern (3 messages):**
- Neither party knows the other's static key initially
- Both parties send their static keys during handshake
- Provides mutual authentication
- Larger handshake (3 messages)

```
→ e
← e, ee, s, es
→ s, se
```

**IK Pattern (2 messages):**
- Initiator knows responder's static key in advance
- Faster handshake (2 messages)
- Responder is authenticated from message 1
- Initiator identity revealed in first message

```
→ e, es, s, ss
← e, ee
```

**Use IK when:**
- You have the server's public key in advance
- You need a faster handshake
- Server identity verification is critical

### Can I use NN pattern in production?

**No!** NN provides **no authentication**.

```python
# DON'T DO THIS IN PRODUCTION
handshake = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
```

**NN pattern:**
- ✅ Provides encryption
- ✅ Provides forward secrecy
- ❌ No authentication (vulnerable to MITM)
- ❌ Anyone can impersonate either party

**Use for:**
- Testing and development
- Demonstrations
- Cases where authentication is handled separately

**Instead use:**
- `XX` for mutual authentication
- `XK` or `NK` for server authentication
- Any pattern with `s` tokens for authentication

---

## Cryptography Questions

### Which cipher should I use: ChaCha20 or AES-GCM?

**Default recommendation:** `ChaChaPoly` (ChaCha20-Poly1305)

| Feature | ChaCha20-Poly1305 | AES-256-GCM |
|---------|-------------------|-------------|
| Software performance | ✅ Excellent | ⚠️ Slower without AES-NI |
| Hardware acceleration | ⚠️ Limited | ✅ AES-NI widely available |
| Constant-time (software) | ✅ Yes | ⚠️ Harder to implement |
| Security | ✅ Excellent | ✅ Excellent |
| Nonce misuse resistance | ⚠️ Catastrophic | ⚠️ Catastrophic |

**Use ChaCha20 for:**
- Mobile devices
- Embedded systems
- Software-only implementations

**Use AES-GCM for:**
- Systems with AES-NI (modern x86 CPUs)
- Hardware acceleration requirements
- Compliance requirements

```python
# ChaCha20 (recommended)
NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")

# AES-GCM
NoiseHandshake("Noise_XX_25519_AESGCM_SHA256")
```

### Should I use Curve25519 or Curve448?

**Default recommendation:** `25519` (Curve25519 / X25519)

| Feature | Curve25519 | Curve448 |
|---------|------------|----------|
| Key size | 32 bytes | 56 bytes |
| Security level | ~128-bit | ~224-bit |
| Performance | ✅ Faster | ⚠️ Slower |
| Adoption | ✅ Very widely used | ⚠️ Less common |
| Security margin | ✅ Sufficient | ✅ Higher |

**Use Curve25519 unless:**
- You have specific compliance requirements for >128-bit security
- You're willing to trade performance for security margin

```python
# Curve25519 (recommended)
NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")

# Curve448
NoiseHandshake("Noise_XX_448_ChaChaPoly_SHA512")
```

### Which hash function should I use?

**Default recommendation:** `SHA256`

| Hash | Output | Use Case |
|------|--------|----------|
| `SHA256` | 32 bytes | Default choice, widely supported |
| `SHA512` | 64 bytes | When using Curve448 |
| `BLAKE2s` | 32 bytes | Higher performance than SHA256 |
| `BLAKE2b` | 64 bytes | Higher performance than SHA512 |

```python
# Most common combinations
"Noise_XX_25519_ChaChaPoly_SHA256"    # Standard
"Noise_XX_25519_ChaChaPoly_BLAKE2s"   # Performance
"Noise_XX_448_ChaChaPoly_SHA512"      # High security
"Noise_XX_448_ChaChaPoly_BLAKE2b"     # High security + performance
```

---

## Implementation Questions

### How do I handle network communication?

NoiseFramework handles encryption only. You need to add:

**1. Transport layer (TCP/UDP):**

```python
import socket

# TCP example
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("server", 8000))

# Perform handshake (omitted)
transport = handshake.to_transport()

# Send encrypted message
ciphertext = transport.send(b"Hello")
sock.sendall(ciphertext)

# Receive encrypted message
ciphertext = sock.recv(1024)
plaintext = transport.receive(ciphertext)
```

**2. Message framing:**

```python
def send_frame(sock, data):
    """Send length-prefixed frame."""
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length + data)

def recv_frame(sock):
    """Receive length-prefixed frame."""
    length = int.from_bytes(sock.recv(4), 'big')
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data
```

**3. Error handling:**

```python
try:
    plaintext = transport.receive(ciphertext)
except ValueError as e:
    print(f"Authentication failed: {e}")
    # Handle tampering or corruption
```

### Can I use async/await?

NoiseFramework's crypto operations are synchronous, but you can use it with async I/O:

```python
import asyncio

async def handle_client(reader, writer):
    # Perform handshake (simplified)
    handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    handshake.set_as_responder()
    # ... setup ...
    
    # Read handshake messages
    msg1 = await reader.read(1024)
    handshake.read_message(msg1)
    
    msg2 = handshake.write_message(b"")
    writer.write(msg2)
    await writer.drain()
    
    # ... complete handshake ...
    transport = handshake.to_transport()
    
    # Encrypted communication
    while True:
        ciphertext = await reader.read(1024)
        if not ciphertext:
            break
        plaintext = transport.receive(ciphertext)
        # ... process plaintext ...
```

### How do I save/load keys?

**Saving keys:**

```python
import os
from pathlib import Path

# Generate keypair
private, public = handshake.generate_keypair()

# Save keys (secure permissions!)
private_file = Path("private.key")
public_file = Path("public.key")

private_file.write_bytes(private)
private_file.chmod(0o600)  # Owner read/write only

public_file.write_bytes(public)
```

**Loading keys:**

```python
private = Path("private.key").read_bytes()
public = Path("public.key").read_bytes()

handshake.set_static_keypair(private, public)
```

**⚠️ Security:**
- Never commit private keys to version control
- Use proper file permissions (0o600)
- Consider encrypting private keys at rest
- Use hardware security modules (HSMs) for high-value keys

---

## Troubleshooting

### "ValueError: Role not set"

**Problem:** Forgot to call `set_as_initiator()` or `set_as_responder()`

**Solution:**

```python
handshake = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
handshake.set_as_initiator()  # or set_as_responder()
handshake.start()
```

### "ValueError: Handshake not started"

**Problem:** Forgot to call `start()`

**Solution:**

```python
handshake.set_as_initiator()
handshake.set_static_keypair(private, public)
handshake.start()  # Must call before write_message/read_message
```

### "ValueError: Decryption failed"

**Possible causes:**

1. **Message tampered:** Authentication tag verification failed
   ```python
   # Attacker modified ciphertext
   ciphertext = ciphertext[:-1] + b"\x00"
   transport.receive(ciphertext)  # ValueError!
   ```

2. **Wrong nonce:** Messages received out of order
   ```python
   # Must process messages in order
   ct1 = transport.send(b"msg1")
   ct2 = transport.send(b"msg2")
   # Don't do: transport.receive(ct2), transport.receive(ct1)
   ```

3. **Handshake mismatch:** Different patterns
   ```python
   # Both must use same pattern
   client = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
   server = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")  # Must match!
   ```

4. **Key mismatch:** Different handshake resulted in different keys

**Debugging:**

```python
try:
    plaintext = transport.receive(ciphertext)
except ValueError as e:
    print(f"Decryption failed: {e}")
    print(f"Nonce: {transport.get_receive_nonce()}")
    print(f"Ciphertext length: {len(ciphertext)}")
    # Check for tampering, corruption, or protocol errors
```

### "ValueError: Invalid pattern string"

**Problem:** Pattern string malformed

**Solution:**

```python
# Wrong
NoiseHandshake("XX_25519_ChaChaPoly_SHA256")  # Missing "Noise_"
NoiseHandshake("Noise_XX_Curve25519_ChaChaPoly_SHA256")  # Wrong DH name

# Correct
NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
```

**Valid format:** `Noise_PATTERN_DH_CIPHER_HASH`

- Pattern: `NN`, `XX`, `IK`, etc.
- DH: `25519` or `448`
- Cipher: `ChaChaPoly` or `AESGCM`
- Hash: `SHA256`, `SHA512`, `BLAKE2s`, or `BLAKE2b`

### Handshake completes but messages fail

**Problem:** Likely swapped send/receive ciphers

**Check:**

```python
# Both parties must use same pattern
client = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
server = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")

client.set_as_initiator()  # Important!
server.set_as_responder()  # Important!

# After handshake
client_transport = client.to_transport()
server_transport = server.to_transport()

# Client sends, server receives
ct = client_transport.send(b"hello")
pt = server_transport.receive(ct)  # Must use server's transport
```

---

## Performance

### How fast is NoiseFramework?

**Ballpark figures** (varies by hardware):

- **Handshake:** ~1-5ms (XX pattern)
- **Encryption:** ~1-10 GB/s (ChaCha20)
- **Decryption:** ~1-10 GB/s (ChaCha20)

**Factors:**
- CPU (AES-NI, vector instructions)
- Python version
- Message size
- Pattern complexity

### How can I improve performance?

**1. Choose faster algorithms:**

```python
# Faster
"Noise_XX_25519_ChaChaPoly_BLAKE2s"

# Slower (but more secure)
"Noise_XX_448_AESGCM_SHA512"
```

**2. Batch messages:**

```python
# Slow: many small messages
for i in range(1000):
    ct = transport.send(f"msg{i}".encode())
    send_to_network(ct)

# Faster: batch messages
batch = b"".join(f"msg{i}\n".encode() for i in range(1000))
ct = transport.send(batch)
send_to_network(ct)
```

**3. Use PyPy** (JIT compiler):

```bash
pypy3 -m pip install noiseframework
pypy3 your_app.py
```

**4. Profile your code:**

```python
import cProfile
cProfile.run('your_function()')
```

### Will nonces ever overflow?

**Theoretically:** After 2^64 messages (~18 quintillion)

**Practically:** No. At 1 million messages/second:
- Time to overflow: 580,000 years

**If you're concerned:**
- Rekey after N messages
- Use connection pooling
- Monitor nonce values

---

## Security

### Is NoiseFramework secure?

**Security status:**
- ✅ Implements Noise Protocol spec correctly
- ✅ Uses vetted `cryptography` library
- ✅ Well-tested implementation
- ⚠️ No formal security audit
- ⚠️ Not constant-time (potential timing attacks)
- ⚠️ Young project (v0.1.0)

**Recommendation:** Suitable for most applications. For high-security environments, conduct additional review.

### How do I report security vulnerabilities?

**DO NOT** open public GitHub issues for security vulnerabilities.

**Instead:**
1. Use [GitHub Security Advisories](https://github.com/juliuspleunes4/noiseframework/security/advisories/new)
2. Or contact maintainers privately via GitHub

See [SECURITY.md](SECURITY.md) for details.

### Can I use NoiseFramework for [specific use case]?

**Good use cases:**
- Custom client-server protocols
- IoT device communication
- P2P applications
- VPN-like systems
- Secure file transfer

**Consider alternatives for:**
- Web browsers → Use TLS
- Email encryption → Use PGP/GPG
- Password storage → Use Argon2/bcrypt
- Disk encryption → Use LUKS/BitLocker

### How does NoiseFramework compare to libsodium?

| Feature | NoiseFramework | libsodium |
|---------|----------------|-----------|
| Focus | Handshake protocols | Crypto primitives |
| Patterns | Multiple (XX, IK, etc.) | Fixed (X25519 + XSalsa20) |
| Authentication | Configurable | Curve25519 only |
| API Level | High-level + low-level | Low-level |
| Spec | Noise Protocol | NaCl API |

**Use NoiseFramework for:**
- Complex handshake patterns
- Flexible crypto choices
- Protocol building

**Use libsodium for:**
- Simple crypto operations
- Low-level crypto building blocks
- C/C++ integration

---

## Still Have Questions?

- **Documentation:** [API Reference](API.md), [Architecture](ARCHITECTURE.md)
- **Examples:** See `examples/` directory
- **GitHub Discussions:** Ask questions
- **GitHub Issues:** Report bugs
- **Contributing:** See [CONTRIBUTING.md](CONTRIBUTING.md)

---

**Happy secure coding! 🔒**
