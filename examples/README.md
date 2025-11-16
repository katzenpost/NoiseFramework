# NoiseFramework Examples

This directory contains practical examples demonstrating how to use NoiseFramework in real-world scenarios.

## Running Examples

All examples can be run directly with Python:

```bash
python examples/basic_client_server.py
python examples/file_encryption.py
python examples/simple_chat.py
```

Or from the package:

```bash
python -m examples.basic_client_server
python -m examples.file_encryption
python -m examples.simple_chat
```

## Examples

### 1. Basic Client/Server (`basic_client_server.py`)

**Demonstrates:**
- Setting up client and server with XX pattern
- Mutual authentication
- Complete handshake flow
- Encrypted bidirectional communication

**Pattern Used:** `Noise_XX_25519_ChaChaPoly_SHA256`

**Key Concepts:**
- Initiator and responder roles
- Three-message handshake (XX pattern)
- Converting to transport mode
- Sending encrypted messages

**Output:**
```
🤝 Performing handshake...
   [1/3] Client sends ephemeral key...
   [2/3] Server sends ephemeral, static keys...
   [3/3] Client sends static key...
   ✓ Handshake complete!
```

### 2. File Encryption (`file_encryption.py`)

**Demonstrates:**
- Encrypting file contents
- Saving handshake state with encrypted data
- Decrypting files
- Verification of decryption

**Pattern Used:** `Noise_NN_25519_ChaChaPoly_SHA256`

**Key Concepts:**
- Using NN pattern for simple encryption
- Serializing handshake messages
- File I/O with encrypted data
- Stateless decryption

**⚠️ Warning:** NN pattern provides **no authentication**. Use XX, IK, or XK patterns for production use.

**Output:**
```
🔒 Encrypting 'sample.txt' -> 'sample.txt.enc'
   Read 156 bytes
   Encrypted to 172 bytes
   ✓ Saved to 'sample.txt.enc'
```

### 3. Simple Chat (`simple_chat.py`)

**Demonstrates:**
- Building a chat application structure
- Bidirectional encrypted communication
- Multiple messages in a session
- Participant abstraction

**Pattern Used:** `Noise_XX_25519_ChaChaPoly_SHA256`

**Key Concepts:**
- Wrapping handshake in a class
- Managing multiple messages
- Nonce tracking
- Simulating real-world chat flow

**Note:** This is a demonstration. Real chat apps need network sockets, async I/O, and message framing.

**Output:**
```
💬 Chat session:
   📨 Alice: Hey Bob! Can you hear me?
   📨 Bob: Hi Alice! Yes, loud and clear!
   ...
```

## Next Steps

After exploring these examples:

1. **Read the [API Documentation](../docs/API.md)** for complete reference
2. **Choose the right pattern** for your use case:
   - **XX**: Mutual authentication (most common)
   - **IK**: Client knows server's public key in advance
   - **NK**: Anonymous client, authenticated server
   - **NN**: No authentication (testing only!)

3. **Implement networking** using:
   - `socket` module for TCP/UDP
   - `asyncio` for async I/O
   - `websockets` for WebSocket connections

4. **Add message framing**:
   ```python
   # Simple length-prefixed framing
   def send_frame(sock, data):
       length = len(data).to_bytes(4, 'big')
       sock.sendall(length + data)
   
   def recv_frame(sock):
       length = int.from_bytes(sock.recv(4), 'big')
       return sock.recv(length)
   ```

5. **Handle errors gracefully**:
   ```python
   try:
       plaintext = transport.receive(ciphertext)
   except ValueError as e:
       print(f"Authentication failed: {e}")
       # Handle tampering or corruption
   ```

## Common Patterns

### Client/Server with Known Server Key (IK)

```python
# Server publishes its public key
server = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
server.set_as_responder()
server_priv, server_pub = server.generate_keypair()
# ... publish server_pub ...

# Client uses known server key
client = NoiseHandshake("Noise_IK_25519_ChaChaPoly_SHA256")
client.set_as_initiator()
client_priv, client_pub = client.generate_keypair()
client.set_static_keypair(client_priv, client_pub)
client.set_remote_static_public_key(server_pub)  # Known key!
```

### With Prologue (Application Context)

```python
# Both parties use same prologue
prologue = b"MyApp v2.0"
client.start(prologue=prologue)
server.start(prologue=prologue)
# Different prologues will cause handshake failure
```

### Error Handling

```python
try:
    handshake = NoiseHandshake(pattern_string)
    handshake.set_as_initiator()
    handshake.start()
    # ... perform handshake ...
    transport = handshake.to_transport()
except ValueError as e:
    print(f"Handshake failed: {e}")
    # Handle invalid pattern, auth failure, etc.
```

## Tips

1. **Always use authenticated patterns** in production (XX, IK, XK, etc.)
2. **Validate peer identity** after handshake using static public keys
3. **Use prologues** to bind handshakes to application context
4. **Handle nonce overflow** (after 2^64 messages, rekey)
5. **Protect private keys** in memory and storage
6. **Test error paths** (tampering, wrong keys, replay attacks)

## Resources

- **[API Reference](../docs/API.md)** - Complete API documentation
- **[Noise Protocol Specification](https://noiseprotocol.org/noise.html)** - Official spec
- **[CONTRIBUTING.md](../docs/CONTRIBUTING.md)** - Contribution guidelines
- **[SECURITY.md](../docs/SECURITY.md)** - Security considerations

## Questions?

Open an issue or discussion on [GitHub](https://github.com/juliuspleunes4/noiseframework).
