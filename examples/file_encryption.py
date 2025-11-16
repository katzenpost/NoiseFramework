"""
File encryption example using Noise Protocol.

This example demonstrates:
- Using Noise_NN pattern for simple encryption
- Encrypting and decrypting file contents
- Saving/loading handshake messages

Note: NN pattern provides no authentication. For production use,
consider XX, IK, or other authenticated patterns.
"""

import sys
from pathlib import Path
from py_noise import NoiseHandshake


def encrypt_file(input_path: str, output_path: str):
    """Encrypt a file using Noise Protocol."""
    print(f"🔒 Encrypting '{input_path}' -> '{output_path}'")

    # Read input file
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ Error: File '{input_path}' not found")
        return False

    plaintext = input_file.read_bytes()
    print(f"   Read {len(plaintext)} bytes")

    # Setup handshake (NN pattern - no authentication)
    encryptor = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
    encryptor.set_as_initiator()
    encryptor.start()

    decryptor = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
    decryptor.set_as_responder()
    decryptor.start()

    # Perform handshake
    msg1 = encryptor.write_message(b"")
    decryptor.read_message(msg1)

    msg2 = decryptor.write_message(b"")
    encryptor.read_message(msg2)

    # Convert to transport
    enc_transport = encryptor.to_transport()

    # Encrypt the file content
    ciphertext = enc_transport.send(plaintext)
    print(f"   Encrypted to {len(ciphertext)} bytes")

    # Save encrypted data with handshake messages
    output_file = Path(output_path)
    with output_file.open("wb") as f:
        # Write handshake messages (needed for decryption)
        f.write(len(msg1).to_bytes(4, "big"))
        f.write(msg1)
        f.write(len(msg2).to_bytes(4, "big"))
        f.write(msg2)
        # Write encrypted content
        f.write(ciphertext)

    print(f"   ✓ Saved to '{output_path}'")
    return True


def decrypt_file(input_path: str, output_path: str):
    """Decrypt a file encrypted with Noise Protocol."""
    print(f"🔓 Decrypting '{input_path}' -> '{output_path}'")

    # Read encrypted file
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ Error: File '{input_path}' not found")
        return False

    with input_file.open("rb") as f:
        # Read handshake message 1
        msg1_len = int.from_bytes(f.read(4), "big")
        msg1 = f.read(msg1_len)

        # Read handshake message 2
        msg2_len = int.from_bytes(f.read(4), "big")
        msg2 = f.read(msg2_len)

        # Read ciphertext
        ciphertext = f.read()

    print(f"   Read {len(ciphertext)} encrypted bytes")

    # Setup handshake
    decryptor = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
    decryptor.set_as_responder()
    decryptor.start()

    # Replay handshake
    decryptor.read_message(msg1)
    decryptor.write_message(b"")  # Generate same msg2 (deterministic for NN)

    # Convert to transport
    dec_transport = decryptor.to_transport()

    # Decrypt
    try:
        plaintext = dec_transport.receive(ciphertext)
        print(f"   Decrypted to {len(plaintext)} bytes")

        # Save decrypted data
        output_file = Path(output_path)
        output_file.write_bytes(plaintext)
        print(f"   ✓ Saved to '{output_path}'")
        return True

    except ValueError as e:
        print(f"❌ Decryption failed: {e}")
        return False


def run_example():
    """Run the file encryption example."""
    print("=" * 60)
    print("NoiseFramework - File Encryption Example")
    print("=" * 60)
    print()

    # Create a sample file
    sample_file = "sample.txt"
    encrypted_file = "sample.txt.enc"
    decrypted_file = "sample_decrypted.txt"

    print("📝 Creating sample file...")
    Path(sample_file).write_text(
        "This is a secret message!\n"
        "It will be encrypted using the Noise Protocol Framework.\n"
        "NoiseFramework makes encryption easy and secure.\n"
    )
    print(f"   ✓ Created '{sample_file}'\n")

    # Encrypt
    if not encrypt_file(sample_file, encrypted_file):
        return

    print()

    # Decrypt
    if not decrypt_file(encrypted_file, decrypted_file):
        return

    print()

    # Verify
    print("✅ Verifying decryption...")
    original = Path(sample_file).read_bytes()
    decrypted = Path(decrypted_file).read_bytes()

    if original == decrypted:
        print("   ✓ Decryption successful - files match!")
    else:
        print("   ❌ Files don't match!")

    print()

    # Cleanup
    print("🧹 Cleanup...")
    Path(sample_file).unlink()
    Path(encrypted_file).unlink()
    Path(decrypted_file).unlink()
    print("   ✓ Temporary files removed")

    print()
    print("=" * 60)
    print("✅ Example completed successfully!")
    print("=" * 60)
    print()
    print("⚠️  Note: This example uses the NN pattern which provides")
    print("    NO authentication. For production, use authenticated")
    print("    patterns like XX, IK, or XK.")


if __name__ == "__main__":
    run_example()
