"""
File encryption example using Noise Protocol.

This example demonstrates:
- Using CipherState directly for file encryption
- Encrypting and decrypting file contents with a derived key
- Simple key-based encryption without handshake

Note: This uses a simple password-based approach for demonstration.
In production, use proper key derivation and key management.
"""

import sys
from pathlib import Path
from noiseframework import NoiseHandshake


def encrypt_file(input_path: str, output_path: str, password: str = "secret"):
    """Encrypt a file using Noise Protocol."""
    print(f"🔒 Encrypting '{input_path}' -> '{output_path}'")

    # Read input file
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ Error: File '{input_path}' not found")
        return False

    plaintext = input_file.read_bytes()
    print(f"   Read {len(plaintext)} bytes")

    # Create a simple cipher from password (demonstration only!)
    # In production, use proper KDF like HKDF
    from noiseframework.noise.state import CipherState
    from noiseframework.crypto.cipher import ChaChaPoly
    from noiseframework.crypto.hash import SHA256
    
    # Derive key from password
    hasher = SHA256()
    key = hasher.hash(password.encode())
    
    # Create cipher state
    cipher_func = ChaChaPoly()
    cipher_state = CipherState(cipher_func)
    cipher_state.initialize_key(key)
    
    # Encrypt
    ciphertext = cipher_state.encrypt_with_ad(b"", plaintext)
    print(f"   Encrypted to {len(ciphertext)} bytes")

    # Save encrypted data
    output_file = Path(output_path)
    output_file.write_bytes(ciphertext)

    print(f"   ✓ Saved to '{output_path}'")
    return True


def decrypt_file(input_path: str, output_path: str, password: str = "secret"):
    """Decrypt a file encrypted with Noise Protocol."""
    print(f"🔓 Decrypting '{input_path}' -> '{output_path}'")

    # Read encrypted file
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ Error: File '{input_path}' not found")
        return False

    ciphertext = input_file.read_bytes()
    print(f"   Read {len(ciphertext)} encrypted bytes")

    # Recreate cipher from same password
    from noiseframework.noise.state import CipherState
    from noiseframework.crypto.cipher import ChaChaPoly
    from noiseframework.crypto.hash import SHA256
    
    # Derive key from password
    hasher = SHA256()
    key = hasher.hash(password.encode())
    
    # Create cipher state
    cipher_func = ChaChaPoly()
    cipher_state = CipherState(cipher_func)
    cipher_state.initialize_key(key)

    # Decrypt
    try:
        plaintext = cipher_state.decrypt_with_ad(b"", ciphertext)
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
    print("⚠️  Note: This example uses a simple password-to-key approach")
    print("    for demonstration. In production:")
    print("    • Use proper key derivation (PBKDF2, Argon2, etc.)")
    print("    • Add salt to prevent rainbow table attacks")
    print("    • Use unique nonces for each encryption")
    print("    • Consider using full Noise handshake for key exchange")


if __name__ == "__main__":
    run_example()
