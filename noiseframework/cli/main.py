"""
Command-line interface for NoiseFramework.

Provides commands for handshakes, encryption, decryption, and key generation.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from noiseframework import NoiseHandshake
from noiseframework.transport.transport import NoiseTransport
from noiseframework.noise.pattern import parse_pattern, validate_pattern_string
from noiseframework.crypto.dh import get_dh_function


def generate_keypair(args: argparse.Namespace) -> int:
    """Generate a static keypair for the specified DH function."""
    try:
        dh_func = get_dh_function(args.dh)
        private, public = dh_func.generate_keypair()
        
        # Write keys to files
        private_path = Path(args.output_prefix + "_private.key")
        public_path = Path(args.output_prefix + "_public.key")
        
        private_path.write_bytes(private)
        public_path.write_bytes(public)
        
        print(f"Generated keypair:")
        print(f"  Private key: {private_path}")
        print(f"  Public key:  {public_path}")
        print(f"  Key size:    {len(private)} bytes")
        
        return 0
    except Exception as e:
        print(f"Error generating keypair: {e}", file=sys.stderr)
        return 1


def validate_pattern(args: argparse.Namespace) -> int:
    """Validate a Noise pattern string."""
    try:
        pattern = parse_pattern(args.pattern)
        print(f"Pattern: {args.pattern}")
        print(f"  Valid: ✓")
        print(f"  Name:       {pattern.name}")
        print(f"  Handshake:  {pattern.handshake_pattern}")
        print(f"  DH:         {pattern.dh_function}")
        print(f"  Cipher:     {pattern.cipher_function}")
        print(f"  Hash:       {pattern.hash_function}")
        
        return 0
    except ValueError as e:
        print(f"Invalid pattern: {e}", file=sys.stderr)
        return 1


def encrypt_file(args: argparse.Namespace) -> int:
    """Encrypt a file using Noise protocol."""
    try:
        # Read input file
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"Input file not found: {input_path}", file=sys.stderr)
            return 1
        
        plaintext = input_path.read_bytes()
        
        # Initialize handshake
        handshake = NoiseHandshake(args.pattern)
        handshake.set_as_initiator()
        
        # Load static key if provided
        if args.static_key:
            static_key = Path(args.static_key).read_bytes()
            handshake.set_static_keypair(static_key)
        else:
            handshake.generate_static_keypair()
        
        # Load remote static key if provided
        if args.remote_key:
            remote_key = Path(args.remote_key).read_bytes()
            handshake.set_remote_static_pubkey(remote_key)
        
        handshake.initialize()
        
        # Perform handshake (simplified - would need peer in real scenario)
        # For now, just use the handshake to derive keys
        print("Note: CLI encryption requires a peer for full handshake.")
        print("This is a simplified example for demonstration.")
        
        return 0
    except Exception as e:
        print(f"Error encrypting file: {e}", file=sys.stderr)
        return 1


def decrypt_file(args: argparse.Namespace) -> int:
    """Decrypt a file using Noise protocol."""
    try:
        print("Note: CLI decryption requires handshake state from encryption.")
        print("This is a simplified example for demonstration.")
        
        return 0
    except Exception as e:
        print(f"Error decrypting file: {e}", file=sys.stderr)
        return 1


def show_info(args: argparse.Namespace) -> int:
    """Show information about NoiseFramework capabilities."""
    print("NoiseFramework - Noise Protocol Framework Implementation")
    print()
    print("Supported DH functions:")
    print("  - 25519 (Curve25519/X25519)")
    print("  - 448 (Curve448/X448)")
    print()
    print("Supported ciphers:")
    print("  - ChaChaPoly (ChaCha20-Poly1305) [recommended]")
    print("  - AESGCM (AES-256-GCM)")
    print()
    print("Supported hash functions:")
    print("  - SHA256 [recommended]")
    print("  - SHA512")
    print("  - BLAKE2s")
    print("  - BLAKE2b")
    print()
    print("Supported patterns:")
    patterns = ["NN", "NK", "NX", "KN", "KK", "KX", "XN", "XK", "XX", "IN", "IK", "IX"]
    print("  " + ", ".join(patterns))
    print()
    print("Example pattern string:")
    print("  Noise_XX_25519_ChaChaPoly_SHA256")
    
    return 0


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="noiseframework",
        description="Noise Protocol Framework implementation in Python",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="noiseframework 1.2.0",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Generate keypair command
    gen_parser = subparsers.add_parser(
        "generate-keypair",
        help="Generate a static keypair",
        aliases=["genkey"],
    )
    gen_parser.add_argument(
        "--dh",
        choices=["25519", "448"],
        default="25519",
        help="DH function to use (default: 25519)",
    )
    gen_parser.add_argument(
        "--output-prefix",
        "-o",
        default="noise_key",
        help="Output file prefix (default: noise_key)",
    )
    gen_parser.set_defaults(func=generate_keypair)
    
    # Validate pattern command
    val_parser = subparsers.add_parser(
        "validate-pattern",
        help="Validate a Noise pattern string",
        aliases=["validate"],
    )
    val_parser.add_argument(
        "pattern",
        help="Pattern string (e.g., Noise_XX_25519_ChaChaPoly_SHA256)",
    )
    val_parser.set_defaults(func=validate_pattern)
    
    # Encrypt file command
    enc_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt a file (requires peer for handshake)",
    )
    enc_parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Input file to encrypt",
    )
    enc_parser.add_argument(
        "--output",
        "-o",
        help="Output file (default: input.enc)",
    )
    enc_parser.add_argument(
        "--pattern",
        "-p",
        default="Noise_XX_25519_ChaChaPoly_SHA256",
        help="Noise pattern to use",
    )
    enc_parser.add_argument(
        "--static-key",
        "-s",
        help="Path to static private key",
    )
    enc_parser.add_argument(
        "--remote-key",
        "-r",
        help="Path to remote static public key",
    )
    enc_parser.set_defaults(func=encrypt_file)
    
    # Decrypt file command
    dec_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt a file (requires handshake state)",
    )
    dec_parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Input file to decrypt",
    )
    dec_parser.add_argument(
        "--output",
        "-o",
        help="Output file (default: input.dec)",
    )
    dec_parser.set_defaults(func=decrypt_file)
    
    # Info command
    info_parser = subparsers.add_parser(
        "info",
        help="Show information about NoiseFramework capabilities",
    )
    info_parser.set_defaults(func=show_info)
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    # Execute command
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
