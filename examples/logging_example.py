"""
Example demonstrating logging configuration for NoiseFramework.

Shows how to configure logging at different levels and observe
handshake and transport operations.
"""

import logging
import sys
from noiseframework import NoiseHandshake, NoiseTransport


def setup_logging(level: int = logging.INFO) -> None:
    """
    Configure logging with a specific level.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    # Create formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.addHandler(handler)


def example_basic_logging() -> None:
    """Demonstrate basic logging with INFO level."""
    print("\n=== Example 1: Basic Logging (INFO level) ===\n")
    setup_logging(logging.INFO)
    
    # Create handshake instances
    initiator = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    responder = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    
    # Set roles
    initiator.set_as_initiator()
    responder.set_as_responder()
    
    # Generate keys
    initiator.generate_static_keypair()
    responder.generate_static_keypair()
    
    # Initialize
    initiator.initialize()
    responder.initialize()
    
    # Perform handshake
    msg1 = initiator.write_message(b"")
    responder.read_message(msg1)
    
    msg2 = responder.write_message(b"")
    initiator.read_message(msg2)
    
    msg3 = initiator.write_message(b"")
    responder.read_message(msg3)
    
    # Create transport
    init_send, init_recv = initiator.to_transport()
    resp_send, resp_recv = responder.to_transport()
    
    init_transport = NoiseTransport(init_send, init_recv)
    resp_transport = NoiseTransport(resp_send, resp_recv)
    
    # Send messages
    encrypted = init_transport.send(b"Hello, World!")
    decrypted = resp_transport.receive(encrypted)
    
    print(f"\nDecrypted message: {decrypted.decode()}\n")


def example_debug_logging() -> None:
    """Demonstrate detailed logging with DEBUG level."""
    print("\n=== Example 2: Debug Logging (DEBUG level) ===\n")
    setup_logging(logging.DEBUG)
    
    # Create simple handshake
    initiator = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
    responder = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
    
    initiator.set_as_initiator()
    responder.set_as_responder()
    
    initiator.initialize()
    responder.initialize()
    
    # Single message exchange with detailed logging
    msg = initiator.write_message(b"Init")
    responder.read_message(msg)
    
    # Create transport
    init_send, init_recv = initiator.to_transport()
    resp_send, resp_recv = responder.to_transport()
    
    print("\n")


def example_custom_logger() -> None:
    """Demonstrate using a custom logger instance."""
    print("\n=== Example 3: Custom Logger ===\n")
    
    # Create custom logger
    custom_logger = logging.getLogger("my_app.noise")
    custom_logger.setLevel(logging.INFO)
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(levelname)s - %(message)s")
    )
    custom_logger.addHandler(handler)
    
    # Pass custom logger to handshake
    handshake = NoiseHandshake(
        "Noise_NN_25519_ChaChaPoly_SHA256",
        logger=custom_logger
    )
    
    handshake.set_as_initiator()
    handshake.generate_static_keypair()
    handshake.initialize()
    
    print("\n")


def example_filtering() -> None:
    """Demonstrate filtering logs by module."""
    print("\n=== Example 4: Filtering by Module ===\n")
    
    # Configure root logger to WARNING
    logging.basicConfig(level=logging.WARNING)
    
    # Only show INFO+ for handshake module
    handshake_logger = logging.getLogger("noiseframework.noise.handshake")
    handshake_logger.setLevel(logging.INFO)
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(name)s: %(message)s")
    )
    handshake_logger.addHandler(handler)
    
    # Create handshake (will log INFO messages)
    handshake = NoiseHandshake("Noise_NN_25519_ChaChaPoly_SHA256")
    handshake.set_as_initiator()
    handshake.initialize()
    
    # Transport operations won't show (WARNING level)
    send, recv = handshake.to_transport()
    transport = NoiseTransport(send, recv)
    
    print("\n")


if __name__ == "__main__":
    # Run all examples
    example_basic_logging()
    example_debug_logging()
    example_custom_logger()
    example_filtering()
    
    print("=== Logging Examples Complete ===\n")
