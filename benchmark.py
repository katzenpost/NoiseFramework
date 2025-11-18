"""
Performance benchmarking script for NoiseFramework.

Measures real-world performance of handshakes, transport encryption,
and key operations across different patterns and message sizes.
"""

import time
import statistics
from typing import List, Dict, Any
from noiseframework import NoiseHandshake, NoiseTransport


def benchmark_handshake(pattern: str, iterations: int = 1000) -> Dict[str, Any]:
    """
    Benchmark complete handshake flow for a given pattern.
    
    Args:
        pattern: Noise pattern string
        iterations: Number of handshakes to perform
        
    Returns:
        Dictionary with timing statistics
    """
    times: List[float] = []
    
    for _ in range(iterations):
        start = time.perf_counter()
        
        # Initiator setup
        initiator = NoiseHandshake(pattern)
        initiator.set_as_initiator()
        initiator.generate_static_keypair()
        initiator.initialize()
        
        # Responder setup
        responder = NoiseHandshake(pattern)
        responder.set_as_responder()
        responder.generate_static_keypair()
        responder.initialize()
        
        # Perform handshake (XX pattern: 3 messages)
        msg1 = initiator.write_message(b"")
        responder.read_message(msg1)
        
        msg2 = responder.write_message(b"")
        initiator.read_message(msg2)
        
        msg3 = initiator.write_message(b"")
        responder.read_message(msg3)
        
        # Create transports
        init_send, init_recv = initiator.to_transport()
        resp_send, resp_recv = responder.to_transport()
        
        end = time.perf_counter()
        times.append(end - start)
    
    return {
        "mean": statistics.mean(times),
        "median": statistics.median(times),
        "stdev": statistics.stdev(times) if len(times) > 1 else 0,
        "min": min(times),
        "max": max(times),
        "iterations": iterations,
    }


def benchmark_transport_encryption(
    message_size: int, iterations: int = 10000
) -> Dict[str, Any]:
    """
    Benchmark transport layer encryption/decryption.
    
    Args:
        message_size: Size of messages in bytes
        iterations: Number of encrypt/decrypt operations
        
    Returns:
        Dictionary with timing and throughput statistics
    """
    # Setup handshake to get transport
    pattern = "Noise_XX_25519_ChaChaPoly_SHA256"
    initiator = NoiseHandshake(pattern)
    initiator.set_as_initiator()
    initiator.generate_static_keypair()
    initiator.initialize()
    
    responder = NoiseHandshake(pattern)
    responder.set_as_responder()
    responder.generate_static_keypair()
    responder.initialize()
    
    msg1 = initiator.write_message(b"")
    responder.read_message(msg1)
    msg2 = responder.write_message(b"")
    initiator.read_message(msg2)
    msg3 = initiator.write_message(b"")
    responder.read_message(msg3)
    
    init_send, init_recv = initiator.to_transport()
    resp_send, resp_recv = responder.to_transport()
    
    init_transport = NoiseTransport(init_send, init_recv)
    resp_transport = NoiseTransport(resp_send, resp_recv)
    
    # Create test message
    plaintext = b"X" * message_size
    
    # Benchmark encryption
    encrypt_times: List[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        ciphertext = init_transport.send(plaintext)
        end = time.perf_counter()
        encrypt_times.append(end - start)
    
    # Benchmark decryption
    # Reset transport for decryption test
    init_send2, init_recv2 = initiator.to_transport()
    resp_send2, resp_recv2 = responder.to_transport()
    init_transport2 = NoiseTransport(init_send2, init_recv2)
    resp_transport2 = NoiseTransport(resp_send2, resp_recv2)
    
    decrypt_times: List[float] = []
    for _ in range(iterations):
        ct = init_transport2.send(plaintext)
        start = time.perf_counter()
        pt = resp_transport2.receive(ct)
        end = time.perf_counter()
        decrypt_times.append(end - start)
    
    encrypt_mean = statistics.mean(encrypt_times)
    decrypt_mean = statistics.mean(decrypt_times)
    
    # Calculate throughput (MB/s)
    encrypt_throughput = (message_size / encrypt_mean) / (1024 * 1024)
    decrypt_throughput = (message_size / decrypt_mean) / (1024 * 1024)
    
    return {
        "message_size": message_size,
        "encrypt_mean": encrypt_mean,
        "encrypt_stdev": statistics.stdev(encrypt_times),
        "encrypt_throughput_mbps": encrypt_throughput,
        "decrypt_mean": decrypt_mean,
        "decrypt_stdev": statistics.stdev(decrypt_times),
        "decrypt_throughput_mbps": decrypt_throughput,
        "iterations": iterations,
    }


def benchmark_key_generation(dh_function: str, iterations: int = 1000) -> Dict[str, Any]:
    """
    Benchmark key generation for a DH function.
    
    Args:
        dh_function: DH function name (e.g., "25519", "448")
        iterations: Number of key generations
        
    Returns:
        Dictionary with timing statistics
    """
    pattern = f"Noise_XX_{dh_function}_ChaChaPoly_SHA256"
    times: List[float] = []
    
    for _ in range(iterations):
        hs = NoiseHandshake(pattern)
        start = time.perf_counter()
        hs.generate_static_keypair()
        end = time.perf_counter()
        times.append(end - start)
    
    return {
        "dh_function": dh_function,
        "mean": statistics.mean(times),
        "median": statistics.median(times),
        "stdev": statistics.stdev(times),
        "min": min(times),
        "max": max(times),
        "iterations": iterations,
    }


def format_time(seconds: float) -> str:
    """Format time in appropriate units."""
    if seconds < 1e-6:
        return f"{seconds * 1e9:.2f} ns"
    elif seconds < 1e-3:
        return f"{seconds * 1e6:.2f} µs"
    elif seconds < 1:
        return f"{seconds * 1e3:.2f} ms"
    else:
        return f"{seconds:.2f} s"


def format_throughput(mbps: float) -> str:
    """Format throughput in appropriate units."""
    if mbps < 1:
        return f"{mbps * 1024:.2f} KB/s"
    elif mbps < 1024:
        return f"{mbps:.2f} MB/s"
    else:
        return f"{mbps / 1024:.2f} GB/s"


def main():
    """Run all benchmarks and display results."""
    print("=" * 80)
    print("NoiseFramework Performance Benchmarks")
    print("=" * 80)
    print()
    
    # Benchmark 1: Handshake patterns
    print("1. HANDSHAKE PERFORMANCE")
    print("-" * 80)
    patterns = [
        "Noise_XX_25519_ChaChaPoly_SHA256",
        "Noise_XX_25519_AESGCM_SHA256",
        "Noise_NN_25519_ChaChaPoly_SHA256",
        "Noise_IK_25519_ChaChaPoly_SHA256",
    ]
    
    for pattern in patterns:
        print(f"\nPattern: {pattern}")
        try:
            results = benchmark_handshake(pattern, iterations=500)
            print(f"  Mean:       {format_time(results['mean'])}")
            print(f"  Median:     {format_time(results['median'])}")
            print(f"  Std Dev:    {format_time(results['stdev'])}")
            print(f"  Min:        {format_time(results['min'])}")
            print(f"  Max:        {format_time(results['max'])}")
            print(f"  Rate:       {int(1 / results['mean'])} handshakes/sec")
        except Exception as e:
            print(f"  Error: {e}")
    
    print("\n" + "=" * 80)
    print("2. TRANSPORT ENCRYPTION PERFORMANCE")
    print("-" * 80)
    
    message_sizes = [64, 256, 1024, 4096, 16384, 65536]
    
    for size in message_sizes:
        print(f"\nMessage size: {size} bytes")
        results = benchmark_transport_encryption(size, iterations=5000)
        print(f"  Encryption:")
        print(f"    Mean:       {format_time(results['encrypt_mean'])}")
        print(f"    Throughput: {format_throughput(results['encrypt_throughput_mbps'])}")
        print(f"  Decryption:")
        print(f"    Mean:       {format_time(results['decrypt_mean'])}")
        print(f"    Throughput: {format_throughput(results['decrypt_throughput_mbps'])}")
    
    print("\n" + "=" * 80)
    print("3. KEY GENERATION PERFORMANCE")
    print("-" * 80)
    
    dh_functions = ["25519", "448"]
    
    for dh in dh_functions:
        print(f"\nDH Function: {dh}")
        try:
            results = benchmark_key_generation(dh, iterations=1000)
            print(f"  Mean:       {format_time(results['mean'])}")
            print(f"  Median:     {format_time(results['median'])}")
            print(f"  Std Dev:    {format_time(results['stdev'])}")
            print(f"  Rate:       {int(1 / results['mean'])} keypairs/sec")
        except Exception as e:
            print(f"  Error: {e}")
    
    print("\n" + "=" * 80)
    print("Benchmarks complete!")
    print("=" * 80)


if __name__ == "__main__":
    main()
