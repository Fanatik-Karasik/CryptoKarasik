import os
import sys

def generate_random_bytes(num_bytes):

    # Sprint 3: Cryptographically secure random number generator

    if num_bytes <= 0:
        raise ValueError("Number of bytes must be positive")
    
    try:
        return os.urandom(num_bytes)
    except Exception as e:
        raise RuntimeError(f"Failed to generate random bytes: {e}")

def generate_key(key_size=16):

    # Sprint 3: Generate random encryption key

    return generate_random_bytes(key_size)

def generate_iv():

    # Sprint 3: Generate random initialization vector

    return generate_random_bytes(16)