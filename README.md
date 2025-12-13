# CryptoCore

A comprehensive cryptographic tool suite developed over 6 sprints, supporting encryption, decryption, hash functions, HMAC, and authenticated encryption.

## Project Evolution

### Sprint 1: Basic AES-ECB Encryption
- Implemented AES-ECB encryption/decryption
- Basic CLI interface with key validation
- File I/O operations
- PKCS#7 padding implementation

### Sprint 2: Multiple Encryption Modes
- Added CBC, CFB, OFB, CTR modes
- IV handling with secure generation
- OpenSSL interoperability
- Enhanced error handling

### Sprint 3: Automatic Key Management
- Cryptographically secure random number generation
- Automatic key generation when --key omitted
- Weak key detection with warnings
- Enhanced CSPRNG testing

### Sprint 4: Hash Functions
- SHA-256 and SHA3-256 implementations from scratch
- New CLI subcommand structure (enc/dgst)
- File integrity verification
- Large file support with chunk processing

### Sprint 5: Message Authentication Codes
- HMAC-SHA256 implementation following RFC 2104
- HMAC verification with --verify flag
- Tamper detection for files and keys
- Support for variable-length keys

### Sprint 6: Authenticated Encryption
- GCM (Galois/Counter Mode) implementation from scratch
- AEAD (Authenticated Encryption with Associated Data)
- AAD (Associated Authenticated Data) support
- Catastrophic failure on authentication errors
- Encrypt-then-MAC paradigm

## Installation

```bash
pip install -r requirements.txt
pip install -e .
```

## Basic Usage

```bash
# Show help
cryptocore --help

# Encryption help
cryptocore enc --help

# Hash/HMAC help
cryptocore dgst --help
```

## Encryption Examples
```bash
# GCM encryption with AAD (Sprint 6)
cryptocore enc --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input file.txt --output file.enc --aad aabbccddeeff

# CBC encryption with auto key (Sprint 3)
cryptocore enc --algorithm aes --mode cbc --encrypt --input file.txt --output file.enc

# CTR decryption (Sprint 2)
cryptocore enc --algorithm aes --mode ctr --decrypt --key 00112233445566778899aabbccddeeff --input file.enc --output file.txt
```

## Hash/HMAC Examples
```bash
# SHA-256 hash (Sprint 4)
cryptocore dgst --algorithm sha256 --input document.pdf

# HMAC generation (Sprint 5)
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt

# HMAC verification (Sprint 5)
cryptocore dgst --algorithm sha256 --hmac --key [KEY] --input file.txt --verify expected_hmac.txt
```

## Testing
```bash
# Run all tests
python -m pytest tests/
```