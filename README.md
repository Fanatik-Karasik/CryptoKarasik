# CryptoCore


### Sprint 1: AES-ECB шифрование
- Implemented AES-ECB encryption/decryption
- Basic CLI interface with key validation
- File I/O operations
- PKCS#7 padding implementation

### Sprint 2  
- Added CBC, CFB, OFB, CTR modes
- IV handling with secure generation
- OpenSSL interoperability
- Enhanced error handling

### Sprint 3: Автоматический ключ
- Cryptographically secure random number generation
- Automatic key generation when --key omitted
- Weak key detection with warnings
- Enhanced CSPRNG testing

### Sprint 4:Хэш функции
- SHA-256 and SHA3-256 implementations
- New CLI subcommand structure (enc/dgst)
- File integrity verification
- Large file support with chunk processing

## Использование

```bash
pip install -r requirements.txt
pip install -e .

# Auto key generation (Sprint 3)
cryptocore enc --algorithm aes --mode cbc --encrypt --input file.txt --output file.enc

# Manual key (Sprint 1-2)
cryptocore enc --algorithm aes --mode ctr --encrypt --key 00112233445566778899aabbccddeeff --input file.txt --output file.enc

# Decryption
cryptocore enc --algorithm aes --mode cbc --decrypt --key [KEY] --input file.enc --output file.txt

# SHA-256 hash
cryptocore dgst --algorithm sha256 --input document.pdf

# SHA3-256 with output file
cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3

# Empty file hash
cryptocore dgst --algorithm sha256 --input empty.txt
```

## Тесты
```bash
python tests/test_hash_functions.py
.\tests\roundtrip_test.ps1
.\tests\test_sprint4_cli.ps1
```

