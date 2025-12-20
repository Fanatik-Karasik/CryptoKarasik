# CryptoCore

<<<<<<< HEAD
Разработка крипто провайдера, имплементирующего блочный шифр
# CryptoCore – AES-128 ECB Encryption Tool

CryptoCore — это командный инструмент для шифрования и расшифрования файлов с использованием **AES-128** в режиме **ECB**.  
Проект создан в рамках Sprint 1 и включает полную реализацию:
=======
A comprehensive cryptographic tool suite developed over 8 sprints, supporting encryption, decryption, hash functions, HMAC, key derivation, and authenticated encryption.

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

### Sprint 7: Key Derivation Functions
- PBKDF2-HMAC-SHA256 implementation following RFC 8018
- HKDF implementation following RFC 5869
- Iteration count configuration (default: 100,000)
- Random salt generation and management
- Password strength recommendations

### Sprint 8: Production Readiness & Documentation
- Complete API documentation with comprehensive examples
- User guide with practical use cases
- Developer guide with contribution guidelines
- Reorganized test suite with unit/integration/vector tests
- Professional repository structure and hygiene
- Security policy and changelog implementation
- Quality assurance and security validation
>>>>>>> sprint8

- AES-128 в режиме ECB  
- PKCS#7 padding  
- Корректную работу с бинарными файлами  
- CLI-парсер аргументов  
- Структурированный и расширяемый код  

---

## Возможности

- Шифрование файлов любых форматов  
- Расшифровка ранее зашифрованных данных  
- Ключ передается в виде 32-символьной hex-строки  
- Работа полностью совместима с OpenSSL  
- Корректное добавление и удаление PKCS#7 padding  
- CLI-утилита `cryptocore`

---

## Установка

### Требования
- Python 3.10+  
- Windows 10/11  
- pip  
- Git (если клонируете репозиторий)

### Установка зависимостей

```powershell
pip install -r requirements.txt
<<<<<<< HEAD
```
### Показать помощь:
```powershell
cryptocore --help
```
### Пример шифрования:
```powershell
cryptocore ^
  --algorithm aes ^
  --mode ecb ^
  --encrypt ^
  --key 00112233445566778899aabbccddeeff ^
  --input plaintext.txt ^
  --output ciphertext.bin
```
### Пример расшифровки:
```powershell
cryptocore ^
  --algorithm aes ^
  --mode ecb ^
  --decrypt ^
  --key 00112233445566778899aabbccddeeff ^
  --input ciphertext.bin ^
  --output decrypted.txt
```
### Другие методы
```powershell
# CBC
cryptocore --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input original.txt --output encrypted.bin
cryptocore --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input encrypted.bin --output decrypted.txt

# CFB
cryptocore --algorithm aes --mode cfb --encrypt --key 00112233445566778899aabbccddeeff --input original.txt --output encrypted.bin
cryptocore --algorithm aes --mode cfb --decrypt --key 00112233445566778899aabbccddeeff --input encrypted.bin --output decrypted.txt

# CTR
cryptocore --algorithm aes --mode ctr --encrypt --key 00112233445566778899aabbccddeeff --input original.txt --output encrypted.bin
cryptocore --algorithm aes --mode ctr --decrypt --key 00112233445566778899aabbccddeeff --input encrypted.bin --output decrypted.txt
```

### Цикл с авто-генерацией ключа
```powershell
# Шифрование с авто-генерацией
cryptocore --algorithm aes --mode cbc --encrypt --input original.txt --output auto_enc.bin

# Запоминаем сгенерированный ключ из вывода
# Расшифровка с сгенерированным ключом  
cryptocore --algorithm aes --mode cbc --decrypt --key [GENERATED_KEY] --input auto_enc.bin --output auto_dec.txt

# Проверка целостности
fc original.txt auto_dec.txt /b
```
## Хэширование 
```powershell
# Базовое хэширование
cryptocore dgst --algorithm sha256 --input file.txt
cryptocore dgst --algorithm sha3-256 --input file.pdf

# Хэширование с сохранением в файл
cryptocore dgst --algorithm sha256 --input document.pdf --output hash.txt

# Хэширование пустого файла
echo -n "" > empty.txt
cryptocore dgst --algorithm sha256 --input empty.txt
```
## Шифрование (обратная совместимость)
```powershell
# Автоматическая генерация ключа
cryptocore enc --algorithm aes --mode cbc --encrypt --input plaintext.txt --output ciphertext.bin

# С явным ключом
cryptocore enc --algorithm aes --mode ctr --encrypt --key 00112233445566778899aabbccddeeff --input file.txt --output file.enc
```

## Дешифровка
```powershell
cryptocore enc --algorithm aes --mode cbc --decrypt --key [KEY] --input ciphertext.bin --output decrypted.txt
Помощь и информация
```
### Запуск тестов:
```powershell
.\tests\sprint3_test.ps1
.\tests\test_csprng_comprehensive.ps1  
.\tests\integration_test.ps1
python tests/test_hash_functions.py
.\tests\test_sprint4_cli.ps1
.\tests\roundtrip_test.ps1
```




=======
pip install -e .
```

## Basic Usage

```bash
# Show help
cryptocore --help

# List all available modes
cryptocore --mode help

# Show version
cryptocore --version
```

## Modes and Examples

### Hash Functions (SHA-256, SHA3-256)
```bash
# SHA-256 hash of a file
cryptocore --mode hash --algorithm sha256 --input document.pdf

# SHA3-256 hash of text
cryptocore --mode hash --algorithm sha3_256 --input-text "sensitive data"

# Save hash to file
cryptocore --mode hash --algorithm sha256 --input largefile.iso --output hash.txt
```

### HMAC Generation and Verification
```bash
# Generate HMAC-SHA256
cryptocore --mode hmac --key aabbccddeeff00112233445566778899 --input transaction.log

# Verify HMAC (manually compare outputs)
cryptocore --mode hmac --key [KEY] --input file.txt
```

### Key Derivation (PBKDF2, HKDF)
```bash
# PBKDF2: Derive key from password with salt
cryptocore --mode pbkdf2 --input-text "MyPassword" --salt $(openssl rand -hex 16) --iterations 100000 --dklen 32

# HKDF: Expand existing key
cryptocore --mode hkdf --key [MASTER_KEY_HEX] --salt [SALT_HEX] --info [CONTEXT_HEX] --dklen 32
```

### Random Data Generation
```bash
# Generate 32-byte cryptographic key
cryptocore --mode random --num-bytes 32

# Generate random salt and save to file
cryptocore --mode random --num-bytes 16 --output salt.bin
```

### Encryption Examples
```bash
# GCM encryption with AAD
cryptocore enc --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input file.txt --output file.enc --aad aabbccddeeff

# CBC encryption with auto-generated key
cryptocore enc --algorithm aes --mode cbc --encrypt --input file.txt --output file.enc

# CTR decryption
cryptocore enc --algorithm aes --mode ctr --decrypt --key 00112233445566778899aabbccddeeff --input file.enc --output file.txt
```

## Project Structure (Sprint 8)

```
cryptocore/
├── src/                    # Source code
│   ├── hash/              # Hash functions (SHA-256, SHA3-256)
│   ├── kdf/               # Key derivation (PBKDF2, HKDF)
│   ├── mac/               # Message authentication (HMAC)
│   └── modes/             # CLI interface and utilities
├── tests/                 # Comprehensive test suite
│   ├── unit/             # Unit tests for individual functions
│   ├── integration/      # Integration and CLI tests
│   ├── vectors/          # NIST/RFC test vectors
│   └── run_tests.py      # Unified test runner
├── docs/                  # Complete documentation
│   ├── API.md            # Full API reference
│   ├── USERGUIDE.md      # User guide with examples
│   └── DEVELOPMENT.md    # Developer guide
├── requirements.txt       # Pinned dependencies
├── setup.py              # Package configuration
├── CHANGELOG.md          # Version history
├── CONTRIBUTING.md       # Contribution guidelines
├── SECURITY.md           # Security policy
└── README.md             # This file
```

## Testing

```bash
# Run all tests
python tests/run_tests.py

# Run with pytest
pytest tests/ -v

# Run specific test categories
pytest tests/unit/           # Unit tests only
pytest tests/integration/    # Integration tests only

# Test coverage report
pytest tests/ --cov=src --cov-report=html
```

## Documentation

- **API Documentation**: See `docs/API.md` for complete function references
- **User Guide**: See `docs/USERGUIDE.md` for practical examples
- **Developer Guide**: See `docs/DEVELOPMENT.md` for contribution guidelines
- **Security Policy**: See `SECURITY.md` for vulnerability reporting
- **Changelog**: See `CHANGELOG.md` for version history

## Security Features (Sprint 8 Enhancements)

- Comprehensive input validation and error handling
- Secure memory management practices
- Constant-time operations for critical functions
- No sensitive data logging or exposure
- Proper key management guidelines
- Security checklist implementation
- Vulnerability disclosure policy

## Requirements

- Python 3.8 or higher
- pycryptodome 3.10.1

## Contributing

Please read `CONTRIBUTING.md` for details on our code of conduct and the process for submitting pull requests.
>>>>>>> sprint8
