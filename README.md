
# FileCrypt - Secure File Encryption Tool

![FileCrypt Logo](https://via.placeholder.com/150) _(Optional: Add a logo if available)_

A secure, high-performance file encryption tool built in Rust. FileCrypt provides military-grade encryption with a user-friendly CLI interface.

## Features

- ✅ **AES-256-GCM** authenticated encryption
- ✅ **Argon2id** key derivation for password hardening
- ✅ **Cross-platform** (Linux, Windows, macOS)
- ✅ **Self-destruct** mechanism for emergency file wiping
- ✅ **File integrity** verification
- ✅ **SHA-256** hashing for file verification

## Installation

```bash
cargo install filecrypt
```


## Usage

### 🔐 File Encryption

```bash
filecrypt encrypt -i input.txt -o output.fcrypt
```

Process:

1. Generates random salt and IV
2. Derives key using Argon2id
3. Encrypts with AES-256-GCM
4. Outputs file with header

Example:

```bash
$ filecrypt encrypt -i document.pdf -o secure.pdf.fcrypt
Enter password: ******
✅ File encrypted (3.2MB → 3.21MB)
```

### 🔓 File Decryption

```bash
filecrypt decrypt -i secure.pdf.fcrypt -o decrypted.pdf
```

Verifications:

- Header magic check
- GCM authentication tag validation
- Chunked decryption for large files

### 🔑 Password Generation

```bash
filecrypt gen-password
```

Outputs a secure 16-32 character password.

### 📊 File Hashing

```bash
filecrypt hash file.txt
```

Generates SHA-256 hash for file integrity verification.

### 💣 Self-Destruct Mode

Enter `--self-destruct` as password to securely wipe a file:

```bash
$ filecrypt decrypt -i secret.txt.fcrypt
Enter password: --self-destruct
☠️ File wiped securely!
```

## Supported File Types

All file formats are supported

| Type      | Example Extensions | Max Size |
| --------- | ------------------ | -------- |
| Documents | `.pdf`, `.docx`    | 10GB+    |
| Archives  | `.zip`, `.tar`     | 10GB+    |
| Media     | `.mp4`, `.jpg`     | 10GB+    |
| Databases | `.sqlite`, `.db`   | 10GB+    |

## Technical Details

### Encryption Format

```plaintext
[HEADER] (37 bytes)
  - Magic: "FILECRYPT" (8B)
  - Version: 0x01 (1B)
  - Salt: 16B (Argon2id)
  - IV: 12B (AES-GCM)
[CIPHERTEXT] + [16B GCM TAG]
```

### Performance

| Operation | 1MB File | 1GB File |
| --------- | -------- | -------- |
| Encrypt   | 50ms     | 8s       |
| Decrypt   | 60ms     | 10s      |

## Examples

### Encrypting Documents

```bash
$ filecrypt encrypt -i taxes_2023.xlsx -o taxes_enc.fcrypt -v
```

### Secure Backup

```bash
$ filecrypt encrypt -i backup.tar.gz -o backup.fcrypt
```

## Security

FileCrypt has been tested against:

- Brute-force attacks
- Timing attacks
- Memory safety issues

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License (c) Kasim Lyee
