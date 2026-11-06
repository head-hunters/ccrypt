
# ccrypt
#### Description:

A command-line file encryption and decryption utility written in C. `ccrypt` uses AES-256-GCM for authenticated encryption and Argon2id for password-based key derivation.

## Setup

### 1. Clone the repository

Clone the repository and navigate into the project directory:

```bash
git clone https://github.com/YOUR_USERNAME/ccrypt.git
cd ccrypt
```

### 2. Install dependencies

The project requires the following dependencies:

- GCC
- Make
- OpenSSL development libraries
- Argon2 development libraries

On Debian-based distributions, these can be installed using:

```bash
sudo apt update
sudo apt install build-essential libssl-dev libargon2-dev
```

### 3. Build the project

Compile the source files using the provided Makefile:

```bash
make
```

Once compilation succeeds, the executable will be available at:

```bash
./build/ccrypt
```

### 4. Clean build files

To remove the compiled executable:

```bash
make clean
```



## Features

- **Authenticated Encryption and Decryption** – Supports authenticated encryption and decryption using AES-256-GCM through OpenSSL's EVP API.
- **Password-Based Key Derivation** – Uses Argon2id as the key derivation function (KDF) to derive encryption keys from user-provided passwords.
- **Verbose Output** – Provides detailed byte-level information about the encryption and decryption processes.
- **Batch Processing** – Supports encrypting and decrypting multiple files in a single operation.
- **Secure Random Generation** – Uses cryptographically secure random generation for salts and nonces.


## Project Structure

The project is organised into the following directories and files:

```text
ccrypt/
├── include/             # Contains header files
│   ├── batch.h
│   ├── constants.h      # Definitions of project-wide constants
│   ├── decrypt.h
│   ├── dumper.h
│   ├── encrypt.h
│   └── helpers.h
├── src/                 # Contains the main source files
│   ├── batch.c          # Implements batch processing
│   ├── ccrypt.c         # Main entry point and command-line argument handling
│   ├── decrypt.c        # Implements file decryption
│   ├── dumper.c         # Implements the hexadecimal dumper for verbose output
│   ├── encrypt.c        # Implements file encryption
│   └── helpers.c        # Contains utility functions used during encryption and decryption
├── tests/               # Contains the automated regression test suite
│   ├── drive.exp
│   ├── interrupt.exp
│   └── run.sh
├── Makefile             # Build configuration
└── README.md            # Project documentation
```





## Cryptographic Design

ccrypt uses the following cryptographic components:

| Component | Implementation |
|---|---|
| Encryption algorithm | AES-256-GCM |
| Key derivation function | Argon2id |
| Salt size | 16 bytes |
| Key size | 32 bytes |
| Nonce size | 12 bytes |
| Authentication tag | 16 bytes |


### Format of an Encrypted File

An encrypted file consists of the following components:

```text
+------------+-------------+----------------+----------------+
| Salt       | Nonce       | Ciphertext     | Auth Tag       |
+------------+-------------+----------------+----------------+
| 16 bytes   | 12 bytes    | Variable       | 16 bytes       |
+------------+-------------+----------------+----------------+
```



### Key Derivation

A user-supplied password is processed using Argon2id to derive
a 256-bit encryption key.

Current Argon2id parameters:

- Time cost: 2
- Memory cost: 65536 KiB
- Parallelism: 1

A randomly generated salt is used for each encryption operation.

### Authenticated Encryption

AES-256-GCM provides confidentiality and authentication.

During decryption, the authentication tag is verified before
the decrypted file is published. If authentication fails,
the temporary plaintext output is discarded.






## Display help


Use the `-h` option to display the available commands and usage information:

```bash
./build/ccrypt -h
```



## Usage

  

    ccrypt <option> <source> <destination>
    ccrypt <option> <source1,source2,...> <destination1,destination2,...>



## Options

| Option | Description |
|---|---|
| `-e` | Encrypt file(s) |
| `-d` | Decrypt file(s) |
| `-ev` | Encrypt file(s) with verbose output |
| `-dv` | Decrypt file(s) with verbose output |

## Arguments

- `source` — File(s) to read (plaintext for encryption, ciphertext for decryption).
- `destination` — File(s) to write (ciphertext for encryption, plaintext for decryption).

## Batch Processing

- Multiple files can be specified using comma-separated lists.
- Each source file is paired with its corresponding destination file by position.
- The number of source and destination files must match.
- Each file is processed independently and requires its own password.

## Examples

**Single-file operations**

    ccrypt -e  plaintext.txt encrypted.bin
    ccrypt -d  encrypted.bin decrypted.txt
    ccrypt -ev plaintext.txt encrypted.bin
    ccrypt -dv encrypted.bin decrypted.txt

**Batch operations**

    ccrypt -e  file1.txt,file2.txt,file3.txt encrypted1.bin,encrypted2.bin,encrypted3.bin
    ccrypt -d  encrypted1.bin,encrypted2.bin,encrypted3.bin decrypted1.txt,decrypted2.txt,decrypted3.txt
    ccrypt -ev file1.txt,file2.txt encrypted1.bin,encrypted2.bin
    ccrypt -dv encrypted1.bin,encrypted2.bin decrypted1.txt,decrypted2.txt


## Testing

The project includes an automated regression test suite.

Run the tests using:

```bash
./tests/run.sh
```

The test suite covers:

- Empty-file encryption and decryption.
- Binary files larger than the processing buffer.
- Password confirmation failures.
- Incorrect passwords.
- Authentication failures following ciphertext modification.
- Truncated encrypted files.
- Batch processing.
- Invalid command-line arguments.
- Preservation of existing destination files after failures.
- SIGINT interruption during encryption and decryption.

The project has also been tested using:

- AddressSanitizer (ASan)
- UndefinedBehaviorSanitizer (UBSan)
- Valgrind

## Security Considerations

- Password strength directly affects resistance to brute-force attacks.
- Salts and nonces are generated using cryptographically secure random number generation.
- AES-256-GCM provides authenticated encryption, allowing tampering to be detected during decryption.
- Decrypted data is written to a temporary file and only published after successful authentication.
- The Argon2id parameters are currently fixed within the implementation.
- The project has not undergone an independent security audit.
