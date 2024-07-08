INTEL-UNNATI-Protecting User Password Keys At Rest (On the Disk)

Application Workflow

1. User Input: The user selects a file or directory to encrypt.
2. Generate File Encryption Key (FEK): A random FEK is generated.
3. Encrypt File/Directory: The selected file or directory is encrypted using the FEK with AES-256 encryption.
4. Key Derivation: A Key Derivation Function (KDF) is used to derive a key from the user’s passphrase.
5. Encrypt FEK: The FEK is encrypted using the derived key from the KDF.
6. Store Encrypted FEK: The encrypted FEK is stored securely.
7. Decryption Process:
   a) The user provides the passphrase.
   b) The KDF generates the key from the passphrase.
   c) The FEK is decrypted using the derived key.
   d) The file or directory is decrypted using the FEK.

Features
  1. AES-256 Encryption: Ensures strong encryption for files and directories.
  2. Key Derivation Function (KDF): Securely derives encryption keys from user passphrases.
  3. Random Key Generation: Generates a random FEK for each encryption operation.
  4. User Passphrase: Protects the FEK and ensures that only authorized users can decrypt the files.

Prerequisites
  a) OpenSSL library (for C++ implementation)
  b) Python 3 and relevant libraries (for Python implementation)
  c) C++ compiler (for C++ implementation)
  d) CMake (for C++ implementation)
