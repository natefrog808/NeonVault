## 1. API Reference: Exhaustive Technical Details

The **API Reference** serves as a comprehensive guide to all functions, modules, and types in the NeonVault Crypto library. It is designed for developers who need to integrate the library into their applications and understand its full capabilities.

### 1.1 Introduction
- **Overview**: NeonVault Crypto is a quantum-resistant cryptographic library built around the CRYSTALS-KYBER algorithm, offering robust encryption and key management tools.
- **Purpose**: This reference provides detailed technical specifications for all library components, including function signatures, parameters, return types, and usage examples.

### 1.2 Modules
- **`kyber`**: Core implementation of the CRYSTALS-KYBER algorithm for key generation, encryption, and decryption.
- **`utils`**: Utility functions for byte manipulation, secure random number generation, and predefined constants.

### 1.3 kyber Module
This section details all functions and constants related to the KYBER algorithm.

#### `generate_keypair()`
- **Description**: Generates a KYBER key pair using the default security level (Kyber-768).
- **Signature**:
  ```rust
  pub fn generate_keypair() -> Result<(PublicKey, PrivateKey), CryptoError>
  ```
- **Returns**:
  - `PublicKey`: For encryption.
  - `PrivateKey`: For decryption.
- **Example**:
  ```rust
  use neonvault_crypto::generate_keypair;
  let (public_key, private_key) = generate_keypair().expect("Failed to generate key pair");
  ```

#### `encrypt(public_key: &PublicKey, message: &[u8])`
- **Description**: Encrypts a message using the provided public key.
- **Signature**:
  ```rust
  pub fn encrypt(public_key: &PublicKey, message: &[u8]) -> Result<Vec<u8>, CryptoError>
  ```
- **Returns**: Encrypted ciphertext as a byte vector.
- **Example**:
  ```rust
  let ciphertext = encrypt(&public_key, b"Secret message").expect("Encryption failed");
  ```

#### `decrypt(private_key: &PrivateKey, ciphertext: &[u8])`
- **Description**: Decrypts a ciphertext using the provided private key.
- **Signature**:
  ```rust
  pub fn decrypt(private_key: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>
  ```
- **Returns**: Decrypted plaintext as a byte vector.
- **Example**:
  ```rust
  let plaintext = decrypt(&private_key, &ciphertext).expect("Decryption failed");
  ```

#### `generate_keypair_with_params(params: KyberParams)`
- **Description**: Generates a key pair with a specified security level (e.g., Kyber-512, Kyber-1024).
- **Signature**:
  ```rust
  pub fn generate_keypair_with_params(params: KyberParams) -> Result<(PublicKey, PrivateKey), CryptoError>
  ```
- **Example**:
  ```rust
  use neonvault_crypto::kyber::KYBER_1024;
  let (pk, sk) = generate_keypair_with_params(KYBER_1024).expect("Keygen failed");
  ```

#### `encrypt_with_params(public_key: &PublicKey, message: &[u8], params: KyberParams)`
- **Description**: Encrypts a message with specified KYBER parameters.
- **Signature**:
  ```rust
  pub fn encrypt_with_params(public_key: &PublicKey, message: &[u8], params: KyberParams) -> Result<Vec<u8>, CryptoError>
  ```

#### `decrypt_with_params(private_key: &PrivateKey, ciphertext: &[u8], params: KyberParams)`
- **Description**: Decrypts a ciphertext with specified KYBER parameters.
- **Signature**:
  ```rust
  pub fn decrypt_with_params(private_key: &PrivateKey, ciphertext: &[u8], params: KyberParams) -> Result<Vec<u8>, CryptoError>
  ```

#### Constants
- `KYBER_512`, `KYBER_768`, `KYBER_1024`: Predefined parameter sets for different security levels.

### 1.4 utils Module
This section covers utility functions that support cryptographic operations.

- **`bytes`**: Functions for byte manipulation (e.g., `to_hex`, `from_hex`).
- **`random`**: Secure random number generation.
  - `SecureRandom::new()`: Initializes a cryptographically secure RNG.
  - `fill_random`: Fills a buffer with secure random bytes.
- **`constants`**: Global constants (e.g., `AES_256_KEY_SIZE`, `PROTOCOL_VERSION`).

### 1.5 Error Handling
- **Common Errors**: `CryptoError` (general cryptographic failures), `RandomError` (RNG issues).
- **Handling**: Use `Result` types and handle errors with `match` or `.expect()` for quick prototyping, ensuring proper logging in production.

---
