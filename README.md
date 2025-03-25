# NeonVault Crypto

![Crates.io](https://img.shields.io/crates/v/neonvault-crypto)
![License](https://img.shields.io/badge/license-%2FApache--2.0-blue)
![Rust Version](https://img.shields.io/badge/rust-1.76%2B-orange)

**NeonVault Crypto** is a quantum-resistant cryptographic library powering the NeonVault secure communication platform. Built with a cyberpunk aesthetic and the security needs of the future, this library implements the CRYSTALS-KYBER post-quantum key encapsulation mechanism standardized by NIST (FIPS 203).

In a world where quantum computers threaten to break traditional cryptography, NeonVault stands as a bastion of privacy with cutting-edge algorithms designed to resist attacks from even the most powerful quantum adversaries.

## ✨ Features

- **🔐 Post-Quantum Security**: Implementation of CRYSTALS-KYBER algorithm resistant to quantum computer attacks
- **🛡️ Multiple Security Levels**: Support for Kyber-512, Kyber-768, and Kyber-1024 variants for different security requirements
- **⚡ Performance Optimized**: NTT-accelerated polynomial operations for efficient encryption/decryption
- **🧪 Zero-Dependency Core**: Critical cryptographic operations use minimal dependencies
- **⏱️ Constant-Time Operations**: Designed to resist timing attacks with secure implementations
- **🔍 Memory Security**: Sensitive values are zeroed after use using the zeroize crate
- **📊 Benchmarking Tools**: Comprehensive benchmarks to measure and optimize performance

## 📊 Performance

| Operation | Kyber-512 | Kyber-768 | Kyber-1024 |
|-----------|-----------|-----------|------------|
| Key Generation | 0.2 ms | 0.3 ms | 0.5 ms |
| Encryption | 0.25 ms | 0.35 ms | 0.55 ms |
| Decryption | 0.2 ms | 0.3 ms | 0.5 ms |

*Benchmarks conducted on an Intel i7-12700K @ 3.6 GHz. Your results may vary.*

## 🚀 Quick Start

### Installation

Add NeonVault Crypto to your `Cargo.toml`:

```toml
[dependencies]
neonvault-crypto = "0.1.0"
```

### Basic Usage

```rust
use neonvault_crypto::{generate_keypair, encrypt, decrypt};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a quantum-resistant key pair
    let (public_key, private_key) = generate_keypair()?;
    
    // Encrypt a message
    let message = b"The future of encryption is quantum-resistant";
    let ciphertext = encrypt(&public_key, message)?;
    
    // Decrypt the message
    let decrypted = decrypt(&private_key, &ciphertext)?;
    assert_eq!(message, &decrypted[..]);
    
    println!("Message successfully encrypted and decrypted with quantum-resistant KYBER!");
    
    Ok(())
}
```

## 📖 Documentation

For comprehensive documentation, see:

- [API Documentation](https://docs.rs/neonvault-crypto) - Detailed API reference
- [Algorithm Details](./docs/kyber.md) - Deep dive into the CRYSTALS-KYBER implementation
- [Security Guidelines](./docs/security.md) - Best practices for using this library securely

## 🔬 CRYSTALS-KYBER Overview

CRYSTALS-KYBER is a lattice-based key encapsulation mechanism that is one of the algorithms selected by NIST for standardization as part of the Post-Quantum Cryptography process. It is based on the hardness of the Module Learning With Errors (MLWE) problem.

Key features of our implementation:

- **FIPS 203 Compliant**: Follows the NIST standard for post-quantum cryptography
- **Side-Channel Resistant**: Designed with timing attack countermeasures 
- **Constant-Time Operations**: Critical operations run in constant time to prevent leaking secrets
- **Future-Proof**: Ready for a world where quantum computers can break RSA and ECC

## 🔧 Advanced Usage

### Using Different Security Levels

```rust
use neonvault_crypto::kyber::{KYBER_512, KYBER_768, KYBER_1024};
use neonvault_crypto::{generate_keypair_with_params, encrypt_with_params, decrypt};

// Generate a key pair with maximum security (Kyber-1024)
let (public_key, private_key) = generate_keypair_with_params(KYBER_1024)?;

// Encrypt using the same parameters
let message = b"Maximum security encryption";
let ciphertext = encrypt_with_params(&public_key, message, KYBER_1024)?;

// Decrypt (parameters automatically detected from key)
let decrypted = decrypt(&private_key, &ciphertext)?;
```

### Working with Deterministic Random Number Generators (for Testing)

```rust
use neonvault_crypto::utils::random::SecureRandom;
use neonvault_crypto::{generate_keypair_with_rng, encrypt_with_rng};

// Create a deterministic RNG from a seed (for testing only!)
let seed = [0u8; 32];
let mut rng = SecureRandom::from_seed(seed);

// Generate a deterministic key pair (for testing)
let (public_key, private_key) = generate_keypair_with_rng(&mut rng)?;

// Generate a fresh RNG for encryption
let mut encryption_rng = SecureRandom::new();
let message = b"Deterministic for testing";
let ciphertext = encrypt_with_rng(&public_key, message, &mut encryption_rng)?;
```

## 🧪 Testing

NeonVault Crypto includes comprehensive test suites:

```bash
# Run all tests
cargo test

# Run benchmarks
cargo bench

# Test with different security levels
cargo test --features="kyber-1024-tests"
```

## 🧩 Project Structure

```
neonvault-crypto/
├── src/
│   ├── lib.rs           # Main library file
│   ├── kyber/           # KYBER implementation
│   │   ├── mod.rs       # Module exports
│   │   ├── key_gen.rs   # Key generation
│   │   ├── encrypt.rs   # Encryption
│   │   ├── decrypt.rs   # Decryption
│   │   ├── params.rs    # Algorithm parameters
│   │   └── polynomial.rs # Polynomial operations
│   └── utils/           # Utility functions
│       ├── mod.rs       # Module exports
│       ├── bytes.rs     # Byte manipulation utilities
│       ├── random.rs    # Secure randomness
│       └── constants.rs # Global constants
└── ...
```

## 🛡️ Security Features

- **Constant-Time Operations**: Critical operations like polynomial comparison use the `subtle` crate for constant-time execution
- **Secure Memory Management**: The `zeroize` crate ensures sensitive data is securely erased from memory
- **Vulnerability Scanning**: CI/CD pipeline includes automatic vulnerability scanning
- **Memory Safety**: Rust's ownership model prevents memory-related vulnerabilities
- **No Unsafe Code**: The codebase forbids unsafe code by default (`#![forbid(unsafe_code)]`)

## 🔭 Roadmap

- [ ] Additional post-quantum algorithms (CRYSTALS-Dilithium signatures)
- [ ] Hardware acceleration for ARM and x86 platforms
- [ ] WebAssembly support for browser-based applications
- [ ] Formal verification of critical components
- [ ] Integration with the full NeonVault secure messaging platform
- [ ] Hybrid encryption schemes combining quantum and classical algorithms

## 🤝 Contributing

Contributions are welcome! Please check out our [contributing guidelines](CONTRIBUTING.md) to get started.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Run the tests (`cargo test`)
4. Commit your changes (`git commit -m 'Add some amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## 📜 License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## 📣 Citation

If you use NeonVault Crypto in academic or research work, please cite:

```bibtex
@software{neonvault_crypto,
  author = {{NeonVault Team}},
  title = {NeonVault Crypto: Quantum-Resistant Cryptography Library},
  url = {https://github.com/neonvault/neonvault-crypto},
  version = {0.1.0},
  year = {2025},
}
```

## 📮 Contact

- **Lead Developer**: [neon_developer@example.com](mailto:neon_developer@example.com)
- **Security Reports**: [security@neonvault.example](mailto:security@neonvault.example)
- **Discord**: [Join our server](https://discord.gg/neonvault)

---

<p align="center">
  <img src="https://imgur.com/placeholder/200/100" alt="NeonVault Footer">
  <br>
  <em>Secure your communications for the quantum age.</em>
</p>
