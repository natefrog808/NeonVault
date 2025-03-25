//! # NeonVault Crypto
//!
//! A quantum-resistant cryptographic library implementing the CRYSTALS-KYBER
//! post-quantum key encapsulation mechanism as standardized by NIST (FIPS 203).
//!
//! This library provides the cryptographic foundation for the NeonVault secure
//! communication platform, ensuring messages remain confidential even against
//! attacks from future quantum computers.
//!
//! ## Features
//!
//! - **Post-Quantum Security**: Based on the Module Learning With Errors (MLWE) problem,
//!   believed to be resistant to attacks from quantum computers.
//! - **Multiple Security Levels**: Supports KYBER-512, KYBER-768, and KYBER-1024 for
//!   different security/performance trade-offs.
//! - **Hybrid Encryption**: Combines KYBER with symmetric encryption (ChaCha20-Poly1305)
//!   for efficient handling of messages of any size.
//! - **Forward Secrecy**: Implements a simple protocol using KYBER keys (see limitations below).
//! - **Side-Channel Resistance**: Implements constant-time operations where possible
//!   to mitigate timing attacks.
//! - **Memory Security**: Sensitive data is zeroed from memory after use using the `zeroize` crate.
//!
//! ## Basic Usage
//!
//! ```rust
//! use neonvault_crypto::{generate_keypair, encrypt, decrypt};
//!
//! // Generate a key pair with default security level (KYBER-768)
//! let (public_key, private_key) = generate_keypair().unwrap();
//!
//! // Encrypt a message
//! let message = b"Top secret nation-state data";
//! let ciphertext = encrypt(&public_key, message).unwrap();
//!
//! // Decrypt the message
//! let decrypted = decrypt(&private_key, &ciphertext).unwrap();
//! assert_eq!(message, &decrypted[..]);
//! ```
//!
//! ## Advanced Usage
//!
//! ### Custom Security Levels
//!
//! Specify different KYBER security levels for key generation and encryption:
//!
//! ```rust
//! use neonvault_crypto::{
//!     generate_keypair_with_params, encrypt_with_params, decrypt, KYBER_1024
//! };
//!
//! // Generate a key pair with the highest security level
//! let (public_key, private_key) = generate_keypair_with_params(KYBER_1024).unwrap();
//!
//! // Encrypt with the same security level
//! let message = b"Top secret quantum-resistant message";
//! let ciphertext = encrypt_with_params(&public_key, message, KYBER_1024).unwrap();
//!
//! // Decrypt (security level is auto-detected)
//! let decrypted = decrypt(&private_key, &ciphertext).unwrap();
//! assert_eq!(message, &decrypted[..]);
//! ```
//!
//! ### Hybrid Encryption for Large Messages
//!
//! Use hybrid encryption for messages exceeding KYBER's 32-byte limit:
//!
//! ```rust
//! use neonvault_crypto::hybrid;
//!
//! let (public_key, private_key) = generate_keypair().unwrap();
//! let large_message = b"This is a large message that exceeds KYBER's native size limit.";
//! let ciphertext = hybrid::encrypt(&public_key, large_message).unwrap();
//! let decrypted = hybrid::decrypt(&private_key, &ciphertext).unwrap();
//! assert_eq!(large_message, &decrypted[..]);
//! ```
//!
//! ### Forward Secrecy
//!
//! Establish a session with forward secrecy properties (with noted limitations):
//!
//! ```rust
//! use neonvault_crypto::forward_secrecy;
//!
//! let (alice_pk, alice_sk) = generate_keypair().unwrap();
//! let (bob_pk, bob_sk) = generate_keypair().unwrap();
//!
//! // Alice initiates a session with Bob
//! let (alice_session, alice_ephemeral_pk) = forward_secrecy::Session::new(&bob_pk).unwrap();
//!
//! // Alice encrypts a message
//! let message = b"Hello, Bob!";
//! let ciphertext = alice_session.encrypt(message).unwrap();
//!
//! // Bob accepts the session and decrypts
//! let bob_session = forward_secrecy::Session::accept(&bob_sk, &alice_ephemeral_pk, &ciphertext).unwrap();
//! let decrypted = bob_session.decrypt(&ciphertext).unwrap();
//! assert_eq!(message, &decrypted[..]);
//! ```
//!
//! **Note**: The current forward secrecy implementation does not provide true forward secrecy.
//! It encrypts a random message with the recipient's long-term public key, meaning that if the
//! recipient's private key is compromised, past sessions could be decrypted. A proper
//! implementation requires ephemeral-ephemeral key exchange, which will be addressed in
//! future versions.
//!
//! ## Security Considerations
//!
//! - **Security Levels**:
//!   - `KYBER_512`: Fastest, suitable for low-security or performance-critical applications.
//!   - `KYBER_768`: Default, recommended for most use cases with balanced security/performance.
//!   - `KYBER_1024`: Highest security, ideal for highly sensitive data at a performance cost.
//! - **Side-Channel Attacks**: Constant-time operations are used where possible, but users
//!   should secure the execution environment.
//! - **Randomness**: Uses `OsRng` for secure randomness; custom RNGs are supported via
//!   `generate_keypair_with_rng` and `encrypt_with_rng`.
//!
//! ## Performance
//!
//! Higher security levels (e.g., KYBER-1024) require more computation than lower ones (e.g.,
//! KYBER-512). KYBER-768 is the default as it balances security and performance effectively.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![deny(clippy::unwrap_used)]

// Core modules
pub mod kyber;
pub mod utils;

// Re-export main functionality
pub use kyber::{
    generate_keypair, generate_keypair_with_rng, generate_keypair_with_params,
    encrypt, encrypt_with_rng, encrypt_with_params,
    decrypt,
};

// Re-export security level parameters
pub use kyber::{
    KYBER_512, KYBER_768, KYBER_1024, NEONVAULT_SECURITY_LEVEL,
};

/// Library error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Error during key generation
    KeyGeneration,
    /// Error during encryption
    Encryption,
    /// Error during decryption
    Decryption,
    /// Invalid input parameters provided
    InvalidParameters,
    /// Invalid key format or length
    InvalidKey,
    /// Invalid ciphertext format or length
    InvalidCiphertext,
    /// Insufficient secure randomness
    RandomnessFailure,
    /// Authentication failure during decryption
    AuthenticationFailure,
    /// Internal algorithm error
    InternalError,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGeneration => write!(f, "Key generation failed"),
            Self::Encryption => write!(f, "Encryption failed"),
            Self::Decryption => write!(f, "Decryption failed"),
            Self::InvalidParameters => write!(f, "Invalid parameters"),
            Self::InvalidKey => write!(f, "Invalid key format"),
            Self::InvalidCiphertext => write!(f, "Invalid ciphertext format"),
            Self::RandomnessFailure => write!(f, "Failed to generate secure random values"),
            Self::AuthenticationFailure => write!(f, "Authentication failed"),
            Self::InternalError => write!(f, "Internal algorithm error"),
        }
    }
}

impl std::error::Error for Error {}

impl From<kyber::KyberError> for Error {
    fn from(err: kyber::KyberError) -> Self {
        match err {
            kyber::KyberError::KeyGenerationFailed => Self::KeyGeneration,
            kyber::KyberError::EncryptionFailed => Self::Encryption,
            kyber::KyberError::DecryptionFailed => Self::Decryption,
            kyber::KyberError::InvalidParameters => Self::InvalidParameters,
            kyber::KyberError::InvalidLength => Self::InvalidParameters,
            kyber::KyberError::RandomGenerationFailed => Self::RandomnessFailure,
            kyber::KyberError::InternalError => Self::InternalError,
        }
    }
}

/// Library result type alias for convenience
pub type Result<T> = std::result::Result<T, Error>;

/// Library version information
pub mod version {
    /// Current version of the library from Cargo.toml
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");

    /// Get the version string
    pub fn get_version() -> &'static str {
        VERSION
    }

    /// Get the version string with security level information
    pub fn get_version_full() -> String {
        format!(
            "{} (KYBER-{})",
            VERSION,
            match crate::NEONVAULT_SECURITY_LEVEL {
                crate::KYBER_512 => "512",
                crate::KYBER_768 => "768",
                crate::KYBER_1024 => "1024",
                _ => "UNKNOWN",
            }
        )
    }
}

/// High-level functions for key management
pub mod keys {
    use crate::{Error, Result, kyber};

    /// Validate a public key's format and length
    ///
    /// # Arguments
    /// - `public_key`: The public key to validate
    /// - `security_level`: Optional security level (defaults to `NEONVAULT_SECURITY_LEVEL`)
    ///
    /// # Returns
    /// `Ok(())` if valid, `Err(Error::InvalidKey)` or `Err(Error::InvalidParameters)` if not
    pub fn validate_public_key(public_key: &[u8], security_level: Option<u8>) -> Result<()> {
        let level = security_level.unwrap_or(crate::NEONVAULT_SECURITY_LEVEL);
        let expected_len = match level {
            crate::KYBER_512 => kyber::params::KYBER512_PUBLICKEYBYTES,
            crate::KYBER_768 => kyber::params::KYBER768_PUBLICKEYBYTES,
            crate::KYBER_1024 => kyber::params::KYBER1024_PUBLICKEYBYTES,
            _ => return Err(Error::InvalidParameters),
        };

        if public_key.len() != expected_len {
            return Err(Error::InvalidKey);
        }
        Ok(())
    }

    /// Validate a private key's format and length
    ///
    /// # Arguments
    /// - `private_key`: The private key to validate
    /// - `security_level`: Optional security level (defaults to `NEONVAULT_SECURITY_LEVEL`)
    ///
    /// # Returns
    /// `Ok(())` if valid, `Err(Error::InvalidKey)` or `Err(Error::InvalidParameters)` if not
    pub fn validate_private_key(private_key: &[u8], security_level: Option<u8>) -> Result<()> {
        let level = security_level.unwrap_or(crate::NEONVAULT_SECURITY_LEVEL);
        let expected_len = match level {
            crate::KYBER_512 => kyber::params::KYBER512_FULLSECRETKEYBYTES,
            crate::KYBER_768 => kyber::params::KYBER768_FULLSECRETKEYBYTES,
            crate::KYBER_1024 => kyber::params::KYBER1024_FULLSECRETKEYBYTES,
            _ => return Err(Error::InvalidParameters),
        };

        if private_key.len() != expected_len {
            return Err(Error::InvalidKey);
        }
        Ok(())
    }

    /// Extract the public key from a private key
    ///
    /// The private key contains the public key as part of its structure.
    ///
    /// # Arguments
    /// - `private_key`: The private key to extract from
    ///
    /// # Returns
    /// The public key as a `Vec<u8>`, or an error if the private key is invalid
    pub fn extract_public_key(private_key: &[u8]) -> Result<Vec<u8>> {
        let (offset_pk, pk_len) = match private_key.len() {
            kyber::params::KYBER512_FULLSECRETKEYBYTES => (
                kyber::params::KYBER512_K * kyber::params::KYBER_POLYBYTES,
                kyber::params::KYBER512_PUBLICKEYBYTES,
            ),
            kyber::params::KYBER768_FULLSECRETKEYBYTES => (
                kyber::params::KYBER768_K * kyber::params::KYBER_POLYBYTES,
                kyber::params::KYBER768_PUBLICKEYBYTES,
            ),
            kyber::params::KYBER1024_FULLSECRETKEYBYTES => (
                kyber::params::KYBER1024_K * kyber::params::KYBER_POLYBYTES,
                kyber::params::KYBER1024_PUBLICKEYBYTES,
            ),
            _ => return Err(Error::InvalidKey),
        };

        if offset_pk + pk_len <= private_key.len() {
            Ok(private_key[offset_pk..offset_pk + pk_len].to_vec())
        } else {
            Err(Error::InvalidKey)
        }
    }
}

/// Hybrid encryption utilities combining KYBER with symmetric encryption
pub mod hybrid {
    use crate::{Error, Result};
    use chacha20poly1305::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        ChaCha20Poly1305, Nonce,
    };
    use sha3::{Digest, Sha3_256};
    use zeroize::Zeroize;

    /// Encrypt a message using hybrid encryption
    ///
    /// Combines KYBER encapsulation with ChaCha20-Poly1305 symmetric encryption.
    ///
    /// # Arguments
    /// - `public_key`: Recipient's public key
    /// - `message`: Plaintext message of any size
    ///
    /// # Returns
    /// Ciphertext in the format: `[kyber_len (4 bytes) || kyber_ciphertext || nonce || encrypted_message]`
    pub fn encrypt(public_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let mut kyber_plaintext = [0u8; 32];
        OsRng.fill_bytes(&mut kyber_plaintext);

        let kyber_ciphertext = crate::encrypt(public_key, &kyber_plaintext)
            .map_err(|_| Error::Encryption)?;

        let mut symmetric_key = derive_key(&kyber_plaintext);
        let cipher = ChaCha20Poly1305::new(symmetric_key.as_ref().into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let encrypted_message = cipher
            .encrypt(&nonce, message)
            .map_err(|_| Error::Encryption)?;

        let mut result = Vec::with_capacity(4 + kyber_ciphertext.len() + nonce.len() + encrypted_message.len());
        result.extend_from_slice(&(kyber_ciphertext.len() as u32).to_be_bytes());
        result.extend_from_slice(&kyber_ciphertext);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&encrypted_message);

        kyber_plaintext.zeroize();
        symmetric_key.zeroize();

        Ok(result)
    }

    /// Decrypt a hybrid-encrypted message
    ///
    /// # Arguments
    /// - `private_key`: Recipient's private key
    /// - `ciphertext`: Encrypted message from `encrypt`
    ///
    /// # Returns
    /// Decrypted plaintext, or an error if decryption fails
    pub fn decrypt(private_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 4 {
            return Err(Error::InvalidCiphertext);
        }

        let kyber_len = u32::from_be_bytes(ciphertext[0..4].try_into().unwrap()) as usize;
        if ciphertext.len() < 4 + kyber_len + 12 {
            return Err(Error::InvalidCiphertext);
        }

        let kyber_ciphertext = &ciphertext[4..4 + kyber_len];
        let nonce = Nonce::from_slice(&ciphertext[4 + kyber_len..4 + kyber_len + 12]);
        let encrypted_message = &ciphertext[4 + kyber_len + 12..];

        let kyber_plaintext = crate::decrypt(private_key, kyber_ciphertext)
            .map_err(|_| Error::Decryption)?;

        let mut symmetric_key = derive_key(&kyber_plaintext);
        let cipher = ChaCha20Poly1305::new(symmetric_key.as_ref().into());

        let plaintext = cipher
            .decrypt(nonce, encrypted_message)
            .map_err(|_| Error::AuthenticationFailure)?;

        symmetric_key.zeroize();

        Ok(plaintext)
    }

    /// Derive a 32-byte symmetric key from KYBER plaintext
    fn derive_key(kyber_plaintext: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(kyber_plaintext);
        hasher.update(b"NeonVault-Hybrid-Encryption-Key");
        let mut key = [0u8; 32];
        key.copy_from_slice(&hasher.finalize());
        key
    }
}

/// Forward secrecy protocol implementation
pub mod forward_secrecy {
    use crate::{Error, Result};
    use zeroize::Zeroize;

    /// A session for forward-secure communication
    #[derive(Debug)]
    pub struct Session {
        recipient_pk: Vec<u8>,
        ephemeral_sk: Vec<u8>,
        shared_secret: [u8; 32],
    }

    impl Drop for Session {
        fn drop(&mut self) {
            self.ephemeral_sk.zeroize();
            self.shared_secret.zeroize();
        }
    }

    impl Session {
        /// Initiate a new session with a recipient
        ///
        /// # Arguments
        /// - `recipient_pk`: Recipient's public key
        ///
        /// # Returns
        /// Tuple of `(Session, ephemeral_public_key)` to send to the recipient
        pub fn new(recipient_pk: &[u8]) -> Result<(Self, Vec<u8>)> {
            let (ephemeral_pk, ephemeral_sk) = crate::generate_keypair()
                .map_err(|_| Error::KeyGeneration)?;

            let mut message = [0u8; 32];
            crate::utils::random::fill_random(&mut message)
                .map_err(|_| Error::RandomnessFailure)?;

            let _ = crate::encrypt(recipient_pk, &message)
                .map_err(|_| Error::Encryption)?;

            let session = Self {
                recipient_pk: recipient_pk.to_vec(),
                ephemeral_sk,
                shared_secret: message,
            };

            Ok((session, ephemeral_pk))
        }

        /// Accept an incoming session
        ///
        /// # Arguments
        /// - `our_sk`: Our private key
        /// - `sender_ephemeral_pk`: Sender's ephemeral public key
        /// - `ciphertext`: Encrypted message from sender
        ///
        /// # Returns
        /// A new `Session` object
        pub fn accept(our_sk: &[u8], sender_ephemeral_pk: &[u8], ciphertext: &[u8]) -> Result<Self> {
            let message = crate::decrypt(our_sk, ciphertext)
                .map_err(|_| Error::Decryption)?;

            if message.len() != 32 {
                return Err(Error::InvalidParameters);
            }

            let mut shared_secret = [0u8; 32];
            shared_secret.copy_from_slice(&message);

            Ok(Self {
                recipient_pk: sender_ephemeral_pk.to_vec(),
                ephemeral_sk: our_sk.to_vec(),
                shared_secret,
            })
        }

        /// Encrypt a message using the session
        pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
            crate::hybrid::encrypt(&self.recipient_pk, message)
        }

        /// Decrypt a message using the session
        pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
            crate::hybrid::decrypt(&self.ephemeral_sk, ciphertext)
        }

        /// Get the session's shared secret
        pub fn shared_secret(&self) -> [u8; 32] {
            self.shared_secret
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        let (public_key, private_key) = generate_keypair().unwrap();
        let message = b"Top secret nation-state data";
        let ciphertext = encrypt(&public_key, message).unwrap();
        let decrypted = decrypt(&private_key, &ciphertext).unwrap();
        assert_eq!(message, decrypted.as_slice());
    }

    #[test]
    fn test_key_validation() {
        let (public_key, private_key) = generate_keypair().unwrap();
        assert!(keys::validate_public_key(&public_key, None).is_ok());
        assert!(keys::validate_private_key(&private_key, None).is_ok());

        let invalid_pk = vec![0u8; 10];
        let invalid_sk = vec![0u8; 10];
        assert!(keys::validate_public_key(&invalid_pk, None).is_err());
        assert!(keys::validate_private_key(&invalid_sk, None).is_err());
    }

    #[test]
    fn test_extract_public_key() {
        let (public_key, private_key) = generate_keypair().unwrap();
        let extracted_pk = keys::extract_public_key(&private_key).unwrap();
        assert_eq!(public_key, extracted_pk);
    }

    #[test]
    fn test_hybrid_encryption() {
        let (public_key, private_key) = generate_keypair().unwrap();
        let message = b"This is a longer message for hybrid encryption.";
        let ciphertext = hybrid::encrypt(&public_key, message).unwrap();
        let decrypted = hybrid::decrypt(&private_key, &ciphertext).unwrap();
        assert_eq!(message, decrypted.as_slice());
    }

    #[test]
    fn test_forward_secrecy() {
        let (alice_pk, alice_sk) = generate_keypair().unwrap();
        let (bob_pk, bob_sk) = generate_keypair().unwrap();

        let (alice_session, alice_ephemeral_pk) = forward_secrecy::Session::new(&bob_pk).unwrap();
        let message = b"Hello, Bob!";
        let ciphertext = alice_session.encrypt(message).unwrap();

        let bob_session = forward_secrecy::Session::accept(&bob_sk, &alice_ephemeral_pk, &ciphertext).unwrap();
        let decrypted = bob_session.decrypt(&ciphertext).unwrap();
        assert_eq!(message, decrypted.as_slice());
    }

    #[test]
    fn test_security_levels() {
        for &level in &[KYBER_512, KYBER_768, KYBER_1024] {
            let (pk, sk) = generate_keypair_with_params(level).unwrap();
            let message = b"Test message";
            let ct = encrypt_with_params(&pk, message, level).unwrap();
            let pt = decrypt(&sk, &ct).unwrap();
            assert_eq!(message, pt.as_slice());
        }
    }

    #[test]
    fn test_version() {
        let v = version::get_version();
        assert!(!v.is_empty());
        let v_full = version::get_version_full();
        assert!(!v_full.is_empty());
        assert!(v_full.contains(v));
    }
}
