//! # CRYSTALS-KYBER Implementation
//!
//! This module provides an implementation of the CRYSTALS-KYBER post-quantum key
//! encapsulation mechanism as standardized by NIST (FIPS 203).
//!
//! CRYSTALS-KYBER is a lattice-based key encapsulation mechanism (KEM) that is
//! believed to be secure against attacks from both classical and quantum computers.
//! It is based on the hardness of the Module Learning With Errors (MLWE) problem.
//!
//! ## Security Levels
//!
//! The implementation supports three security levels:
//!
//! - **Kyber-512**: Roughly equivalent to AES-128 security level (NIST Level 1)
//! - **Kyber-768**: Roughly equivalent to AES-192 security level (NIST Level 3)
//! - **Kyber-1024**: Roughly equivalent to AES-256 security level (NIST Level 5)
//!
//! By default, NeonVault uses Kyber-768 for a good balance of security and performance.
//!
//! ## Usage
//!
//! ```rust
//! use neonvault_crypto::{generate_keypair, encrypt, decrypt};
//!
//! // Generate a new key pair
//! let (public_key, private_key) = generate_keypair().unwrap();
//!
//! // Encrypt a message
//! let message = b"Secret message";
//! let ciphertext = encrypt(&public_key, message).unwrap();
//!
//! // Decrypt the message
//! let decrypted = decrypt(&private_key, &ciphertext).unwrap();
//! assert_eq!(message, &decrypted[..]);
//! ```
//!
//! ## Security Considerations
//!
//! - **Random Number Generation**: The default functions (`generate_keypair` and `encrypt`)
//!   use a secure random number generator. When using the `_with_rng` variants, ensure the
//!   provided RNG is cryptographically secure.
//! - **Key Handling**: Private keys must be kept secret and handled securely. Public keys
//!   can be shared openly.
//! - **Message Size**: The public-key encryption (PKE) scheme implemented here encrypts
//!   messages up to 32 bytes. Longer messages are truncated. For larger messages, consider
//!   a hybrid encryption scheme using KYBER KEM to establish a shared secret for symmetric
//!   encryption.
//! - **Thread Safety**: All functions are thread-safe as they do not share mutable state.

// Internal module structure
mod key_gen;
mod encrypt;
mod decrypt;
mod params;
mod polynomial;
mod ntt;
mod indcpa;
mod cbd;

// Public re-exports for the main module API
pub use key_gen::generate as generate_keypair;
pub use key_gen::generate_with_rng as generate_keypair_with_rng;
pub use encrypt::encrypt;
pub use encrypt::encrypt_with_rng;
pub use decrypt::decrypt;

// Public re-exports of main security parameters
pub use params::{
    KYBER512_K, KYBER768_K, KYBER1024_K,
    KYBER_512, KYBER_768, KYBER_1024,
    N, Q,
};

/// Current default security level for the NeonVault application
pub const NEONVAULT_SECURITY_LEVEL: u8 = KYBER_768;

// Internal module re-exports for use between submodules
#[doc(hidden)]
pub(crate) use params::{
    KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, KYBER_CIPHERTEXTBYTES,
    KYBER_INDCPA_MSGBYTES, KYBER_SYMBYTES, KYBER_POLYBYTES, 
    KYBER_POLYVECBYTES, KYBER_ETA1, KYBER_ETA2,
};

#[doc(hidden)]
pub(crate) use polynomial::{Poly, PolyVec};

#[doc(hidden)]
pub(crate) use ntt::{ntt, invntt, basemul};

#[doc(hidden)]
pub(crate) use cbd::{poly_cbd_eta1, poly_cbd_eta2};

#[doc(hidden)]
pub(crate) use indcpa::{indcpa_keypair, indcpa_enc, indcpa_dec};

// Custom error type for KYBER operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KyberError {
    /// Failed to generate a key pair
    KeyGenerationFailed,
    
    /// Failed to encrypt a message
    EncryptionFailed,
    
    /// Failed to decrypt a message
    DecryptionFailed,
    
    /// Invalid parameters were provided
    InvalidParameters,
    
    /// Input data had an invalid length
    InvalidLength,
    
    /// Failure in random number generation
    RandomGenerationFailed,
    
    /// Internal algorithm error
    InternalError,
}

impl std::fmt::Display for KyberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGenerationFailed => write!(f, "Failed to generate KYBER key pair"),
            Self::EncryptionFailed => write!(f, "Failed to encrypt message with KYBER"),
            Self::DecryptionFailed => write!(f, "Failed to decrypt KYBER ciphertext"),
            Self::InvalidParameters => write!(f, "Invalid KYBER parameters"),
            Self::InvalidLength => write!(f, "Input data has invalid length"),
            Self::RandomGenerationFailed => write!(f, "Failed to generate secure random numbers"),
            Self::InternalError => write!(f, "Internal KYBER algorithm error"),
        }
    }
}

impl std::error::Error for KyberError {}

/// Result type for KYBER operations
pub type Result<T> = std::result::Result<T, KyberError>;

// Public API functions with detailed documentation

/// Generate a new KYBER key pair
///
/// Generates a public-private key pair for the KYBER post-quantum public-key encryption
/// scheme using a secure random number generator. The current implementation uses
/// Kyber-768 as the default security level.
///
/// # Returns
/// A tuple containing the public key and private key as byte vectors, or an error if
/// key generation fails.
///
/// # Examples
/// ```rust
/// let (pk, sk) = neonvault_crypto::generate_keypair().unwrap();
/// assert_eq!(pk.len(), neonvault_crypto::KYBER_PUBLICKEYBYTES);
/// assert_eq!(sk.len(), neonvault_crypto::KYBER_SECRETKEYBYTES);
/// ```
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    generate_keypair()
}

/// Generate a new KYBER key pair with a custom RNG
///
/// Similar to `generate_keypair`, but allows specifying a custom random number generator.
/// This is useful for deterministic testing or specific use cases requiring a non-default RNG.
///
/// # Parameters
/// - `rng`: A mutable reference to a type implementing `rand::Rng` and `rand::CryptoRng`.
///
/// # Returns
/// A tuple containing the public key and private key as byte vectors, or an error if
/// key generation fails.
pub fn generate_keypair_with_rng<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
    generate_keypair_with_rng(rng)
}

/// Encrypt a message using KYBER
///
/// Encrypts a message using the provided public key with the KYBER post-quantum
/// public-key encryption scheme. Messages are limited to 32 bytes; longer messages
/// are truncated.
///
/// # Parameters
/// - `public_key`: The recipient's public key as a byte slice.
/// - `message`: The message to encrypt (up to 32 bytes).
///
/// # Returns
/// The encrypted ciphertext as a byte vector, or an error if encryption fails.
///
/// # Examples
/// ```rust
/// let (pk, sk) = neonvault_crypto::generate_keypair().unwrap();
/// let msg = b"Hello, KYBER!";
/// let ct = neonvault_crypto::encrypt(&pk, msg).unwrap();
/// ```
pub fn encrypt(public_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    encrypt(public_key, message)
}

/// Encrypt a message using KYBER with a custom RNG
///
/// Similar to `encrypt`, but allows specifying a custom random number generator.
///
/// # Parameters
/// - `public_key`: The recipient's public key as a byte slice.
/// - `message`: The message to encrypt (up to 32 bytes).
/// - `rng`: A mutable reference to a type implementing `rand::Rng` and `rand::CryptoRng`.
///
/// # Returns
/// The encrypted ciphertext as a byte vector, or an error if encryption fails.
pub fn encrypt_with_rng<R: rand::Rng + rand::CryptoRng>(public_key: &[u8], message: &[u8], rng: &mut R) -> Result<Vec<u8>> {
    encrypt_with_rng(public_key, message, rng)
}

/// Decrypt a ciphertext using KYBER
///
/// Decrypts a ciphertext using the provided private key with the KYBER post-quantum
/// public-key encryption scheme.
///
/// # Parameters
/// - `private_key`: The recipient's private key as a byte slice.
/// - `ciphertext`: The encrypted message as a byte slice.
///
/// # Returns
/// The decrypted message as a byte vector, or an error if decryption fails.
///
/// # Examples
/// ```rust
/// let (pk, sk) = neonvault_crypto::generate_keypair().unwrap();
/// let msg = b"Hello, KYBER!";
/// let ct = neonvault_crypto::encrypt(&pk, msg).unwrap();
/// let decrypted = neonvault_crypto::decrypt(&sk, &ct).unwrap();
/// assert_eq!(msg, decrypted.as_slice());
/// ```
pub fn decrypt(private_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    decrypt(private_key, ciphertext)
}

// Public validation functions

/// Validate a public key
///
/// Checks if the provided public key has the correct length for the current security level
/// (Kyber-768).
///
/// # Parameters
/// - `pk`: The public key to validate as a byte slice.
///
/// # Returns
/// `Ok(())` if the length is correct, or an error if invalid.
///
/// # Examples
/// ```rust
/// let (pk, _) = neonvault_crypto::generate_keypair().unwrap();
/// assert!(neonvault_crypto::validate_public_key(&pk).is_ok());
/// ```
pub fn validate_public_key(pk: &[u8]) -> Result<()> {
    if pk.len() != KYBER_PUBLICKEYBYTES {
        Err(KyberError::InvalidLength)
    } else {
        Ok(())
    }
}

/// Validate a private key
///
/// Checks if the provided private key has the correct length for the current security level
/// (Kyber-768).
///
/// # Parameters
/// - `sk`: The private key to validate as a byte slice.
///
/// # Returns
/// `Ok(())` if the length is correct, or an error if invalid.
pub fn validate_private_key(sk: &[u8]) -> Result<()> {
    if sk.len() != KYBER_SECRETKEYBYTES {
        Err(KyberError::InvalidLength)
    } else {
        Ok(())
    }
}

/// Validate a ciphertext
///
/// Checks if the provided ciphertext has the correct length for the current security level
/// (Kyber-768).
///
/// # Parameters
/// - `ct`: The ciphertext to validate as a byte slice.
///
/// # Returns
/// `Ok(())` if the length is correct, or an error if invalid.
pub fn validate_ciphertext(ct: &[u8]) -> Result<()> {
    if ct.len() != KYBER_CIPHERTEXTBYTES {
        Err(KyberError::InvalidLength)
    } else {
        Ok(())
    }
}

// Internal helper functions (kept from the original)
#[inline]
pub(crate) fn validate_public_key_internal(pk: &[u8]) -> Result<()> {
    if pk.len() != KYBER_PUBLICKEYBYTES {
        return Err(KyberError::InvalidLength);
    }
    Ok(())
}

#[inline]
pub(crate) fn validate_private_key_internal(sk: &[u8]) -> Result<()> {
    if sk.len() != KYBER_SECRETKEYBYTES {
        return Err(KyberError::InvalidLength);
    }
    Ok(())
}

#[inline]
pub(crate) fn validate_ciphertext_internal(ct: &[u8]) -> Result<()> {
    if ct.len() != KYBER_CIPHERTEXTBYTES {
        return Err(KyberError::InvalidLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt_cycle() {
        let (public_key, private_key) = generate_keypair().unwrap();
        assert_eq!(public_key.len(), KYBER_PUBLICKEYBYTES);
        assert_eq!(private_key.len(), KYBER_SECRETKEYBYTES);
        
        // Small message
        let message = b"Top secret nation-state data";
        let ciphertext = encrypt(&public_key, message).unwrap();
        let decrypted = decrypt(&private_key, &ciphertext).unwrap();
        assert_eq!(message, decrypted.as_slice());
        
        // Empty message
        let empty_message = b"";
        let empty_ciphertext = encrypt(&public_key, empty_message).unwrap();
        let empty_decrypted = decrypt(&private_key, &empty_ciphertext).unwrap();
        assert_eq!(empty_message, empty_decrypted.as_slice());
        
        // Maximum sized message
        let max_message = vec![0xAA; KYBER_INDCPA_MSGBYTES];
        let max_ciphertext = encrypt(&public_key, &max_message).unwrap();
        let max_decrypted = decrypt(&private_key, &max_ciphertext).unwrap();
        assert_eq!(max_message, max_decrypted);
    }
    
    #[test]
    fn test_invalid_keys_and_ciphertexts() {
        let (valid_pk, valid_sk) = generate_keypair().unwrap();
        let message = b"Test message";
        let valid_ct = encrypt(&valid_pk, message).unwrap();
        
        // Truncated public key
        let truncated_pk = &valid_pk[..valid_pk.len() - 1];
        let result = encrypt(truncated_pk, message);
        assert!(matches!(result, Err(KyberError::InvalidLength)));
        
        // Extended public key
        let mut extended_pk = valid_pk.clone();
        extended_pk.push(0);
        let result = encrypt(&extended_pk, message);
        assert!(matches!(result, Err(KyberError::InvalidLength)));
        
        // Truncated private key
        let truncated_sk = &valid_sk[..valid_sk.len() - 1];
        let result = decrypt(truncated_sk, &valid_ct);
        assert!(matches!(result, Err(KyberError::InvalidLength)));
        
        // Extended private key
        let mut extended_sk = valid_sk.clone();
        extended_sk.push(0);
        let result = decrypt(&extended_sk, &valid_ct);
        assert!(matches!(result, Err(KyberError::InvalidLength)));
        
        // Truncated ciphertext
        let truncated_ct = &valid_ct[..valid_ct.len() - 1];
        let result = decrypt(&valid_sk, truncated_ct);
        assert!(matches!(result, Err(KyberError::InvalidLength)));
        
        // Extended ciphertext
        let mut extended_ct = valid_ct.clone();
        extended_ct.push(0);
        let result = decrypt(&valid_sk, &extended_ct);
        assert!(matches!(result, Err(KyberError::InvalidLength)));
    }
    
    #[test]
    fn test_different_keys() {
        let (pk1, sk1) = generate_keypair().unwrap();
        let (pk2, sk2) = generate_keypair().unwrap();
        
        assert_ne!(pk1, pk2);
        assert_ne!(sk1, sk2);
        
        let message = b"Secret message";
        let ct1 = encrypt(&pk1, message).unwrap();
        
        let decrypted = decrypt(&sk1, &ct1).unwrap();
        assert_eq!(message, decrypted.as_slice());
        
        let decrypted2 = decrypt(&sk2, &ct1).unwrap();
        assert_ne!(message, decrypted2.as_slice());
    }
    
    #[test]
    fn test_validation_functions() {
        let (pk, sk) = generate_keypair().unwrap();
        let message = b"Test";
        let ct = encrypt(&pk, message).unwrap();
        
        // Valid inputs
        assert!(validate_public_key(&pk).is_ok());
        assert!(validate_private_key(&sk).is_ok());
        assert!(validate_ciphertext(&ct).is_ok());
        
        // Invalid public key lengths
        let short_pk = &pk[..pk.len() - 1];
        let long_pk = [&pk, &[0]].concat();
        assert!(validate_public_key(short_pk).is_err());
        assert!(validate_public_key(&long_pk).is_err());
        
        // Invalid private key lengths
        let short_sk = &sk[..sk.len() - 1];
        let long_sk = [&sk, &[0]].concat();
        assert!(validate_private_key(short_sk).is_err());
        assert!(validate_private_key(&long_sk).is_err());
        
        // Invalid ciphertext lengths
        let short_ct = &ct[..ct.len() - 1];
        let long_ct = [&ct, &[0]].concat();
        assert!(validate_ciphertext(short_ct).is_err());
        assert!(validate_ciphertext(&long_ct).is_err());
    }
}
