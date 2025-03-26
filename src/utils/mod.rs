//! # Utility Functions for NeonVault Crypto
//!
//! This module provides utility functions and types used throughout the
//! NeonVault Crypto library, including:
//!
//! - Random number generation
//! - Byte manipulation utilities
//! - Constant-time operations
//! - Benchmarking utilities
//! - Common cryptographic primitives

// Sub-modules
pub mod bytes;
pub mod random;
pub mod constant_time;
pub mod benchmark;

// Re-exports for commonly used utilities
pub use bytes::{to_bytes, from_bytes, ByteConversion};
pub use random::{SecureRandom, fill_random};
pub use constant_time::{ct_eq, ct_ne, ct_select};

/// Safely compare two byte slices in constant time
///
/// This function compares two byte slices without introducing
/// timing side-channels that could leak information about the data.
///
/// # Arguments
///
/// * `a` - First byte slice
/// * `b` - Second byte slice
///
/// # Returns
///
/// `true` if the slices are equal, `false` otherwise
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    constant_time::ct_eq(a, b)
}

/// Encode a byte slice as a hexadecimal string
///
/// This function converts a byte slice to a lowercase hexadecimal string.
///
/// # Arguments
///
/// * `data` - The byte slice to encode
///
/// # Returns
///
/// A hex-encoded string representing the input data
pub fn hex_encode(data: &[u8]) -> String {
    bytes::to_hex(data)
}

/// Decode a hexadecimal string to bytes
///
/// This function converts a hexadecimal string to a byte vector.
///
/// # Arguments
///
/// * `hex` - The hexadecimal string to decode
///
/// # Returns
///
/// A `Result` containing either the decoded bytes or an error
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, crate::Error> {
    bytes::from_hex(hex).map_err(|_| crate::Error::InvalidParameters)
}

/// Combine multiple byte slices into a single vector
///
/// This function concatenates multiple byte slices into a single vector.
///
/// # Arguments
///
/// * `slices` - A slice of byte slices to concatenate
///
/// # Returns
///
/// A new vector containing all input slices concatenated together
pub fn concat_bytes(slices: &[&[u8]]) -> Vec<u8> {
    let total_len = slices.iter().map(|s| s.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    
    for slice in slices {
        result.extend_from_slice(slice);
    }
    
    result
}

/// Split a byte slice into chunks of a specified size
///
/// This function splits a byte slice into chunks of the specified size,
/// with the last chunk potentially being smaller.
///
/// # Arguments
///
/// * `data` - The byte slice to split
/// * `chunk_size` - The size of each chunk
///
/// # Returns
///
/// A vector of byte slices, each of size `chunk_size` (except possibly the last)
pub fn split_bytes(data: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    if chunk_size == 0 {
        return vec![];
    }
    
    let chunks = data.len() / chunk_size + if data.len() % chunk_size > 0 { 1 } else { 0 };
    let mut result = Vec::with_capacity(chunks);
    
    for i in 0..chunks {
        let start = i * chunk_size;
        let end = std::cmp::min(start + chunk_size, data.len());
        result.push(&data[start..end]);
    }
    
    result
}

/// Calculate HMAC-SHA256 of a message using a key
///
/// This function computes the HMAC-SHA256 of a message using the provided key.
///
/// # Arguments
///
/// * `key` - The HMAC key
/// * `message` - The message to authenticate
///
/// # Returns
///
/// A 32-byte HMAC-SHA256 digest
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    use hmac::{Hmac, Mac};
    
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(message);
    
    let result = mac.finalize();
    let bytes = result.into_bytes();
    
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    output
}

/// Derive a key using PBKDF2-HMAC-SHA256
///
/// This function derives a key from a password and salt using PBKDF2 with
/// HMAC-SHA256 as the pseudorandom function.
///
/// # Arguments
///
/// * `password` - The password bytes
/// * `salt` - The salt bytes
/// * `iterations` - The number of iterations
/// * `key_len` - The desired key length in bytes
///
/// # Returns
///
/// A vector containing the derived key
pub fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
) -> Vec<u8> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    
    let mut result = vec![0u8; key_len];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut result);
    result
}

/// Derive multiple keys from a single master key using HKDF
///
/// This function derives multiple keys from a single master key using
/// HKDF with SHA-256.
///
/// # Arguments
///
/// * `master_key` - The master key bytes
/// * `salt` - The salt bytes
/// * `info` - The context info
/// * `key_sizes` - A slice of desired key sizes in bytes
///
/// # Returns
///
/// A vector of derived keys
pub fn hkdf_sha256(
    master_key: &[u8],
    salt: &[u8],
    info: &[u8],
    key_sizes: &[usize],
) -> Vec<Vec<u8>> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master_key);
    
    let mut result = Vec::with_capacity(key_sizes.len());
    
    for &size in key_sizes {
        let mut okm = vec![0u8; size];
        hkdf.expand(info, &mut okm)
            .expect("HKDF expansion failed");
        result.push(okm);
    }
    
    result
}

/// Hash a message using SHA-256
///
/// This function computes the SHA-256 hash of a message.
///
/// # Arguments
///
/// * `message` - The message to hash
///
/// # Returns
///
/// A 32-byte SHA-256 digest
pub fn sha256(message: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(message);
    
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Encrypt using AES-256-GCM with a key and nonce
///
/// This function encrypts a message using AES-256-GCM with the provided key and nonce.
///
/// # Arguments
///
/// * `key` - A 32-byte key
/// * `nonce` - A 12-byte nonce
/// * `plaintext` - The plaintext to encrypt
/// * `associated_data` - Optional associated data for authentication
///
/// # Returns
///
/// A `Result` containing either the ciphertext with authentication tag appended,
/// or an error
pub fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, crate::Error> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    
    if key.len() != 32 {
        return Err(crate::Error::InvalidParameters);
    }
    
    if nonce.len() != 12 {
        return Err(crate::Error::InvalidParameters);
    }
    
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| crate::Error::InternalError)?;
    
    let nonce = Nonce::from_slice(nonce);
    
    let ciphertext = if let Some(aad) = associated_data {
        cipher.encrypt(nonce, aead::Payload { msg: plaintext, aad })
            .map_err(|_| crate::Error::Encryption)?
    } else {
        cipher.encrypt(nonce, plaintext)
            .map_err(|_| crate::Error::Encryption)?
    };
    
    Ok(ciphertext)
}

/// Decrypt using AES-256-GCM with a key and nonce
///
/// This function decrypts a message using AES-256-GCM with the provided key and nonce.
///
/// # Arguments
///
/// * `key` - A 32-byte key
/// * `nonce` - A 12-byte nonce
/// * `ciphertext` - The ciphertext to decrypt (including authentication tag)
/// * `associated_data` - Optional associated data for authentication
///
/// # Returns
///
/// A `Result` containing either the decrypted plaintext, or an error
pub fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, crate::Error> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    
    if key.len() != 32 {
        return Err(crate::Error::InvalidParameters);
    }
    
    if nonce.len() != 12 {
        return Err(crate::Error::InvalidParameters);
    }
    
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| crate::Error::InternalError)?;
    
    let nonce = Nonce::from_slice(nonce);
    
    let plaintext = if let Some(aad) = associated_data {
        cipher.decrypt(nonce, aead::Payload { msg: ciphertext, aad })
            .map_err(|_| crate::Error::AuthenticationFailure)?
    } else {
        cipher.decrypt(nonce, ciphertext)
            .map_err(|_| crate::Error::AuthenticationFailure)?
    };
    
    Ok(plaintext)
}

/// A utility for measuring execution time
pub struct Stopwatch {
    start_time: std::time::Instant,
}

impl Stopwatch {
    /// Create a new stopwatch and start timing
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
        }
    }
    
    /// Get the elapsed time in milliseconds
    pub fn elapsed_ms(&self) -> f64 {
        let duration = self.start_time.elapsed();
        duration.as_secs_f64() * 1000.0
    }
    
    /// Get the elapsed time in microseconds
    pub fn elapsed_us(&self) -> f64 {
        let duration = self.start_time.elapsed();
        duration.as_secs_f64() * 1_000_000.0
    }
    
    /// Reset the stopwatch
    pub fn reset(&mut self) {
        self.start_time = std::time::Instant::now();
    }
}

impl Default for Stopwatch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    /// Test secure comparison
    #[test]
    fn test_secure_compare() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        let c = [1, 2, 3, 4, 6];
        
        assert!(secure_compare(&a, &b));
        assert!(!secure_compare(&a, &c));
        assert!(!secure_compare(&a, &b[..4]));
    }
    
    /// Test hex encoding and decoding
    #[test]
    fn test_hex_codec() {
        let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex = hex_encode(&data);
        
        assert_eq!(hex, "0123456789abcdef");
        
        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, data);
        
        assert!(hex_decode("0123456g").is_err());
    }
    
    /// Test byte concatenation and splitting
    #[test]
    fn test_byte_operations() {
        let a = [1, 2, 3];
        let b = [4, 5];
        let c = [6, 7, 8, 9];
        
        let combined = concat_bytes(&[&a, &b, &c]);
        assert_eq!(combined, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
        
        let chunks = split_bytes(&combined, 3);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], &[1, 2, 3]);
        assert_eq!(chunks[1], &[4, 5, 6]);
        assert_eq!(chunks[2], &[7, 8, 9]);
        
        assert_eq!(split_bytes(&combined, 0), Vec::<&[u8]>::new());
        let big_chunks = split_bytes(&combined, 10);
        assert_eq!(big_chunks.len(), 1);
        assert_eq!(big_chunks[0], &combined);
    }
    
    /// Test cryptographic operations
    #[test]
    fn test_crypto_operations() {
        let message = b"hello, world";
        let hash = sha256(message);
        assert_eq!(hex_encode(&hash), "09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b");
        
        let key = b"secret-key";
        let hmac = hmac_sha256(key, message);
        assert_eq!(hex_encode(&hmac), "7fd04df92f6f52aa3aa4f32b186c49873e2a5521b6c5ea5139eeb3ceeb8a73c5");
        
        let password = b"password";
        let salt = b"salt";
        let derived = pbkdf2_sha256(password, salt, 1000, 32);
        assert_eq!(hex_encode(&derived), "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
        
        let master_key = b"master-key";
        let info = b"context-info";
        let key_sizes = [16, 32];
        let derived_keys = hkdf_sha256(master_key, salt, info, &key_sizes);
        assert_eq!(derived_keys.len(), 2);
        assert_eq!(derived_keys[0].len(), 16);
        assert_eq!(derived_keys[1].len(), 32);
    }
    
    /// Test AES-GCM encryption and decryption
    #[test]
    fn test_aes_gcm() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"secret message";
        let aad = b"additional data";
        
        let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext, Some(aad)).unwrap();
        let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext, Some(aad)).unwrap();
        assert_eq!(decrypted, plaintext);
        
        let wrong_aad = b"wrong data";
        assert!(aes_gcm_decrypt(&key, &nonce, &ciphertext, Some(wrong_aad)).is_err());
        
        let ciphertext_no_aad = aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();
        let decrypted_no_aad = aes_gcm_decrypt(&key, &nonce, &ciphertext_no_aad, None).unwrap();
        assert_eq!(decrypted_no_aad, plaintext);
        
        let short_key = [0u8; 16];
        assert!(aes_gcm_encrypt(&short_key, &nonce, plaintext, None).is_err());
        
        let short_nonce = [0u8; 8];
        assert!(aes_gcm_encrypt(&key, &short_nonce, plaintext, None).is_err());
    }
    
    /// Test the stopwatch utility
    #[test]
    fn test_stopwatch() {
        let mut sw = Stopwatch::new();
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        let elapsed_ms = sw.elapsed_ms();
        assert!(elapsed_ms > 0.0);
        
        sw.reset();
        let new_elapsed = sw.elapsed_ms();
        assert!(new_elapsed < elapsed_ms);
        
        let elapsed_us = sw.elapsed_us();
        assert!(elapsed_us > 0.0);
        assert!(elapsed_us > new_elapsed * 1000.0);
    }
    
    /// Test random number generation
    #[test]
    fn test_random() {
        let mut buf = [0u8; 32];
        fill_random(&mut buf).unwrap();
        assert!(!buf.iter().all(|&b| b == 0));
        
        let mut rng = SecureRandom::new();
        let r1 = rng.next_u32();
        let r2 = rng.next_u32();
        assert_ne!(r1, r2);
    }
}
