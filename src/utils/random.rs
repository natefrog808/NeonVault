//! # Secure Random Number Generation
//!
//! This module provides utilities for generating cryptographically secure
//! random numbers and bytes for use in cryptographic operations.
//!
//! It includes:
//! - A secure random number generator that uses the system's entropy source
//! - Functions for generating random bytes, integers, and other values
//! - Deterministic random number generation for testing purposes

use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroize;
use std::cell::RefCell;
use std::sync::{Mutex, Once};
use std::ops::{Deref, DerefMut};

/// Error type for random number generation operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomError {
    /// System entropy source is unavailable
    EntropySourceUnavailable,
    /// Failed to generate random data
    GenerationFailed,
    /// Random number generator is not properly initialized
    NotInitialized,
    /// Requested operation is not supported
    UnsupportedOperation,
}

impl std::fmt::Display for RandomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EntropySourceUnavailable => write!(f, "Entropy source unavailable"),
            Self::GenerationFailed => write!(f, "Failed to generate random data"),
            Self::NotInitialized => write!(f, "Random number generator not initialized"),
            Self::UnsupportedOperation => write!(f, "Operation not supported"),
        }
    }
}

impl std::error::Error for RandomError {}

/// Result type for random number generation operations
pub type Result<T> = std::result::Result<T, RandomError>;

//------------------------------------------------------------------------------
// Secure Random Number Generator
//------------------------------------------------------------------------------

/// A cryptographically secure random number generator
///
/// This type provides a wrapper around the system's secure random number
/// generator with additional safeguards and functionality. It uses the
/// ChaCha20 algorithm, which is widely considered secure for cryptographic use.
///
/// # Example
///
/// ```rust
/// use neonvault_crypto::utils::random::SecureRandom;
/// use rand::RngCore;
///
/// let mut rng = SecureRandom::new();
///
/// // Generate a random u32
/// let value = rng.next_u32();
///
/// // Fill a buffer with random bytes
/// let mut buffer = [0u8; 32];
/// rng.fill_bytes(&mut buffer);
/// ```
pub struct SecureRandom {
    inner: ChaCha20Rng,
}

// Global PRNG instance for the default generator
// We use thread-local storage for better performance
thread_local! {
    static THREAD_RNG: RefCell<Option<SecureRandom>> = RefCell::new(None);
}

// Mutex for global RNG that can be used when thread-local storage isn't available
lazy_static::lazy_static! {
    static ref GLOBAL_RNG: Mutex<Option<SecureRandom>> = Mutex::new(None);
    static ref FORCE_RESEED: Mutex<bool> = Mutex::new(false);
}

// Initialization tracking
static INIT: Once = Once::new();
static mut IS_INITIALIZED: bool = false;

impl SecureRandom {
    /// Create a new instance of the secure random number generator
    ///
    /// This function creates a new PRNG instance seeded from the system's entropy source.
    pub fn new() -> Self {
        initialize();
        let seed = generate_seed().expect("Failed to generate random seed");
        Self {
            inner: ChaCha20Rng::from_seed(seed),
        }
    }

    /// Create a new instance with a specific seed
    ///
    /// This function creates a deterministic PRNG instance with the given seed.
    /// Useful for testing, but should never be used in production cryptographic operations.
    ///
    /// # Warning
    ///
    /// Using a fixed seed makes the output predictable and insecure for cryptographic purposes.
    /// Only use this for testing.
    ///
    /// # Example
    ///
    /// ```rust
    /// use neonvault_crypto::utils::random::SecureRandom;
    /// use rand::RngCore;
    ///
    /// let seed = [0u8; 32];
    /// let mut rng1 = SecureRandom::from_seed(seed);
    /// let mut rng2 = SecureRandom::from_seed(seed);
    /// assert_eq!(rng1.next_u32(), rng2.next_u32());
    /// ```
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: ChaCha20Rng::from_seed(seed),
        }
    }

    /// Reseed the PRNG with fresh entropy from the system
    pub fn reseed(&mut self) -> Result<()> {
        let seed = generate_seed()?;
        self.inner = ChaCha20Rng::from_seed(seed);
        Ok(())
    }

    /// Generate a random value within a range [0, n)
    pub fn gen_range_u32(&mut self, n: u32) -> u32 {
        use rand::Rng;
        self.inner.gen_range(0..n)
    }

    /// Generate a random value within a range [0, n)
    pub fn gen_range_u64(&mut self, n: u64) -> u64 {
        use rand::Rng;
        self.inner.gen_range(0..n)
    }

    /// Generate a random boolean with a given probability of being true
    pub fn gen_bool(&mut self, probability: f64) -> bool {
        use rand::Rng;
        self.inner.gen_bool(probability)
    }

    /// Fill a buffer with random bytes
    pub fn fill(&mut self, buf: &mut [u8]) {
        self.fill_bytes(buf);
    }

    /// Generate a random u32 value
    pub fn gen_u32(&mut self) -> u32 {
        self.next_u32()
    }

    /// Generate a random u64 value
    pub fn gen_u64(&mut self) -> u64 {
        self.next_u64()
    }

    /// Generate a vector of random bytes
    pub fn gen_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        self.fill_bytes(&mut buf);
        buf
    }
}

impl RngCore for SecureRandom {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
        self.inner.try_fill_bytes(dest)
    }
}

impl CryptoRng for SecureRandom {}

impl Default for SecureRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecureRandom {
    fn drop(&mut self) {
        // Note: ChaCha20Rng does not implement Zeroize yet, so this is a no-op for now
    }
}

//------------------------------------------------------------------------------
// Global Functions
//------------------------------------------------------------------------------

/// Initialize the random number generator system
pub fn initialize() {
    INIT.call_once(|| {
        match ChaCha20Rng::from_entropy() {
            Ok(inner) => {
                let mut global = GLOBAL_RNG.lock().unwrap();
                *global = Some(SecureRandom { inner });
                unsafe { IS_INITIALIZED = true; }
            }
            Err(_) => {
                unsafe { IS_INITIALIZED = false; }
            }
        }
    });
}

/// Check if the random number generator system is initialized
pub fn is_initialized() -> bool {
    unsafe { IS_INITIALIZED }
}

/// Get the thread-local RNG, initializing it if necessary
fn get_thread_rng() -> Result<impl Deref<Target = SecureRandom> + '_> {
    initialize();
    THREAD_RNG.with(|rng| {
        let mut rng_ref = rng.borrow_mut();
        if rng_ref.is_none() {
            *rng_ref = Some(SecureRandom::new());
        }
        let force_reseed = FORCE_RESEED.lock().unwrap();
        if *force_reseed {
            if let Some(ref mut rng) = *rng_ref {
                rng.reseed().ok();
            }
        }
        struct RngRef<'a>(std::cell::RefMut<'a, Option<SecureRandom>>);
        impl<'a> Deref for RngRef<'a> {
            type Target = SecureRandom;
            fn deref(&self) -> &Self::Target {
                self.0.as_ref().unwrap()
            }
        }
        Ok(RngRef(rng_ref))
    })
}

/// Get a mutable reference to the thread-local RNG
fn get_thread_rng_mut() -> Result<impl DerefMut<Target = SecureRandom> + '_> {
    initialize();
    THREAD_RNG.with(|rng| {
        let mut rng_ref = rng.borrow_mut();
        if rng_ref.is_none() {
            *rng_ref = Some(SecureRandom::new());
        }
        struct RngRefMut<'a>(std::cell::RefMut<'a, Option<SecureRandom>>);
        impl<'a> Deref for RngRefMut<'a> {
            type Target = SecureRandom;
            fn deref(&self) -> &Self::Target {
                self.0.as_ref().unwrap()
            }
        }
        impl<'a> DerefMut for RngRefMut<'a> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                self.0.as_mut().unwrap()
            }
        }
        Ok(RngRefMut(rng_ref))
    })
}

/// Generate a random seed for an RNG
fn generate_seed() -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    let result = THREAD_RNG.with(|rng| {
        let rng_ref = rng.borrow();
        if let Some(ref rng) = *rng_ref {
            let mut seed_copy = [0u8; 32];
            rng.inner.fill_bytes(&mut seed_copy);
            seed_copy
        } else {
            let global = GLOBAL_RNG.lock().unwrap();
            match *global {
                Some(ref g) => {
                    let mut seed_copy = [0u8; 32];
                    g.inner.clone().fill_bytes(&mut seed_copy);
                    seed_copy
                }
                None => match rand::rngs::OsRng.try_fill_bytes(&mut seed) {
                    Ok(()) => seed,
                    Err(_) => [0u8; 32],
                },
            }
        }
    });
    if result == [0u8; 32] {
        return Err(RandomError::EntropySourceUnavailable);
    }
    seed.copy_from_slice(&result);
    Ok(seed)
}

/// Force all thread-local RNGs to reseed on next use
pub fn force_reseed() {
    let mut force_reseed = FORCE_RESEED.lock().unwrap();
    *force_reseed = true;
}

/// Fill a buffer with random bytes
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    let mut rng = get_thread_rng_mut()?;
    rng.fill_bytes(buf);
    Ok(())
}

/// Generate a random u32 value
pub fn random_u32() -> Result<u32> {
    let mut rng = get_thread_rng_mut()?;
    Ok(rng.next_u32())
}

/// Generate a random u64 value
pub fn random_u64() -> Result<u64> {
    let mut rng = get_thread_rng_mut()?;
    Ok(rng.next_u64())
}

/// Generate a random value within a range [0, n)
pub fn random_range(n: u32) -> Result<u32> {
    let mut rng = get_thread_rng_mut()?;
    Ok(rng.gen_range_u32(n))
}

/// Generate a vector of random bytes
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut rng = get_thread_rng_mut()?;
    Ok(rng.gen_bytes(len))
}

/// Generate a random boolean with a given probability of being true
pub fn random_bool(probability: f64) -> Result<bool> {
    let mut rng = get_thread_rng_mut()?;
    Ok(rng.gen_bool(probability))
}

/// Generate a cryptographically secure random nonce
pub fn generate_nonce(len: usize) -> Result<Vec<u8>> {
    random_bytes(len)
}

/// Generate a cryptographically secure random key
pub fn generate_key(len: usize) -> Result<Vec<u8>> {
    random_bytes(len)
}

/// Shuffle a slice in place using the Fisher-Yates algorithm
pub fn shuffle<T>(slice: &mut [T]) -> Result<()> {
    let mut rng = get_thread_rng_mut()?;
    for i in (1..slice.len()).rev() {
        let j = rng.gen_range_u32((i + 1) as u32) as usize;
        slice.swap(i, j);
    }
    Ok(())
}

/// Generate a random index into a slice
pub fn random_index<T>(slice: &[T]) -> Result<usize> {
    if slice.is_empty() {
        return Err(RandomError::UnsupportedOperation);
    }
    let mut rng = get_thread_rng_mut()?;
    Ok(rng.gen_range_u32(slice.len() as u32) as usize)
}

/// Choose a random element from a slice
pub fn random_choice<T: Copy>(slice: &[T]) -> Result<T> {
    if slice.is_empty() {
        return Err(RandomError::UnsupportedOperation);
    }
    let index = random_index(slice)?;
    Ok(slice[index])
}

/// Sample k elements from a slice without replacement
pub fn random_sample<T: Copy>(slice: &[T], k: usize) -> Result<Vec<T>> {
    if slice.is_empty() || k > slice.len() {
        return Err(RandomError::UnsupportedOperation);
    }
    if k == 0 {
        return Ok(Vec::new());
    }
    let mut copy = slice.to_vec();
    shuffle(&mut copy)?;
    Ok(copy[..k].to_vec())
}

//------------------------------------------------------------------------------
// Helper Functions
//------------------------------------------------------------------------------

/// Create a deterministic RNG for testing purposes
///
/// # Warning
///
/// This function is intended only for testing and should not be used in production.
pub fn create_test_rng() -> SecureRandom {
    let seed = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];
    SecureRandom::from_seed(seed)
}

//------------------------------------------------------------------------------
// Tests
//------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rng_basics() {
        let mut rng = SecureRandom::new();
        let value = rng.next_u32();
        let value2 = rng.next_u64();
        assert_ne!(value as u64, value2);
        let mut buffer = [0u8; 32];
        rng.fill_bytes(&mut buffer);
        assert_ne!(buffer, [0u8; 32]);
    }

    #[test]
    fn test_deterministic_rng() {
        let seed = [0u8; 32];
        let mut rng1 = SecureRandom::from_seed(seed);
        let mut rng2 = SecureRandom::from_seed(seed);
        for _ in 0..10 {
            assert_eq!(rng1.next_u32(), rng2.next_u32());
        }
        rng1.reseed().unwrap();
        assert_ne!(rng1.next_u32(), rng2.next_u32());
    }

    #[test]
    fn test_thread_local_rng() {
        initialize();
        assert!(is_initialized());
        let mut buffer = [0u8; 32];
        fill_random(&mut buffer).unwrap();
        assert_ne!(buffer, [0u8; 32]);
        let value = random_u32().unwrap();
        let value2 = random_u64().unwrap();
        assert_ne!(value as u64, value2);
    }

    #[test]
    fn test_utility_functions() {
        let value = random_range(100).unwrap();
        assert!(value < 100);
        let bytes = random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
        let _ = random_bool(0.5).unwrap();
        let nonce = generate_nonce(12).unwrap();
        assert_eq!(nonce.len(), 12);
        let key = generate_key(32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_shuffle() {
        let original = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut data = original.clone();
        shuffle(&mut data).unwrap();
        assert_ne!(data, original);
        let mut sorted = data.clone();
        sorted.sort();
        assert_eq!(sorted, original);
    }

    #[test]
    fn test_random_sample() {
        let data = [1, 2, 3, 4, 5];
        let sample = random_sample(&data, 3).unwrap();
        assert_eq!(sample.len(), 3);
        for &item in &sample {
            assert!(data.contains(&item));
        }
        for i in 0..sample.len() {
            for j in (i + 1)..sample.len() {
                assert_ne!(sample[i], sample[j]);
            }
        }
        assert_eq!(random_sample(&data, 0).unwrap().len(), 0);
        assert_eq!(random_sample(&data, 5).unwrap().len(), 5);
        assert!(random_sample(&data, 6).is_err());
        assert!(random_sample(&[] as &[i32], 1).is_err());
    }

    #[test]
    fn test_test_rng() {
        let mut rng = create_test_rng();
        let value1 = rng.next_u32();
        let mut rng2 = create_test_rng();
        let value2 = rng2.next_u32();
        assert_eq!(value1, value2);
        for _ in 0..10 {
            assert_eq!(rng.next_u32(), rng2.next_u32());
        }
    }

    #[test]
    fn test_error_handling() {
        let empty: [i32; 0] = [];
        assert!(matches!(
            random_index(&empty),
            Err(RandomError::UnsupportedOperation)
        ));
        assert!(matches!(
            random_choice(&empty),
            Err(RandomError::UnsupportedOperation)
        ));
        assert!(matches!(
            random_sample(&[1, 2, 3], 4),
            Err(RandomError::UnsupportedOperation)
        ));
    }

    #[test]
    fn test_distribution() {
        let mut rng = SecureRandom::new();
        let mut counts = [0; 10];
        for _ in 0..1000 {
            let value = rng.gen_range_u32(10) as usize;
            counts[value] += 1;
        }
        for &count in &counts {
            assert!(count > 0);
        }
    }
}
