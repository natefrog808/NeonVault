//! Encryption for CRYSTALS-KYBER
//!
//! This module implements encryption for the CRYSTALS-KYBER post-quantum
//! key encapsulation mechanism as specified in FIPS 203.
//!
//! The encryption process takes a public key and a message, and produces
//! a ciphertext that can only be decrypted with the corresponding private key.

use rand::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_256, Sha3_512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;
use super::{
    Result, KyberError, validate_public_key,
    KYBER_PUBLICKEYBYTES, KYBER_CIPHERTEXTBYTES, 
    KYBER_SYMBYTES, KYBER_INDCPA_MSGBYTES,
    N, Q, KYBER_ETA1, KYBER_ETA2, NEONVAULT_SECURITY_LEVEL,
    Poly, PolyVec, ntt, poly_cbd_eta1, poly_cbd_eta2, indcpa_enc,
};
use crate::utils::random::SecureRandom;

/// Encrypt a message using KYBER
///
/// This function encrypts a message using the provided public key. The message
/// is first encapsulated using the KYBER key encapsulation mechanism, producing
/// a shared secret and a ciphertext. The shared secret is then used to encrypt
/// the actual message using a simplified XOR-based scheme (in a production
/// environment, this would typically use AES-GCM).
///
/// # Parameters
///
/// * `public_key` - The recipient's public key (must be `KYBER_PUBLICKEYBYTES` bytes)
/// * `message` - The plaintext message to encrypt (arbitrary length)
///
/// # Returns
///
/// A `Result` containing the encrypted ciphertext as a `Vec<u8>` on success, or a `KyberError` on failure.
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::{generate_keypair, encrypt, decrypt};
///
/// let (public_key, private_key) = generate_keypair().unwrap();
/// let message = b"Secret message";
/// let ciphertext = encrypt(&public_key, message).unwrap();
/// let decrypted = decrypt(&private_key, &ciphertext).unwrap();
/// assert_eq!(message, decrypted.as_slice());
/// ```
pub fn encrypt(public_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut rng = SecureRandom::new();
    encrypt_with_rng(public_key, message, &mut rng)
}

/// Encrypt a message using KYBER with a provided random number generator
///
/// This function allows specifying a custom RNG for encryption, which is useful for
/// deterministic testing or when using a specific entropy source.
///
/// # Parameters
///
/// * `public_key` - The recipient's public key (must be `KYBER_PUBLICKEYBYTES` bytes)
/// * `message` - The plaintext message to encrypt (arbitrary length)
/// * `rng` - A mutable reference to a cryptographically secure random number generator
///
/// # Returns
///
/// A `Result` containing the encrypted ciphertext as a `Vec<u8>` on success, or a `KyberError` on failure.
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::{encrypt_with_rng, utils::random::SecureRandom};
///
/// let mut rng = SecureRandom::new();
/// let public_key = vec![/* ... */]; // Recipient's public key
/// let message = b"Secret message";
/// let ciphertext = encrypt_with_rng(&public_key, message, &mut rng).unwrap();
/// ```
pub fn encrypt_with_rng<R>(public_key: &[u8], message: &[u8], rng: &mut R) -> Result<Vec<u8>>
where
    R: RngCore + CryptoRng,
{
    // Validate the public key length
    validate_public_key(public_key)?;

    // Generate random coins for the encryption process
    let mut coin = [0u8; KYBER_SYMBYTES];
    rng.fill_bytes(&mut coin);

    // Hash the message to a fixed-size input for KYBER encapsulation
    let mut m_hash = [0u8; KYBER_SYMBYTES];
    hash_h(message, &mut m_hash);

    // Perform IND-CPA encryption to encapsulate the hashed message
    let mut c_indcpa = Vec::new();
    indcpa_enc_internal(public_key, &m_hash, &coin, &mut c_indcpa)?;

    // Derive a shared secret and randomness using hash function G
    let mut kr = [0u8; 64]; // 32 bytes for K (shared secret), 32 bytes for r
    hash_g(&c_indcpa, &m_hash, &mut kr);
    let (k, r) = kr.split_at(32);

    // Encrypt the actual message payload using the shared secret
    let mut payload = encrypt_payload(message, k);

    // Construct the final ciphertext by combining IND-CPA ciphertext and encrypted payload
    let mut ciphertext = Vec::with_capacity(c_indcpa.len() + payload.len());
    ciphertext.extend_from_slice(&c_indcpa);
    ciphertext.append(&mut payload);

    // Zeroize sensitive data to prevent memory leaks
    coin.zeroize();
    m_hash.zeroize();
    kr.zeroize();

    Ok(ciphertext)
}

/// Encrypt a message using KYBER with a specific security level
///
/// This function allows specifying a security level (KYBER_512, KYBER_768, or KYBER_1024).
/// Note: In this implementation, the security level is validated but does not yet dynamically
/// adjust parameters (this would require additional configuration in a full system).
///
/// # Parameters
///
/// * `public_key` - The recipient's public key (must match the security level)
/// * `message` - The plaintext message to encrypt (arbitrary length)
/// * `security_level` - The KYBER security level (e.g., `super::KYBER_1024`)
///
/// # Returns
///
/// A `Result` containing the encrypted ciphertext as a `Vec<u8>` on success, or a `KyberError` on failure.
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::{encrypt_with_params, KYBER_1024};
///
/// let public_key = vec![/* ... */]; // Recipient's public key
/// let message = b"Secret message";
/// let ciphertext = encrypt_with_params(&public_key, message, KYBER_1024).unwrap();
/// ```
pub fn encrypt_with_params(public_key: &[u8], message: &[u8], security_level: u8) -> Result<Vec<u8>> {
    // Validate the security level
    match security_level {
        super::KYBER_512 | super::KYBER_768 | super::KYBER_1024 => (),
        _ => return Err(KyberError::InvalidParameters),
    }
    // Note: In a full implementation, this would adjust parameters like k, eta1, eta2, etc.
    encrypt(public_key, message)
}

/// Encrypt a message using KYBER with a specific security level and RNG
///
/// Combines the flexibility of specifying both a security level and a custom RNG.
///
/// # Parameters
///
/// * `public_key` - The recipient's public key (must match the security level)
/// * `message` - The plaintext message to encrypt (arbitrary length)
/// * `security_level` - The KYBER security level (e.g., `super::KYBER_1024`)
/// * `rng` - A mutable reference to a cryptographically secure random number generator
///
/// # Returns
///
/// A `Result` containing the encrypted ciphertext as a `Vec<u8>` on success, or a `KyberError` on failure.
pub fn encrypt_with_params_and_rng<R>(
    public_key: &[u8],
    message: &[u8],
    security_level: u8,
    rng: &mut R,
) -> Result<Vec<u8>>
where
    R: RngCore + CryptoRng,
{
    // Validate the security level
    match security_level {
        super::KYBER_512 | super::KYBER_768 | super::KYBER_1024 => (),
        _ => return Err(KyberError::InvalidParameters),
    }
    // Note: In a full implementation, this would adjust parameters like k, eta1, eta2, etc.
    encrypt_with_rng(public_key, message, rng)
}

// ### Internal Implementation Functions

/// Encrypt a message using the IND-CPA secure encryption scheme
///
/// Implements the core KYBER IND-CPA encryption algorithm, which is secure against chosen plaintext attacks.
///
/// # Parameters
///
/// * `pk` - The public key (must be `KYBER_PUBLICKEYBYTES` bytes)
/// * `msg` - The message to encapsulate (must be `KYBER_INDCPA_MSGBYTES` bytes)
/// * `coins` - Random coins for encryption (must be `KYBER_SYMBYTES` bytes)
/// * `ciphertext` - Buffer to store the resulting ciphertext
///
/// # Returns
///
/// `Ok(())` on success, or a `KyberError` on failure.
fn indcpa_enc_internal(pk: &[u8], msg: &[u8], coins: &[u8], ciphertext: &mut Vec<u8>) -> Result<()> {
    // Validate input lengths
    if pk.len() != KYBER_PUBLICKEYBYTES || msg.len() != KYBER_INDCPA_MSGBYTES || coins.len() != KYBER_SYMBYTES {
        return Err(KyberError::InvalidLength);
    }

    // Determine the parameter k based on the security level
    let k = match NEONVAULT_SECURITY_LEVEL {
        super::KYBER_512 => super::KYBER512_K,
        super::KYBER_768 => super::KYBER768_K,
        super::KYBER_1024 => super::KYBER1024_K,
        _ => return Err(KyberError::InvalidParameters),
    };

    // Split the public key into polynomial vector and seed
    let offset = k * super::KYBER_POLYBYTES;
    let pk_t = &pk[..offset];
    let pk_seed = &pk[offset..offset + KYBER_SYMBYTES];

    // Decode the public key polynomial vector
    let mut pkpv = bytes_to_polyvec(pk_t, k);

    // Convert the message to a polynomial and encode it
    let mut m = bytes_to_poly(msg);
    for i in 0..N {
        m.coeffs[i] = (((m.coeffs[i] & 1) * (Q + 1) / 2) as u16) % Q;
    }

    // Generate the public matrix A (transposed)
    let mut at = vec![PolyVec::new(k); k];
    gen_matrix(&mut at, pk_seed, true);

    // Sample secret vector sp and error vector ep
    let mut sp = PolyVec::new(k);
    let mut ep = PolyVec::new(k);
    for i in 0..k {
        poly_cbd_eta1(&mut sp.vec[i], coins, i as u8);
        poly_cbd_eta2(&mut ep.vec[i], coins, (k + i) as u8);
    }

    // Transform sp to the NTT domain
    for i in 0..k {
        ntt(&mut sp.vec[i]);
    }

    // Sample additional error term epp
    let mut epp = Poly::new();
    poly_cbd_eta2(&mut epp, coins, (2 * k) as u8);

    // Compute u = A^T * sp + ep (first part of ciphertext)
    let mut b = PolyVec::new(k);
    for i in 0..k {
        matrix_vec_mul(&at, &sp, &mut b, i);
        for j in 0..N {
            b.vec[i].coeffs[j] = (b.vec[i].coeffs[j] + ep.vec[i].coeffs[j]) % Q;
        }
    }

    // Compute v = sp^T * t + epp + m (second part of ciphertext)
    let mut v = Poly::new();
    for i in 0..k {
        ntt(&mut pkpv.vec[i]);
        let mut tmp = Poly::new();
        tmp.coeffs.copy_from_slice(&pkpv.vec[i].coeffs);
        for j in 0..N {
            tmp.coeffs[j] = (tmp.coeffs[j] as u32 * sp.vec[i].coeffs[j] as u32 % Q as u32) as u16;
        }
        for j in 0..N {
            v.coeffs[j] = (v.coeffs[j] + tmp.coeffs[j]) % Q;
        }
    }
    for i in 0..N {
        v.coeffs[i] = (v.coeffs[i] + epp.coeffs[i] + m.coeffs[i]) % Q;
    }

    // Compress and serialize the ciphertext
    *ciphertext = vec![0u8; KYBER_CIPHERTEXTBYTES];
    compress_polyvec(&b, ciphertext);
    let offset = k * super::KYBER_POLYBYTES;
    compress_poly(&v, &mut ciphertext[offset..]);

    // Zeroize sensitive data
    sp.zeroize();
    ep.zeroize();
    epp.zeroize();

    Ok(())
}

/// Convert a byte array to a polynomial vector
///
/// Decodes a byte array into a `PolyVec` with `k` polynomials.
///
/// # Parameters
///
/// * `bytes` - The byte array to decode
/// * `k` - The number of polynomials in the vector
///
/// # Returns
///
/// A `PolyVec` containing the decoded polynomials.
fn bytes_to_polyvec(bytes: &[u8], k: usize) -> PolyVec {
    let mut pv = PolyVec::new(k);
    let poly_bytes = N * 3 / 2; // 384 bytes per polynomial
    for i in 0..k {
        let offset = i * poly_bytes;
        pv.vec[i] = bytes_to_poly(&bytes[offset..offset + poly_bytes]);
    }
    pv
}

/// Convert a byte array to a polynomial
///
/// Decodes a byte array into a `Poly`, handling both message and polynomial encodings.
///
/// # Parameters
///
/// * `bytes` - The byte array to decode
///
/// # Returns
///
/// A `Poly` containing the decoded coefficients.
fn bytes_to_poly(bytes: &[u8]) -> Poly {
    let mut p = Poly::new();
    if bytes.len() == KYBER_INDCPA_MSGBYTES {
        // Message encoding: 32 bytes -> 256 bits
        for i in 0..N {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let bit = (bytes[byte_idx] >> bit_idx) & 1;
            p.coeffs[i] = bit as u16;
        }
    } else {
        // Polynomial encoding: 384 bytes -> 256 coefficients (12 bits each)
        for i in 0..N / 2 {
            let b0 = bytes[3 * i];
            let b1 = bytes[3 * i + 1];
            let b2 = bytes[3 * i + 2];
            p.coeffs[2 * i] = (b0 as u16) | ((b1 as u16 & 0x0F) << 8);
            p.coeffs[2 * i + 1] = ((b1 as u16 & 0xF0) >> 4) | ((b2 as u16) << 4);
        }
    }
    p
}

/// Compress a polynomial vector for the ciphertext
///
/// Compresses a `PolyVec` into a byte array by reducing coefficient precision.
///
/// # Parameters
///
/// * `a` - The polynomial vector to compress
/// * `r` - The byte array to store the compressed data
fn compress_polyvec(a: &PolyVec, r: &mut [u8]) {
    let k = a.vec.len();
    for i in 0..k {
        let offset = i * super::KYBER_POLYBYTES;
        compress_poly(&a.vec[i], &mut r[offset..]);
    }
}

/// Compress a polynomial for the ciphertext
///
/// Compresses a `Poly` into a byte array, reducing coefficients to 4 bits.
///
/// # Parameters
///
/// * `a` - The polynomial to compress
/// * `r` - The byte array to store the compressed data
fn compress_poly(a: &Poly, r: &mut [u8]) {
    let mut t = [0u8; 8];
    for i in 0..N / 8 {
        for j in 0..8 {
            t[j] = ((((a.coeffs[8 * i + j] << 4) + Q / 2) / Q) & 15) as u8;
        }
        r[i] = t[0] | (t[1] << 4);
        r[N / 8 + i] = t[2] | (t[3] << 4);
        r[2 * N / 8 + i] = t[4] | (t[5] << 4);
        r[3 * N / 8 + i] = t[6] | (t[7] << 4);
    }
}

/// Generate the public matrix A from a seed
///
/// Generates a `k x k` matrix of polynomials deterministically from a seed.
///
/// # Parameters
///
/// * `a` - The matrix to populate
/// * `seed` - The seed for deterministic generation
/// * `transposed` - Whether to generate A^T (true) or A (false)
fn gen_matrix(a: &mut [PolyVec], seed: &[u8], transposed: bool) {
    let k = a.len();
    let mut xof_input = Vec::with_capacity(KYBER_SYMBYTES + 2);
    xof_input.extend_from_slice(seed);
    xof_input.push(0);
    xof_input.push(0);

    for i in 0..k {
        for j in 0..k {
            let (idx1, idx2) = if transposed { (j, i) } else { (i, j) };
            xof_input[KYBER_SYMBYTES] = idx1 as u8;
            xof_input[KYBER_SYMBYTES + 1] = idx2 as u8;
            a[i].vec[j] = gen_poly_from_seed(&xof_input);
        }
    }
}

/// Generate a polynomial from a seed using SHAKE-128
///
/// Uses SHAKE-128 as an extendable output function to generate polynomial coefficients.
///
/// # Parameters
///
/// * `seed` - The seed for polynomial generation
///
/// # Returns
///
/// A `Poly` with coefficients in [0, Q-1].
fn gen_poly_from_seed(seed: &[u8]) -> Poly {
    use sha3::Shake128;
    use sha3::digest::{ExtendableOutput, XofReader};

    let mut poly = Poly::new();
    let mut shake = Shake128::default();
    shake.update(seed);
    let mut xof = shake.finalize_xof();

    let mut buf = [0u8; 168];
    let mut buflen = 0;
    let mut pos = 0;
    let mut ctr = 0;

    while ctr < N {
        if pos + 2 > buflen {
            buflen = 168;
            xof.read(&mut buf);
            pos = 0;
        }
        let val = ((buf[pos] as u16) | ((buf[pos + 1] as u16) << 8)) & 0x0FFF;
        pos += 2;
        if val < Q {
            poly.coeffs[ctr] = val;
            ctr += 1;
        }
    }
    poly
}

/// Multiply a matrix by a vector
///
/// Computes one row of the matrix-vector product A * s.
///
/// # Parameters
///
/// * `a` - The matrix (array of `PolyVec`)
/// * `s` - The vector (`PolyVec`)
/// * `t` - The result vector to update
/// * `row` - The row index to compute
fn matrix_vec_mul(a: &[PolyVec], s: &PolyVec, t: &mut PolyVec, row: usize) {
    let k = a[0].vec.len();
    let mut r = Poly::new();

    for i in 0..k {
        let mut prod = Poly::new();
        prod.coeffs.copy_from_slice(&a[row].vec[i].coeffs);
        for j in 0..N {
            prod.coeffs[j] = (prod.coeffs[j] as u32 * s.vec[i].coeffs[j] as u32 % Q as u32) as u16;
        }
        for j in 0..N {
            r.coeffs[j] = (r.coeffs[j] + prod.coeffs[j]) % Q;
        }
    }
    t.vec[row].coeffs.copy_from_slice(&r.coeffs);
}

/// Hash a message to a fixed-size output
///
/// Uses SHA3-256 to produce a 32-byte hash.
///
/// # Parameters
///
/// * `message` - The input message
/// * `output` - The buffer to store the hash (must be 32 bytes)
fn hash_h(message: &[u8], output: &mut [u8]) {
    let mut hasher = Sha3_256::new();
    hasher.update(message);
    let result = hasher.finalize();
    output.copy_from_slice(&result);
}

/// Hash function G for key derivation
///
/// Uses SHA3-512 to produce a 64-byte output from ciphertext and message.
///
/// # Parameters
///
/// * `ciphertext` - The IND-CPA ciphertext
/// * `message` - The hashed message
/// * `output` - The buffer to store the hash (must be 64 bytes)
fn hash_g(ciphertext: &[u8], message: &[u8], output: &mut [u8]) {
    let mut hasher = Sha3_512::new();
    hasher.update(ciphertext);
    hasher.update(message);
    let result = hasher.finalize();
    output.copy_from_slice(&result);
}

/// Encrypt a message payload using the shared secret
///
/// Encrypts the message using a SHAKE-256-derived keystream XORed with the message.
/// In a production environment, this would use AES-GCM or another AEAD scheme.
///
/// # Parameters
///
/// * `message` - The plaintext message
/// * `shared_secret` - The 32-byte shared secret
///
/// # Returns
///
/// The encrypted payload as a `Vec<u8>`.
fn encrypt_payload(message: &[u8], shared_secret: &[u8]) -> Vec<u8> {
    use sha3::Shake256;
    use sha3::digest::{ExtendableOutput, XofReader};

    let mut keystream = vec![0u8; message.len()];
    let mut shake = Shake256::default();
    shake.update(shared_secret);
    let mut xof = shake.finalize_xof();
    xof.read(&mut keystream);

    let mut ciphertext = vec![0u8; message.len()];
    for i in 0..message.len() {
        ciphertext[i] = message[i] ^ keystream[i];
    }

    keystream.zeroize();
    ciphertext
}

// ### Tests

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::decrypt::decrypt;
    use super::super::key_gen::generate_keypair;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_encrypt_decrypt_cycle() {
        let (public_key, private_key) = generate_keypair().unwrap();
        let message = b"Top secret nation-state data";
        let ciphertext = encrypt(&public_key, message).unwrap();
        let decrypted = decrypt(&private_key, &ciphertext).unwrap();
        assert_eq!(message, decrypted.as_slice());
    }

    #[test]
    fn test_message_sizes() {
        let (public_key, private_key) = generate_keypair().unwrap();
        let messages = [
            b"",
            b"Short",
            b"12345678901234567890123456789012",
            b"This is a longer message that exceeds the 32-byte limit.",
        ];
        for msg in messages.iter() {
            let ciphertext = encrypt(&public_key, msg).unwrap();
            let decrypted = decrypt(&private_key, &ciphertext).unwrap();
            assert_eq!(msg, &decrypted.as_slice());
        }
    }

    #[test]
    fn test_deterministic_encryption() {
        let seed = [0u8; 32];
        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let mut rng2 = ChaCha20Rng::from_seed(seed);
        let (pk, _) = super::super::key_gen::generate_with_rng(&mut rng1).unwrap();
        let message = b"Secret message";
        let ct1 = encrypt_with_rng(&pk, message, &mut rng1).unwrap();
        let ct2 = encrypt_with_rng(&pk, message, &mut rng2).unwrap();
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_different_keys() {
        let (pk1, _) = generate_keypair().unwrap();
        let (pk2, _) = generate_keypair().unwrap();
        assert_ne!(pk1, pk2);
        let message = b"Secret message";
        let ct1 = encrypt(&pk1, message).unwrap();
        let ct2 = encrypt(&pk2, message).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_invalid_inputs() {
        let (valid_pk, _) = generate_keypair().unwrap();
        let truncated_pk = &valid_pk[..valid_pk.len() - 1];
        let result = encrypt(truncated_pk, b"Test message");
        assert!(matches!(result, Err(KyberError::InvalidLength)));
        let mut extended_pk = valid_pk.clone();
        extended_pk.push(0);
        let result = encrypt(&extended_pk, b"Test message");
        assert!(matches!(result, Err(KyberError::InvalidLength)));
    }
}
