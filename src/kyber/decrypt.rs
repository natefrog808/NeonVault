//! Decryption for CRYSTALS-KYBER
//!
//! This module implements decryption for the CRYSTALS-KYBER post-quantum
//! key encapsulation mechanism as specified in FIPS 203.
//!
//! The decryption process takes a ciphertext and a private key, and recovers
//! the original message. Only the holder of the correct private key can
//! decrypt the ciphertext.

use sha3::{Digest, Sha3_256, Sha3_512};
use zeroize::{Zeroize, ZeroizeOnDrop};
use subtle::{ConstantTimeEq, Choice};

use crate::Error;
use super::{
    Result, KyberError, validate_private_key, validate_ciphertext,
    KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, KYBER_CIPHERTEXTBYTES,
    KYBER_SYMBYTES, KYBER_INDCPA_MSGBYTES, KYBER_POLYVECBYTES,
    N, Q, NEONVAULT_SECURITY_LEVEL,
    Poly, PolyVec, ntt, invntt, indcpa_dec,
};

/// Decrypt a ciphertext using KYBER
///
/// This function decrypts a ciphertext that was encrypted with the corresponding
/// public key. It recovers the original plaintext message.
///
/// # Parameters
///
/// * `private_key` - The recipient's private key
/// * `ciphertext` - The ciphertext to decrypt
///
/// # Returns
///
/// The decrypted plaintext message as a byte vector, or an error if decryption fails.
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
/// assert_eq!(message, &decrypted[..]);
/// ```
pub fn decrypt(private_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    // Validate inputs
    validate_private_key(private_key)?;
    validate_ciphertext(ciphertext)?;
    
    // Extract parts of the private key
    // Format: indcpa_secretkey || public_key || z || hash(pk)
    let k = match NEONVAULT_SECURITY_LEVEL {
        super::KYBER_512 => super::KYBER512_K,
        super::KYBER_768 => super::KYBER768_K,
        super::KYBER_1024 => super::KYBER1024_K,
        _ => return Err(KyberError::InvalidParameters),
    };
    
    let offset_pk = KYBER_POLYVECBYTES;
    let offset_z = offset_pk + KYBER_PUBLICKEYBYTES;
    let offset_hash = offset_z + KYBER_SYMBYTES;
    
    let sk_s = &private_key[..offset_pk];
    let pk = &private_key[offset_pk..offset_z];
    let z = &private_key[offset_z..offset_hash];
    
    // Extract the IND-CPA ciphertext from the full ciphertext
    let indcpa_ct_len = KYBER_CIPHERTEXTBYTES;
    let indcpa_ct = &ciphertext[..indcpa_ct_len];
    let payload = &ciphertext[indcpa_ct_len..];
    
    // Decrypt the encapsulated key using IND-CPA decryption
    let mut m = [0u8; KYBER_INDCPA_MSGBYTES];
    indcpa_dec_internal(indcpa_ct, sk_s, &mut m)?;
    
    // Compute the shared key and confirmation hash
    let mut kr = [0u8; 64]; // Will hold (K || r)
    hash_g(indcpa_ct, &m, &mut kr);
    
    // Split kr into K and r (shared secret and re-encryption randomness)
    let (k, _r) = kr.split_at(32);
    
    // Decrypt the payload using the shared secret
    let plaintext = decrypt_payload(payload, k);
    
    // Zero out sensitive data
    m.zeroize();
    kr.zeroize();
    
    Ok(plaintext)
}

// ### Internal Implementation Functions

/// Decrypt a ciphertext using the IND-CPA secure decryption scheme
///
/// This function implements the core KYBER decryption algorithm that is
/// IND-CPA secure (secure against chosen plaintext attacks).
///
/// # Parameters
///
/// * `ct` - The IND-CPA ciphertext
/// * `sk` - The IND-CPA private key
/// * `msg` - Buffer to store the resulting plaintext message
///
/// # Returns
///
/// `Ok(())` if decryption succeeds, or an error if it fails.
fn indcpa_dec_internal(
    ct: &[u8],
    sk: &[u8],
    msg: &mut [u8],
) -> Result<()> {
    // Verify input sizes
    if ct.len() != KYBER_CIPHERTEXTBYTES {
        return Err(KyberError::InvalidLength);
    }
    if sk.len() != KYBER_POLYVECBYTES {
        return Err(KyberError::InvalidLength);
    }
    if msg.len() != KYBER_INDCPA_MSGBYTES {
        return Err(KyberError::InvalidLength);
    }
    
    // Get the parameter k based on security level
    let k = match NEONVAULT_SECURITY_LEVEL {
        super::KYBER_512 => super::KYBER512_K,
        super::KYBER_768 => super::KYBER768_K,
        super::KYBER_1024 => super::KYBER1024_K,
        _ => return Err(KyberError::InvalidParameters),
    };
    
    // Extract ciphertext components
    let ct_u_len = k * (N / 8);
    let ct_u = &ct[..ct_u_len];
    let ct_v = &ct[ct_u_len..];
    
    // Decompress the polynomial vector u
    let mut u = decompress_polyvec(ct_u, k);
    
    // Decompress the polynomial v
    let mut v = decompress_poly(ct_v);
    
    // Decode the secret key
    let mut skpv = bytes_to_polyvec(sk, k);
    
    // Transform u to NTT domain
    for i in 0..k {
        ntt(&mut u.vec[i]);
    }
    
    // Compute v - u^T * s
    let mut mp = Poly::new();
    mp.coeffs.copy_from_slice(&v.coeffs);
    
    // Compute u^T * s
    let mut tmp = PolyVec::new(k);
    for i in 0..k {
        for j in 0..N {
            tmp.vec[i].coeffs[j] = (u.vec[i].coeffs[j] as u32 * skpv.vec[i].coeffs[j] as u32) as u16 % Q;
        }
    }
    
    // Compute sum of u^T * s
    let mut poly_sum = Poly::new();
    for i in 0..k {
        for j in 0..N {
            poly_sum.coeffs[j] = (poly_sum.coeffs[j] + tmp.vec[i].coeffs[j]) % Q;
        }
    }
    
    // Transform back from NTT domain
    invntt(&mut poly_sum);
    
    // Subtract from v
    for j in 0..N {
        mp.coeffs[j] = (mp.coeffs[j] + 2*Q - poly_sum.coeffs[j]) % Q;
    }
    
    // Convert polynomial to message bytes
    poly_to_msg(&mp, msg);
    
    // Zero out sensitive data
    u.zeroize();
    v.zeroize();
    skpv.zeroize();
    mp.zeroize();
    poly_sum.zeroize();
    
    Ok(())
}

/// Convert a byte array to a polynomial vector
fn bytes_to_polyvec(bytes: &[u8], k: usize) -> PolyVec {
    let mut pv = PolyVec::new(k);
    let poly_bytes = N * 3 / 2;
    
    for i in 0..k {
        let offset = i * poly_bytes;
        let poly_slice = &bytes[offset..offset + poly_bytes];
        pv.vec[i] = bytes_to_poly(poly_slice);
    }
    
    pv
}

/// Convert a byte array to a polynomial
fn bytes_to_poly(bytes: &[u8]) -> Poly {
    let mut p = Poly::new();
    
    if bytes.len() == KYBER_INDCPA_MSGBYTES {
        for i in 0..N {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let bit = (bytes[byte_idx] >> bit_idx) & 1;
            p.coeffs[i] = bit as u16;
        }
    } else {
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

/// Decompress a polynomial vector from the ciphertext
fn decompress_polyvec(a: &[u8], k: usize) -> PolyVec {
    let mut r = PolyVec::new(k);
    
    for i in 0..k {
        let offset = i * (N / 8);
        r.vec[i] = decompress_poly(&a[offset..offset + (N / 8)]);
    }
    
    r
}

/// Decompress a polynomial from the ciphertext
fn decompress_poly(a: &[u8]) -> Poly {
    let mut r = Poly::new();
    
    for i in 0..N/2 {
        r.coeffs[2*i] = decompress_4bit(a[i] & 0x0F);
        r.coeffs[2*i+1] = decompress_4bit((a[i] >> 4) & 0x0F);
    }
    
    r
}

/// Decompress a 4-bit value to a full coefficient
fn decompress_4bit(x: u8) -> u16 {
    ((x as u32 * Q as u32 + 8) / 16) as u16
}

/// Convert a polynomial to a message
fn poly_to_msg(a: &Poly, msg: &mut [u8]) {
    for i in 0..N/8 {
        msg[i] = 0;
        for j in 0..8 {
            let bit = ((((a.coeffs[8*i+j] << 1) + Q/2) / Q) & 1) as u8;
            msg[i] |= bit << j;
        }
    }
}

/// Hash function G used for key derivation
fn hash_g(ciphertext: &[u8], message: &[u8], output: &mut [u8]) {
    let mut hasher = Sha3_512::new();
    hasher.update(ciphertext);
    hasher.update(message);
    let result = hasher.finalize();
    output.copy_from_slice(&result);
}

/// Decrypt a message payload using the shared secret
fn decrypt_payload(ciphertext: &[u8], shared_secret: &[u8]) -> Vec<u8> {
    use sha3::Shake256;
    use sha3::digest::{ExtendableOutput, XofReader};
    
    let mut keystream = vec![0u8; ciphertext.len()];
    let mut shake = Shake256::default();
    shake.update(shared_secret);
    let mut xof = shake.finalize_xof();
    xof.read(&mut keystream);
    
    let mut plaintext = vec![0u8; ciphertext.len()];
    for i in 0..ciphertext.len() {
        plaintext[i] = ciphertext[i] ^ keystream[i];
    }
    
    keystream.zeroize();
    plaintext
}

/// Constant-time comparison for ciphertexts
fn constant_time_compare(a: &[u8], b: &[u8]) -> Choice {
    if a.len() != b.len() {
        return Choice::from(0);
    }
    
    let mut result = 1u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result &= x.ct_eq(y).unwrap_u8();
    }
    
    Choice::from(result)
}

// ### Tests

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::encrypt::encrypt;
    use super::super::key_gen::generate_keypair;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_decrypt_valid() {
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
    fn test_decrypt_wrong_key() {
        let (public_key1, private_key1) = generate_keypair().unwrap();
        let (_, private_key2) = generate_keypair().unwrap();
        let message = b"Secret message for recipient 1";
        let ciphertext = encrypt(&public_key1, message).unwrap();
        let decrypted = decrypt(&private_key2, &ciphertext).unwrap();
        assert_ne!(message, decrypted.as_slice());
    }

    #[test]
    fn test_invalid_inputs() {
        let (public_key, private_key) = generate_keypair().unwrap();
        let message = b"Test message";
        let valid_ct = encrypt(&public_key, message).unwrap();

        let truncated_sk = &private_key[..private_key.len() - 1];
        let result = decrypt(truncated_sk, &valid_ct);
        assert!(matches!(result, Err(KyberError::InvalidLength)));

        let mut extended_sk = private_key.clone();
        extended_sk.push(0);
        let result = decrypt(&extended_sk, &valid_ct);
        assert!(matches!(result, Err(KyberError::InvalidLength)));

        let truncated_ct = &valid_ct[..valid_ct.len() - 1];
        let result = decrypt(&private_key, truncated_ct);
        assert!(matches!(result, Err(KyberError::InvalidLength)));
    }

    #[test]
    fn test_corrupted_ciphertext() {
        let (public_key, private_key) = generate_keypair().unwrap();
        let message = b"Message that will be corrupted";
        let mut ciphertext = encrypt(&public_key, message).unwrap();
        let index = ciphertext.len() / 2;
        ciphertext[index] ^= 0xFF;
        let decrypted = decrypt(&private_key, &ciphertext).unwrap();
        assert_ne!(message, decrypted.as_slice());
    }

    #[test]
    fn test_algorithm_constants() {
        assert!(NEONVAULT_SECURITY_LEVEL == super::super::KYBER_512 ||
                NEONVAULT_SECURITY_LEVEL == super::super::KYBER_768 ||
                NEONVAULT_SECURITY_LEVEL == super::super::KYBER_1024);
        assert_eq!(N, 256);
        assert_eq!(Q, 3329);
    }

    #[test]
    fn test_poly_conversion() {
        let mut msg = [0u8; KYBER_INDCPA_MSGBYTES];
        for i in 0..KYBER_INDCPA_MSGBYTES {
            msg[i] = i as u8;
        }
        
        let mut p = Poly::new();
        for i in 0..N {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let bit = (msg[byte_idx] >> bit_idx) & 1;
            p.coeffs[i] = (bit as u16) * ((Q + 1) / 2);
        }
        
        let mut msg2 = [0u8; KYBER_INDCPA_MSGBYTES];
        poly_to_msg(&p, &mut msg2);
        
        for i in 0..N {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let bit1 = (msg[byte_idx] >> bit_idx) & 1;
            let bit2 = (msg2[byte_idx] >> bit_idx) & 1;
            assert_eq!(bit1, bit2);
        }
    }

    #[test]
    fn test_known_seed() {
        let seed = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        ];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let (pk, sk) = super::super::key_gen::generate_with_rng(&mut rng).unwrap();
        
        let mut rng = ChaCha20Rng::from_seed(seed);
        let message = b"Test message for known seed";
        let ciphertext = super::super::encrypt::encrypt_with_rng(&pk, message, &mut rng).unwrap();
        
        let decrypted = decrypt(&sk, &ciphertext).unwrap();
        assert_eq!(message, decrypted.as_slice());
    }
}
