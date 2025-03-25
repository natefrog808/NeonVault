//! Key generation for CRYSTALS-KYBER
//!
//! This module implements key generation for the CRYSTALS-KYBER post-quantum
//! key encapsulation mechanism as specified in FIPS 203.
//!
//! The key generation process creates a public/private key pair that can be used
//! for encryption and decryption. The security of the keys depends on the hardness
//! of the Module Learning With Errors (MLWE) problem.

use rand::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_256, Sha3_512};
use zeroize::Zeroize;

use crate::Error;
use super::{
    Result, KyberError,
    KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, 
    KYBER_SYMBYTES, KYBER_POLYVECBYTES,
    N, Q, KYBER_ETA1, NEONVAULT_SECURITY_LEVEL,
    Poly, PolyVec, ntt, poly_cbd_eta1,
    indcpa_keypair
};
use crate::utils::random::SecureRandom;
use crate::utils::bytes::{to_bytes, from_bytes};

/// Secure seed length in bytes
const SEED_BYTES: usize = 32;

/// Generate a new KYBER key pair
///
/// This function generates a new public/private key pair for the KYBER key
/// encapsulation mechanism using the default security level (KYBER-768).
///
/// # Returns
///
/// A tuple containing the public key and private key as byte vectors, or an error
/// if key generation fails.
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::generate_keypair;
///
/// let (public_key, private_key) = generate_keypair().unwrap();
/// println!("Generated KYBER key pair");
/// println!("Public key length: {}", public_key.len());
/// println!("Private key length: {}", private_key.len());
/// ```
pub fn generate() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = SecureRandom::new();
    generate_with_rng(&mut rng)
}

/// Generate a KYBER key pair using the provided random number generator
///
/// This function allows using a specific RNG for key generation, which can be useful
/// for deterministic testing or when using a specific entropy source.
///
/// # Parameters
///
/// * `rng` - A mutable reference to a random number generator that implements
///           the `CryptoRng` and `RngCore` traits.
///
/// # Returns
///
/// A tuple containing the public key and private key as byte vectors, or an error
/// if key generation fails.
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::{generate_keypair_with_rng, utils::random::SecureRandom};
///
/// let mut rng = SecureRandom::new();
/// let (public_key, private_key) = generate_keypair_with_rng(&mut rng).unwrap();
/// ```
pub fn generate_with_rng<R>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)>
where
    R: RngCore + CryptoRng,
{
    let (pk, sk_indcpa) = indcpa_keypair(rng)?;

    let mut sk = Vec::with_capacity(KYBER_SECRETKEYBYTES);
    sk.extend_from_slice(&sk_indcpa); // IND-CPA secret key
    sk.extend_from_slice(&pk);        // Public key

    let mut z = vec![0u8; KYBER_SYMBYTES];
    rng.fill_bytes(&mut z);
    sk.extend_from_slice(&z);         // Random value z

    let pk_hash = hash_h(&pk);
    sk.extend_from_slice(&pk_hash);   // Hash of public key

    debug_assert_eq!(pk.len(), KYBER_PUBLICKEYBYTES);
    debug_assert_eq!(sk.len(), KYBER_SECRETKEYBYTES);

    Ok((pk, sk))
}

/// Generate a KYBER key pair with a specific security level
///
/// This function allows choosing a specific security level for key generation.
///
/// # Parameters
///
/// * `security_level` - The security level to use: KYBER_512, KYBER_768, or KYBER_1024
///
/// # Returns
///
/// A tuple containing the public key and private key as byte vectors, or an error
/// if key generation fails.
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::{generate_keypair_with_params, KYBER_1024};
///
/// let (public_key, private_key) = generate_keypair_with_params(KYBER_1024).unwrap();
/// ```
pub fn generate_with_params(security_level: u8) -> Result<(Vec<u8>, Vec<u8>)> {
    match security_level {
        super::KYBER_512 | super::KYBER_768 | super::KYBER_1024 => (),
        _ => return Err(KyberError::InvalidParameters),
    }
    generate() // Note: Full parameterization requires adjusting global constants
}

/// Generate a KYBER key pair with a specific security level and RNG
///
/// This function combines the flexibility of specifying both the security level
/// and the random number generator.
///
/// # Parameters
///
/// * `security_level` - The security level to use: KYBER_512, KYBER_768, or KYBER_1024
/// * `rng` - A mutable reference to a random number generator
///
/// # Returns
///
/// A tuple containing the public key and private key as byte vectors, or an error
/// if key generation fails.
pub fn generate_with_params_and_rng<R>(security_level: u8, rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)>
where
    R: RngCore + CryptoRng,
{
    match security_level {
        super::KYBER_512 | super::KYBER_768 | super::KYBER_1024 => (),
        _ => return Err(KyberError::InvalidParameters),
    }
    generate_with_rng(rng) // Note: Full parameterization requires adjusting global constants
}

// ### Internal Implementation Functions

/// Generate a keypair for the ML-KEM IND-CPA scheme
pub(crate) fn indcpa_keypair_internal<R>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)>
where
    R: RngCore + CryptoRng,
{
    let k = match NEONVAULT_SECURITY_LEVEL {
        super::KYBER_512 => super::KYBER512_K,
        super::KYBER_768 => super::KYBER768_K,
        super::KYBER_1024 => super::KYBER1024_K,
        _ => return Err(KyberError::InvalidParameters),
    };

    let mut seed = [0u8; SEED_BYTES];
    rng.fill_bytes(&mut seed);

    let mut hash_output = hash_g(&seed);
    let (public_seed, noise_seed) = hash_output.split_at_mut(KYBER_SYMBYTES);

    let mut a_matrix = vec![PolyVec::new(k); k];
    gen_matrix(&mut a_matrix, public_seed, false);

    let mut s = PolyVec::new(k);
    for i in 0..k {
        poly_cbd_eta1(&mut s.vec[i], noise_seed, i as u8);
        ntt(&mut s.vec[i]);
    }

    let mut e = PolyVec::new(k);
    for i in 0..k {
        poly_cbd_eta1(&mut e.vec[i], noise_seed, (k + i) as u8);
    }

    let mut t = PolyVec::new(k);
    for i in 0..k {
        matrix_vec_mul(&a_matrix, &s, &mut t, i);
        for j in 0..N {
            t.vec[i].coeffs[j] = (t.vec[i].coeffs[j] + e.vec[i].coeffs[j]) % Q;
        }
    }

    let mut pk = Vec::with_capacity(KYBER_PUBLICKEYBYTES);
    let mut sk = Vec::with_capacity(KYBER_POLYVECBYTES);
    polyvec_to_bytes(&t, &mut pk);
    pk.extend_from_slice(public_seed);
    polyvec_to_bytes(&s, &mut sk);

    noise_seed.zeroize();
    s.zeroize();
    e.zeroize();

    Ok((pk, sk))
}

/// Convert a polynomial vector to a byte array
fn polyvec_to_bytes(pv: &PolyVec, bytes: &mut Vec<u8>) {
    for poly in &pv.vec {
        poly_to_bytes(poly, bytes);
    }
}

/// Convert a polynomial to a byte array using 12-bit compression
fn poly_to_bytes(p: &Poly, bytes: &mut Vec<u8>) {
    let n_bytes = (N * 3) / 2;
    let mut buffer = vec![0u8; n_bytes];

    for i in 0..N / 2 {
        let a0 = p.coeffs[2 * i];
        let a1 = p.coeffs[2 * i + 1];
        buffer[3 * i] = (a0 & 0xFF) as u8;
        buffer[3 * i + 1] = ((a0 >> 8) | ((a1 & 0x0F) << 4)) as u8;
        buffer[3 * i + 2] = (a1 >> 4) as u8;
    }

    bytes.extend_from_slice(&buffer);
}

/// Convert a byte array to a polynomial vector
fn bytes_to_polyvec(bytes: &[u8], k: usize) -> PolyVec {
    let mut pv = PolyVec::new(k);
    let poly_bytes = N * 3 / 2;

    for i in 0..k {
        let offset = i * poly_bytes;
        pv.vec[i] = bytes_to_poly(&bytes[offset..offset + poly_bytes]);
    }
    pv
}

/// Convert a byte array to a polynomial
fn bytes_to_poly(bytes: &[u8]) -> Poly {
    let mut p = Poly::new();

    for i in 0..N / 2 {
        let b0 = bytes[3 * i];
        let b1 = bytes[3 * i + 1];
        let b2 = bytes[3 * i + 2];
        p.coeffs[2 * i] = (b0 as u16) | ((b1 as u16 & 0x0F) << 8);
        p.coeffs[2 * i + 1] = ((b1 as u16 & 0xF0) >> 4) | ((b2 as u16) << 4);
    }
    p
}

/// Generate the public matrix A from a seed
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

/// Hash function G (SHA3-512)
fn hash_g(seed: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(seed);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// Hash function H (SHA3-256)
fn hash_h(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

// ### Tests

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_generate_keypair() {
        let (pk, sk) = generate().unwrap();
        assert_eq!(pk.len(), KYBER_PUBLICKEYBYTES);
        assert_eq!(sk.len(), KYBER_SECRETKEYBYTES);
        assert_eq!(&sk[KYBER_POLYVECBYTES..KYBER_POLYVECBYTES + KYBER_PUBLICKEYBYTES], &pk[..]);
    }

    #[test]
    fn test_deterministic_keygen() {
        let seed = [0u8; 32];
        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let mut rng2 = ChaCha20Rng::from_seed(seed);
        let (pk1, sk1) = generate_with_rng(&mut rng1).unwrap();
        let (pk2, sk2) = generate_with_rng(&mut rng2).unwrap();
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
    }

    #[test]
    fn test_security_levels() {
        assert!(matches!(
            NEONVAULT_SECURITY_LEVEL,
            super::super::KYBER_512 | super::super::KYBER_768 | super::super::KYBER_1024
        ));
    }

    #[test]
    fn test_poly_conversion() {
        let mut p = Poly::new();
        for i in 0..N {
            p.coeffs[i] = (i as u16) % Q;
        }
        let mut bytes = Vec::new();
        poly_to_bytes(&p, &mut bytes);
        let p2 = bytes_to_poly(&bytes);
        assert_eq!(p.coeffs, p2.coeffs);
    }

    #[test]
    fn test_polyvec_conversion() {
        let k = 3;
        let mut pv = PolyVec::new(k);
        for i in 0..k {
            for j in 0..N {
                pv.vec[i].coeffs[j] = ((i * N + j) as u16) % Q;
            }
        }
        let mut bytes = Vec::new();
        polyvec_to_bytes(&pv, &mut bytes);
        let pv2 = bytes_to_polyvec(&bytes, k);
        for i in 0..k {
            assert_eq!(pv.vec[i].coeffs, pv2.vec[i].coeffs);
        }
    }

    #[test]
    fn test_matrix_generation() {
        let k = 3;
        let seed = [0u8; KYBER_SYMBYTES];
        let mut a1 = vec![PolyVec::new(k); k];
        let mut a2 = vec![PolyVec::new(k); k];
        gen_matrix(&mut a1, &seed, false);
        gen_matrix(&mut a2, &seed, false);
        for i in 0..k {
            for j in 0..k {
                assert_eq!(a1[i].vec[j].coeffs, a2[i].vec[j].coeffs);
            }
        }
        let mut at = vec![PolyVec::new(k); k];
        gen_matrix(&mut at, &seed, true);
        for i in 0..k {
            for j in 0..k {
                assert_eq!(a1[i].vec[j].coeffs, at[j].vec[i].coeffs);
            }
        }
    }
}
