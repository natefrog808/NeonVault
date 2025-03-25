//! Polynomial operations for CRYSTALS-KYBER
//!
//! This module implements polynomial operations for the CRYSTALS-KYBER
//! post-quantum key encapsulation mechanism as specified in FIPS 203.
//!
//! The primary structures are `Poly` (representing a single polynomial)
//! and `PolyVec` (representing a vector of polynomials), which form the
//! mathematical foundation for the lattice-based cryptography in KYBER.

use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{CryptoRng, RngCore};
use sha3::{Shake128, Shake256};
use sha3::digest::{ExtendableOutput, XofReader};

use super::params::{
    N, Q, KYBER_ETA1, KYBER_ETA2, KYBER_NTT_ZETAS, KYBER_NTT_ZETAS_INV,
    montgomery_reduce, barrett_reduce, to_mont, cmov,
};

// ### Polynomial Structure and Operations

/// A polynomial of degree N-1 with coefficients in Z_q
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct Poly {
    /// Coefficients of the polynomial
    pub coeffs: [i16; N],
}

impl Poly {
    /// Create a new polynomial with all coefficients set to 0
    pub fn new() -> Self {
        Self { coeffs: [0; N] }
    }
    
    /// Add another polynomial to this one (coefficient-wise addition modulo Q)
    pub fn add(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = barrett_reduce(self.coeffs[i] + b.coeffs[i]);
        }
    }
    
    /// Subtract another polynomial from this one (coefficient-wise subtraction modulo Q)
    pub fn sub(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = barrett_reduce(self.coeffs[i] - b.coeffs[i]);
        }
    }
    
    /// Multiply by a constant (coefficient-wise multiplication modulo Q)
    pub fn mul_scalar(&mut self, scalar: i16) {
        for i in 0..N {
            self.coeffs[i] = montgomery_reduce(self.coeffs[i] as i32 * scalar as i32);
        }
    }
    
    /// Pointwise multiplication with another polynomial in the NTT domain
    pub fn pointwise_multiply(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = montgomery_reduce(self.coeffs[i] as i32 * b.coeffs[i] as i32);
        }
    }
    
    /// Reduce all coefficients modulo Q
    pub fn reduce(&mut self) {
        for i in 0..N {
            self.coeffs[i] = barrett_reduce(self.coeffs[i]);
        }
    }
    
    /// Convert polynomial to Montgomery domain
    pub fn to_mont(&mut self) {
        for i in 0..N {
            self.coeffs[i] = to_mont(self.coeffs[i]);
        }
    }
}

/// A vector of K polynomials
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct PolyVec {
    /// The vector of polynomials
    pub vec: Vec<Poly>,
}

impl PolyVec {
    /// Create a new vector of K polynomials initialized to zero
    pub fn new(k: usize) -> Self {
        let mut vec = Vec::with_capacity(k);
        for _ in 0..k {
            vec.push(Poly::new());
        }
        Self { vec }
    }
    
    /// Add another polynomial vector (coefficient-wise vector addition)
    pub fn add(&mut self, b: &PolyVec) {
        if self.vec.len() != b.vec.len() {
            panic!("PolyVec dimension mismatch in addition");
        }
        
        for i in 0..self.vec.len() {
            self.vec[i].add(&b.vec[i]);
        }
    }
    
    /// Subtract another polynomial vector (coefficient-wise vector subtraction)
    pub fn sub(&mut self, b: &PolyVec) {
        if self.vec.len() != b.vec.len() {
            panic!("PolyVec dimension mismatch in subtraction");
        }
        
        for i in 0..self.vec.len() {
            self.vec[i].sub(&b.vec[i]);
        }
    }
    
    /// Multiply all polynomials in the vector by a scalar
    pub fn mul_scalar(&mut self, scalar: i16) {
        for poly in &mut self.vec {
            poly.mul_scalar(scalar);
        }
    }
    
    /// Reduce all coefficients in all polynomials modulo Q
    pub fn reduce(&mut self) {
        for poly in &mut self.vec {
            poly.reduce();
        }
    }
    
    /// Convert all polynomials to Montgomery domain
    pub fn to_mont(&mut self) {
        for poly in &mut self.vec {
            poly.to_mont();
        }
    }
}

// ### NTT (Number Theoretic Transform) Operations

/// Forward NTT transformation of a polynomial
///
/// Converts a polynomial from the normal domain to the NTT domain for efficient multiplication.
pub fn ntt(poly: &mut Poly) {
    let mut layer = 1;
    let mut len = 128;
    
    while len >= 2 {
        let mut j = 0;
        let mut k = 0;
        
        while j < N {
            let zeta = KYBER_NTT_ZETAS[k] as i32;
            k += 1;
            
            for i in j..(j + len) {
                let t = montgomery_reduce(zeta * poly.coeffs[i + len] as i32);
                poly.coeffs[i + len] = poly.coeffs[i] - t;
                poly.coeffs[i] = poly.coeffs[i] + t;
            }
            
            j += 2 * len;
        }
        
        len >>= 1;
        layer += 1;
    }
}

/// Inverse NTT transformation of a polynomial
///
/// Converts a polynomial from the NTT domain back to the normal domain.
pub fn invntt(poly: &mut Poly) {
    let mut layer = 0;
    let mut len = 2;
    
    while len <= 128 {
        let mut j = 0;
        let mut k = 0;
        
        while j < N {
            let zeta = KYBER_NTT_ZETAS_INV[k] as i32;
            k += 1;
            
            for i in j..(j + len) {
                let t = poly.coeffs[i];
                poly.coeffs[i] = barrett_reduce(t + poly.coeffs[i + len]);
                poly.coeffs[i + len] = t - poly.coeffs[i + len];
                poly.coeffs[i + len] = montgomery_reduce(zeta * poly.coeffs[i + len] as i32);
            }
            
            j += 2 * len;
        }
        
        len <<= 1;
        layer += 1;
    }
    
    // Scale by n^(-1) mod Q
    for i in 0..N {
        poly.coeffs[i] = montgomery_reduce(poly.coeffs[i] as i32 * 3303 as i32);
    }
}

/// Multiply two polynomials in the NTT domain (element-wise)
///
/// Stores the result in the first polynomial.
pub fn basemul(r: &mut Poly, a: &Poly, b: &Poly, offset: usize) {
    for i in 0..N / 4 {
        let idx = 4 * i + offset;
        let a_0 = a.coeffs[idx] as i32;
        let a_1 = a.coeffs[idx + 2] as i32;
        let b_0 = b.coeffs[idx] as i32;
        let b_1 = b.coeffs[idx + 2] as i32;
        let zeta = KYBER_NTT_ZETAS[N / 4 + i] as i32;
        
        r.coeffs[idx] = montgomery_reduce(a_0 * b_0);
        r.coeffs[idx + 2] = montgomery_reduce(a_1 * b_1);
        r.coeffs[idx + 1] = montgomery_reduce(a_0 * b_1);
        r.coeffs[idx + 3] = montgomery_reduce(a_1 * b_0);
    }
}

// ### Sampling Functions

/// Sample a polynomial from the centered binomial distribution with parameter eta1
pub fn poly_cbd_eta1(r: &mut Poly, seed: &[u8], nonce: u8) {
    poly_cbd(r, seed, nonce, KYBER_ETA1);
}

/// Sample a polynomial from the centered binomial distribution with parameter eta2
pub fn poly_cbd_eta2(r: &mut Poly, seed: &[u8], nonce: u8) {
    poly_cbd(r, seed, nonce, KYBER_ETA2);
}

/// Sample a polynomial from the centered binomial distribution with parameter eta
fn poly_cbd(r: &mut Poly, seed: &[u8], nonce: u8, eta: u8) {
    let mut buf = Vec::with_capacity(seed.len() + 1);
    buf.extend_from_slice(seed);
    buf.push(nonce);
    
    let mut shake = Shake256::default();
    shake.update(&buf);
    let mut xof = shake.finalize_xof();
    
    let buf_len = 64 * eta as usize;
    let mut buf = vec![0u8; buf_len];
    xof.read(&mut buf);
    
    let mut idx = 0;
    for i in 0..N {
        let mut t = 0i16;
        for j in 0..eta {
            let a = buf[idx] as i16;
            let b = buf[idx + 1] as i16;
            idx += 2;
            
            let a_bits = (a & 1) + ((a >> 1) & 1) + ((a >> 2) & 1) + ((a >> 3) & 1) +
                         ((a >> 4) & 1) + ((a >> 5) & 1) + ((a >> 6) & 1) + ((a >> 7) & 1);
            let b_bits = (b & 1) + ((b >> 1) & 1) + ((b >> 2) & 1) + ((b >> 3) & 1) +
                         ((b >> 4) & 1) + ((b >> 5) & 1) + ((b >> 6) & 1) + ((b >> 7) & 1);
            
            t += a_bits - b_bits;
        }
        r.coeffs[i] = t;
    }
}

/// Sample a polynomial with uniform random coefficients
pub fn poly_uniform<R: RngCore + CryptoRng>(r: &mut Poly, rng: &mut R) {
    for i in 0..N {
        loop {
            let mut buf = [0u8; 2];
            rng.fill_bytes(&mut buf);
            let val = u16::from_le_bytes(buf) & 0x0FFF;
            if val < Q as u16 {
                r.coeffs[i] = val as i16;
                break;
            }
        }
    }
}

/// Sample a polynomial deterministically from a seed
pub fn poly_uniform_from_seed(r: &mut Poly, seed: &[u8], nonce: u16) {
    let mut buf = Vec::with_capacity(seed.len() + 2);
    buf.extend_from_slice(seed);
    buf.push((nonce >> 0) as u8);
    buf.push((nonce >> 8) as u8);
    
    let mut shake = Shake128::default();
    shake.update(&buf);
    let mut xof = shake.finalize_xof();
    
    let mut buf = [0u8; 168];
    let mut pos = 168;
    
    let mut i = 0;
    while i < N {
        if pos >= 168 {
            xof.read(&mut buf);
            pos = 0;
        }
        
        let val = if pos + 2 <= 168 {
            u16::from_le_bytes([buf[pos], buf[pos+1]])
        } else {
            let mut tmp = [0u8; 2];
            tmp[0] = buf[pos];
            xof.read(&mut buf);
            tmp[1] = buf[0];
            pos = 0;
            u16::from_le_bytes(tmp)
        };
        pos += 2;
        
        let val = val & 0x0FFF;
        if val < Q as u16 {
            r.coeffs[i] = val as i16;
            i += 1;
        }
    }
}

// ### Message Conversion Functions

/// Convert a 32-byte message to a polynomial
pub fn poly_frommsg(r: &mut Poly, msg: &[u8]) {
    if msg.len() != 32 {
        panic!("Message must be exactly 32 bytes");
    }
    
    for i in 0..N {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let bit = (msg[byte_idx] >> bit_idx) & 1;
        r.coeffs[i] = (bit as i16) * ((Q as i16 + 1) / 2);
    }
}

/// Convert a polynomial to a 32-byte message
pub fn poly_tomsg(msg: &mut [u8], a: &Poly) {
    if msg.len() != 32 {
        panic!("Message buffer must be exactly 32 bytes");
    }
    
    for i in 0..32 {
        msg[i] = 0;
    }
    
    for i in 0..N {
        let t = ((((a.coeffs[i] << 1) + (Q as i16 / 2)) / (Q as i16)) & 1) as u8;
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        msg[byte_idx] |= t << bit_idx;
    }
}

// ### Compression and Decompression Functions

/// Compress a polynomial
pub fn poly_compress(a: &Poly, r: &mut [u8], compress_to_bits: u32) {
    match compress_to_bits {
        4 => {
            if r.len() < N / 2 {
                panic!("Destination buffer too small");
            }
            for i in 0..N / 2 {
                let t0 = ((((a.coeffs[2*i] << 4) + (Q as i16 / 2)) / (Q as i16)) & 15) as u8;
                let t1 = ((((a.coeffs[2*i+1] << 4) + (Q as i16 / 2)) / (Q as i16)) & 15) as u8;
                r[i] = t0 | (t1 << 4);
            }
        }
        5 => {
            if r.len() < (N * 5) / 8 {
                panic!("Destination buffer too small");
            }
            let mut k = 0;
            let mut i = 0;
            while i < N {
                let mut b = 0u32;
                for j in 0..8 {
                    if i + j < N {
                        let t = ((((a.coeffs[i+j] << 5) + (Q as i16 / 2)) / (Q as i16)) & 31) as u32;
                        b |= t << (5 * j);
                    }
                }
                r[k] = (b >> 0) as u8;
                r[k+1] = (b >> 8) as u8;
                r[k+2] = (b >> 16) as u8;
                r[k+3] = (b >> 24) as u8;
                r[k+4] = (b >> 32) as u8;
                i += 8;
                k += 5;
            }
        }
        10 => {
            if r.len() < (N * 10) / 8 {
                panic!("Destination buffer too small");
            }
            let mut k = 0;
            let mut i = 0;
            while i < N {
                let mut b = 0u64;
                for j in 0..4 {
                    if i + j < N {
                        let t = ((((a.coeffs[i+j] << 10) + (Q as i16 / 2)) / (Q as i16)) & 1023) as u64;
                        b |= t << (10 * j);
                    }
                }
                r[k] = (b >> 0) as u8;
                r[k+1] = (b >> 8) as u8;
                r[k+2] = (b >> 16) as u8;
                r[k+3] = (b >> 24) as u8;
                r[k+4] = (b >> 32) as u8;
                i += 4;
                k += 5;
            }
        }
        _ => panic!("Unsupported compression bits"),
    }
}

/// Decompress a polynomial
pub fn poly_decompress(r: &mut Poly, a: &[u8], decompress_from_bits: u32) {
    match decompress_from_bits {
        4 => {
            if a.len() < N / 2 {
                panic!("Source buffer too small");
            }
            for i in 0..N / 2 {
                let t0 = a[i] & 15;
                let t1 = (a[i] >> 4) & 15;
                r.coeffs[2*i] = ((t0 * (Q as u8) + 8) >> 4) as i16;
                r.coeffs[2*i+1] = ((t1 * (Q as u8) + 8) >> 4) as i16;
            }
        }
        5 => {
            if a.len() < (N * 5) / 8 {
                panic!("Source buffer too small");
            }
            let mut k = 0;
            let mut i = 0;
            while i < N {
                let mut b = a[k] as u64;
                b |= (a[k+1] as u64) << 8;
                b |= (a[k+2] as u64) << 16;
                b |= (a[k+3] as u64) << 24;
                b |= (a[k+4] as u64) << 32;
                for j in 0..8 {
                    if i + j < N {
                        let t = ((b >> (5 * j)) & 31) as u16;
                        r.coeffs[i+j] = ((t * (Q as u16) + 16) >> 5) as i16;
                    }
                }
                i += 8;
                k += 5;
            }
        }
        10 => {
            if a.len() < (N * 10) / 8 {
                panic!("Source buffer too small");
            }
            let mut k = 0;
            let mut i = 0;
            while i < N {
                let mut b = a[k] as u64;
                b |= (a[k+1] as u64) << 8;
                b |= (a[k+2] as u64) << 16;
                b |= (a[k+3] as u64) << 24;
                b |= (a[k+4] as u64) << 32;
                for j in 0..4 {
                    if i + j < N {
                        let t = ((b >> (10 * j)) & 1023) as u16;
                        r.coeffs[i+j] = ((t * (Q as u16) + 512) >> 10) as i16;
                    }
                }
                i += 4;
                k += 5;
            }
        }
        _ => panic!("Unsupported decompression bits"),
    }
}

// ### Serialization and Deserialization Functions

/// Pack a polynomial into a byte array
pub fn poly_tobytes(r: &mut [u8], a: &Poly) {
    let mut t = [0u16; 4];
    
    for i in 0..N / 4 {
        for j in 0..4 {
            t[j] = a.coeffs[4*i+j] as u16;
            if t[j] >= Q as u16 {
                t[j] -= Q as u16;
            }
        }
        
        r[5*i+0] = (t[0] >> 0) as u8;
        r[5*i+1] = ((t[0] >> 8) | (t[1] << 5)) as u8;
        r[5*i+2] = ((t[1] >> 3) | (t[2] << 2)) as u8;
        r[5*i+3] = ((t[2] >> 6) | (t[3] << 7)) as u8;
        r[5*i+4] = (t[3] >> 1) as u8;
    }
}

/// Unpack a byte array into a polynomial
pub fn poly_frombytes(r: &mut Poly, a: &[u8]) {
    for i in 0..N / 4 {
        r.coeffs[4*i+0] = (((a[5*i+0] as u16) >> 0) | ((a[5*i+1] as u16) << 8)) & 0x1FFF;
        r.coeffs[4*i+1] = (((a[5*i+1] as u16) >> 5) | ((a[5*i+2] as u16) << 3)) & 0x1FFF;
        r.coeffs[4*i+2] = (((a[5*i+2] as u16) >> 2) | ((a[5*i+3] as u16) << 6)) & 0x1FFF;
        r.coeffs[4*i+3] = (((a[5*i+3] as u16) >> 7) | ((a[5*i+4] as u16) << 1)) & 0x1FFF;
    }
}

/// Pack a polynomial vector into a byte array
pub fn polyvec_tobytes(r: &mut [u8], a: &PolyVec) {
    let k = a.vec.len();
    for i in 0..k {
        poly_tobytes(&mut r[i * 320..(i+1) * 320], &a.vec[i]);
    }
}

/// Unpack a byte array into a polynomial vector
pub fn polyvec_frombytes(r: &mut PolyVec, a: &[u8]) {
    let k = r.vec.len();
    for i in 0..k {
        poly_frombytes(&mut r.vec[i], &a[i * 320..(i+1) * 320]);
    }
}

// ### Testing Functions

/// Check if a polynomial is zero
pub fn poly_is_zero(a: &Poly) -> bool {
    for i in 0..N {
        if a.coeffs[i] != 0 {
            return false;
        }
    }
    true
}

/// Compare two polynomials for equality
pub fn poly_equals(a: &Poly, b: &Poly) -> bool {
    for i in 0..N {
        if a.coeffs[i] != b.coeffs[i] {
            return false;
        }
    }
    true
}

// ### Unit Tests

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_poly_operations() {
        let mut a = Poly::new();
        let mut b = Poly::new();
        for i in 0..N {
            a.coeffs[i] = (i as i16) % Q;
            b.coeffs[i] = ((2 * i) as i16) % Q;
        }
        let mut c = a.clone();
        c.add(&b);
        for i in 0..N {
            let expected = barrett_reduce(a.coeffs[i] + b.coeffs[i]);
            assert_eq!(c.coeffs[i], expected);
        }
        let mut d = a.clone();
        d.sub(&b);
        for i in 0..N {
            let expected = barrett_reduce(a.coeffs[i] - b.coeffs[i]);
            assert_eq!(d.coeffs[i], expected);
        }
    }

    #[test]
    fn test_ntt() {
        let mut a = Poly::new();
        for i in 0..N {
            a.coeffs[i] = i as i16;
        }
        let orig = a.clone();
        ntt(&mut a);
        invntt(&mut a);
        assert!(poly_equals(&a, &orig));
    }

    #[test]
    fn test_sampling() {
        let seed = [0u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut a = Poly::new();
        poly_uniform(&mut a, &mut rng);
        for i in 0..N {
            assert!(a.coeffs[i] >= 0 && a.coeffs[i] < Q);
        }
    }

    #[test]
    fn test_message_conversion() {
        let mut msg = [0u8; 32];
        for i in 0..32 {
            msg[i] = i as u8;
        }
        let mut a = Poly::new();
        poly_frommsg(&mut a, &msg);
        let mut msg2 = [0u8; 32];
        poly_tomsg(&mut msg2, &a);
        assert_eq!(msg, msg2);
    }

    #[test]
    fn test_compression() {
        let mut a = Poly::new();
        for i in 0..N {
            a.coeffs[i] = (i as i16) % Q;
        }
        let mut buf = vec![0u8; N / 2];
        poly_compress(&a, &mut buf, 4);
        let mut b = Poly::new();
        poly_decompress(&mut b, &buf, 4);
        for i in 0..N {
            let diff = (a.coeffs[i] - b.coeffs[i]).abs();
            assert!(diff < 150);
        }
    }
}
