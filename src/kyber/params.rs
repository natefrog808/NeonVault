//! Parameters for CRYSTALS-KYBER
//!
//! This module defines all the necessary parameters for the CRYSTALS-KYBER
//! post-quantum key encapsulation mechanism as specified in FIPS 203.
//!
//! The parameters determine the security level, performance characteristics,
//! and other properties of the KYBER algorithm.

// ### General Parameters

/// Polynomial degree (number of coefficients in each polynomial, fixed across all variants)
pub const N: usize = 256;

/// Modulus (prime number defining the ring R_q = Z_q[X]/(X^n + 1))
pub const Q: u16 = 3329;

/// Montgomery reduction constant R mod Q, where R = 2^16
pub const MONT: u16 = 2285;

/// Montgomery reduction constant R^2 mod Q
pub const MONT2: u16 = 1353;

/// Modular multiplicative inverse of Q mod 2^16
pub const QINV: u16 = 3327;

// ### Security Level Identifiers

/// Symbolic constant for KYBER-512 security level
pub const KYBER_512: u8 = 2;

/// Symbolic constant for KYBER-768 security level (default for NeonVault)
pub const KYBER_768: u8 = 3;

/// Symbolic constant for KYBER-1024 security level
pub const KYBER_1024: u8 = 4;

// ### Module Rank (k) Parameters

/// Module rank k for KYBER-512
pub const KYBER512_K: usize = 2;

/// Module rank k for KYBER-768
pub const KYBER768_K: usize = 3;

/// Module rank k for KYBER-1024
pub const KYBER1024_K: usize = 4;

// ### Noise Parameters

/// Noise parameter eta1 for KYBER-512 and KYBER-768 (used in CBD sampling)
pub const KYBER_ETA1: u8 = 3;

/// Noise parameter eta1 for KYBER-1024 (used in CBD sampling)
pub const KYBER1024_ETA1: u8 = 2;

/// Noise parameter eta2 for all security levels (used in CBD sampling)
pub const KYBER_ETA2: u8 = 2;

// ### Size Constants

/// Size of random seed in bytes (used for key generation and hashing)
pub const KYBER_SYMBYTES: usize = 32;

/// Size of a single polynomial in bytes (compressed format, 12 bits per coefficient)
pub const KYBER_POLYBYTES: usize = 384;

/// Size of a single polynomial in compressed format for messages (32 bytes)
pub const KYBER_INDCPA_MSGBYTES: usize = 32;

// ### KYBER-512 Specific Parameters

/// Size of public key for KYBER-512 in bytes (k * 384 + 32)
pub const KYBER512_PUBLICKEYBYTES: usize = KYBER512_K * KYBER_POLYBYTES + KYBER_SYMBYTES;

/// Size of IND-CPA secret key for KYBER-512 in bytes (k * 384)
pub const KYBER512_SECRETKEYBYTES: usize = KYBER512_K * KYBER_POLYBYTES;

/// Size of ciphertext for KYBER-512 in bytes (k * 384 + 384)
pub const KYBER512_CIPHERTEXTBYTES: usize = KYBER512_K * KYBER_POLYBYTES + KYBER_POLYBYTES;

/// Size of full secret key for KYBER-512 (IND-CPA sk + pk + z + H(pk))
pub const KYBER512_FULLSECRETKEYBYTES: usize = KYBER512_SECRETKEYBYTES +
                                               KYBER512_PUBLICKEYBYTES +
                                               2 * KYBER_SYMBYTES;

// ### KYBER-768 Specific Parameters

/// Size of public key for KYBER-768 in bytes (k * 384 + 32)
pub const KYBER768_PUBLICKEYBYTES: usize = KYBER768_K * KYBER_POLYBYTES + KYBER_SYMBYTES;

/// Size of IND-CPA secret key for KYBER-768 in bytes (k * 384)
pub const KYBER768_SECRETKEYBYTES: usize = KYBER768_K * KYBER_POLYBYTES;

/// Size of ciphertext for KYBER-768 in bytes (k * 384 + 384)
pub const KYBER768_CIPHERTEXTBYTES: usize = KYBER768_K * KYBER_POLYBYTES + KYBER_POLYBYTES;

/// Size of full secret key for KYBER-768 (IND-CPA sk + pk + z + H(pk))
pub const KYBER768_FULLSECRETKEYBYTES: usize = KYBER768_SECRETKEYBYTES +
                                               KYBER768_PUBLICKEYBYTES +
                                               2 * KYBER_SYMBYTES;

// ### KYBER-1024 Specific Parameters

/// Size of public key for KYBER-1024 in bytes (k * 384 + 32)
pub const KYBER1024_PUBLICKEYBYTES: usize = KYBER1024_K * KYBER_POLYBYTES + KYBER_SYMBYTES;

/// Size of IND-CPA secret key for KYBER-1024 in bytes (k * 384)
pub const KYBER1024_SECRETKEYBYTES: usize = KYBER1024_K * KYBER_POLYBYTES;

/// Size of ciphertext for KYBER-1024 in bytes (k * 384 + 384)
pub const KYBER1024_CIPHERTEXTBYTES: usize = KYBER1024_K * KYBER_POLYBYTES + KYBER_POLYBYTES;

/// Size of full secret key for KYBER-1024 (IND-CPA sk + pk + z + H(pk))
pub const KYBER1024_FULLSECRETKEYBYTES: usize = KYBER1024_SECRETKEYBYTES +
                                                KYBER1024_PUBLICKEYBYTES +
                                                2 * KYBER_SYMBYTES;

// ### Default Parameters (KYBER-768)

/// Size of polynomial vector in bytes (default: KYBER-768)
pub const KYBER_POLYVECBYTES: usize = KYBER768_K * KYBER_POLYBYTES;

/// Size of public key in bytes (default: KYBER-768)
pub const KYBER_PUBLICKEYBYTES: usize = KYBER768_PUBLICKEYBYTES;

/// Size of secret key in bytes (default: KYBER-768, full KEM secret key)
pub const KYBER_SECRETKEYBYTES: usize = KYBER768_FULLSECRETKEYBYTES;

/// Size of ciphertext in bytes (default: KYBER-768)
pub const KYBER_CIPHERTEXTBYTES: usize = KYBER768_CIPHERTEXTBYTES;

// ### NTT-Related Constants

/// Number of bits in Q (log2(Q) rounded up)
pub const KYBER_Q_BITS: u32 = 12;

/// Precomputed zetas table for forward NTT operations
pub const KYBER_NTT_ZETAS: [i16; 128] = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
    2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
    732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
    1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
    107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
    430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
    1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
    418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
    1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
    478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628,
];

/// Precomputed inverse zetas table for inverse NTT operations
pub const KYBER_NTT_ZETAS_INV: [i16; 128] = [
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,
    1278, 1530, 1185, 1659, 1187, 3109, 2266, 2007, 486, 2591, 2221, 2409, 3012,
    1260, 2143, 1691, 2081, 721, 3297, 1162, 1153, 1768, 2250, 2125, 1230, 2110,
    1926, 1343, 2553, 2176, 1828, 1902, 2079, 1789, 1927, 2083, 779, 1436, 2881,
    2039, 846, 1217, 2209, 1618, 1977, 683, 1095, 2881, 2767, 1245, 1246, 1981,
    1170, 1375, 3207, 1561, 1464, 2050, 2266, 983, 1870, 2033, 1863, 1726, 411,
    3248, 757, 2885, 3039, 3050, 414, 993, 2856, 3074, 3275, 3136, 246, 1098,
    824, 2998, 2655, 1267, 1305, 1618, 1943, 955, 1766, 1723, 1213, 2279, 1046,
    2654, 1902, 1974, 536, 1301, 2817, 2106, 1293, 1924, 3143, 1031, 90, 3161,
    133, 1461, 2811, 1755, 1458, 1470, 2731, 1420, 2506,
];

// ### Compression/Decompression Parameters (Default: KYBER-768)

/// Number of bits for compressing the polynomial vector in the public key/ciphertext (default)
pub const KYBER_DU: u32 = 10;

/// Number of bits for compressing the polynomial element in the ciphertext (default)
pub const KYBER_DV: u32 = 4;

// ### Dynamic Parameter Functions

/// Get the module rank k for the specified security level
///
/// **Arguments:**
/// - `security_level`: The security level (KYBER_512, KYBER_768, or KYBER_1024)
///
/// **Returns:**
/// The module rank k for the specified security level
pub fn get_k(security_level: u8) -> usize {
    match security_level {
        KYBER_512 => KYBER512_K,
        KYBER_768 => KYBER768_K,
        KYBER_1024 => KYBER1024_K,
        _ => panic!("Invalid security level"),
    }
}

/// Get the noise parameter eta1 for the specified security level
///
/// **Arguments:**
/// - `security_level`: The security level (KYBER_512, KYBER_768, or KYBER_1024)
///
/// **Returns:**
/// The noise parameter eta1 for the specified security level
pub fn get_eta1(security_level: u8) -> u8 {
    match security_level {
        KYBER_512 => KYBER_ETA1,
        KYBER_768 => KYBER_ETA1,
        KYBER_1024 => KYBER1024_ETA1,
        _ => panic!("Invalid security level"),
    }
}

/// Get the public key size for the specified security level
///
/// **Arguments:**
/// - `security_level`: The security level (KYBER_512, KYBER_768, or KYBER_1024)
///
/// **Returns:**
/// The public key size in bytes for the specified security level
pub fn get_publickeybytes(security_level: u8) -> usize {
    match security_level {
        KYBER_512 => KYBER512_PUBLICKEYBYTES,
        KYBER_768 => KYBER768_PUBLICKEYBYTES,
        KYBER_1024 => KYBER1024_PUBLICKEYBYTES,
        _ => panic!("Invalid security level"),
    }
}

/// Get the secret key size for the specified security level
///
/// **Arguments:**
/// - `security_level`: The security level (KYBER_512, KYBER_768, or KYBER_1024)
///
/// **Returns:**
/// The full secret key size in bytes for the specified security level
pub fn get_secretkeybytes(security_level: u8) -> usize {
    match security_level {
        KYBER_512 => KYBER512_FULLSECRETKEYBYTES,
        KYBER_768 => KYBER768_FULLSECRETKEYBYTES,
        KYBER_1024 => KYBER1024_FULLSECRETKEYBYTES,
        _ => panic!("Invalid security level"),
    }
}

/// Get the ciphertext size for the specified security level
///
/// **Arguments:**
/// - `security_level`: The security level (KYBER_512, KYBER_768, or KYBER_1024)
///
/// **Returns:**
/// The ciphertext size in bytes for the specified security level
pub fn get_ciphertextbytes(security_level: u8) -> usize {
    match security_level {
        KYBER_512 => KYBER512_CIPHERTEXTBYTES,
        KYBER_768 => KYBER768_CIPHERTEXTBYTES,
        KYBER_1024 => KYBER1024_CIPHERTEXTBYTES,
        _ => panic!("Invalid security level"),
    }
}

/// Get the polynomial vector size for the specified security level
///
/// **Arguments:**
/// - `security_level`: The security level (KYBER_512, KYBER_768, or KYBER_1024)
///
/// **Returns:**
/// The polynomial vector size in bytes for the specified security level
pub fn get_polyvecbytes(security_level: u8) -> usize {
    get_k(security_level) * KYBER_POLYBYTES
}

/// Get the du value (compression bits for u vector) for the specified security level
///
/// **Arguments:**
/// - `security_level`: The security level (KYBER_512, KYBER_768, or KYBER_1024)
///
/// **Returns:**
/// The number of bits for compressing the u vector in the ciphertext
pub fn get_du(security_level: u8) -> u32 {
    match security_level {
        KYBER_512 => 10,
        KYBER_768 => 10,
        KYBER_1024 => 11,
        _ => panic!("Invalid security level"),
    }
}

/// Get the dv value (compression bits for v polynomial) for the specified security level
///
/// **Arguments:**
/// - `security_level`: The security level (KYBER_512, KYBER_768, or KYBER_1024)
///
/// **Returns:**
/// The number of bits for compressing the v polynomial in the ciphertext
pub fn get_dv(security_level: u8) -> u32 {
    match security_level {
        KYBER_512 => 4,
        KYBER_768 => 4,
        KYBER_1024 => 5,
        _ => panic!("Invalid security level"),
    }
}

// ### Compression/Decompression Helper Functions

/// Calculate compression factor for a given bit size
///
/// **Arguments:**
/// - `bits`: The number of bits to compress to
///
/// **Returns:**
/// The compression factor (Q / 2^bits)
pub fn compression_factor(bits: u32) -> u32 {
    (Q as u32) / (1 << bits)
}

/// Compress a coefficient to a specified number of bits
///
/// **Arguments:**
/// - `x`: The coefficient to compress (in Z_q)
/// - `bits`: The number of bits to compress to
///
/// **Returns:**
/// The compressed coefficient
pub fn compress(x: u16, bits: u32) -> u16 {
    let factor = compression_factor(bits);
    (((x as u32 * (1 << bits) + factor / 2) / factor) & ((1 << bits) - 1)) as u16
}

/// Decompress a coefficient from a specified number of bits
///
/// **Arguments:**
/// - `x`: The compressed coefficient
/// - `bits`: The number of bits it was compressed to
///
/// **Returns:**
/// The decompressed coefficient (approximate, in Z_q)
pub fn decompress(x: u16, bits: u32) -> u16 {
    let factor = compression_factor(bits);
    ((x as u32 * factor + (1 << (bits - 1))) >> bits) as u16
}

// ### Arithmetic Helper Functions

/// Perform Montgomery reduction
///
/// **Arguments:**
/// - `a`: The value to reduce
///
/// **Returns:**
/// The Montgomery reduced value in [-Q/2, Q/2]
pub fn montgomery_reduce(a: i32) -> i16 {
    let u = (a as u32).wrapping_mul(QINV as u32) & 0xFFFF;
    let t = u.wrapping_mul(Q as u32);
    let r = (a as u32).wrapping_sub(t) >> 16;
    if r < Q as u32 { r as i16 } else { (r - Q as u32) as i16 }
}

/// Perform Barrett reduction
///
/// **Arguments:**
/// - `a`: The value to reduce
///
/// **Returns:**
/// The Barrett reduced value in [0, Q)
pub fn barrett_reduce(a: i16) -> i16 {
    let v = ((1 << 26) + Q as i32 / 2) / Q as i32;
    let t = v.wrapping_mul((a as i32) << 10) >> 16;
    let t = t.wrapping_mul(Q as i32);
    let r = (a as i32) - t;
    if r < Q as i32 { r as i16 } else { (r - Q as i32) as i16 }
}

/// Convert a value to Montgomery form
///
/// **Arguments:**
/// - `a`: The value to convert
///
/// **Returns:**
/// The value in Montgomery form (a * R mod Q)
pub fn to_mont(a: i16) -> i16 {
    montgomery_reduce((a as i32) * (MONT2 as i32))
}

/// Perform a constant-time conditional move
///
/// **Arguments:**
/// - `a`: The first value
/// - `b`: The second value
/// - `c`: The condition (0 or 1)
///
/// **Returns:**
/// `b` if `c` is 1, otherwise `a`
pub fn cmov(a: u8, b: u8, c: u8) -> u8 {
    a ^ (c & (a ^ b))
}

// ### Tests

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that parameter retrieval functions return correct values
    #[test]
    fn test_parameter_functions() {
        // Test k values
        assert_eq!(get_k(KYBER_512), KYBER512_K);
        assert_eq!(get_k(KYBER_768), KYBER768_K);
        assert_eq!(get_k(KYBER_1024), KYBER1024_K);

        // Test eta1 values
        assert_eq!(get_eta1(KYBER_512), KYBER_ETA1);
        assert_eq!(get_eta1(KYBER_768), KYBER_ETA1);
        assert_eq!(get_eta1(KYBER_1024), KYBER1024_ETA1);

        // Test public key sizes
        assert_eq!(get_publickeybytes(KYBER_512), KYBER512_PUBLICKEYBYTES);
        assert_eq!(get_publickeybytes(KYBER_768), KYBER768_PUBLICKEYBYTES);
        assert_eq!(get_publickeybytes(KYBER_1024), KYBER1024_PUBLICKEYBYTES);

        // Test secret key sizes
        assert_eq!(get_secretkeybytes(KYBER_512), KYBER512_FULLSECRETKEYBYTES);
        assert_eq!(get_secretkeybytes(KYBER_768), KYBER768_FULLSECRETKEYBYTES);
        assert_eq!(get_secretkeybytes(KYBER_1024), KYBER1024_FULLSECRETKEYBYTES);

        // Test ciphertext sizes
        assert_eq!(get_ciphertextbytes(KYBER_512), KYBER512_CIPHERTEXTBYTES);
        assert_eq!(get_ciphertextbytes(KYBER_768), KYBER768_CIPHERTEXTBYTES);
        assert_eq!(get_ciphertextbytes(KYBER_1024), KYBER1024_CIPHERTEXTBYTES);

        // Test polynomial vector sizes
        assert_eq!(get_polyvecbytes(KYBER_512), KYBER512_K * KYBER_POLYBYTES);
        assert_eq!(get_polyvecbytes(KYBER_768), KYBER768_K * KYBER_POLYBYTES);
        assert_eq!(get_polyvecbytes(KYBER_1024), KYBER1024_K * KYBER_POLYBYTES);
    }

    /// Test that compression parameters are correct for each security level
    #[test]
    fn test_compression_parameters() {
        assert_eq!(get_du(KYBER_512), 10);
        assert_eq!(get_du(KYBER_768), 10);
        assert_eq!(get_du(KYBER_1024), 11);

        assert_eq!(get_dv(KYBER_512), 4);
        assert_eq!(get_dv(KYBER_768), 4);
        assert_eq!(get_dv(KYBER_1024), 5);
    }

    /// Test consistency of parameter values with the KYBER specification
    #[test]
    fn test_parameter_consistency() {
        // Basic parameters
        assert_eq!(N, 256);
        assert_eq!(Q, 3329);

        // KYBER-512
        assert_eq!(KYBER512_K, 2);
        assert_eq!(KYBER512_PUBLICKEYBYTES, 800); // 2 * 384 + 32
        assert_eq!(KYBER512_SECRETKEYBYTES, 768); // 2 * 384
        assert_eq!(KYBER512_CIPHERTEXTBYTES, 1152); // 2 * 384 + 384
        assert_eq!(KYBER512_FULLSECRETKEYBYTES, 1632); // 768 + 800 + 64

        // KYBER-768
        assert_eq!(KYBER768_K, 3);
        assert_eq!(KYBER768_PUBLICKEYBYTES, 1184); // 3 * 384 + 32
        assert_eq!(KYBER768_SECRETKEYBYTES, 1152); // 3 * 384
        assert_eq!(KYBER768_CIPHERTEXTBYTES, 1536); // 3 * 384 + 384
        assert_eq!(KYBER768_FULLSECRETKEYBYTES, 2400); // 1152 + 1184 + 64

        // KYBER-1024
        assert_eq!(KYBER1024_K, 4);
        assert_eq!(KYBER1024_PUBLICKEYBYTES, 1568); // 4 * 384 + 32
        assert_eq!(KYBER1024_SECRETKEYBYTES, 1536); // 4 * 384
        assert_eq!(KYBER1024_CIPHERTEXTBYTES, 1920); // 4 * 384 + 384
        assert_eq!(KYBER1024_FULLSECRETKEYBYTES, 3168); // 1536 + 1568 + 64

        // Default parameters (KYBER-768)
        assert_eq!(KYBER_POLYVECBYTES, 1152);
        assert_eq!(KYBER_PUBLICKEYBYTES, 1184);
        assert_eq!(KYBER_SECRETKEYBYTES, 2400);
        assert_eq!(KYBER_CIPHERTEXTBYTES, 1536);
    }

    /// Test NTT constants and Montgomery parameters
    #[test]
    fn test_ntt_constants() {
        assert_eq!(KYBER_NTT_ZETAS[0], 2285);
        assert_eq!(KYBER_NTT_ZETAS[127], 1628);
        assert_eq!(KYBER_NTT_ZETAS_INV[0], 1701);
        assert_eq!(KYBER_NTT_ZETAS_INV[127], 2506);
        assert_eq!(KYBER_NTT_ZETAS.len(), 128);
        assert_eq!(KYBER_NTT_ZETAS_INV.len(), 128);
        assert_eq!(MONT, 2285);
        assert_eq!(MONT2, 1353);
        assert_eq!(QINV, 3327);
    }

    /// Test that invalid security levels cause a panic
    #[test]
    #[should_panic(expected = "Invalid security level")]
    fn test_invalid_security_level() {
        get_k(5); // Invalid security level
    }

    /// Test compression and decompression functions
    #[test]
    fn test_compress_decompress() {
        let x = 1234u16;
        let bits = 4;
        let compressed = compress(x, bits);
        let decompressed = decompress(compressed, bits);
        // Compression is lossy; check that the difference is within expected bounds
        let diff = (x as i32 - decompressed as i32).abs();
        assert!(diff <= (Q as i32 / (1 << bits)), "Compression error too large");
    }
}
