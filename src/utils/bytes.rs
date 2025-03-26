//! # Byte Manipulation Utilities
//!
//! This module provides utilities for working with bytes and byte arrays,
//! including conversion functions, encoding/decoding utilities, and other
//! helpers for cryptographic operations.

use std::fmt;
use byteorder::{ByteOrder, LittleEndian, BigEndian};
use base64;

/// Trait for types that can be converted to and from bytes
pub trait ByteConversion: Sized {
    /// Convert the value to a byte array
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Convert from a byte array to a value
    fn from_bytes(bytes: &[u8]) -> Option<Self>;
}

/// Error that occurs during byte conversion operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteError {
    /// Input data was not the expected length
    InvalidLength,
    
    /// Input data had an invalid format
    InvalidFormat,
    
    /// The conversion operation is not supported
    UnsupportedOperation,
}

impl fmt::Display for ByteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "Input data has invalid length"),
            Self::InvalidFormat => write!(f, "Input data has invalid format"),
            Self::UnsupportedOperation => write!(f, "Operation not supported"),
        }
    }
}

impl std::error::Error for ByteError {}

/// Result type for byte operations
pub type Result<T> = std::result::Result<T, ByteError>;

// ## Primitive Type Conversions

/// Convert a type to its byte representation
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::to_bytes;
///
/// let value: u32 = 0x12345678;
/// let bytes = to_bytes(&value);
/// assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12]);
/// ```
pub fn to_bytes<T: ByteConversion>(value: &T) -> Vec<u8> {
    value.to_bytes()
}

/// Convert from byte representation to a value
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::from_bytes;
///
/// let bytes = [0x78, 0x56, 0x34, 0x12];
/// let value: Option<u32> = from_bytes(&bytes);
/// assert_eq!(value, Some(0x12345678));
/// ```
pub fn from_bytes<T: ByteConversion>(bytes: &[u8]) -> Option<T> {
    T::from_bytes(bytes)
}

// Implement ByteConversion for primitive types
impl ByteConversion for u16 {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 2];
        LittleEndian::write_u16(&mut bytes, *self);
        bytes
    }
    
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= 2 {
            Some(LittleEndian::read_u16(bytes))
        } else {
            None
        }
    }
}

impl ByteConversion for u32 {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 4];
        LittleEndian::write_u32(&mut bytes, *self);
        bytes
    }
    
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= 4 {
            Some(LittleEndian::read_u32(bytes))
        } else {
            None
        }
    }
}

impl ByteConversion for u64 {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 8];
        LittleEndian::write_u64(&mut bytes, *self);
        bytes
    }
    
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= 8 {
            Some(LittleEndian::read_u64(bytes))
        } else {
            None
        }
    }
}

impl ByteConversion for i16 {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 2];
        LittleEndian::write_i16(&mut bytes, *self);
        bytes
    }
    
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= 2 {
            Some(LittleEndian::read_i16(bytes))
        } else {
            None
        }
    }
}

impl ByteConversion for i32 {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 4];
        LittleEndian::write_i32(&mut bytes, *self);
        bytes
    }
    
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= 4 {
            Some(LittleEndian::read_i32(bytes))
        } else {
            None
        }
    }
}

impl ByteConversion for i64 {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 8];
        LittleEndian::write_i64(&mut bytes, *self);
        bytes
    }
    
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= 8 {
            Some(LittleEndian::read_i64(bytes))
        } else {
            None
        }
    }
}

impl ByteConversion for f32 {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 4];
        LittleEndian::write_f32(&mut bytes, *self);
        bytes
    }
    
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= 4 {
            Some(LittleEndian::read_f32(bytes))
        } else {
            None
        }
    }
}

impl ByteConversion for f64 {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 8];
        LittleEndian::write_f64(&mut bytes, *self);
        bytes
    }
    
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= 8 {
            Some(LittleEndian::read_f64(bytes))
        } else {
            None
        }
    }
}

impl<const N: usize> ByteConversion for [u8; N] {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= N {
            let mut result = [0u8; N];
            result.copy_from_slice(&bytes[..N]);
            Some(result)
        } else {
            None
        }
    }
}

impl ByteConversion for String {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        String::from_utf8(bytes.to_vec()).ok()
    }
}

// ## Encoding and Decoding Functions

/// Encode a byte slice as a hexadecimal string
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::to_hex;
///
/// let bytes = [0x01, 0x23, 0x45, 0x67];
/// let hex = to_hex(&bytes);
/// assert_eq!(hex, "01234567");
/// ```
pub fn to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode a hexadecimal string to bytes
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::from_hex;
///
/// let hex = "01234567";
/// let bytes = from_hex(hex).unwrap();
/// assert_eq!(bytes, [0x01, 0x23, 0x45, 0x67]);
/// ```
pub fn from_hex(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(ByteError::InvalidLength);
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|_| ByteError::InvalidFormat)?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Encode data as base64
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::to_base64;
///
/// let data = b"test";
/// let encoded = to_base64(data);
/// assert_eq!(encoded, "dGVzdA==");
/// ```
pub fn to_base64(data: &[u8]) -> String {
    base64::encode(data)
}

/// Decode base64 data
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::from_base64;
///
/// let encoded = "dGVzdA==";
/// let decoded = from_base64(encoded).unwrap();
/// assert_eq!(decoded, b"test");
/// ```
pub fn from_base64(data: &str) -> Result<Vec<u8>> {
    base64::decode(data).map_err(|_| ByteError::InvalidFormat)
}

// ## Byte Manipulation Functions

/// Extract a u16 value from a byte slice in little-endian order
pub fn read_u16_le(bytes: &[u8]) -> Result<u16> {
    if bytes.len() < 2 {
        return Err(ByteError::InvalidLength);
    }
    Ok(LittleEndian::read_u16(bytes))
}

/// Extract a u32 value from a byte slice in little-endian order
pub fn read_u32_le(bytes: &[u8]) -> Result<u32> {
    if bytes.len() < 4 {
        return Err(ByteError::InvalidLength);
    }
    Ok(LittleEndian::read_u32(bytes))
}

/// Extract a u64 value from a byte slice in little-endian order
pub fn read_u64_le(bytes: &[u8]) -> Result<u64> {
    if bytes.len() < 8 {
        return Err(ByteError::InvalidLength);
    }
    Ok(LittleEndian::read_u64(bytes))
}

/// Extract a u16 value from a byte slice in big-endian order
pub fn read_u16_be(bytes: &[u8]) -> Result<u16> {
    if bytes.len() < 2 {
        return Err(ByteError::InvalidLength);
    }
    Ok(BigEndian::read_u16(bytes))
}

/// Extract a u32 value from a byte slice in big-endian order
pub fn read_u32_be(bytes: &[u8]) -> Result<u32> {
    if bytes.len() < 4 {
        return Err(ByteError::InvalidLength);
    }
    Ok(BigEndian::read_u32(bytes))
}

/// Extract a u64 value from a byte slice in big-endian order
pub fn read_u64_be(bytes: &[u8]) -> Result<u64> {
    if bytes.len() < 8 {
        return Err(ByteError::InvalidLength);
    }
    Ok(BigEndian::read_u64(bytes))
}

/// Write a u16 value to a byte array in little-endian order
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::write_u16_le;
///
/// let mut bytes = [0u8; 2];
/// write_u16_le(&mut bytes, 0x5678).unwrap();
/// assert_eq!(bytes, [0x78, 0x56]);
/// ```
pub fn write_u16_le(bytes: &mut [u8], value: u16) -> Result<()> {
    if bytes.len() < 2 {
        return Err(ByteError::InvalidLength);
    }
    LittleEndian::write_u16(bytes, value);
    Ok(())
}

/// Write a u32 value to a byte array in little-endian order
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::write_u32_le;
///
/// let mut bytes = [0u8; 4];
/// write_u32_le(&mut bytes, 0x12345678).unwrap();
/// assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12]);
/// ```
pub fn write_u32_le(bytes: &mut [u8], value: u32) -> Result<()> {
    if bytes.len() < 4 {
        return Err(ByteError::InvalidLength);
    }
    LittleEndian::write_u32(bytes, value);
    Ok(())
}

/// Write a u64 value to a byte array in little-endian order
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::write_u64_le;
///
/// let mut bytes = [0u8; 8];
/// write_u64_le(&mut bytes, 0x89ABCDEF12345678).unwrap();
/// assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x89]);
/// ```
pub fn write_u64_le(bytes: &mut [u8], value: u64) -> Result<()> {
    if bytes.len() < 8 {
        return Err(ByteError::InvalidLength);
    }
    LittleEndian::write_u64(bytes, value);
    Ok(())
}

/// Write a u16 value to a byte array in big-endian order
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::write_u16_be;
///
/// let mut bytes = [0u8; 2];
/// write_u16_be(&mut bytes, 0x5678).unwrap();
/// assert_eq!(bytes, [0x56, 0x78]);
/// ```
pub fn write_u16_be(bytes: &mut [u8], value: u16) -> Result<()> {
    if bytes.len() < 2 {
        return Err(ByteError::InvalidLength);
    }
    BigEndian::write_u16(bytes, value);
    Ok(())
}

/// Write a u32 value to a byte array in big-endian order
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::write_u32_be;
///
/// let mut bytes = [0u8; 4];
/// write_u32_be(&mut bytes, 0x12345678).unwrap();
/// assert_eq!(bytes, [0x12, 0x34, 0x56, 0x78]);
/// ```
pub fn write_u32_be(bytes: &mut [u8], value: u32) -> Result<()> {
    if bytes.len() < 4 {
        return Err(ByteError::InvalidLength);
    }
    BigEndian::write_u32(bytes, value);
    Ok(())
}

/// Write a u64 value to a byte array in big-endian order
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::write_u64_be;
///
/// let mut bytes = [0u8; 8];
/// write_u64_be(&mut bytes, 0x89ABCDEF12345678).unwrap();
/// assert_eq!(bytes, [0x89, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78]);
/// ```
pub fn write_u64_be(bytes: &mut [u8], value: u64) -> Result<()> {
    if bytes.len() < 8 {
        return Err(ByteError::InvalidLength);
    }
    BigEndian::write_u64(bytes, value);
    Ok(())
}

/// Zero out a byte slice
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::zero_out;
///
/// let mut data = vec![1, 2, 3];
/// zero_out(&mut data);
/// assert_eq!(data, vec![0, 0, 0]);
/// ```
pub fn zero_out(bytes: &mut [u8]) {
    bytes.fill(0);
}

/// Fill a byte slice with a specific value
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::fill;
///
/// let mut data = vec![0; 3];
/// fill(&mut data, 0xFF);
/// assert_eq!(data, vec![0xFF, 0xFF, 0xFF]);
/// ```
pub fn fill(bytes: &mut [u8], value: u8) {
    bytes.fill(value);
}

/// Copy bytes from one slice to another with bounds checking
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::copy_bytes;
///
/// let src = [1, 2, 3, 4];
/// let mut dst = [0; 2];
/// let copied = copy_bytes(&mut dst, &src);
/// assert_eq!(dst, [1, 2]);
/// assert_eq!(copied, 2);
/// ```
pub fn copy_bytes(dst: &mut [u8], src: &[u8]) -> usize {
    let len = dst.len().min(src.len());
    dst[..len].copy_from_slice(&src[..len]);
    len
}

/// Compare two byte slices in constant time
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::constant_time_eq;
///
/// let a = [1, 2, 3];
/// let b = [1, 2, 3];
/// assert!(constant_time_eq(&a, &b));
/// assert!(!constant_time_eq(&a, &[1, 2, 4]));
/// ```
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Rotate a byte array left by n bits
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::rotate_left;
///
/// let mut bytes = [0x01, 0x02];
/// rotate_left(&mut bytes, 8);
/// assert_eq!(bytes, [0x02, 0x01]);
/// ```
pub fn rotate_left(bytes: &mut [u8], n: usize) {
    if bytes.is_empty() || n == 0 {
        return;
    }
    let n = n % (bytes.len() * 8);
    let byte_shift = n / 8;
    let bit_shift = n % 8;
    if bit_shift == 0 {
        bytes.rotate_left(byte_shift);
    } else {
        let mut temp = bytes.to_vec();
        for i in 0..bytes.len() {
            let prev_idx = (i + bytes.len() - byte_shift - 1) % bytes.len();
            let curr_idx = (i + bytes.len() - byte_shift) % bytes.len();
            bytes[i] = (temp[curr_idx] << bit_shift) | (temp[prev_idx] >> (8 - bit_shift));
        }
    }
}

/// Rotate a byte array right by n bits
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::rotate_right;
///
/// let mut bytes = [0x01, 0x02];
/// rotate_right(&mut bytes, 8);
/// assert_eq!(bytes, [0x02, 0x01]);
/// ```
pub fn rotate_right(bytes: &mut [u8], n: usize) {
    if bytes.is_empty() || n == 0 {
        return;
    }
    let n = n % (bytes.len() * 8);
    rotate_left(bytes, bytes.len() * 8 - n);
}

/// Extract bits from a byte array
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::extract_bits;
///
/// let bytes = [0b10101010, 0b11001100];
/// let bits = extract_bits(&bytes, 2, 4).unwrap();
/// assert_eq!(bits, [0b1010]);
/// ```
pub fn extract_bits(bytes: &[u8], start_bit: usize, num_bits: usize) -> Result<Vec<u8>> {
    if start_bit + num_bits > bytes.len() * 8 {
        return Err(ByteError::InvalidLength);
    }
    let mut result = vec![0; (num_bits + 7) / 8];
    for i in 0..num_bits {
        let bit_idx = start_bit + i;
        let byte_idx = bit_idx / 8;
        let bit_pos = bit_idx % 8;
        let bit = (bytes[byte_idx] >> bit_pos) & 1;
        result[i / 8] |= bit << (i % 8);
    }
    Ok(result)
}

/// Pack bits into a byte array
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::pack_bits;
///
/// let bits = [true, false, true];
/// let bytes = pack_bits(&bits);
/// assert_eq!(bytes, [0b101]);
/// ```
pub fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let mut result = vec![0; (bits.len() + 7) / 8];
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            result[i / 8] |= 1 << (i % 8);
        }
    }
    Ok(result)
}

/// Unpack bits from a byte array
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::unpack_bits;
///
/// let bytes = [0b101];
/// let bits = unpack_bits(&bytes, 3);
/// assert_eq!(bits, vec![true, false, true]);
/// ```
pub fn unpack_bits(bytes: &[u8], num_bits: usize) -> Vec<bool> {
    let mut result = Vec::with_capacity(num_bits);
    for i in 0..num_bits {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        result.push(byte_idx < bytes.len() && (bytes[byte_idx] & (1 << bit_idx)) != 0);
    }
    result
}

// ## Byte Array Utilities

/// Concatenate multiple byte slices
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::concat;
///
/// let slices = [&[1, 2][..], &[3][..]];
/// let result = concat(&slices);
/// assert_eq!(result, vec![1, 2, 3]);
/// ```
pub fn concat(slices: &[&[u8]]) -> Vec<u8> {
    let mut result = Vec::new();
    for slice in slices {
        result.extend_from_slice(slice);
    }
    result
}

/// Split a byte slice into chunks
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::chunk;
///
/// let data = [1, 2, 3, 4, 5];
/// let chunks = chunk(&data, 2);
/// assert_eq!(chunks, vec![&[1, 2][..], &[3, 4][..], &[5][..]]);
/// ```
pub fn chunk(data: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    if chunk_size == 0 {
        return vec![];
    }
    (0..data.len()).step_by(chunk_size).map(|i| {
        &data[i..(i + chunk_size).min(data.len())]
    }).collect()
}

/// XOR two byte slices
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::xor;
///
/// let a = [0x1, 0x2];
/// let b = [0x3, 0x4];
/// let result = xor(&a, &b);
/// assert_eq!(result, vec![0x2, 0x6]);
/// ```
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    let len = a.len().min(b.len());
    a[..len].iter().zip(&b[..len]).map(|(&x, &y)| x ^ y).collect()
}

/// XOR a byte slice with a single byte
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::xor_with_byte;
///
/// let data = [0x1, 0x2];
/// let result = xor_with_byte(&data, 0xFF);
/// assert_eq!(result, vec![0xFE, 0xFD]);
/// ```
pub fn xor_with_byte(data: &[u8], value: u8) -> Vec<u8> {
    data.iter().map(|&x| x ^ value).collect()
}

/// Find a pattern in a byte slice
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::find_pattern;
///
/// let data = [1, 2, 3, 4];
/// let pattern = [2, 3];
/// assert_eq!(find_pattern(&data, &pattern), Some(1));
/// ```
pub fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() {
        return Some(0);
    }
    data.windows(pattern.len()).position(|w| w == pattern)
}

/// Replace all occurrences of a pattern in a byte slice
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::replace_pattern;
///
/// let data = [1, 2, 3, 2, 3];
/// let result = replace_pattern(&data, &[2, 3], &[4, 5]);
/// assert_eq!(result, vec![1, 4, 5, 4, 5]);
/// ```
pub fn replace_pattern(data: &[u8], pattern: &[u8], replacement: &[u8]) -> Vec<u8> {
    if pattern.is_empty() {
        return data.to_vec();
    }
    let mut result = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i..].starts_with(pattern) {
            result.extend_from_slice(replacement);
            i += pattern.len();
        } else {
            result.push(data[i]);
            i += 1;
        }
    }
    result
}

/// Pad a byte slice to a specific length
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::pad_to_length;
///
/// let data = vec![1, 2];
/// let padded = pad_to_length(&data, 4, 0);
/// assert_eq!(padded, vec![1, 2, 0, 0]);
/// ```
pub fn pad_to_length(data: &[u8], target_length: usize, padding: u8) -> Vec<u8> {
    let mut result = data.to_vec();
    if result.len() < target_length {
        result.resize(target_length, padding);
    }
    result
}

/// Apply PKCS#7 padding
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::pad_pkcs7;
///
/// let data = vec![1, 2, 3];
/// let padded = pad_pkcs7(&data, 5);
/// assert_eq!(padded, vec![1, 2, 3, 2, 2]);
/// ```
pub fn pad_pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
    if block_size == 0 || block_size > 255 {
        return data.to_vec();
    }
    let padding_len = block_size - (data.len() % block_size);
    let mut result = data.to_vec();
    result.extend(vec![padding_len as u8; padding_len]);
    result
}

/// Remove PKCS#7 padding
///
/// # Examples
///
/// ```rust
/// use neonvault_crypto::utils::bytes::{pad_pkcs7, unpad_pkcs7};
///
/// let data = vec![1, 2, 3];
/// let padded = pad_pkcs7(&data, 5);
/// let unpadded = unpad_pkcs7(&padded).unwrap();
/// assert_eq!(unpadded, vec![1, 2, 3]);
/// ```
pub fn unpad_pkcs7(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(ByteError::InvalidLength);
    }
    let padding_len = *data.last().unwrap() as usize;
    if padding_len == 0 || padding_len > data.len() || padding_len > 255 {
        return Err(ByteError::InvalidFormat);
    }
    if data[data.len() - padding_len..].iter().all(|&x| x == padding_len as u8) {
        Ok(data[..data.len() - padding_len].to_vec())
    } else {
        Err(ByteError::InvalidFormat)
    }
}

// ## Unit Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_conversion() {
        let val: u32 = 0x12345678;
        let bytes = to_bytes(&val);
        assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(from_bytes::<u32>(&bytes), Some(val));
    }

    #[test]
    fn test_hex() {
        let data = [0xAB, 0xCD];
        let hex = to_hex(&data);
        assert_eq!(hex, "abcd");
        assert_eq!(from_hex(&hex).unwrap(), data);
    }

    #[test]
    fn test_base64() {
        let data = b"test";
        let encoded = to_base64(data);
        assert_eq!(encoded, "dGVzdA==");
        assert_eq!(from_base64(&encoded).unwrap(), data);
    }

    #[test]
    fn test_read_write() {
        let mut bytes = [0u8; 8];
        write_u32_le(&mut bytes[..4], 0x12345678).unwrap();
        assert_eq!(bytes[..4], [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(read_u32_le(&bytes[..4]).unwrap(), 0x12345678);

        write_u64_be(&mut bytes, 0x89ABCDEF12345678).unwrap();
        assert_eq!(bytes, [0x89, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_memory_ops() {
        let mut data = vec![1, 2, 3];
        zero_out(&mut data);
        assert_eq!(data, vec![0, 0, 0]);

        fill(&mut data, 0xFF);
        assert_eq!(data, vec![0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(&[1, 2], &[1, 2]));
        assert!(!constant_time_eq(&[1, 2], &[1, 3]));
    }

    #[test]
    fn test_padding() {
        let data = vec![1, 2, 3];
        let padded = pad_pkcs7(&data, 5);
        assert_eq!(padded, vec![1, 2, 3, 2, 2]);
        assert_eq!(unpad_pkcs7(&padded).unwrap(), data);
    }
}
