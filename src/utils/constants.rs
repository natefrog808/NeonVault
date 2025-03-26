//! # Global Constants for NeonVault Crypto
//!
//! This module defines global constants used throughout the NeonVault
//! cryptographic library, including algorithm identifiers, version information,
//! cryptographic parameters, error codes, and utility functions.

/// Current version of the NeonVault Crypto library
pub const VERSION: &str = "0.1.0";

/// Build timestamp (set at compile time)
pub const BUILD_TIMESTAMP: &str = env!("CARGO_PKG_VERSION");

/// Git commit hash (set at compile time if available)
#[cfg(feature = "build-info")]
pub const GIT_COMMIT_HASH: &str = env!("GIT_HASH");

#[cfg(not(feature = "build-info"))]
pub const GIT_COMMIT_HASH: &str = "unknown";

//------------------------------------------------------------------------------
// Algorithm Identifiers
//------------------------------------------------------------------------------

/// Algorithm identifier for KYBER-512
pub const ALG_KYBER_512: u8 = 0x01;
/// Algorithm identifier for KYBER-768
pub const ALG_KYBER_768: u8 = 0x02;
/// Algorithm identifier for KYBER-1024
pub const ALG_KYBER_1024: u8 = 0x03;
/// Algorithm identifier for AES-256-GCM
pub const ALG_AES_256_GCM: u8 = 0x11;
/// Algorithm identifier for ChaCha20-Poly1305
pub const ALG_CHACHA20_POLY1305: u8 = 0x12;
/// Algorithm identifier for SHA-256
pub const ALG_SHA_256: u8 = 0x21;
/// Algorithm identifier for SHA-512
pub const ALG_SHA_512: u8 = 0x22;
/// Algorithm identifier for SHA-3-256
pub const ALG_SHA3_256: u8 = 0x23;
/// Algorithm identifier for SHA-3-512
pub const ALG_SHA3_512: u8 = 0x24;
/// Algorithm identifier for HMAC-SHA-256
pub const ALG_HMAC_SHA_256: u8 = 0x31;
/// Algorithm identifier for HMAC-SHA-512
pub const ALG_HMAC_SHA_512: u8 = 0x32;
/// Algorithm identifier for PBKDF2-HMAC-SHA-256
pub const ALG_PBKDF2_HMAC_SHA_256: u8 = 0x41;

//------------------------------------------------------------------------------
// Protocol Constants
//------------------------------------------------------------------------------

/// Magic bytes for NeonVault protocol messages ("NVLT")
pub const PROTOCOL_MAGIC: [u8; 4] = [0x4E, 0x56, 0x4C, 0x54];
/// Current protocol version
pub const PROTOCOL_VERSION: u8 = 0x01;
/// Maximum message size in bytes (1 MB)
pub const MAX_MESSAGE_SIZE: usize = 1 << 20;
/// Default buffer size for I/O operations (8 KB)
pub const DEFAULT_BUFFER_SIZE: usize = 8192;
/// Token for file transfer operations
pub const FILE_TRANSFER_TOKEN: &str = "NeonVault-File-Transfer-v1";

//------------------------------------------------------------------------------
// Cryptographic Parameters
//------------------------------------------------------------------------------

/// Size of AES-256 key in bytes
pub const AES_256_KEY_SIZE: usize = 32;
/// Size of AES-256-GCM nonce in bytes
pub const AES_256_GCM_NONCE_SIZE: usize = 12;
/// Size of AES-256-GCM tag in bytes
pub const AES_256_GCM_TAG_SIZE: usize = 16;
/// Size of ChaCha20 key in bytes
pub const CHACHA20_KEY_SIZE: usize = 32;
/// Size of ChaCha20-Poly1305 nonce in bytes
pub const CHACHA20_POLY1305_NONCE_SIZE: usize = 12;
/// Size of ChaCha20-Poly1305 tag in bytes
pub const CHACHA20_POLY1305_TAG_SIZE: usize = 16;
/// Default number of iterations for PBKDF2
pub const PBKDF2_DEFAULT_ITERATIONS: u32 = 100_000;
/// Recommended minimum number of iterations for PBKDF2
pub const PBKDF2_MIN_ITERATIONS: u32 = 10_000;
/// Size of SHA-256 digest in bytes
pub const SHA_256_DIGEST_SIZE: usize = 32;
/// Size of SHA-512 digest in bytes
pub const SHA_512_DIGEST_SIZE: usize = 64;
/// Size of SHA-3-256 digest in bytes
pub const SHA3_256_DIGEST_SIZE: usize = 32;
/// Size of SHA-3-512 digest in bytes
pub const SHA3_512_DIGEST_SIZE: usize = 64;
/// Default salt size for key derivation in bytes
pub const DEFAULT_SALT_SIZE: usize = 16;

//------------------------------------------------------------------------------
// Key Management Constants
//------------------------------------------------------------------------------

/// Key usage: encryption
pub const KEY_USAGE_ENCRYPTION: u8 = 0x01;
/// Key usage: signature
pub const KEY_USAGE_SIGNATURE: u8 = 0x02;
/// Key usage: key derivation
pub const KEY_USAGE_KEY_DERIVATION: u8 = 0x04;
/// Key usage: authentication
pub const KEY_USAGE_AUTHENTICATION: u8 = 0x08;
/// Key state: active
pub const KEY_STATE_ACTIVE: u8 = 0x01;
/// Key state: deactivated
pub const KEY_STATE_DEACTIVATED: u8 = 0x02;
/// Key state: compromised
pub const KEY_STATE_COMPROMISED: u8 = 0x03;
/// Key state: destroyed
pub const KEY_STATE_DESTROYED: u8 = 0x04;
/// Minimum acceptable key size for asymmetric keys in bits
pub const MIN_ASYMMETRIC_KEY_SIZE: usize = 2048;
/// Recommended key size for RSA keys in bits
pub const RECOMMENDED_RSA_KEY_SIZE: usize = 3072;
/// Recommended key size for elliptic curve keys in bits
pub const RECOMMENDED_EC_KEY_SIZE: usize = 256;
/// Maximum key lifetime in days for high-security deployments
pub const MAX_KEY_LIFETIME_DAYS: u32 = 365;

//------------------------------------------------------------------------------
// Authentication Constants
//------------------------------------------------------------------------------

/// Default token expiry time in seconds (1 hour)
pub const DEFAULT_TOKEN_EXPIRY: u64 = 3600;
/// Maximum token lifetime in seconds (24 hours)
pub const MAX_TOKEN_LIFETIME: u64 = 86400;
/// Minimum password length
pub const MIN_PASSWORD_LENGTH: usize = 12;
/// Number of allowed authentication attempts before lockout
pub const MAX_AUTH_ATTEMPTS: u32 = 5;
/// Account lockout duration in seconds (5 minutes)
pub const ACCOUNT_LOCKOUT_DURATION: u64 = 300;
/// Authentication token cookie name
pub const AUTH_TOKEN_COOKIE: &str = "neonvault_auth";

//------------------------------------------------------------------------------
// Network Protocol Constants
//------------------------------------------------------------------------------

/// Default port for NeonVault protocol
pub const DEFAULT_PORT: u16 = 8422;
/// Connection timeout in milliseconds
pub const CONNECTION_TIMEOUT_MS: u64 = 5000;
/// Handshake timeout in milliseconds
pub const HANDSHAKE_TIMEOUT_MS: u64 = 10000;
/// Maximum connection retries
pub const MAX_CONNECTION_RETRIES: u32 = 3;
/// Default keepalive interval in seconds
pub const KEEPALIVE_INTERVAL: u64 = 30;
/// Default message chunk size in bytes (16 KB)
pub const MESSAGE_CHUNK_SIZE: usize = 16384;
/// Maximum simultaneous connections per client
pub const MAX_SIMULTANEOUS_CONNECTIONS: u32 = 5;

//------------------------------------------------------------------------------
// Error Codes
//------------------------------------------------------------------------------

/// Error code: success
pub const ERROR_SUCCESS: i32 = 0;
/// Error code: general failure
pub const ERROR_GENERAL_FAILURE: i32 = -1;
/// Error code: invalid parameters
pub const ERROR_INVALID_PARAMETERS: i32 = -2;
/// Error code: authentication failure
pub const ERROR_AUTHENTICATION_FAILURE: i32 = -3;
/// Error code: encryption failure
pub const ERROR_ENCRYPTION_FAILURE: i32 = -4;
/// Error code: decryption failure
pub const ERROR_DECRYPTION_FAILURE: i32 = -5;
/// Error code: connection failure
pub const ERROR_CONNECTION_FAILURE: i32 = -6;
/// Error code: protocol violation
pub const ERROR_PROTOCOL_VIOLATION: i32 = -7;
/// Error code: timeout
pub const ERROR_TIMEOUT: i32 = -8;
/// Error code: resource not found
pub const ERROR_RESOURCE_NOT_FOUND: i32 = -9;
/// Error code: permission denied
pub const ERROR_PERMISSION_DENIED: i32 = -10;
/// Error code: resource busy
pub const ERROR_RESOURCE_BUSY: i32 = -11;
/// Error code: resource exhausted
pub const ERROR_RESOURCE_EXHAUSTED: i32 = -12;
/// Error code: not implemented
pub const ERROR_NOT_IMPLEMENTED: i32 = -13;

//------------------------------------------------------------------------------
// Feature Flags
//------------------------------------------------------------------------------

/// Feature flag: enable hybrid encryption
pub const FEATURE_HYBRID_ENCRYPTION: u32 = 0x00000001;
/// Feature flag: enable forward secrecy
pub const FEATURE_FORWARD_SECRECY: u32 = 0x00000002;
/// Feature flag: enable authenticated encryption
pub const FEATURE_AUTHENTICATED_ENCRYPTION: u32 = 0x00000004;
/// Feature flag: enable compression
pub const FEATURE_COMPRESSION: u32 = 0x00000008;
/// Feature flag: enable message signing
pub const FEATURE_MESSAGE_SIGNING: u32 = 0x00000010;
/// Feature flag: enable key escrow
pub const FEATURE_KEY_ESCROW: u32 = 0x00000020;
/// Feature flag: enable key rotation
pub const FEATURE_KEY_ROTATION: u32 = 0x00000040;
/// Feature flag: enable secure deletion
pub const FEATURE_SECURE_DELETION: u32 = 0x00000080;

//------------------------------------------------------------------------------
// Cyberpunk Themed Constants
//------------------------------------------------------------------------------

/// The year in the NeonVault cyberpunk narrative
pub const CYBERPUNK_YEAR: u32 = 2077;
/// Runner status: active
pub const RUNNER_STATUS_ACTIVE: u8 = 0x01;
/// Runner status: hidden
pub const RUNNER_STATUS_HIDDEN: u8 = 0x02;
/// Runner status: compromised
pub const RUNNER_STATUS_COMPROMISED: u8 = 0x03;
/// Runner status: retired
pub const RUNNER_STATUS_RETIRED: u8 = 0x04;
/// Mission status: pending
pub const MISSION_STATUS_PENDING: u8 = 0x01;
/// Mission status: active
pub const MISSION_STATUS_ACTIVE: u8 = 0x02;
/// Mission status: completed
pub const MISSION_STATUS_COMPLETED: u8 = 0x03;
/// Mission status: failed
pub const MISSION_STATUS_FAILED: u8 = 0x04;
/// Mission status: aborted
pub const MISSION_STATUS_ABORTED: u8 = 0x05;
/// Reputation threshold for Trusted level
pub const REPUTATION_THRESHOLD_TRUSTED: u32 = 100;
/// Reputation threshold for Veteran level
pub const REPUTATION_THRESHOLD_VETERAN: u32 = 500;
/// Reputation threshold for Elite level
pub const REPUTATION_THRESHOLD_ELITE: u32 = 1000;
/// Reputation threshold for Legend level
pub const REPUTATION_THRESHOLD_LEGEND: u32 = 5000;
/// Cyberpunk-themed error message for authentication failure
pub const ERROR_MESSAGE_AUTHENTICATION: &str = "ACCESS DENIED: Neural pattern mismatch detected.";
/// Cyberpunk-themed error message for encryption/decryption failure
pub const ERROR_MESSAGE_ENCRYPTION: &str = "ENCRYPTION FAILURE: Quantum interference detected.";
/// Cyberpunk-themed error message for connection/protocol issues
pub const ERROR_MESSAGE_CONNECTION: &str = "CONNECTION LOST: Corporate firewalls blocking signal.";
/// Cyberpunk-themed error message for timeouts
pub const ERROR_MESSAGE_TIMEOUT: &str = "TIMEOUT: Signal lost in the net. Trace back impossible.";
/// Cyberpunk-themed error message for resource issues
pub const ERROR_MESSAGE_RESOURCE: &str = "RESOURCE LOCKED: Corporate ICE detected on target system.";

//------------------------------------------------------------------------------
// Testing Constants
//------------------------------------------------------------------------------

/// Test vector seed for deterministic testing
pub const TEST_VECTOR_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
];
/// Test key for cryptographic operations
pub const TEST_KEY: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
];
/// Test nonce for cryptographic operations
pub const TEST_NONCE: [u8; 12] = [
    0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
];
/// Test message for cryptographic operations
pub const TEST_MESSAGE: &[u8] = b"This is a test message for NeonVault cryptographic operations.";

//------------------------------------------------------------------------------
// Utility Functions
//------------------------------------------------------------------------------

/// Get a human-readable string for an algorithm identifier
///
/// # Arguments
///
/// * `alg_id` - The algorithm identifier
///
/// # Returns
///
/// A string representation of the algorithm
pub fn algorithm_name(alg_id: u8) -> &'static str {
    match alg_id {
        ALG_KYBER_512 => "KYBER-512",
        ALG_KYBER_768 => "KYBER-768",
        ALG_KYBER_1024 => "KYBER-1024",
        ALG_AES_256_GCM => "AES-256-GCM",
        ALG_CHACHA20_POLY1305 => "ChaCha20-Poly1305",
        ALG_SHA_256 => "SHA-256",
        ALG_SHA_512 => "SHA-512",
        ALG_SHA3_256 => "SHA3-256",
        ALG_SHA3_512 => "SHA3-512",
        ALG_HMAC_SHA_256 => "HMAC-SHA-256",
        ALG_HMAC_SHA_512 => "HMAC-SHA-512",
        ALG_PBKDF2_HMAC_SHA_256 => "PBKDF2-HMAC-SHA-256",
        _ => "Unknown Algorithm",
    }
}

/// Get a human-readable string for an error code
///
/// # Arguments
///
/// * `error_code` - The error code
///
/// # Returns
///
/// A string representation of the error
pub fn error_description(error_code: i32) -> &'static str {
    match error_code {
        ERROR_SUCCESS => "Operation completed successfully",
        ERROR_GENERAL_FAILURE => "An unspecified error occurred",
        ERROR_INVALID_PARAMETERS => "Invalid parameters were provided",
        ERROR_AUTHENTICATION_FAILURE => "Authentication failed",
        ERROR_ENCRYPTION_FAILURE => "Encryption operation failed",
        ERROR_DECRYPTION_FAILURE => "Decryption operation failed",
        ERROR_CONNECTION_FAILURE => "Connection to remote system failed",
        ERROR_PROTOCOL_VIOLATION => "Protocol violation detected",
        ERROR_TIMEOUT => "Operation timed out",
        ERROR_RESOURCE_NOT_FOUND => "Requested resource not found",
        ERROR_PERMISSION_DENIED => "Permission denied for the requested operation",
        ERROR_RESOURCE_BUSY => "Resource is currently busy or locked",
        ERROR_RESOURCE_EXHAUSTED => "Resource has been exhausted",
        ERROR_NOT_IMPLEMENTED => "Requested functionality is not implemented",
        _ => "Unknown error code",
    }
}

/// Get a cyberpunk-themed error message for an error code
///
/// # Arguments
///
/// * `error_code` - The error code
///
/// # Returns
///
/// A cyberpunk-themed error message
pub fn cyberpunk_error_message(error_code: i32) -> &'static str {
    match error_code {
        ERROR_AUTHENTICATION_FAILURE => ERROR_MESSAGE_AUTHENTICATION,
        ERROR_ENCRYPTION_FAILURE | ERROR_DECRYPTION_FAILURE => ERROR_MESSAGE_ENCRYPTION,
        ERROR_CONNECTION_FAILURE | ERROR_PROTOCOL_VIOLATION => ERROR_MESSAGE_CONNECTION,
        ERROR_TIMEOUT => ERROR_MESSAGE_TIMEOUT,
        ERROR_RESOURCE_NOT_FOUND | ERROR_RESOURCE_BUSY | ERROR_RESOURCE_EXHAUSTED => ERROR_MESSAGE_RESOURCE,
        _ => "SYSTEM ERROR: Neural interface glitch detected in the matrix.",
    }
}

/// Convert bit flags to a string representation
///
/// # Arguments
///
/// * `flags` - The bit flags
/// * `flag_names` - A slice of (flag value, flag name) tuples
///
/// # Returns
///
/// A string representation of the flags
pub fn flags_to_string(flags: u32, flag_names: &[(u32, &str)]) -> String {
    let mut result = Vec::new();
    for &(flag, name) in flag_names {
        if flags & flag != 0 {
            result.push(name);
        }
    }
    if result.is_empty() {
        "None".to_string()
    } else {
        result.join(", ")
    }
}

/// Get a string representation of key usage flags
///
/// # Arguments
///
/// * `usage` - The key usage flags
///
/// # Returns
///
/// A string representation of the key usage
pub fn key_usage_to_string(usage: u8) -> String {
    let flag_names = [
        (KEY_USAGE_ENCRYPTION as u32, "Encryption"),
        (KEY_USAGE_SIGNATURE as u32, "Signature"),
        (KEY_USAGE_KEY_DERIVATION as u32, "Key Derivation"),
        (KEY_USAGE_AUTHENTICATION as u32, "Authentication"),
    ];
    flags_to_string(usage as u32, &flag_names)
}

/// Get a string representation of key state
///
/// # Arguments
///
/// * `state` - The key state
///
/// # Returns
///
/// A string representation of the key state
pub fn key_state_to_string(state: u8) -> &'static str {
    match state {
        KEY_STATE_ACTIVE => "Active",
        KEY_STATE_DEACTIVATED => "Deactivated",
        KEY_STATE_COMPROMISED => "Compromised",
        KEY_STATE_DESTROYED => "Destroyed",
        _ => "Unknown",
    }
}

/// Get a string representation of runner status
///
/// # Arguments
///
/// * `status` - The runner status
///
/// # Returns
///
/// A string representation of the runner status
pub fn runner_status_to_string(status: u8) -> &'static str {
    match status {
        RUNNER_STATUS_ACTIVE => "Active",
        RUNNER_STATUS_HIDDEN => "Hidden",
        RUNNER_STATUS_COMPROMISED => "Compromised",
        RUNNER_STATUS_RETIRED => "Retired",
        _ => "Unknown",
    }
}

/// Get a string representation of mission status
///
/// # Arguments
///
/// * `status` - The mission status
///
/// # Returns
///
/// A string representation of the mission status
pub fn mission_status_to_string(status: u8) -> &'static str {
    match status {
        MISSION_STATUS_PENDING => "Pending",
        MISSION_STATUS_ACTIVE => "Active",
        MISSION_STATUS_COMPLETED => "Completed",
        MISSION_STATUS_FAILED => "Failed",
        MISSION_STATUS_ABORTED => "Aborted",
        _ => "Unknown",
    }
}

/// Get a string representation of reputation level
///
/// # Arguments
///
/// * `reputation` - The reputation points
///
/// # Returns
///
/// A string representation of the reputation level
pub fn reputation_level_to_string(reputation: u32) -> &'static str {
    if reputation >= REPUTATION_THRESHOLD_LEGEND {
        "Legend"
    } else if reputation >= REPUTATION_THRESHOLD_ELITE {
        "Elite"
    } else if reputation >= REPUTATION_THRESHOLD_VETERAN {
        "Veteran"
    } else if reputation >= REPUTATION_THRESHOLD_TRUSTED {
        "Trusted"
    } else {
        "Novice"
    }
}

//------------------------------------------------------------------------------
// Tests
//------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_name() {
        assert_eq!(algorithm_name(ALG_KYBER_768), "KYBER-768");
        assert_eq!(algorithm_name(ALG_AES_256_GCM), "AES-256-GCM");
        assert_eq!(algorithm_name(ALG_SHA_256), "SHA-256");
        assert_eq!(algorithm_name(0xFF), "Unknown Algorithm");
    }

    #[test]
    fn test_error_description() {
        assert_eq!(error_description(ERROR_SUCCESS), "Operation completed successfully");
        assert_eq!(error_description(ERROR_ENCRYPTION_FAILURE), "Encryption operation failed");
        assert_eq!(error_description(0x1234), "Unknown error code");
    }

    #[test]
    fn test_cyberpunk_error_message() {
        assert_eq!(cyberpunk_error_message(ERROR_AUTHENTICATION_FAILURE), ERROR_MESSAGE_AUTHENTICATION);
        assert_eq!(cyberpunk_error_message(ERROR_ENCRYPTION_FAILURE), ERROR_MESSAGE_ENCRYPTION);
        assert_eq!(cyberpunk_error_message(0x1234), "SYSTEM ERROR: Neural interface glitch detected in the matrix.");
    }

    #[test]
    fn test_flags_to_string() {
        let flag_names = [
            (0x01, "Flag1"),
            (0x02, "Flag2"),
            (0x04, "Flag3"),
            (0x08, "Flag4"),
        ];
        assert_eq!(flags_to_string(0x00, &flag_names), "None");
        assert_eq!(flags_to_string(0x01, &flag_names), "Flag1");
        assert_eq!(flags_to_string(0x03, &flag_names), "Flag1, Flag2");
        assert_eq!(flags_to_string(0x0F, &flag_names), "Flag1, Flag2, Flag3, Flag4");
    }

    #[test]
    fn test_key_usage_to_string() {
        assert_eq!(key_usage_to_string(0x00), "None");
        assert_eq!(key_usage_to_string(KEY_USAGE_ENCRYPTION), "Encryption");
        assert_eq!(key_usage_to_string(KEY_USAGE_ENCRYPTION | KEY_USAGE_SIGNATURE), "Encryption, Signature");
        assert_eq!(
            key_usage_to_string(KEY_USAGE_ENCRYPTION | KEY_USAGE_SIGNATURE | KEY_USAGE_AUTHENTICATION),
            "Encryption, Signature, Authentication"
        );
    }

    #[test]
    fn test_key_state_to_string() {
        assert_eq!(key_state_to_string(KEY_STATE_ACTIVE), "Active");
        assert_eq!(key_state_to_string(KEY_STATE_COMPROMISED), "Compromised");
        assert_eq!(key_state_to_string(0xFF), "Unknown");
    }

    #[test]
    fn test_runner_status_to_string() {
        assert_eq!(runner_status_to_string(RUNNER_STATUS_ACTIVE), "Active");
        assert_eq!(runner_status_to_string(RUNNER_STATUS_HIDDEN), "Hidden");
        assert_eq!(runner_status_to_string(0xFF), "Unknown");
    }

    #[test]
    fn test_mission_status_to_string() {
        assert_eq!(mission_status_to_string(MISSION_STATUS_PENDING), "Pending");
        assert_eq!(mission_status_to_string(MISSION_STATUS_COMPLETED), "Completed");
        assert_eq!(mission_status_to_string(0xFF), "Unknown");
    }

    #[test]
    fn test_reputation_level_to_string() {
        assert_eq!(reputation_level_to_string(0), "Novice");
        assert_eq!(reputation_level_to_string(REPUTATION_THRESHOLD_TRUSTED), "Trusted");
        assert_eq!(reputation_level_to_string(REPUTATION_THRESHOLD_VETERAN), "Veteran");
        assert_eq!(reputation_level_to_string(REPUTATION_THRESHOLD_ELITE), "Elite");
        assert_eq!(reputation_level_to_string(REPUTATION_THRESHOLD_LEGEND), "Legend");
        assert_eq!(reputation_level_to_string(REPUTATION_THRESHOLD_LEGEND + 1), "Legend");
    }

    #[test]
    fn test_protocol_constants() {
        assert_eq!(PROTOCOL_MAGIC, [0x4E, 0x56, 0x4C, 0x54]);
        assert_eq!(PROTOCOL_VERSION, 0x01);
        assert!(MAX_MESSAGE_SIZE >= 1 << 20);
    }

    #[test]
    fn test_crypto_parameters() {
        assert_eq!(AES_256_KEY_SIZE, 32);
        assert_eq!(CHACHA20_KEY_SIZE, 32);
        assert_eq!(AES_256_GCM_NONCE_SIZE, 12);
        assert_eq!(CHACHA20_POLY1305_NONCE_SIZE, 12);
        assert_eq!(AES_256_GCM_TAG_SIZE, 16);
        assert_eq!(CHACHA20_POLY1305_TAG_SIZE, 16);
        assert_eq!(SHA_256_DIGEST_SIZE, 32);
        assert_eq!(SHA_512_DIGEST_SIZE, 64);
        assert_eq!(SHA3_256_DIGEST_SIZE, 32);
        assert_eq!(SHA3_512_DIGEST_SIZE, 64);
    }
}
