//! KREL - Secure File Encryption Engine
//!
//! A high-performance, async-first file encryption engine using:
//! - Argon2id for key derivation
//! - BLAKE3 for hashing and commitments
//! - XChaCha20-Poly1305 for authenticated encryption
//!
//! # Security Features
//! - Memory-safe `Secret` wrapper with automatic zeroization
//! - Authenticated encryption with AEAD
//! - Integrity verification via BLAKE3 hashing
//! - Key commitment to prevent key-substitution attacks
//!
//! # Architecture
//! - `error`: Error types and result aliases
//! - `secret`: Memory-safe secret wrappers
//! - `format`: File format structures (Header, Trailer)
//!
//! # Example
//! ```rust,ignore
//! use krel::secret::Secret;
//!
//! let password = Secret::new(b"my-password".to_vec());
//! password.expose(|data| {
//!     // Use the password data here
//!     println!("Password length: {}", data.len());
//! });
//! // Password is automatically zeroized when dropped
//! ```

pub mod error;
pub mod secret;
pub mod format;
pub mod crypto;
pub mod stream;
pub mod ops;
pub mod ffi;

// Re-export commonly used types
pub use error::{KrelError, Result};
pub use secret::{Secret, SecretArray};
pub use format::{Header, Trailer, MAGIC, VERSION};
pub use crypto::{wrap_dek, unwrap_dek, derive_master_key};
pub use stream::{encrypt, decrypt, CHUNK_SIZE};
pub use ops::{rekey, verify, verify_full};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify that key types are accessible
        let _secret = Secret::new(vec![1, 2, 3]);
        let _secret_array = SecretArray::<32>::new([0u8; 32]);
        
        // Verify error types
        let _err: Result<()> = Err(KrelError::ContainerError("test".to_string()));
        
        // Verify format constants
        assert_eq!(MAGIC, *b"KREL");
        assert_eq!(VERSION, 1);
    }
}
