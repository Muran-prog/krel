use crate::error::{KrelError, Result};
use crate::format::{Header, MAGIC, VERSION};
use crate::secret::Secret;
use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use blake3;
use subtle::ConstantTimeEq;

// Argon2id parameters
const ARGON2_MEM_COST: u32 = 256 * 1024; // 256 MB
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

// Key sizes
const MASTER_KEY_SIZE: usize = 32;
const KEK_SIZE: usize = 32;
const DEK_SIZE: usize = 32;
const COMMITMENT_KEY_SIZE: usize = 32;

// BLAKE3 contexts for domain separation
const CONTEXT_KEK: &str = "krel_enc";
const CONTEXT_COMMITMENT: &str = "krel_commit";
const CONTEXT_NONCE: &str = "nonce";

/// Derive a master key from password and salt using Argon2id
/// 
/// Parameters:
/// - Memory: 256 MB
/// - Iterations: 3
/// - Parallelism: 4
/// 
/// # Security
/// These parameters provide strong resistance against brute-force attacks
/// while remaining practical for user-facing applications.
pub fn derive_master_key(password: &Secret, salt: &[u8; 16]) -> Result<Secret> {
    if salt.iter().all(|&b| b == 0) {
        return Err(KrelError::InvalidParameter(
            "Salt must not be all zeros".to_string()
        ));
    }

    // Build Argon2id parameters
    let params = ParamsBuilder::new()
        .m_cost(ARGON2_MEM_COST)
        .t_cost(ARGON2_TIME_COST)
        .p_cost(ARGON2_PARALLELISM)
        .output_len(MASTER_KEY_SIZE)
        .build()
        .map_err(|e| KrelError::CryptoError(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Derive key
    let mut output = vec![0u8; MASTER_KEY_SIZE];
    password.expose(|pwd| {
        argon2
            .hash_password_into(pwd, salt, &mut output)
            .map_err(|e| KrelError::CryptoError(format!("Argon2 failed: {}", e)))
    })?;

    Ok(Secret::new(output))
}

/// Derive a sub-key from master key using BLAKE3 KDF
/// 
/// # Security
/// Uses BLAKE3's derive_key function with domain separation contexts
/// to ensure keys for different purposes are cryptographically independent.
fn derive_subkey(master_key: &Secret, context: &str, size: usize) -> Secret {
    master_key.expose(|key| {
        let derived = blake3::derive_key(context, key);
        Secret::from_slice(&derived[..size])
    })
}

/// Derive the Key Encryption Key (KEK) from master key
pub fn derive_kek(master_key: &Secret) -> Secret {
    derive_subkey(master_key, CONTEXT_KEK, KEK_SIZE)
}

/// Derive the commitment key from master key
pub fn derive_commitment_key(master_key: &Secret) -> Secret {
    derive_subkey(master_key, CONTEXT_COMMITMENT, COMMITMENT_KEY_SIZE)
}

/// Generate a nonce for DEK wrapping from salt
/// 
/// # Security
/// Uses BLAKE3 to derive a 24-byte nonce from the salt,
/// ensuring the nonce is deterministic but cryptographically independent.
fn generate_wrapping_nonce(salt: &[u8; 16]) -> [u8; 24] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(salt);
    hasher.update(CONTEXT_NONCE.as_bytes());
    let hash = hasher.finalize();
    
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&hash.as_bytes()[..24]);
    nonce
}

/// Compute Additional Authenticated Data (AAD) for DEK wrapping
/// 
/// CRITICAL: AAD must only include IMMUTABLE header fields to support rekey operations.
/// If the AAD included the entire header hash, rekeying would fail because the header changes.
/// 
/// # Security
/// Binds the wrapped DEK to the container's immutable metadata,
/// preventing key substitution attacks while allowing header modifications for rekey.
fn compute_wrapping_aad(salt: &[u8; 16], nonce_base: &[u8; 16]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    
    // Include only immutable fields
    hasher.update(&MAGIC);
    hasher.update(&VERSION.to_be_bytes());
    hasher.update(salt);
    hasher.update(nonce_base);
    
    let hash = hasher.finalize();
    *hash.as_bytes()
}

/// Compute key commitment for the DEK
/// 
/// # Security
/// The commitment allows verification that the unwrapped DEK is correct
/// without exposing the DEK itself. Uses keyed BLAKE3 for binding.
fn compute_commitment(dek: &Secret, salt: &[u8; 16]) -> [u8; 32] {
    dek.expose(|key| {
        let mut hasher = blake3::Hasher::new_keyed(
            key.try_into().expect("DEK must be 32 bytes")
        );
        hasher.update(salt);
        *hasher.finalize().as_bytes()
    })
}

/// Wrap (encrypt) a Data Encryption Key with password-derived key
/// 
/// Returns: (wrapped_dek, commitment)
/// 
/// # Security
/// - Uses XChaCha20-Poly1305 for authenticated encryption
/// - Nonce derived from salt (deterministic but unique per salt)
/// - AAD binds to immutable header fields only
/// - Commitment enables verification after unwrapping
pub fn wrap_dek(
    dek: &Secret,
    password: &Secret,
    salt: &[u8; 16],
    nonce_base: &[u8; 16],
) -> Result<([u8; 48], [u8; 32])> {
    // Validate DEK size
    if dek.len() != DEK_SIZE {
        return Err(KrelError::InvalidParameter(format!(
            "DEK must be {} bytes, got {}",
            DEK_SIZE,
            dek.len()
        )));
    }

    // Derive master key from password
    let master_key = derive_master_key(password, salt)?;
    
    // Derive KEK from master key
    let kek = derive_kek(&master_key);

    // Generate nonce for wrapping
    let nonce = generate_wrapping_nonce(salt);

    // Compute AAD from immutable fields
    let aad = compute_wrapping_aad(salt, nonce_base);

    // Wrap DEK with XChaCha20-Poly1305
    let wrapped = kek.expose(|kek_bytes| {
        dek.expose(|dek_bytes| {
            let cipher = XChaCha20Poly1305::new_from_slice(kek_bytes)
                .map_err(|e| KrelError::CryptoError(format!("Invalid KEK: {}", e)))?;
            
            let payload = Payload {
                msg: dek_bytes,
                aad: &aad,
            };

            let ciphertext = cipher
                .encrypt(&nonce.into(), payload)
                .map_err(|e| KrelError::CryptoError(format!("Encryption failed: {}", e)))?;

            // Ciphertext should be DEK_SIZE + 16 (tag)
            if ciphertext.len() != 48 {
                return Err(KrelError::CryptoError(format!(
                    "Invalid ciphertext length: {}",
                    ciphertext.len()
                )));
            }

            let mut wrapped_dek = [0u8; 48];
            wrapped_dek.copy_from_slice(&ciphertext);
            Ok(wrapped_dek)
        })
    })?;

    // Compute commitment
    let commitment = compute_commitment(dek, salt);

    Ok((wrapped, commitment))
}

/// Unwrap (decrypt) a Data Encryption Key from header
/// 
/// # Security
/// - Verifies commitment using constant-time comparison
/// - Returns AuthError if commitment doesn't match (wrong password or tampered data)
pub fn unwrap_dek(header: &Header, password: &Secret) -> Result<Secret> {
    // Derive master key from password
    let master_key = derive_master_key(password, &header.salt)?;
    
    // Derive KEK from master key
    let kek = derive_kek(&master_key);

    // Generate nonce (same derivation as wrapping)
    let nonce = generate_wrapping_nonce(&header.salt);

    // Compute AAD (same as wrapping)
    let aad = compute_wrapping_aad(&header.salt, &header.nonce_base);

    // Unwrap DEK with XChaCha20-Poly1305
    let dek = kek.expose(|kek_bytes| {
        let cipher = XChaCha20Poly1305::new_from_slice(kek_bytes)
            .map_err(|e| KrelError::CryptoError(format!("Invalid KEK: {}", e)))?;
        
        let payload = Payload {
            msg: &header.wrapped_dek,
            aad: &aad,
        };

        let plaintext = cipher
            .decrypt(&nonce.into(), payload)
            .map_err(|_| {
                // Don't leak specific error details about authentication failure
                KrelError::AuthError("Invalid password or corrupted data".to_string())
            })?;

        if plaintext.len() != DEK_SIZE {
            return Err(KrelError::CryptoError(format!(
                "Invalid DEK size: {}",
                plaintext.len()
            )));
        }

        Ok(Secret::new(plaintext))
    })?;

    // Verify commitment using constant-time comparison
    let expected_commitment = compute_commitment(&dek, &header.salt);
    let commitments_match = expected_commitment.ct_eq(&header.commitment);

    if !bool::from(commitments_match) {
        // Zeroize the DEK before returning error
        drop(dek);
        return Err(KrelError::AuthError(
            "Commitment verification failed".to_string()
        ));
    }

    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_password() -> Secret {
        Secret::from_slice(b"test-password-123")
    }

    fn test_salt() -> [u8; 16] {
        [1u8; 16]
    }

    fn test_nonce_base() -> [u8; 16] {
        [2u8; 16]
    }

    fn test_dek() -> Secret {
        Secret::new(vec![42u8; 32])
    }

    #[test]
    fn test_derive_master_key() {
        let password = test_password();
        let salt = test_salt();
        
        let master_key = derive_master_key(&password, &salt).unwrap();
        assert_eq!(master_key.len(), 32);
    }

    #[test]
    fn test_derive_master_key_deterministic() {
        let password = test_password();
        let salt = test_salt();
        
        let mk1 = derive_master_key(&password, &salt).unwrap();
        let mk2 = derive_master_key(&password, &salt).unwrap();
        
        // Should produce same key for same inputs
        mk1.expose(|k1| {
            mk2.expose(|k2| {
                assert_eq!(k1, k2);
            });
        });
    }

    #[test]
    fn test_derive_master_key_different_salts() {
        let password = test_password();
        let salt1 = [1u8; 16];
        let salt2 = [2u8; 16];
        
        let mk1 = derive_master_key(&password, &salt1).unwrap();
        let mk2 = derive_master_key(&password, &salt2).unwrap();
        
        // Different salts should produce different keys
        mk1.expose(|k1| {
            mk2.expose(|k2| {
                assert_ne!(k1, k2);
            });
        });
    }

    #[test]
    fn test_derive_subkeys() {
        let password = test_password();
        let salt = test_salt();
        let master_key = derive_master_key(&password, &salt).unwrap();
        
        let kek = derive_kek(&master_key);
        let commitment_key = derive_commitment_key(&master_key);
        
        assert_eq!(kek.len(), 32);
        assert_eq!(commitment_key.len(), 32);
        
        // Keys should be different
        kek.expose(|k1| {
            commitment_key.expose(|k2| {
                assert_ne!(k1, k2);
            });
        });
    }

    #[test]
    fn test_wrap_unwrap_dek() {
        let dek = test_dek();
        let password = test_password();
        let salt = test_salt();
        let nonce_base = test_nonce_base();
        
        // Wrap DEK
        let (wrapped_dek, commitment) = wrap_dek(&dek, &password, &salt, &nonce_base).unwrap();
        
        // Create header
        let header = Header::new(salt, nonce_base, wrapped_dek, commitment);
        
        // Unwrap DEK
        let unwrapped = unwrap_dek(&header, &password).unwrap();
        
        // Verify unwrapped DEK matches original
        dek.expose(|original| {
            unwrapped.expose(|recovered| {
                assert_eq!(original, recovered);
            });
        });
    }

    #[test]
    fn test_unwrap_wrong_password() {
        let dek = test_dek();
        let password = test_password();
        let wrong_password = Secret::from_slice(b"wrong-password");
        let salt = test_salt();
        let nonce_base = test_nonce_base();
        
        // Wrap with correct password
        let (wrapped_dek, commitment) = wrap_dek(&dek, &password, &salt, &nonce_base).unwrap();
        let header = Header::new(salt, nonce_base, wrapped_dek, commitment);
        
        // Try to unwrap with wrong password
        let result = unwrap_dek(&header, &wrong_password);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KrelError::AuthError(_)));
    }

    #[test]
    fn test_unwrap_corrupted_commitment() {
        let dek = test_dek();
        let password = test_password();
        let salt = test_salt();
        let nonce_base = test_nonce_base();
        
        // Wrap DEK
        let (wrapped_dek, mut commitment) = wrap_dek(&dek, &password, &salt, &nonce_base).unwrap();
        
        // Corrupt commitment
        commitment[0] ^= 1;
        
        let header = Header::new(salt, nonce_base, wrapped_dek, commitment);
        
        // Try to unwrap
        let result = unwrap_dek(&header, &password);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KrelError::AuthError(_)));
    }

    #[test]
    fn test_unwrap_corrupted_wrapped_dek() {
        let dek = test_dek();
        let password = test_password();
        let salt = test_salt();
        let nonce_base = test_nonce_base();
        
        // Wrap DEK
        let (mut wrapped_dek, commitment) = wrap_dek(&dek, &password, &salt, &nonce_base).unwrap();
        
        // Corrupt wrapped DEK
        wrapped_dek[0] ^= 1;
        
        let header = Header::new(salt, nonce_base, wrapped_dek, commitment);
        
        // Try to unwrap
        let result = unwrap_dek(&header, &password);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KrelError::AuthError(_)));
    }

    #[test]
    fn test_aad_immutable_fields_only() {
        let salt1 = [1u8; 16];
        let salt2 = [2u8; 16];
        let nonce_base = [3u8; 16];
        
        let aad1 = compute_wrapping_aad(&salt1, &nonce_base);
        let aad2 = compute_wrapping_aad(&salt2, &nonce_base);
        
        // Different salts should produce different AADs
        assert_ne!(aad1, aad2);
        
        // Same inputs should produce same AAD
        let aad3 = compute_wrapping_aad(&salt1, &nonce_base);
        assert_eq!(aad1, aad3);
    }
}
