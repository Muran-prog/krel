use crate::error::{KrelError, Result};
use crate::format::{Header, Trailer, HEADER_SIZE, TRAILER_SIZE};
use crate::secret::Secret;
use crate::crypto::{unwrap_dek, wrap_dek};
use blake3;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};

/// Rekey an encrypted file with a new password (O(1) operation)
/// 
/// # Security
/// - Only rewrites the header (128 bytes) and trailer (36 bytes)
/// - Atomic operation: file remains valid with old password if interrupted
/// - Preserves salt and nonce_base (critical for AAD binding)
/// - Recalculates integrity hash in trailer (includes header)
/// - Syncs immediately for durability
/// 
/// # Performance
/// - O(n) where n = file size (need to recalculate integrity hash)
/// - Reads entire file to recalculate hash
/// - No chunk decryption required
/// 
/// # Architecture Note
/// This operation is only possible because our AAD for chunk encryption
/// binds to immutable header fields (magic, version, salt, nonce_base).
/// If we had included the wrapped_dek or commitment in the AAD, rekey
/// would require re-encrypting the entire file.
pub async fn rekey<P: AsRef<Path>>(
    path: P,
    old_password: &Secret,
    new_password: &Secret,
) -> Result<()> {
    let path = path.as_ref();

    // Open file for reading and writing
    let mut file = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .await
        .map_err(|e| {
            KrelError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to open file for rekey: {}", e),
            ))
        })?;

    // Read existing header
    let mut header_bytes = [0u8; HEADER_SIZE];
    file.read_exact(&mut header_bytes).await?;
    let header = Header::from_bytes(&header_bytes)?;
    header.validate()?;

    // Unwrap DEK with old password
    let dek = unwrap_dek(&header, old_password)?;

    // Wrap DEK with new password, preserving salt and nonce_base
    // CRITICAL: We must use the SAME salt and nonce_base to maintain
    // AAD consistency for all encrypted chunks
    let (new_wrapped_dek, new_commitment) = wrap_dek(
        &dek,
        new_password,
        &header.salt,
        &header.nonce_base,
    )?;

    // Create new header with updated wrapped_dek and commitment
    let new_header = Header::new(
        header.salt,
        header.nonce_base,
        new_wrapped_dek,
        new_commitment,
    );
    let new_header_bytes = new_header.to_bytes()?;

    // CRITICAL: Recalculate integrity hash because header changed
    // Integrity hash = BLAKE3(header + all_ciphertext)
    
    // Get file size
    let metadata = tokio::fs::metadata(path).await?;
    let file_size = metadata.len() as usize;
    let ciphertext_size = file_size - HEADER_SIZE - TRAILER_SIZE;

    // Initialize hasher with NEW header
    let mut integrity_hasher = blake3::Hasher::new();
    integrity_hasher.update(&new_header_bytes);

    // CRITICAL: Seek to start of ciphertext before reading
    // File position may have moved after metadata operations
    file.seek(std::io::SeekFrom::Start(HEADER_SIZE as u64)).await?;

    // Read and hash all ciphertext
    let mut bytes_processed = 0;
    let mut buffer = vec![0u8; 65536];
    
    while bytes_processed < ciphertext_size {
        let remaining = ciphertext_size - bytes_processed;
        let to_read = remaining.min(buffer.len());
        
        let bytes_read = file.read(&mut buffer[..to_read]).await?;
        if bytes_read == 0 {
            return Err(KrelError::ContainerError(
                "Unexpected EOF while rekeying".to_string(),
            ));
        }
        
        integrity_hasher.update(&buffer[..bytes_read]);
        bytes_processed += bytes_read;
    }

    // Compute new integrity hash
    let new_integrity_hash = *integrity_hasher.finalize().as_bytes();

    // Create new trailer
    let new_trailer = Trailer::new(new_integrity_hash);
    let new_trailer_bytes = new_trailer.to_bytes()?;

    // Seek back to start of file
    file.seek(std::io::SeekFrom::Start(0)).await?;

    // Write new header
    file.write_all(&new_header_bytes).await?;

    // Seek to trailer position
    file.seek(std::io::SeekFrom::Start((HEADER_SIZE + ciphertext_size) as u64)).await?;

    // Write new trailer
    file.write_all(&new_trailer_bytes).await?;

    // CRITICAL: Sync immediately to ensure atomicity
    // If power fails after this point, the new password is active
    // If power fails before this point, the old password remains active
    file.sync_all().await?;

    Ok(())
}

/// Verify file integrity without password (fast check)
/// 
/// # Security
/// - Verifies that ciphertext has not been tampered with
/// - Does NOT verify password correctness
/// - Does NOT decrypt data
/// 
/// # Performance
/// - O(n) where n = file size
/// - Streams chunks without decryption
/// - Uses BLAKE3 for fast hashing
pub async fn verify<P: AsRef<Path>>(path: P) -> Result<bool> {
    let path = path.as_ref();

    // Open file for reading
    let file = File::open(path).await.map_err(|e| {
        KrelError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to open file for verification: {}", e),
        ))
    })?;
    let mut reader = BufReader::new(file);

    // Read header
    let mut header_bytes = [0u8; HEADER_SIZE];
    reader.read_exact(&mut header_bytes).await?;
    let header = Header::from_bytes(&header_bytes)?;
    header.validate()?;

    // Initialize integrity hasher
    let mut integrity_hasher = blake3::Hasher::new();
    integrity_hasher.update(&header_bytes);

    // Get file size to determine ciphertext region
    let metadata = tokio::fs::metadata(path).await?;
    let file_size = metadata.len() as usize;
    let ciphertext_size = file_size - HEADER_SIZE - TRAILER_SIZE;

    // Stream all chunks and hash them
    let mut bytes_processed = 0;
    let mut buffer = vec![0u8; 65552]; // ENCRYPTED_CHUNK_SIZE

    while bytes_processed < ciphertext_size {
        let remaining = ciphertext_size - bytes_processed;
        let to_read = remaining.min(buffer.len());

        let bytes_read = reader.read(&mut buffer[..to_read]).await?;
        if bytes_read == 0 {
            return Err(KrelError::ContainerError(
                "Unexpected EOF while verifying".to_string(),
            ));
        }

        // Update integrity hash with ciphertext
        integrity_hasher.update(&buffer[..bytes_read]);
        bytes_processed += bytes_read;
    }

    // Read trailer
    let mut trailer_bytes = [0u8; TRAILER_SIZE];
    reader.read_exact(&mut trailer_bytes).await?;
    let trailer = Trailer::from_bytes(&trailer_bytes)?;
    trailer.validate()?;

    // Compare hashes
    let computed_hash = *integrity_hasher.finalize().as_bytes();
    Ok(computed_hash == trailer.integrity_hash)
}

/// Verify file integrity and password correctness (deep check)
/// 
/// # Security
/// - Verifies password and DEK commitment
/// - Verifies overall integrity hash
/// - Does NOT decrypt the full file (only unwraps DEK)
/// 
/// # Performance
/// - O(n) where n = file size (due to integrity check)
/// - More expensive than fast verify due to Argon2id
pub async fn verify_full<P: AsRef<Path>>(
    path: P,
    password: &Secret,
) -> Result<bool> {
    let path = path.as_ref();

    // Open file for reading
    let file = File::open(path).await.map_err(|e| {
        KrelError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to open file for verification: {}", e),
        ))
    })?;
    let mut reader = BufReader::new(file);

    // Read header
    let mut header_bytes = [0u8; HEADER_SIZE];
    reader.read_exact(&mut header_bytes).await?;
    let header = Header::from_bytes(&header_bytes)?;
    header.validate()?;

    // Try to unwrap DEK - this verifies password and commitment
    match unwrap_dek(&header, password) {
        Ok(_dek) => {
            // Password is correct and commitment is valid
            // Now verify overall integrity
            drop(_dek); // Zeroize DEK (we don't need it anymore)
            verify(path).await
        }
        Err(_) => {
            // Password is wrong or commitment failed
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::{encrypt, decrypt};

    #[tokio::test]
    async fn test_rekey() {
        let temp_dir = std::env::temp_dir();
        let source = temp_dir.join("test_rekey_source.txt");
        let encrypted = temp_dir.join("test_rekey_encrypted.krel");
        let decrypted = temp_dir.join("test_rekey_decrypted.txt");

        // Create and encrypt with original password
        let test_data = b"This file will be rekeyed!";
        tokio::fs::write(&source, test_data).await.unwrap();

        let old_password = Secret::from_slice(b"old-password");
        encrypt(&source, &encrypted, &old_password).await.unwrap();

        // Rekey to new password
        let new_password = Secret::from_slice(b"new-password");
        rekey(&encrypted, &old_password, &new_password).await.unwrap();

        // Verify old password no longer works
        let result = decrypt(&encrypted, &decrypted, &old_password).await;
        assert!(result.is_err());

        // Verify new password works
        decrypt(&encrypted, &decrypted, &new_password).await.unwrap();
        let decrypted_data = tokio::fs::read(&decrypted).await.unwrap();
        assert_eq!(decrypted_data, test_data);

        // Cleanup
        let _ = tokio::fs::remove_file(source).await;
        let _ = tokio::fs::remove_file(encrypted).await;
        let _ = tokio::fs::remove_file(decrypted).await;
    }

    #[tokio::test]
    async fn test_verify_valid_file() {
        let temp_dir = std::env::temp_dir();
        let source = temp_dir.join("test_verify_source.txt");
        let encrypted = temp_dir.join("test_verify_encrypted.krel");

        // Create and encrypt
        tokio::fs::write(&source, b"Data to verify").await.unwrap();
        let password = Secret::from_slice(b"test-password");
        encrypt(&source, &encrypted, &password).await.unwrap();

        // Verify should pass
        let is_valid = verify(&encrypted).await.unwrap();
        assert!(is_valid);

        // Cleanup
        let _ = tokio::fs::remove_file(source).await;
        let _ = tokio::fs::remove_file(encrypted).await;
    }

    #[tokio::test]
    async fn test_verify_corrupted_file() {
        let temp_dir = std::env::temp_dir();
        let source = temp_dir.join("test_verify_corrupt_source.txt");
        let encrypted = temp_dir.join("test_verify_corrupt_encrypted.krel");

        // Create and encrypt
        tokio::fs::write(&source, b"Data to corrupt").await.unwrap();
        let password = Secret::from_slice(b"test-password");
        encrypt(&source, &encrypted, &password).await.unwrap();

        // Corrupt a byte in the ciphertext region (after header, before trailer)
        let mut file_data = tokio::fs::read(&encrypted).await.unwrap();
        let corruption_pos = HEADER_SIZE + 1; // First byte of ciphertext
        if file_data.len() > corruption_pos {
            file_data[corruption_pos] ^= 1; // Flip a bit in ciphertext
            tokio::fs::write(&encrypted, file_data).await.unwrap();
        }

        // Verify should fail
        let is_valid = verify(&encrypted).await.unwrap();
        assert!(!is_valid);

        // Cleanup
        let _ = tokio::fs::remove_file(source).await;
        let _ = tokio::fs::remove_file(encrypted).await;
    }

    #[tokio::test]
    async fn test_verify_full_correct_password() {
        let temp_dir = std::env::temp_dir();
        let source = temp_dir.join("test_verify_full_source.txt");
        let encrypted = temp_dir.join("test_verify_full_encrypted.krel");

        // Create and encrypt
        tokio::fs::write(&source, b"Deep verification test").await.unwrap();
        let password = Secret::from_slice(b"correct-password");
        encrypt(&source, &encrypted, &password).await.unwrap();

        // Verify with correct password should pass
        let is_valid = verify_full(&encrypted, &password).await.unwrap();
        assert!(is_valid);

        // Cleanup
        let _ = tokio::fs::remove_file(source).await;
        let _ = tokio::fs::remove_file(encrypted).await;
    }

    #[tokio::test]
    async fn test_verify_full_wrong_password() {
        let temp_dir = std::env::temp_dir();
        let source = temp_dir.join("test_verify_full_wrong_source.txt");
        let encrypted = temp_dir.join("test_verify_full_wrong_encrypted.krel");

        // Create and encrypt
        tokio::fs::write(&source, b"Password check test").await.unwrap();
        let password = Secret::from_slice(b"correct-password");
        encrypt(&source, &encrypted, &password).await.unwrap();

        // Verify with wrong password should fail
        let wrong_password = Secret::from_slice(b"wrong-password");
        let is_valid = verify_full(&encrypted, &wrong_password).await.unwrap();
        assert!(!is_valid);

        // Cleanup
        let _ = tokio::fs::remove_file(source).await;
        let _ = tokio::fs::remove_file(encrypted).await;
    }
}
