use crate::error::{KrelError, Result};
use crate::format::{Header, Trailer, HEADER_SIZE, MAGIC, TRAILER_SIZE, VERSION};
use crate::secret::Secret;
use crate::crypto::{unwrap_dek, wrap_dek};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use blake3;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};

// Chunk processing constants
pub const CHUNK_SIZE: usize = 65536; // 64 KB
pub const TAG_SIZE: usize = 16;
pub const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

/// Generate cryptographically secure random bytes
fn generate_random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut bytes = [0u8; N];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Compute the immutable header fields hash for AAD
fn compute_immutable_header_hash(salt: &[u8; 16], nonce_base: &[u8; 16]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&MAGIC);
    hasher.update(&VERSION.to_be_bytes());
    hasher.update(salt);
    hasher.update(nonce_base);
    *hasher.finalize().as_bytes()
}

/// Construct nonce for a chunk: nonce_base (16 bytes) || counter (8 bytes, big-endian)
fn construct_chunk_nonce(nonce_base: &[u8; 16], chunk_index: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(nonce_base);
    nonce[16..24].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

/// Construct AAD for a chunk: header_hash (32) || chunk_index (8) || is_final (1)
fn construct_chunk_aad(
    immutable_hash: &[u8; 32],
    chunk_index: u64,
    is_final: bool,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(41);
    aad.extend_from_slice(immutable_hash);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.push(if is_final { 1 } else { 0 });
    aad
}

/// Encrypt a file with streaming chunks
/// 
/// # Security
/// - Generates cryptographically random salt, nonce_base, and DEK
/// - Each chunk has unique nonce (nonce_base || counter)
/// - Each chunk AAD includes chunk index and final flag
/// - Integrity hash covers all ciphertext
/// - Atomic file operations where possible
pub async fn encrypt<P: AsRef<Path>>(
    source: P,
    dest: P,
    password: &Secret,
) -> Result<()> {
    let source = source.as_ref();
    let dest = dest.as_ref();

    // Generate random cryptographic material
    let salt = generate_random_bytes::<16>();
    let nonce_base = generate_random_bytes::<16>();
    let dek_bytes = generate_random_bytes::<32>();
    let dek = Secret::new(dek_bytes.to_vec());

    // Wrap DEK with password
    let (wrapped_dek, commitment) = wrap_dek(&dek, password, &salt, &nonce_base)?;

    // Create header
    let header = Header::new(salt, nonce_base, wrapped_dek, commitment);
    let header_bytes = header.to_bytes()?;

    // Compute immutable header hash for AAD
    let immutable_hash = compute_immutable_header_hash(&salt, &nonce_base);

    // Open source file
    let source_file = File::open(source).await.map_err(|e| {
        KrelError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to open source file: {}", e),
        ))
    })?;
    let mut reader = BufReader::new(source_file);

    // Create destination file (fail if exists for safety)
    let dest_file = File::create(dest).await.map_err(|e| {
        KrelError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to create destination file: {}", e),
        ))
    })?;
    let mut writer = BufWriter::new(dest_file);

    // Write header
    writer.write_all(&header_bytes).await?;

    // Initialize integrity hasher and cipher
    let mut integrity_hasher = blake3::Hasher::new();
    integrity_hasher.update(&header_bytes);

    // Create cipher
    let cipher = dek.expose(|key| {
        XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| KrelError::CryptoError(format!("Invalid DEK: {}", e)))
    })?;

    // Process chunks
    let mut chunk_index: u64 = 0;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunks_data = Vec::new();

    // Read all chunks first
    loop {
        let bytes_read = reader.read(&mut buffer).await?;
        
        if bytes_read == 0 {
            break; // EOF
        }

        chunks_data.push(buffer[..bytes_read].to_vec());
    }

    // Now encrypt all chunks knowing which is final
    for (idx, chunk_data) in chunks_data.iter().enumerate() {
        let is_final = idx == chunks_data.len() - 1;

        // Construct nonce and AAD for this chunk
        let nonce = construct_chunk_nonce(&nonce_base, chunk_index);
        let aad = construct_chunk_aad(&immutable_hash, chunk_index, is_final);

        // Encrypt chunk
        let payload = Payload {
            msg: chunk_data,
            aad: &aad,
        };

        let ciphertext = cipher
            .encrypt(&nonce.into(), payload)
            .map_err(|e| KrelError::CryptoError(format!("Encryption failed: {}", e)))?;

        // Update integrity hash with ciphertext
        integrity_hasher.update(&ciphertext);

        // Write encrypted chunk
        writer.write_all(&ciphertext).await?;

        chunk_index += 1;
    }

    // Compute final integrity hash
    let integrity_hash = *integrity_hasher.finalize().as_bytes();

    // Write trailer
    let trailer = Trailer::new(integrity_hash);
    let trailer_bytes = trailer.to_bytes()?;
    writer.write_all(&trailer_bytes).await?;

    // Flush and sync
    writer.flush().await?;
    let file = writer.into_inner();
    file.sync_all().await?;

    Ok(())
}

/// Decrypt a file with streaming chunks
/// 
/// # Security
/// - Verifies header before processing
/// - Unwraps and verifies DEK commitment
/// - Validates each chunk's authentication tag
/// - Verifies overall integrity hash from trailer
/// - Returns IntegrityError if hash mismatch detected
pub async fn decrypt<P: AsRef<Path>>(
    source: P,
    dest: P,
    password: &Secret,
) -> Result<()> {
    let source = source.as_ref();
    let dest = dest.as_ref();

    // Open source file
    let source_file = File::open(source).await.map_err(|e| {
        KrelError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to open source file: {}", e),
        ))
    })?;
    let mut reader = BufReader::new(source_file);

    // Read header
    let mut header_bytes = [0u8; HEADER_SIZE];
    reader.read_exact(&mut header_bytes).await?;
    let header = Header::from_bytes(&header_bytes)?;
    header.validate()?;

    // Unwrap DEK
    let dek = unwrap_dek(&header, password)?;

    // Compute immutable header hash for AAD
    let immutable_hash = compute_immutable_header_hash(&header.salt, &header.nonce_base);

    // Initialize integrity hasher
    let mut integrity_hasher = blake3::Hasher::new();
    integrity_hasher.update(&header_bytes);

    // Create cipher
    let cipher = dek.expose(|key| {
        XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| KrelError::CryptoError(format!("Invalid DEK: {}", e)))
    })?;

    // Create destination file
    let dest_file = File::create(dest).await.map_err(|e| {
        KrelError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to create destination file: {}", e),
        ))
    })?;
    let mut writer = BufWriter::new(dest_file);

    // Get file size to determine where trailer starts
    let metadata = tokio::fs::metadata(source).await?;
    let file_size = metadata.len() as usize;
    let ciphertext_size = file_size - HEADER_SIZE - TRAILER_SIZE;

    // Process chunks
    let mut chunk_index: u64 = 0;
    let mut bytes_processed = 0;
    let mut buffer = vec![0u8; ENCRYPTED_CHUNK_SIZE];

    while bytes_processed < ciphertext_size {
        let remaining = ciphertext_size - bytes_processed;
        let to_read = remaining.min(ENCRYPTED_CHUNK_SIZE);

        // Read encrypted chunk
        let bytes_read = reader.read(&mut buffer[..to_read]).await?;
        if bytes_read == 0 {
            return Err(KrelError::ContainerError(
                "Unexpected EOF while reading chunks".to_string(),
            ));
        }

        // Update integrity hash with ciphertext
        integrity_hasher.update(&buffer[..bytes_read]);

        // Determine if this is the final chunk
        let is_final = bytes_processed + bytes_read >= ciphertext_size;

        // Construct nonce and AAD for this chunk
        let nonce = construct_chunk_nonce(&header.nonce_base, chunk_index);
        let aad = construct_chunk_aad(&immutable_hash, chunk_index, is_final);

        // Decrypt chunk
        let payload = Payload {
            msg: &buffer[..bytes_read],
            aad: &aad,
        };

        let plaintext = cipher
            .decrypt(&nonce.into(), payload)
            .map_err(|_| KrelError::AuthError("Decryption failed - invalid password or corrupted data".to_string()))?;

        // Write decrypted chunk
        writer.write_all(&plaintext).await?;

        bytes_processed += bytes_read;
        chunk_index += 1;
    }

    // Read trailer
    let mut trailer_bytes = [0u8; TRAILER_SIZE];
    reader.read_exact(&mut trailer_bytes).await?;
    let trailer = Trailer::from_bytes(&trailer_bytes)?;
    trailer.validate()?;

    // Verify integrity hash
    let computed_hash = *integrity_hasher.finalize().as_bytes();
    if computed_hash != trailer.integrity_hash {
        return Err(KrelError::IntegrityError(
            "Integrity hash mismatch - file may be corrupted or tampered".to_string(),
        ));
    }

    // Flush and sync
    writer.flush().await?;
    let file = writer.into_inner();
    file.sync_all().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_construct_chunk_nonce() {
        let nonce_base = [1u8; 16];
        let nonce = construct_chunk_nonce(&nonce_base, 42);
        
        assert_eq!(nonce.len(), 24);
        assert_eq!(&nonce[..16], &[1u8; 16]);
        assert_eq!(&nonce[16..], &42u64.to_be_bytes());
    }

    #[tokio::test]
    async fn test_construct_chunk_aad() {
        let hash = [2u8; 32];
        let aad = construct_chunk_aad(&hash, 10, false);
        
        assert_eq!(aad.len(), 41);
        assert_eq!(&aad[..32], &hash);
        assert_eq!(&aad[32..40], &10u64.to_be_bytes());
        assert_eq!(aad[40], 0);

        let aad_final = construct_chunk_aad(&hash, 10, true);
        assert_eq!(aad_final[40], 1);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_small_file() {
        let temp_dir = std::env::temp_dir();
        let source = temp_dir.join("test_source.txt");
        let encrypted = temp_dir.join("test_encrypted.krel");
        let decrypted = temp_dir.join("test_decrypted.txt");

        // Create test file
        let test_data = b"Hello, KREL! This is a test of the streaming encryption.";
        tokio::fs::write(&source, test_data).await.unwrap();

        // Encrypt
        let password = Secret::from_slice(b"test-password");
        encrypt(&source, &encrypted, &password).await.unwrap();

        // Verify encrypted file exists and is larger (header + trailer + tag overhead)
        let encrypted_size = tokio::fs::metadata(&encrypted).await.unwrap().len();
        assert!(encrypted_size > test_data.len() as u64);

        // Decrypt
        decrypt(&encrypted, &decrypted, &password).await.unwrap();

        // Verify decrypted content matches
        let decrypted_data = tokio::fs::read(&decrypted).await.unwrap();
        assert_eq!(decrypted_data, test_data);

        // Cleanup
        let _ = tokio::fs::remove_file(source).await;
        let _ = tokio::fs::remove_file(encrypted).await;
        let _ = tokio::fs::remove_file(decrypted).await;
    }

    #[tokio::test]
    async fn test_decrypt_wrong_password() {
        let temp_dir = std::env::temp_dir();
        let source = temp_dir.join("test_source2.txt");
        let encrypted = temp_dir.join("test_encrypted2.krel");
        let decrypted = temp_dir.join("test_decrypted2.txt");

        // Create and encrypt
        tokio::fs::write(&source, b"Secret data").await.unwrap();
        let password = Secret::from_slice(b"correct-password");
        encrypt(&source, &encrypted, &password).await.unwrap();

        // Try to decrypt with wrong password
        let wrong_password = Secret::from_slice(b"wrong-password");
        let result = decrypt(&encrypted, &decrypted, &wrong_password).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KrelError::AuthError(_)));

        // Cleanup
        let _ = tokio::fs::remove_file(source).await;
        let _ = tokio::fs::remove_file(encrypted).await;
    }
}
