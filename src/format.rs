use crate::error::{KrelError, Result};
use std::io::{Read, Write};

/// Magic bytes identifying a KREL container
pub const MAGIC: [u8; 4] = *b"KREL";

/// Current version of the KREL format
pub const VERSION: u16 = 1;

/// Size of the header in bytes (fixed)
pub const HEADER_SIZE: usize = 128;

/// Size of the trailer in bytes (fixed)
pub const TRAILER_SIZE: usize = 36;

/// KREL container header (128 bytes fixed size)
/// 
/// Layout:
/// - magic: [u8; 4] = b"KREL"
/// - version: u16 = 1
/// - salt: [u8; 16] (random, for key derivation)
/// - nonce_base: [u8; 16] (random, base for nonce derivation)
/// - wrapped_dek: [u8; 48] (32 bytes DEK + 16 bytes AEAD tag)
/// - commitment: [u8; 32] (BLAKE3 hash for verification)
/// - reserved: [u8; 10] (zeros for future use)
#[derive(Debug, Clone)]
pub struct Header {
    /// Magic bytes identifying the container format
    pub magic: [u8; 4],
    
    /// Format version
    pub version: u16,
    
    /// Random salt for key derivation (Argon2id)
    pub salt: [u8; 16],
    
    /// Base nonce for XChaCha20-Poly1305 (combined with chunk index)
    pub nonce_base: [u8; 16],
    
    /// Wrapped Data Encryption Key (32 bytes key + 16 bytes Poly1305 tag)
    pub wrapped_dek: [u8; 48],
    
    /// BLAKE3 commitment hash for integrity verification
    pub commitment: [u8; 32],
    
    /// Reserved space for future extensions
    pub reserved: [u8; 10],
}

impl Header {
    /// Create a new header with the given parameters
    pub fn new(
        salt: [u8; 16],
        nonce_base: [u8; 16],
        wrapped_dek: [u8; 48],
        commitment: [u8; 32],
    ) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            salt,
            nonce_base,
            wrapped_dek,
            commitment,
            reserved: [0u8; 10],
        }
    }

    /// Serialize the header to bytes (exactly 128 bytes)
    pub fn to_bytes(&self) -> Result<[u8; HEADER_SIZE]> {
        let mut buf = [0u8; HEADER_SIZE];
        let mut cursor = &mut buf[..];
        
        // Write magic (4 bytes)
        cursor.write_all(&self.magic)?;
        
        // Write version (2 bytes, big-endian)
        cursor.write_all(&self.version.to_be_bytes())?;
        
        // Write salt (16 bytes)
        cursor.write_all(&self.salt)?;
        
        // Write nonce_base (16 bytes)
        cursor.write_all(&self.nonce_base)?;
        
        // Write wrapped_dek (48 bytes)
        cursor.write_all(&self.wrapped_dek)?;
        
        // Write commitment (32 bytes)
        cursor.write_all(&self.commitment)?;
        
        // Write reserved (10 bytes)
        cursor.write_all(&self.reserved)?;
        
        Ok(buf)
    }

    /// Deserialize a header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_SIZE {
            return Err(KrelError::ContainerError(format!(
                "Invalid header size: expected {}, got {}",
                HEADER_SIZE,
                bytes.len()
            )));
        }

        let mut cursor = bytes;
        
        // Read magic (4 bytes)
        let mut magic = [0u8; 4];
        cursor.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(KrelError::ContainerError(format!(
                "Invalid magic bytes: expected {:?}, got {:?}",
                MAGIC, magic
            )));
        }

        // Read version (2 bytes)
        let mut version_bytes = [0u8; 2];
        cursor.read_exact(&mut version_bytes)?;
        let version = u16::from_be_bytes(version_bytes);
        if version != VERSION {
            return Err(KrelError::ContainerError(format!(
                "Unsupported version: {}, expected {}",
                version, VERSION
            )));
        }

        // Read salt (16 bytes)
        let mut salt = [0u8; 16];
        cursor.read_exact(&mut salt)?;

        // Read nonce_base (16 bytes)
        let mut nonce_base = [0u8; 16];
        cursor.read_exact(&mut nonce_base)?;

        // Read wrapped_dek (48 bytes)
        let mut wrapped_dek = [0u8; 48];
        cursor.read_exact(&mut wrapped_dek)?;

        // Read commitment (32 bytes)
        let mut commitment = [0u8; 32];
        cursor.read_exact(&mut commitment)?;

        // Read reserved (10 bytes)
        let mut reserved = [0u8; 10];
        cursor.read_exact(&mut reserved)?;

        Ok(Self {
            magic,
            version,
            salt,
            nonce_base,
            wrapped_dek,
            commitment,
            reserved,
        })
    }

    /// Validate the header's integrity
    pub fn validate(&self) -> Result<()> {
        if self.magic != MAGIC {
            return Err(KrelError::ContainerError(
                "Invalid magic bytes".to_string()
            ));
        }
        
        if self.version != VERSION {
            return Err(KrelError::ContainerError(format!(
                "Unsupported version: {}",
                self.version
            )));
        }
        
        Ok(())
    }
}

/// KREL container trailer (36 bytes fixed size)
/// 
/// Layout:
/// - integrity_hash: [u8; 32] (BLAKE3 hash of entire file excluding this field)
/// - magic: [u8; 4] = b"KREL"
#[derive(Debug, Clone)]
pub struct Trailer {
    /// BLAKE3 hash of the entire file (header + ciphertext)
    pub integrity_hash: [u8; 32],
    
    /// Magic bytes (redundant check)
    pub magic: [u8; 4],
}

impl Trailer {
    /// Create a new trailer with the given integrity hash
    pub fn new(integrity_hash: [u8; 32]) -> Self {
        Self {
            integrity_hash,
            magic: MAGIC,
        }
    }

    /// Serialize the trailer to bytes (exactly 36 bytes)
    pub fn to_bytes(&self) -> Result<[u8; TRAILER_SIZE]> {
        let mut buf = [0u8; TRAILER_SIZE];
        let mut cursor = &mut buf[..];
        
        // Write integrity_hash (32 bytes)
        cursor.write_all(&self.integrity_hash)?;
        
        // Write magic (4 bytes)
        cursor.write_all(&self.magic)?;
        
        Ok(buf)
    }

    /// Deserialize a trailer from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != TRAILER_SIZE {
            return Err(KrelError::ContainerError(format!(
                "Invalid trailer size: expected {}, got {}",
                TRAILER_SIZE,
                bytes.len()
            )));
        }

        let mut cursor = bytes;
        
        // Read integrity_hash (32 bytes)
        let mut integrity_hash = [0u8; 32];
        cursor.read_exact(&mut integrity_hash)?;

        // Read magic (4 bytes)
        let mut magic = [0u8; 4];
        cursor.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(KrelError::ContainerError(format!(
                "Invalid trailer magic bytes: expected {:?}, got {:?}",
                MAGIC, magic
            )));
        }

        Ok(Self {
            integrity_hash,
            magic,
        })
    }

    /// Validate the trailer's integrity
    pub fn validate(&self) -> Result<()> {
        if self.magic != MAGIC {
            return Err(KrelError::ContainerError(
                "Invalid trailer magic bytes".to_string()
            ));
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_size() {
        let header = Header::new(
            [1u8; 16],
            [2u8; 16],
            [3u8; 48],
            [4u8; 32],
        );
        let bytes = header.to_bytes().unwrap();
        assert_eq!(bytes.len(), HEADER_SIZE);
    }

    #[test]
    fn test_header_roundtrip() {
        let original = Header::new(
            [1u8; 16],
            [2u8; 16],
            [3u8; 48],
            [4u8; 32],
        );
        
        let bytes = original.to_bytes().unwrap();
        let decoded = Header::from_bytes(&bytes).unwrap();
        
        assert_eq!(decoded.magic, MAGIC);
        assert_eq!(decoded.version, VERSION);
        assert_eq!(decoded.salt, [1u8; 16]);
        assert_eq!(decoded.nonce_base, [2u8; 16]);
        assert_eq!(decoded.wrapped_dek, [3u8; 48]);
        assert_eq!(decoded.commitment, [4u8; 32]);
    }

    #[test]
    fn test_header_invalid_magic() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0..4].copy_from_slice(b"XXXX");
        bytes[4..6].copy_from_slice(&VERSION.to_be_bytes());
        
        let result = Header::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KrelError::ContainerError(_)));
    }

    #[test]
    fn test_trailer_size() {
        let trailer = Trailer::new([5u8; 32]);
        let bytes = trailer.to_bytes().unwrap();
        assert_eq!(bytes.len(), TRAILER_SIZE);
    }

    #[test]
    fn test_trailer_roundtrip() {
        let original = Trailer::new([5u8; 32]);
        
        let bytes = original.to_bytes().unwrap();
        let decoded = Trailer::from_bytes(&bytes).unwrap();
        
        assert_eq!(decoded.integrity_hash, [5u8; 32]);
        assert_eq!(decoded.magic, MAGIC);
    }

    #[test]
    fn test_trailer_invalid_magic() {
        let mut bytes = [0u8; TRAILER_SIZE];
        bytes[32..36].copy_from_slice(b"XXXX");
        
        let result = Trailer::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KrelError::ContainerError(_)));
    }
}
