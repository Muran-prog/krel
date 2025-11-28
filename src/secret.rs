use zeroize::{Zeroize, ZeroizeOnDrop};
use std::fmt;

/// A secure wrapper around sensitive data that:
/// - Zeroes memory on drop
/// - Prevents cloning to reduce copies
/// - Prevents debug printing to avoid logs
/// - Provides controlled access via closures
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret {
    // Using Vec<u8> for dynamic size support
    data: Vec<u8>,
}

impl Secret {
    /// Create a new Secret from a byte vector
    /// 
    /// SECURITY: The input vector will be consumed and zeroized when Secret is dropped
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a new Secret from a byte slice (copies data)
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            data: slice.to_vec(),
        }
    }

    /// Create a new Secret with specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Get the length of the secret data
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the secret is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Access the secret data through a closure
    /// 
    /// SECURITY: This is the ONLY safe way to access the secret data.
    /// The data is exposed only within the closure scope to minimize exposure time.
    /// 
    /// # Example
    /// ```
    /// let secret = Secret::new(vec![1, 2, 3]);
    /// let sum = secret.expose(|data| data.iter().sum::<u8>());
    /// ```
    pub fn expose<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.data)
    }

    /// Mutably access the secret data through a closure
    /// 
    /// SECURITY: Use with extreme caution. Allows modification of the secret.
    pub fn expose_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Vec<u8>) -> R,
    {
        f(&mut self.data)
    }

    /// Explicitly zeroize the secret
    /// 
    /// Note: This is also done automatically on drop, but can be called
    /// explicitly for immediate cleanup.
    pub fn zeroize_now(&mut self) {
        self.data.zeroize();
    }
}

// SECURITY: Do NOT implement Clone to prevent accidental copies
// that could leave sensitive data in memory.

// SECURITY: Do NOT implement Debug to prevent secrets from
// appearing in logs, panic messages, or debug output.
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("data", &"<redacted>")
            .finish()
    }
}

/// Fixed-size secret for known-size secrets (e.g., keys)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretArray<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SecretArray<N> {
    /// Create a new SecretArray from a fixed-size array
    pub fn new(data: [u8; N]) -> Self {
        Self { data }
    }

    /// Create a new SecretArray filled with zeros
    pub fn zero() -> Self {
        Self { data: [0u8; N] }
    }

    /// Access the secret data through a closure
    pub fn expose<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; N]) -> R,
    {
        f(&self.data)
    }

    /// Mutably access the secret data through a closure
    pub fn expose_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8; N]) -> R,
    {
        f(&mut self.data)
    }

    /// Explicitly zeroize the secret
    pub fn zeroize_now(&mut self) {
        self.data.zeroize();
    }
}

// SECURITY: Do NOT implement Clone or Debug for the same reasons as Secret
impl<const N: usize> fmt::Debug for SecretArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretArray")
            .field("data", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_creation_and_access() {
        let secret = Secret::new(vec![1, 2, 3, 4]);
        assert_eq!(secret.len(), 4);
        
        let sum = secret.expose(|data| data.iter().sum::<u8>());
        assert_eq!(sum, 10);
    }

    #[test]
    fn test_secret_zeroize() {
        let mut secret = Secret::new(vec![42, 43, 44]);
        let original_len = secret.len();
        assert_eq!(original_len, 3);
        
        secret.zeroize_now();
        
        // After zeroize, the vector is cleared (length = 0)
        // The important part is that the memory was zeroed before clearing
        secret.expose(|data| {
            assert_eq!(data.len(), 0);
        });
    }

    #[test]
    fn test_secret_array() {
        let secret = SecretArray::<32>::new([1u8; 32]);
        secret.expose(|data| {
            assert_eq!(data.len(), 32);
            assert_eq!(data[0], 1);
        });
    }

    #[test]
    fn test_secret_debug_redacted() {
        let secret = Secret::new(vec![1, 2, 3]);
        let debug_str = format!("{:?}", secret);
        assert!(debug_str.contains("redacted"));
        assert!(!debug_str.contains("1"));
    }
}
