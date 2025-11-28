use crate::error::KrelError;
use crate::secret::Secret;
use crate::{decrypt, encrypt, rekey, verify, verify_full};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyByteArray;
use std::path::PathBuf;

/// Convert KrelError to Python exception
fn krel_error_to_py(err: KrelError) -> PyErr {
    match err {
        KrelError::ContainerError(msg) => PyValueError::new_err(format!("Container error: {}", msg)),
        KrelError::IntegrityError(msg) => {
            PyRuntimeError::new_err(format!("Integrity error: {}", msg))
        }
        KrelError::AuthError(msg) => PyValueError::new_err(format!("Authentication error: {}", msg)),
        KrelError::IoError(err) => PyRuntimeError::new_err(format!("I/O error: {}", err)),
        KrelError::CryptoError(msg) => PyRuntimeError::new_err(format!("Crypto error: {}", msg)),
        KrelError::InvalidParameter(msg) => {
            PyValueError::new_err(format!("Invalid parameter: {}", msg))
        }
    }
}

/// Extract password from Python bytearray and IMMEDIATELY zero it
/// 
/// # Security - CRITICAL
/// This function implements a critical security pattern:
/// 1. Lock the Python bytearray buffer
/// 2. Copy bytes to Rust Secret wrapper
/// 3. IMMEDIATELY zero the Python bytearray in-place
/// 4. Return the Secret (which will be zeroized when dropped)
/// 
/// This prevents the password from lingering in Python's memory.
fn extract_and_zero_password(_py: Python, pwd: &PyByteArray) -> PyResult<Secret> {
    // SAFETY: We need unsafe to access the PyByteArray buffer
    // This is safe because:
    // 1. We hold a reference to the PyByteArray
    // 2. We're only reading and then zeroing it
    // 3. Python's GIL is held
    unsafe {
        // Get immutable view for copying
        let pwd_bytes = pwd.as_bytes();
        
        // Copy to Secret wrapper
        let secret = Secret::from_slice(pwd_bytes);
        
        // CRITICAL: Zero the Python bytearray immediately
        // Get mutable view and zero it
        let pwd_bytes_mut = pwd.as_bytes_mut();
        for byte in pwd_bytes_mut.iter_mut() {
            *byte = 0;
        }
        
        Ok(secret)
    }
}

/// KREL Encryption Engine
/// 
/// A secure file encryption engine with streaming support for large files.
/// 
/// # Security Notes
/// - Passwords MUST be passed as `bytearray` (not `bytes` or `str`)
/// - Passwords are automatically zeroed after use
/// - Uses Argon2id, XChaCha20-Poly1305, and BLAKE3
#[pyclass]
struct KrelEngine;

#[pymethods]
impl KrelEngine {
    #[new]
    fn new() -> Self {
        KrelEngine
    }

    /// Encrypt a file
    /// 
    /// Args:
    ///     src: Source file path
    ///     dst: Destination encrypted file path
    ///     pwd: Password as bytearray (will be zeroed)
    /// 
    /// # Security
    /// The password bytearray will be zeroed immediately after copying.
    fn encrypt<'p>(
        &self,
        py: Python<'p>,
        src: String,
        dst: String,
        pwd: &PyByteArray,
    ) -> PyResult<&'p PyAny> {
        let password = extract_and_zero_password(py, pwd)?;
        let src_path = PathBuf::from(src);
        let dst_path = PathBuf::from(dst);

        pyo3_asyncio::tokio::future_into_py(py, async move {
            encrypt(&src_path, &dst_path, &password)
                .await
                .map_err(krel_error_to_py)?;
            Ok(())
        })
    }

    /// Decrypt a file
    /// 
    /// Args:
    ///     src: Source encrypted file path
    ///     dst: Destination decrypted file path
    ///     pwd: Password as bytearray (will be zeroed)
    /// 
    /// # Security
    /// The password bytearray will be zeroed immediately after copying.
    fn decrypt<'p>(
        &self,
        py: Python<'p>,
        src: String,
        dst: String,
        pwd: &PyByteArray,
    ) -> PyResult<&'p PyAny> {
        let password = extract_and_zero_password(py, pwd)?;
        let src_path = PathBuf::from(src);
        let dst_path = PathBuf::from(dst);

        pyo3_asyncio::tokio::future_into_py(py, async move {
            decrypt(&src_path, &dst_path, &password)
                .await
                .map_err(krel_error_to_py)?;
            Ok(())
        })
    }

    /// Change password (O(1) operation)
    /// 
    /// Args:
    ///     path: Encrypted file path
    ///     old_pwd: Current password as bytearray (will be zeroed)
    ///     new_pwd: New password as bytearray (will be zeroed)
    /// 
    /// # Security
    /// Both password bytearrays will be zeroed immediately after copying.
    fn rekey<'p>(
        &self,
        py: Python<'p>,
        path: String,
        old_pwd: &PyByteArray,
        new_pwd: &PyByteArray,
    ) -> PyResult<&'p PyAny> {
        let old_password = extract_and_zero_password(py, old_pwd)?;
        let new_password = extract_and_zero_password(py, new_pwd)?;
        let file_path = PathBuf::from(path);

        pyo3_asyncio::tokio::future_into_py(py, async move {
            rekey(&file_path, &old_password, &new_password)
                .await
                .map_err(krel_error_to_py)?;
            Ok(())
        })
    }

    /// Verify file integrity (fast, no password required)
    /// 
    /// Args:
    ///     path: Encrypted file path
    /// 
    /// Returns:
    ///     True if file integrity is valid, False otherwise
    fn verify<'p>(&self, py: Python<'p>, path: String) -> PyResult<&'p PyAny> {
        let file_path = PathBuf::from(path);

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let result = verify(&file_path).await.map_err(krel_error_to_py)?;
            Ok(result)
        })
    }

    /// Verify file integrity and password (deep check)
    /// 
    /// Args:
    ///     path: Encrypted file path
    ///     pwd: Password as bytearray (will be zeroed)
    /// 
    /// Returns:
    ///     True if both password and integrity are valid, False otherwise
    /// 
    /// # Security
    /// The password bytearray will be zeroed immediately after copying.
    fn verify_full<'p>(
        &self,
        py: Python<'p>,
        path: String,
        pwd: &PyByteArray,
    ) -> PyResult<&'p PyAny> {
        let password = extract_and_zero_password(py, pwd)?;
        let file_path = PathBuf::from(path);

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let result = verify_full(&file_path, &password)
                .await
                .map_err(krel_error_to_py)?;
            Ok(result)
        })
    }
}

/// KREL Python module
#[pymodule]
fn _core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<KrelEngine>()?;
    Ok(())
}
