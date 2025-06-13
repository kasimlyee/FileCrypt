use std::io;
use std::path::PathBuf;

use aes_gcm::aead::Error as AeadError;
use argon2::password_hash::Error as PasswordHashError;
use argon2::Error as Argon2Error;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum FileCryptError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Password hashing error: {0}")]
    PasswordHash(#[from] PasswordHashError),

    #[error("Encryption/decryption error: {0}")]
    Crypto(#[from] AeadError),

    #[error("Key derivation error: {0}")]
    Kdf(#[from] Argon2Error),

    #[error("Invalid file format or header")]
    InvalidFileFormat,

    #[error("Authentication failed - wrong password or corrupted file")]
    AuthenticationFailed,

    #[error("File not found: {0}")]
    FileNotFound(PathBuf),


    #[error("Self-destruct triggered - file has been securely wiped")]
    SelfDestruct,

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid UTF-8 sequence: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("Invalid hex string: {0}")]
    Hex(#[from] hex::FromHexError),

}

impl Zeroize for FileCryptError {
    fn zeroize(&mut self) {
        // No sensitive data in errors
    }
}