use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{SaltString},
    Argon2, PasswordHasher,
};
use rand::{RngCore, thread_rng};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

use crate::{
    constants::*,
    errors::FileCryptError,
    utils::{get_password, secure_wipe_file},
};

/// Encrypts a file using AES-256-GCM with Argon2id key derivation
pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    verbose: bool,
    dry_run: bool,
) -> Result<(), FileCryptError> {
    if verbose {
        println!(
            "{} Encrypting {} → {}",
            "•".blue(),
            input_path.display(),
            output_path.display()
        );
    }

    // Check input file exists
    if !input_path.exists() {
        return Err(FileCryptError::FileNotFound(input_path.to_path_buf()));
    }

    // Get password from user (twice for confirmation)
    let password = get_password("Enter encryption password: ")?;
    let confirm_password = get_password("Confirm password: ")?;

    if password != confirm_password {
        return Err(FileCryptError::AuthenticationFailed);
    }

    // Check for self-destruct password
    if password == SELF_DESTRUCT_PASSWORD {
        secure_wipe_file(input_path)?;
        return Err(FileCryptError::SelfDestruct);
    }

    // Generate random salt and IV
    let mut salt = [0u8; 16];
    thread_rng().fill_bytes(&mut salt);
    let salt_str = SaltString::encode_b64(&salt)
        .map_err(|e| FileCryptError::PasswordHash(e))?;
    let iv = Aes256Gcm::generate_nonce(&mut OsRng);

    // Derive key using Argon2id
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(ARGON2_OUTPUT_LEN),
    )?);

    let key = argon2
        .hash_password(password.as_bytes(), &salt_str)?
        .hash
        .ok_or(FileCryptError::Kdf(argon2::Error::OutputTooShort))?;

    let key = Key::<Aes256Gcm>::from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(key);

    if dry_run {
        println!("{} Dry run - no files will be modified", "!".yellow());
        return Ok(());
    }

    // Read input file
    let input_size = fs::metadata(input_path)?.len();
    let mut input_file = File::open(input_path)?;

    // Create output file
    let mut output_file = File::create(output_path)?;

    // Write header (magic + version + salt + iv)
    output_file.write_all(FILE_MAGIC)?;
    output_file.write_all(&[VERSION])?;
    output_file.write_all(&salt)?;
    output_file.write_all(&iv)?;

    // Initialize progress bar
    let pb = if verbose {
        let pb = ProgressBar::new(input_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
                )
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

// Process file in chunks to handle large files
let mut buffer = [0u8; 4096];
let mut total_read = 0;

loop {
    let read = input_file.read(&mut buffer)?;
    if read == 0 {
        break;
    }

    let chunk = &buffer[..read];
    let ciphertext = cipher.encrypt(&iv, chunk)
        .map_err(|e| {
            if verbose {
                println!("{} Encryption failed at position {}", "✗".red(), total_read);
            }
            FileCryptError::Crypto(e)
        })?;

    // Write ciphertext (which includes the authentication tag)
    output_file.write_all(&ciphertext)?;

    total_read += read as u64;
    if let Some(pb) = &pb {
        pb.set_position(total_read);
    }
}

    if let Some(pb) = pb {
        pb.finish_with_message("Encryption complete");
    }

    if verbose {
        println!(
            "{} File encrypted successfully ({} bytes)",
            "✓".green(),
            input_size
        );
    }

    Ok(())
}

/// Decrypts a file using AES-256-GCM with Argon2id key derivation
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    verbose: bool,
    dry_run: bool,
) -> Result<(), FileCryptError> {
    if verbose {
        println!(
            "{} Decrypting {} → {}",
            "•".blue(),
            input_path.display(),
            output_path.display()
        );
    }

    // Check input file exists
    if !input_path.exists() {
        return Err(FileCryptError::FileNotFound(input_path.to_path_buf()));
    }

    // Get password from user
    let password = get_password("Enter decryption password: ")?;

    // Check for self-destruct password
    if password == SELF_DESTRUCT_PASSWORD {
        secure_wipe_file(input_path)?;
        return Err(FileCryptError::SelfDestruct);
    }

    if dry_run {
        println!("{} Dry run - no files will be modified", "!".yellow());
        return Ok(());
    }

    // Read input file
    let input_size = fs::metadata(input_path)?.len();
    let mut input_file = File::open(input_path)?;

    // Read and validate header
    let mut header = [0u8; HEADER_SIZE];
    input_file.read_exact(&mut header)?;

    if &header[..8] != FILE_MAGIC {
        return Err(FileCryptError::InvalidFileFormat);
    }

    let version = header[8];
    if version != VERSION {
        return Err(FileCryptError::InvalidFileFormat);
    }

    let salt = &header[9..25];
    let salt_str = SaltString::encode_b64(salt)
        .map_err(|e| FileCryptError::PasswordHash(e))?;
    let iv = Nonce::from_slice(&header[25..37]);

    // Derive key using Argon2id
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(ARGON2_OUTPUT_LEN),
    )?);

    let key = argon2
        .hash_password(password.as_bytes(), &salt_str)?
        .hash
        .ok_or(FileCryptError::Kdf(argon2::Error::OutputTooShort))?;

    let key = Key::<Aes256Gcm>::from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(key);

    // Create output file
    let mut output_file = File::create(output_path)?;

    // Initialize progress bar
    let pb = if verbose {
        let pb = ProgressBar::new(input_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
                )
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    // Process file in chunks
    let mut buffer = vec![0u8; 4096 + 16]; // Account for GCM tag
    let mut total_read = HEADER_SIZE as u64;

    loop {
        let read = input_file.read(&mut buffer)?;
        if read == 0 {
            break;
        }

        // The entire chunk includes the authentication tag
        let chunk = &buffer[..read];
        let plaintext = cipher.decrypt(iv, chunk)
            .map_err(|e| {
                if verbose {
                    println!("{} Decryption failed at position {}", "✗".red(), total_read);
                }
                FileCryptError::Crypto(e)
            })?;

        output_file.write_all(&plaintext)?;

        total_read += read as u64;
        if let Some(pb) = &pb {
            pb.set_position(total_read);
        }
    }

    if let Some(pb) = pb {
        pb.finish_with_message("Decryption complete");
    }

    if verbose {
        println!(
            "{} File decrypted successfully ({} bytes)",
            "✓".green(),
            input_size - HEADER_SIZE as u64
        );
    }

    Ok(())
}