use colored::Colorize;
use rand::{
    distributions::{Alphanumeric, DistString},
    thread_rng, Rng,
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    time::Instant,
};
use walkdir::WalkDir;

use crate::{
    constants::*,
    
    errors::FileCryptError,
};

/// Securely gets a password from user input (no echo)
pub fn get_password(prompt: &str) -> Result<String, FileCryptError> {
    loop {
        let password = rpassword::prompt_password(prompt)?;

        if password.is_empty() {
            println!("{} Password cannot be empty", "✗".red());
            continue;
        }

        return Ok(password);
    }
}

/// Generates a strong random password
pub fn generate_password() -> Result<(), FileCryptError> {
    let mut rng = thread_rng();
    let length = rng.gen_range(16..=32);
    let password = Alphanumeric.sample_string(&mut rng, length);

    println!(
        "{} Generated password: {}",
        "✓".green(),
        password.yellow()
    );

    Ok(())
}

/// Computes SHA-256 hash of a file
pub fn hash_file(file_path: &Path) -> Result<(), FileCryptError> {
    let mut file = File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 4096];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    let hash = hasher.finalize();
    println!("{} {}", "SHA-256:".bold(), hex::encode(hash));

    Ok(())
}

/// Securely wipes a file by overwriting with random data before deletion
pub fn secure_wipe_file(file_path: &Path) -> Result<(), FileCryptError> {
    let file_size = std::fs::metadata(file_path)?.len();
    let mut rng = rand::thread_rng();

    // Overwrite with random data 3 times
    for _ in 0..3 {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(file_path)?;

        let mut remaining = file_size;
        let mut buffer = [0u8; 4096];

        while remaining > 0 {
            let chunk_size = std::cmp::min(remaining, buffer.len() as u64);
            rng.fill(&mut buffer[..chunk_size as usize]);
            file.write_all(&buffer[..chunk_size as usize])?;
            remaining -= chunk_size;
        }

        file.sync_all()?;
    }

    // Finally delete the file
    std::fs::remove_file(file_path)?;

    Ok(())
}

/// Audits a folder for encrypted files, checking their integrity
pub fn audit_folder(dir_path: &Path) -> Result<(), FileCryptError> {
    println!("{} Auditing folder: {}", "•".blue(), dir_path.display());

    let mut total_files = 0;
    let mut corrupted_files = 0;
    let mut valid_files = 0;

    let start_time = Instant::now();

    for entry in WalkDir::new(dir_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if let Some(ext) = path.extension() {
            if ext == "fcrypt" {
                total_files += 1;

                print!("Checking {}... ", path.display());
                std::io::stdout().flush()?;

                match check_file_integrity(path) {
                    Ok(_) => {
                        println!("{}", "✓".green());
                        valid_files += 1;
                    }
                    Err(e) => {
                        println!("{} ({})", "✗".red(), e);
                        corrupted_files += 1;
                    }
                }
            }
        }
    }

    let duration = start_time.elapsed();

    println!("\nAudit completed in {:.2?}", duration);
    println!("{} Total encrypted files: {}", "•".blue(), total_files);
    println!("{} Valid files: {}", "✓".green(), valid_files);
    println!("{} Corrupted files: {}", "✗".red(), corrupted_files);

    Ok(())
}

/// Checks the integrity of an encrypted file
fn check_file_integrity(file_path: &Path) -> Result<(), FileCryptError> {
    let mut file = File::open(file_path)?;

    // Read and validate header
    let mut header = [0u8; HEADER_SIZE];
    file.read_exact(&mut header)?;

    if &header[..8] != FILE_MAGIC {
        return Err(FileCryptError::InvalidFileFormat);
    }

    let version = header[8];
    if version != VERSION {
        return Err(FileCryptError::InvalidFileFormat);
    }

    // The rest of the file should be ciphertext
    Ok(())
}