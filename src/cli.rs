use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "filecrypt",
    version,
    author,
    about = "A secure file encryption tool",
    long_about = "FileCrypt is a CLI tool for secure file encryption using AES-256-GCM and Argon2id.\n\nFeatures:\n- Secure encryption/decryption\n- Password generation\n- File hashing\n- Folder integrity audit\n- Self-destruct option"
)]
pub struct FileCrypt {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt a file
    Encrypt {
        /// Input file to encrypt
        #[arg(short, long, value_name = "FILE")]
        input_file: PathBuf,

        /// Output file (encrypted)
        #[arg(short, long, value_name = "FILE")]
        output_file: PathBuf,

        /// Verbose output
        #[arg(short, long, action)]
        verbose: bool,

        /// Dry run (don't actually encrypt)
        #[arg(long, action)]
        dry_run: bool,
    },

    /// Decrypt a file
    Decrypt {
        /// Input file to decrypt
        #[arg(short, long, value_name = "FILE")]
        input_file: PathBuf,

        /// Output file (decrypted)
        #[arg(short, long, value_name = "FILE")]
        output_file: PathBuf,

        /// Verbose output
        #[arg(short, long, action)]
        verbose: bool,

        /// Dry run (don't actually decrypt)
        #[arg(long, action)]
        dry_run: bool,
    },

    /// Generate a strong random password
    GenPassword,

    /// Compute SHA-256 hash of a file
    Hash {
        /// File to hash
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },

    /// Audit folder for encrypted file integrity
    Audit {
        /// Directory to audit
        #[arg(value_name = "DIR")]
        dir: PathBuf,
    },
}

#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Text,
    Json,
}