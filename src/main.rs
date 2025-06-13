//! FileCrypt: A command-line tool for encrypting, decrypting, and auditing files securely.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod cli;
mod constants;
mod crypto;
mod errors;
mod utils;

use clap::Parser;
use colored::Colorize;
use std::process;

use crate::cli::{Commands, FileCrypt};
use crate::errors::FileCryptError;

fn main() {
    if let Err(e) = run() {
        eprintln!("{}: {}", "error".red().bold(), e);
        process::exit(1);
    }
}

fn run() -> Result<(), FileCryptError> {
    let args = FileCrypt::parse();

    // Initialize console
    console::set_colors_enabled(true);
    console::set_colors_enabled_stderr(true);

    match args.command {
        Commands::Encrypt {
            input_file,
            output_file,
            verbose,
            dry_run,
        } => crypto::encrypt_file(&input_file, &output_file, verbose, dry_run)?,
        Commands::Decrypt {
            input_file,
            output_file,
            verbose,
            dry_run,
        } => crypto::decrypt_file(&input_file, &output_file, verbose, dry_run)?,
        Commands::GenPassword => utils::generate_password()?,
        Commands::Hash { file } => utils::hash_file(&file)?,
        Commands::Audit { dir } => utils::audit_folder(&dir)?,
    }

    Ok(())
}