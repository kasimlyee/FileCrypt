use lazy_static::lazy_static;
use std::sync::atomic::{AtomicBool};

// File format constants
pub const FILE_MAGIC: &[u8; 8] = b"FILECRPT";
pub const VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 8 + 1 + 16 + 12; // magic + version + salt + iv + tag

// Security parameters
pub const ARGON2_M_COST: u32 = 19456; // 19MB
pub const ARGON2_T_COST: u32 = 2;
pub const ARGON2_P_COST: u32 = 1;
pub const ARGON2_OUTPUT_LEN: usize = 32;

// Self-destruct password
pub const SELF_DESTRUCT_PASSWORD: &str = "--self-destruct";

lazy_static! {
    pub static ref VERBOSE: AtomicBool = AtomicBool::new(false);
}