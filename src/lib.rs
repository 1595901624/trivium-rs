//! Trivium stream cipher crate
//!
//! Provides a small, tested implementation of the Trivium stream cipher
//! with a helper `trivium_xor` for XORing data with the generated keystream,
//! and public types for advanced usage (`Trivium`, `BitOrder`, `PackOrder`).
//!
//! # Examples
//!
//! Basic helper usage:
//! ```
//! let key = vec![0u8; 10];
//! let iv = vec![0u8; 10];
//! let data = b"hello".to_vec();
//! let ct = trivium::trivium_xor(key.clone(), iv.clone(), data.clone()).unwrap();
//! let pt = trivium::trivium_xor(key, iv, ct).unwrap();
//! assert_eq!(pt, data);
//! ```
//!
//! Direct usage (custom options):
//! ```
//! use trivium::{Trivium, BitOrder, PackOrder};
//! let key = vec![0u8; 10];
//! let iv = vec![0u8; 10];
//! let data = b"hello".to_vec();
//! let ct = Trivium::new(&key, &iv, BitOrder::Lsb, PackOrder::Lsb).xor_bytes(&data);
//! let pt = Trivium::new(&key, &iv, BitOrder::Lsb, PackOrder::Lsb).xor_bytes(&ct);
//! assert_eq!(pt, data);
//! ```


mod trivium;

pub use trivium::{trivium_xor, Trivium, BitOrder, PackOrder};

