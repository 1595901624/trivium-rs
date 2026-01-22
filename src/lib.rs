//! Trivium stream cipher crate
//!
//! Provides a small, tested implementation of the Trivium stream cipher
//! with a single exported helper `trivium_xor` for XORing data with the
//! generated keystream.
//!
//! # Example
//!
//! ```
//! let key = vec![0u8; 10];
//! let iv = vec![0u8; 10];
//! let data = b"hello".to_vec();
//! let ct = trivium::trivium_xor(key.clone(), iv.clone(), data.clone()).unwrap();
//! let pt = trivium::trivium_xor(key, iv, ct).unwrap();
//! assert_eq!(pt, data);
//! ```


mod trivium;

pub use trivium::trivium_xor;

