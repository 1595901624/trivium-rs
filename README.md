# trivium

A small Rust implementation of the Trivium stream cipher.

- Exported function: `trivium::trivium_xor(key, iv, data, bit_order)`
  - `key` and `iv` are arbitrary-length `Vec<u8>` values; they are truncated/padded to 10 bytes (80 bits)
  - `bit_order` is an `Option<String>`: accepted values include `"msb"` (default) and `"lsb"`

Example:

```rust
let key = vec![0u8; 10];
let iv = vec![0u8; 10];
let data = b"hello".to_vec();
let ct = trivium::trivium_xor(key.clone(), iv.clone(), data.clone(), Some("msb".into())).unwrap();
let pt = trivium::trivium_xor(key, iv, ct, Some("msb".into())).unwrap();
assert_eq!(pt, data);
```
