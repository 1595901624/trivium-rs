# trivium

A small Rust implementation of the Trivium stream cipher.

- Exported helper: `trivium::trivium_xor(key, iv, data)`
  - `key` and `iv` are arbitrary-length `Vec<u8>` values; they are truncated/padded to 10 bytes (80 bits)
  - Key/IV bits are interpreted MSB-first by default when using the helper.
- Public types for advanced use:
  - `trivium::Trivium` — construct directly with `Trivium::new(...)` for custom options.
  - `trivium::BitOrder` and `trivium::PackOrder` — control how bits are read and packed.

Basic example (helper):

```rust
let key = vec![0u8; 10];
let iv = vec![0u8; 10];
let data = b"hello".to_vec();
let ct = trivium::trivium_xor(key.clone(), iv.clone(), data.clone()).unwrap();
let pt = trivium::trivium_xor(key, iv, ct).unwrap();
assert_eq!(pt, data);
```

Direct usage example (custom options):

```rust
use trivium::{Trivium, BitOrder, PackOrder};

let key = vec![0u8; 10];
let iv = vec![0u8; 10];
let data = b"hello".to_vec();

// Instantiate with LSB load order and LSB packing for output bytes
let ct = Trivium::new(&key, &iv, BitOrder::Lsb, PackOrder::Lsb).xor_bytes(&data);
let pt = Trivium::new(&key, &iv, BitOrder::Lsb, PackOrder::Lsb).xor_bytes(&ct);
assert_eq!(pt, data);
```

> Note: The crate also exposes `Trivium`, `BitOrder`, and `PackOrder` and includes a direct-usage example in the crate documentation (see `src/lib.rs` doctests).

## Migration / Breaking changes

- The `trivium_xor` helper no longer accepts a `bit_order` parameter. It now defaults to MSB when reading key/IV bits within each byte.
- For LSB loading or other custom behavior, construct directly with `Trivium::new(&key, &iv, BitOrder::Lsb, PackOrder::Lsb)` and call `.xor_bytes(&data)`.
- `Trivium::new` and `Trivium::xor_bytes` are public, and `BitOrder`/`PackOrder` are exported from the crate root.