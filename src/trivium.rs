#[allow(dead_code)]
const KEY_BYTES: usize = 10;
#[allow(dead_code)]
const IV_BYTES: usize = 10;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum BitOrder {
    Msb,
    Lsb,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum PackOrder {
    Lsb,
} 

// `parse_bit_order` removed: key/IV bits are interpreted MSB-first by default.


fn normalize_to_fixed(input: &[u8], target_len: usize) -> [u8; KEY_BYTES] {
    // NOTE: target_len is always 10 in our usage; keep small and simple.
    let mut out = [0u8; KEY_BYTES];
    let n = input.len().min(target_len);
    out[..n].copy_from_slice(&input[..n]);
    out
}

fn get_bit(bytes: &[u8], bit_index: usize, order: BitOrder) -> u8 {
    let byte_index = bit_index >> 3;
    let bit_in_byte = bit_index & 7;
    if byte_index >= bytes.len() {
        return 0;
    }
    let b = bytes[byte_index];
    match order {
        // bit_index 0 is the MSB of the first byte
        BitOrder::Msb => (b >> (7 - bit_in_byte)) & 1,
        // bit_index 0 is the LSB of the first byte
        BitOrder::Lsb => (b >> bit_in_byte) & 1,
    }
}

#[derive(Clone)]
pub struct Trivium {
    s1: [u8; 93],
    s2: [u8; 84],
    s3: [u8; 111],
    pack_order: PackOrder,
}

impl Trivium {
    /// Create a new `Trivium` instance.
    ///
    /// `load_order` controls how key/IV bits are read within each input byte (MSB or LSB).
    /// `pack_order` controls how keystream bits are packed into output bytes.
    pub fn new(key_raw: &[u8], iv_raw: &[u8], load_order: BitOrder, pack_order: PackOrder) -> Self {
        let key = normalize_to_fixed(key_raw, KEY_BYTES);
        let iv = normalize_to_fixed(iv_raw, IV_BYTES);

        let mut s1 = [0u8; 93];
        let mut s2 = [0u8; 84];
        let mut s3 = [0u8; 111];

        // s1: 80-bit key then 13 zeros
        for (i, b) in s1.iter_mut().enumerate().take(80) {
            *b = get_bit(&key, i, load_order);
        }

        // s2: 80-bit IV then 4 zeros
        for (i, b) in s2.iter_mut().enumerate().take(80) {
            *b = get_bit(&iv, i, load_order);
        }

        // s3: 108 zeros then 3 ones
        s3[108] = 1;
        s3[109] = 1;
        s3[110] = 1;

        let mut st = Self {
            s1,
            s2,
            s3,
            pack_order,
        };

        // Warm-up: 4 * 288 = 1152 steps
        for _ in 0..(4 * 288) {
            let _ = st.next_bit();
        }

        st
    }

    #[inline]
    fn shift_in(reg: &mut [u8], new_bit: u8) {
        for i in (1..reg.len()).rev() {
            reg[i] = reg[i - 1];
        }
        reg[0] = new_bit & 1;
    }

    fn next_bit(&mut self) -> u8 {
        // Indices are 0-based (spec positions minus 1)
        let t1 = self.s1[65] ^ self.s1[92];
        let t2 = self.s2[68] ^ self.s2[83];
        let t3 = self.s3[65] ^ self.s3[110];
        let z = t1 ^ t2 ^ t3;

        let t1n = t1 ^ (self.s1[90] & self.s1[91]) ^ self.s2[77];
        let t2n = t2 ^ (self.s2[81] & self.s2[82]) ^ self.s3[86];
        let t3n = t3 ^ (self.s3[108] & self.s3[109]) ^ self.s1[68];

        Self::shift_in(&mut self.s1, t3n);
        Self::shift_in(&mut self.s2, t1n);
        Self::shift_in(&mut self.s3, t2n);

        z & 1
    }

    fn keystream_byte(&mut self) -> u8 {
        match self.pack_order {
            PackOrder::Lsb => {
                // Pack bits LSB-first within each output byte: first output bit becomes bit 0.
                let mut b = 0u8;
                for j in 0..8 {
                    b |= (self.next_bit() & 1) << j;
                }
                b
            }
        }
    }

    /// XOR `data` with the Trivium keystream produced by this instance.
    ///
    /// Consumes the `Trivium` instance (it owns the state progression).
    pub fn xor_bytes(mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for &v in data {
            let k = self.keystream_byte();
            out.push(v ^ k);
        }
        out
    }
}

/// Trivium stream cipher XOR (encrypt/decrypt)
///
/// - `key` / `iv`: arbitrary-length bytes; will be truncated/padded to 10 bytes (80-bit)
/// - `data`: input bytes
/// - Key/IV bits are read MSB-first within each byte.
///
/// # Examples
/// ```
/// let key = vec![0u8; 10];
/// let iv = vec![0u8; 10];
/// let data = b"hello".to_vec();
/// let ct = trivium::trivium_xor(key.clone(), iv.clone(), data.clone()).unwrap();
/// let pt = trivium::trivium_xor(key, iv, ct).unwrap();
/// assert_eq!(pt, data);
/// ```
pub fn trivium_xor(
    key: Vec<u8>,
    iv: Vec<u8>,
    data: Vec<u8>,
) -> Result<Vec<u8>, String> {
    // Default to MSB when reading key/IV bits within each byte.
    let trivium = Trivium::new(&key, &iv, BitOrder::Msb, PackOrder::Lsb);
    Ok(trivium.xor_bytes(&data))
} 

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let clean: String = s
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .trim_start_matches("0x")
            .to_string();
        assert!(clean.len().is_multiple_of(2), "hex must have even length");
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).expect("hex byte"))
            .collect()
    }

    fn make_prng(seed: u32) -> impl FnMut() -> u32 {
        let mut x = seed;
        move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        }
    }

    fn random_bytes(mut prng: impl FnMut() -> u32, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        for b in &mut out {
            *b = (prng() & 0xff) as u8;
        }
        out
    }

    #[test]
    fn xor_is_symmetric_msb() {
        let mut prng = make_prng(0x1234_5678);

        for _ in 0..64 {
            let key = random_bytes(&mut prng, 10);
            let iv = random_bytes(&mut prng, 10);
            let msg_len = (prng() as usize) % 512;
            let msg = random_bytes(&mut prng, msg_len);

            let ct = trivium_xor(key.clone(), iv.clone(), msg.clone()).expect("encrypt");
            let pt = trivium_xor(key, iv, ct).expect("decrypt");

            assert_eq!(pt, msg);
        }
    }

    #[test]
    fn xor_is_symmetric_lsb() {
        let mut prng = make_prng(0x9e37_79b9);

        for _ in 0..64 {
            let key = random_bytes(&mut prng, 10);
            let iv = random_bytes(&mut prng, 10);
            let msg_len = (prng() as usize) % 512;
            let msg = random_bytes(&mut prng, msg_len);

            let ct = Trivium::new(&key, &iv, BitOrder::Lsb, PackOrder::Lsb).xor_bytes(&msg);
            let pt = Trivium::new(&key, &iv, BitOrder::Lsb, PackOrder::Lsb).xor_bytes(&ct);

            assert_eq!(pt, msg);
        }
    }

    #[test]
    fn accepts_short_key_iv_by_padding_with_zeros() {
        let key = vec![1, 2, 3];
        let iv = vec![4, 5];
        let msg = b"hello".to_vec();

        let ct = trivium_xor(key.clone(), iv.clone(), msg.clone()).unwrap();
        let pt = trivium_xor(key, iv, ct).unwrap();

        assert_eq!(pt, msg);
    }

    #[test]
    fn known_vector_hello_key_iv() {
        // User-provided known-answer test:
        // plaintext: "hello"
        // key (hex): 00000010000000000000
        // iv  (hex): 00000000000000000000
        // expected ciphertext (hex): 9f804f6861
        let key = hex_to_bytes("00000010000000000000");
        let iv = hex_to_bytes("00000000000000000000");
        let msg = b"hello".to_vec();

        let expected = hex_to_bytes("9f804f6861");

        // This project interprets HEX key/IV as big-endian 80-bit values in the UI,
        // then reverses the 10-byte sequence before sending to Rust.
        // The backend reads bits MSB-first (bitOrder=msb) and packs keystream bytes LSB-first.
        let mut key_reversed = key.clone();
        key_reversed.reverse();

        let ct = trivium_xor(key_reversed, iv, msg).unwrap();
        assert_eq!(ct, expected);
    }
}
