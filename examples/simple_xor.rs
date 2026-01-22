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

fn main() {
    let key = hex_to_bytes("00000010000000000000");
    let mut key_reversed = key.clone();
    key_reversed.reverse();
    let iv = hex_to_bytes("00000000000000000000");
    let msg = b"hello".to_vec();

    let ct = trivium::trivium_xor(key_reversed.clone(), iv.clone(), msg.clone())
        .expect("encrypt");
    let hex = ct.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    println!("ciphertext: {}", hex);

    let pt = trivium::trivium_xor(key_reversed, iv, ct)
        .expect("decrypt");
    assert_eq!(pt, msg);
    println!("decrypted ok");
}
