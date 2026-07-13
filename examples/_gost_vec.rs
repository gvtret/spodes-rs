#![allow(clippy::needless_borrow)]

fn main() {
    use cmac::{Cmac, KeyInit, Mac};
    use kuznyechik::Kuznyechik;
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    let k_em = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    let iv = hex("4d4d4d0000bc614e01234567");
    let stoc = hex("8899aabbccddeeff");
    let ctos = hex("0011223344556677");
    let key = &k_em[32..];
    let mut mac = Cmac::<Kuznyechik>::new_from_slice(key).unwrap();
    mac.update(&iv);
    mac.update(&[0x30u8]);
    mac.update(&stoc);
    mac.update(&ctos);
    let m = mac.finalize().into_bytes();
    print!("MAC: ");
    for b in m.iter() {
        print!("{:02x}", b);
    }
    println!();
    use streebog::Digest;
    let mut d = streebog::Streebog256::new();
    d.update(b"secret16bytes!!!");
    d.update(b"CCCCCCCC");
    d.update(b"SSSSSSSS");
    d.update([1, 2].as_ref());
    d.update([3, 4].as_ref());
    let h = d.finalize();
    print!("STREEBOG: ");
    for b in h.iter() {
        print!("{:02x}", b);
    }
    println!();
}
