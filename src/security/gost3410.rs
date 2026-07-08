//! GOST R 34.10-2018 (256-bit) digital signatures — HLS mechanism 10.
//!
//! No mature Rust crate implements the GOST elliptic-curve signature scheme, so
//! it is provided here from scratch over the curve mandated by the DLMS GOST
//! profile: `id-tc26-gost-3410-2012-256-paramSetB`, OID `1.2.643.7.1.2.1.1.2`
//! (Р 1323565.1.024-2019, cryptographic suite 9). The message digest is
//! Streebog-256 (GOST R 34.11-2018).
//!
//! During the HLS handshake (Р 1323565.1, §7.5.3) the signed message is
//! `SystemTitle-a ‖ SystemTitle-b ‖ challenge_a ‖ challenge_b`; each party signs
//! with its own signing key `d_sign` and verifies the peer's response with the
//! peer's verification key `Q_sign`.
//!
//! Keys and signatures use the profile's fixed-width big-endian encodings:
//! `d_sign` is `Vec256(d)` (32 octets), the verification key is
//! `π_x(Q) ‖ π_y(Q)` (64 octets), and a signature is `Vec256(r) ‖ Vec256(s)`
//! (64 octets), matching GOST R 34.10 and the control examples in Р 1323565.1.

use hmac::{Hmac, Mac};
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};
use streebog::{Digest, Streebog256};

/// Curve parameters of `id-tc26-gost-3410-2012-256-paramSetB`.
struct Curve {
    p: BigUint,
    a: BigUint,
    b: BigUint,
    q: BigUint,
    gx: BigUint,
    gy: BigUint,
}

fn hexint(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).expect("valid curve constant")
}

fn curve() -> Curve {
    Curve {
        p: hexint("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
        a: hexint("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94"),
        b: hexint("00000000000000000000000000000000000000000000000000000000000000A6"),
        q: hexint("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"),
        gx: hexint("0000000000000000000000000000000000000000000000000000000000000001"),
        gy: hexint("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"),
    }
}

/// Affine point on the curve; `None` is the point at infinity.
type Point = Option<(BigUint, BigUint)>;

/// Modular inverse of `x` mod `m` (m prime, x != 0).
fn modinv(x: &BigUint, m: &BigUint) -> BigUint {
    let g = BigInt::from_biguint(Sign::Plus, x.clone()).extended_gcd(&BigInt::from_biguint(Sign::Plus, m.clone()));
    // g.gcd == 1 for a prime modulus and non-zero x.
    let mm = BigInt::from_biguint(Sign::Plus, m.clone());
    let inv = ((g.x % &mm) + &mm) % &mm;
    inv.to_biguint().expect("non-negative inverse")
}

fn mod_sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    if a >= b {
        (a - b) % p
    } else {
        (p - ((b - a) % p)) % p
    }
}

/// Point addition on the short-Weierstrass curve `y^2 = x^3 + a·x + b (mod p)`.
fn point_add(c: &Curve, p1: &Point, p2: &Point) -> Point {
    match (p1, p2) {
        (None, _) => p2.clone(),
        (_, None) => p1.clone(),
        (Some((x1, y1)), Some((x2, y2))) => {
            if x1 == x2 && (y1 != y2 || y1.is_zero()) {
                // P + (-P) = O, or a vertical tangent.
                return None;
            }
            let lambda = if x1 == x2 {
                // Doubling: (3·x1^2 + a) / (2·y1).
                let num = (BigUint::from(3u32) * x1 * x1 + &c.a) % &c.p;
                let den = (BigUint::from(2u32) * y1) % &c.p;
                (num * modinv(&den, &c.p)) % &c.p
            } else {
                let num = mod_sub(y2, y1, &c.p);
                let den = mod_sub(x2, x1, &c.p);
                (num * modinv(&den, &c.p)) % &c.p
            };
            let x3 = mod_sub(&mod_sub(&(&lambda * &lambda % &c.p), x1, &c.p), x2, &c.p);
            let y3 = mod_sub(&(&lambda * mod_sub(x1, &x3, &c.p) % &c.p), y1, &c.p);
            Some((x3, y3))
        }
    }
}

/// Scalar multiplication `k·point` by double-and-add.
fn point_mul(c: &Curve, k: &BigUint, point: &Point) -> Point {
    let mut result: Point = None;
    let mut addend = point.clone();
    let mut n = k.clone();
    while !n.is_zero() {
        if n.bit(0) {
            result = point_add(c, &result, &addend);
        }
        addend = point_add(c, &addend, &addend);
        n >>= 1;
    }
    result
}

/// Streebog-256 digest of `message` as an integer. GOST R 34.10 maps the hash
/// vector to the integer α with the first digest octet least significant.
fn hash_to_int(message: &[u8]) -> BigUint {
    let mut h = Streebog256::new();
    h.update(message);
    BigUint::from_bytes_le(&h.finalize())
}

/// Encodes an integer as a 32-octet `Vec256`. The DLMS GOST profile
/// (Р 1323565.1) uses little-endian byte order for scalars, coordinates and
/// signature components, unlike the big-endian mathematical notation of the
/// GOST R 34.10 standard itself.
fn vec256(x: &BigUint) -> [u8; 32] {
    let bytes = x.to_bytes_le();
    let mut out = [0u8; 32];
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}

/// Decodes a little-endian `Vec256` scalar/coordinate.
fn int_le(b: &[u8]) -> BigUint {
    BigUint::from_bytes_le(b)
}

/// Errors from GOST signing or verification.
#[derive(Debug, PartialEq, Eq)]
pub enum GostError {
    /// The signing key was zero or out of range.
    InvalidPrivateKey,
    /// The verification key was not a valid curve point.
    InvalidPublicKey,
    /// The signature had the wrong length or an out-of-range component.
    InvalidSignature,
    /// The signature did not verify.
    VerificationFailed,
}

/// Signs `message` with signing key `d` (32-octet big-endian `Vec256`) using a
/// caller-supplied `k` (32 octets, `1 ≤ k < q`). Returns `Vec256(r) ‖ Vec256(s)`.
///
/// Exposing `k` makes signing deterministic for the standard control examples;
/// production callers use [`gost_sign`], which draws `k` from a secure RNG.
pub fn gost_sign_with_k(d: &[u8], message: &[u8], k: &[u8]) -> Result<[u8; 64], GostError> {
    let c = curve();
    let d = int_le(d);
    if d.is_zero() || d >= c.q {
        return Err(GostError::InvalidPrivateKey);
    }
    let alpha = hash_to_int(message);
    let mut e = &alpha % &c.q;
    if e.is_zero() {
        e = BigUint::one();
    }
    let k = int_le(k);
    if k.is_zero() || k >= c.q {
        return Err(GostError::InvalidSignature);
    }
    let g = Some((c.gx.clone(), c.gy.clone()));
    let cpoint = point_mul(&c, &k, &g).ok_or(GostError::InvalidSignature)?;
    let r = cpoint.0 % &c.q;
    if r.is_zero() {
        return Err(GostError::InvalidSignature);
    }
    let s = (&r * &d + &k * &e) % &c.q;
    if s.is_zero() {
        return Err(GostError::InvalidSignature);
    }
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&vec256(&r));
    sig[32..].copy_from_slice(&vec256(&s));
    Ok(sig)
}

/// Signs `message` with signing key `d`, drawing a random `k` from a secure RNG.
pub fn gost_sign(d: &[u8], message: &[u8]) -> Result<[u8; 64], GostError> {
    use rand::Rng;
    let c = curve();
    let mut rng = rand::rng();
    loop {
        let mut kb = [0u8; 32];
        rng.fill(&mut kb);
        let k = BigUint::from_bytes_be(&kb) % &c.q;
        if k.is_zero() {
            continue;
        }
        match gost_sign_with_k(d, message, &vec256(&k)) {
            Ok(sig) => return Ok(sig),
            // A zero r or s is astronomically unlikely; just draw a fresh k.
            Err(GostError::InvalidSignature) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Verifies signature `sig` (`Vec256(r) ‖ Vec256(s)`, 64 octets) over `message`
/// with verification key `q_pub` (`π_x(Q) ‖ π_y(Q)`, 64 octets).
pub fn gost_verify(q_pub: &[u8], message: &[u8], sig: &[u8]) -> Result<(), GostError> {
    if q_pub.len() != 64 || sig.len() != 64 {
        return Err(GostError::InvalidSignature);
    }
    let c = curve();
    let r = int_le(&sig[..32]);
    let s = int_le(&sig[32..]);
    if r.is_zero() || r >= c.q || s.is_zero() || s >= c.q {
        return Err(GostError::InvalidSignature);
    }
    let qx = int_le(&q_pub[..32]);
    let qy = int_le(&q_pub[32..]);
    if qx >= c.p || qy >= c.p {
        return Err(GostError::InvalidPublicKey);
    }
    // The verification key must lie on the curve: y^2 == x^3 + a·x + b (mod p).
    let lhs = (&qy * &qy) % &c.p;
    let rhs = (&qx * &qx % &c.p * &qx + &c.a * &qx + &c.b) % &c.p;
    if lhs != rhs {
        return Err(GostError::InvalidPublicKey);
    }
    let q_point = Some((qx, qy));

    let alpha = hash_to_int(message);
    let mut e = &alpha % &c.q;
    if e.is_zero() {
        e = BigUint::one();
    }
    let v = modinv(&e, &c.q);
    let z1 = (&s * &v) % &c.q;
    let z2 = (&c.q - (&r * &v) % &c.q) % &c.q;
    let g = Some((c.gx.clone(), c.gy.clone()));
    let point = point_add(&c, &point_mul(&c, &z1, &g), &point_mul(&c, &z2, &q_point));
    match point {
        Some((x, _)) if (&x % &c.q) == r => Ok(()),
        _ => Err(GostError::VerificationFailed),
    }
}

/// VKO_GOST3410_2012_256 key-agreement function (R 50.1.113-2016 / RFC 7836).
///
/// Computes the shared key-encryption key from our private key `d`
/// (little-endian `Vec256`), the peer public key `q_pub` (`π_x(Q) ‖ π_y(Q)`,
/// 64 octets) and the user keying material `ukm` (little-endian). The curve has
/// cofactor 1, so the agreed point is `S = (ukm · d mod q) · Q`; the key is
/// `Streebog256(π_x(S) ‖ π_y(S))`.
pub fn vko(d: &[u8], q_pub: &[u8], ukm: &[u8]) -> Result<[u8; 32], GostError> {
    if q_pub.len() != 64 {
        return Err(GostError::InvalidPublicKey);
    }
    let c = curve();
    let d = int_le(d);
    if d.is_zero() || d >= c.q {
        return Err(GostError::InvalidPrivateKey);
    }
    let qx = int_le(&q_pub[..32]);
    let qy = int_le(&q_pub[32..]);
    if qx >= c.p || qy >= c.p {
        return Err(GostError::InvalidPublicKey);
    }
    let q_point = Some((qx, qy));
    let ukm = int_le(ukm);
    // Cofactor is 1 for this curve; scalar = ukm · d mod q.
    let scalar = (ukm * d) % &c.q;
    let (sx, sy) = point_mul(&c, &scalar, &q_point).ok_or(GostError::InvalidPublicKey)?;
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(&vec256(&sx));
    input.extend_from_slice(&vec256(&sy));
    let mut h = Streebog256::new();
    h.update(&input);
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&h.finalize());
    Ok(kek)
}

/// KDF_TREE_GOSTR3411_2012_256 (R 50.1.113-2016 / RFC 7836) with a one-octet
/// counter (`R = 1`).
///
/// Derives `output_len` octets from key `k`, a `label` and a `seed`:
/// each 256-bit block `K_i = HMAC_Streebog256(k, i ‖ label ‖ 0x00 ‖ seed ‖ L)`,
/// where `i` is a one-octet counter (1-based) and `L` is the total output length
/// in bits, encoded as a 16-bit big-endian integer. In the DLMS GOST profile
/// the diversified key is 768 bits: `Key = LSB512`, `M = MSB256`.
pub fn kdf_tree(k: &[u8], label: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    let l_bits = (output_len * 8) as u16;
    let blocks = output_len.div_ceil(32);
    let mut out = Vec::with_capacity(blocks * 32);
    for i in 1..=blocks as u8 {
        let mut mac = <Hmac<Streebog256> as hmac::digest::KeyInit>::new_from_slice(k).expect("HMAC accepts any key length");
        mac.update(&[i]);
        mac.update(label);
        mac.update(&[0x00]);
        mac.update(seed);
        mac.update(&l_bits.to_be_bytes());
        out.extend_from_slice(&mac.finalize().into_bytes());
    }
    out.truncate(output_len);
    out
}

/// Derives the verification key `π_x(Q) ‖ π_y(Q)` (64 octets) from a signing
/// key `d` (`Vec256`), where `Q = d·P`.
pub fn public_key(d: &[u8]) -> Result<[u8; 64], GostError> {
    let c = curve();
    let d = int_le(d);
    if d.is_zero() || d >= c.q {
        return Err(GostError::InvalidPrivateKey);
    }
    let g = Some((c.gx.clone(), c.gy.clone()));
    let (x, y) = point_mul(&c, &d, &g).ok_or(GostError::InvalidPrivateKey)?;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&vec256(&x));
    out[32..].copy_from_slice(&vec256(&y));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hb(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn ec_math_matches_gost_standard_example() {
        // GOST R 34.10-2018 Appendix control example (test curve, e given directly).
        let sc = Curve {
            p: hexint("8000000000000000000000000000000000000000000000000000000000000431"),
            a: hexint("0000000000000000000000000000000000000000000000000000000000000007"),
            b: hexint("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E"),
            q: hexint("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"),
            gx: hexint("0000000000000000000000000000000000000000000000000000000000000002"),
            gy: hexint("08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"),
        };
        let d = hexint("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28");
        let k = hexint("77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3");
        let e = hexint("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5");
        let g = Some((sc.gx.clone(), sc.gy.clone()));
        let r = point_mul(&sc, &k, &g).unwrap().0 % &sc.q;
        assert_eq!(r, hexint("41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493"));
        let s = (&r * &d + &k * &e) % &sc.q;
        assert_eq!(s, hexint("1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40"));
    }

    #[test]
    fn sign_matches_r1323565_a3_control_example() {
        // Р 1323565.1, A.3 — protection of data with a digital signature.
        let d = hb("48494a4b4c4d4e4f4041424344454647bbbbaaaa999988884444555566667777");
        let sign_data = hb("77006611552244338899aabbccddeeff001122334455667789abcdef");
        // Fixed k used across all SIGN_256 control examples.
        let k = hb("43730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011");
        let expected = hb("d3b72bb12fb7da1a06f8e11acdec034ffcf14588301a3315bbe8cd611fc4545e\
             a9fae88aeac47cd46a0858711d942223c523bfd53cbadff97e0eec1f69a3efca");
        let sig = gost_sign_with_k(&d, &sign_data, &k).unwrap();
        assert_eq!(sig.to_vec(), expected);
    }

    #[test]
    fn sign_verify_round_trip() {
        let d = hb("48494a4b4c4d4e4f4041424344454647bbbbaaaa999988884444555566667777");
        let pk = public_key(&d).unwrap();
        let msg = b"SystemTitle-a||SystemTitle-b||StoC||CtoS";
        let sig = gost_sign(&d, msg).unwrap();
        gost_verify(&pk, msg, &sig).unwrap();
        // Tampered message must fail.
        assert_eq!(gost_verify(&pk, b"other message", &sig), Err(GostError::VerificationFailed));
    }

    #[test]
    fn vko_matches_r1323565_key_agreement_example() {
        // Р 1323565.1, key-agreement control example: P_VU = VKO256(d_e,U, Q_s,V, r_U).
        let d = hb("68696a6b6c6d6e6f6061626364656667ddddddddccccccccaaaaaaaabbbbbbbb");
        let q = hb("212daf02de1c91ea961e58e01e42df1733c00748998bc34d76dad96b3b256378\
             7b9cffcfa0f24753d6d5eb6133b35a95375a0ef683b3ff5be7d61b99d7fe6617");
        let ukm = hb("f0f0f0f0e1e1e1e1d2d2d2d2c3c3c3c3");
        let expected = hb("4f54f663029709c0271facd5bb6d58187410477e102555a893d45a04ab0cafc0");
        assert_eq!(vko(&d, &q, &ukm).unwrap().to_vec(), expected);
    }

    #[test]
    fn kdf_tree_matches_r1323565_key_agreement_example() {
        // Р 1323565.1: T_VU = KDFTREE(P_VU, AlgorithmID, sysU ‖ sysV) ∈ V768.
        let k = hb("4f54f663029709c0271facd5bb6d58187410477e102555a893d45a04ab0cafc0");
        let label = hb("60857406080304"); // AlgorithmID
        let seed = hb("ff00ee11dd22cc33bb44aa5599668877"); // sysU ‖ sysV
        let expected = hb("e7f74dc8fcafd9738fd14d5aa542834bac7e883eff37931c082a9a80b45f60dd\
             159d1118b56f8e78e938c28715c34c3c197a2339638901de1c610180f7de34ac\
             424237f626e9ae5b55dbfa12ffd9cb7dfb903019eecc8228876015b2c15cbc89");
        let t = kdf_tree(&k, &label, &seed, 96);
        assert_eq!(t, expected);
        // M_VU = MSB256(T_VU).
        assert_eq!(&t[..32], &hb("e7f74dc8fcafd9738fd14d5aa542834bac7e883eff37931c082a9a80b45f60dd")[..]);
    }

    #[test]
    fn verify_rejects_wrong_lengths() {
        assert_eq!(gost_verify(&[0u8; 63], b"m", &[0u8; 64]), Err(GostError::InvalidSignature));
        assert_eq!(gost_verify(&[0u8; 64], b"m", &[0u8; 10]), Err(GostError::InvalidSignature));
    }
}
