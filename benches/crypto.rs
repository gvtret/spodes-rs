use criterion::{black_box, criterion_group, criterion_main, Criterion};
use spodes_rs::security::gost3410;
use spodes_rs::security::hls;
use spodes_rs::security::signature;
use spodes_rs::security::SecuritySuite;

fn bench_gost3410_sign(c: &mut Criterion) {
    let sk = [0x11u8; 32];
    let msg = b"benchmark message for GOST 34.10 signing";

    c.bench_function("GOST 34.10 sign", |b| {
        b.iter(|| {
            gost3410::gost_sign(black_box(&sk), black_box(msg)).unwrap();
        });
    });
}

fn bench_gost3410_verify(c: &mut Criterion) {
    let sk = [0x11u8; 32];
    let pk = gost3410::public_key(&sk).unwrap();
    let msg = b"benchmark message for GOST 34.10 verification";
    let sig = gost3410::gost_sign(&sk, msg).unwrap();

    c.bench_function("GOST 34.10 verify", |b| {
        b.iter(|| {
            gost3410::gost_verify(black_box(&pk), black_box(msg), black_box(&sig)).unwrap();
        });
    });
}

fn bench_gost3410_vko(c: &mut Criterion) {
    let sk = [0x11u8; 32];
    let pk = gost3410::public_key(&sk).unwrap();
    let ukm = [0x22u8; 32];

    c.bench_function("GOST VKO key agreement", |b| {
        b.iter(|| {
            gost3410::vko(black_box(&sk), black_box(&pk), black_box(&ukm)).unwrap();
        });
    });
}

fn bench_gost_cmac(c: &mut Criterion) {
    // K_EM must be 64 bytes; gost_cmac uses LSB256 (last 32 bytes)
    let mut k_em = [0u8; 64];
    k_em[32..].copy_from_slice(&[0x11u8; 32]);
    let iv = [0x22u8; 12];
    let data = [0x33u8; 64];

    c.bench_function("Kuznyechik CMAC", |b| {
        b.iter(|| {
            hls::gost_cmac(black_box(&k_em), black_box(&iv), 0x10, black_box(&data), black_box(&data)).unwrap();
        });
    });
}

fn bench_ecdsa_sign_p256(c: &mut Criterion) {
    let sk = [0x11u8; 32];
    let msg = b"benchmark message for ECDSA P-256 signing";

    c.bench_function("ECDSA P-256 sign", |b| {
        b.iter(|| {
            signature::ecdsa_sign(black_box(SecuritySuite::Suite1), black_box(&sk), black_box(msg)).unwrap();
        });
    });
}

fn bench_ecdsa_verify_p256(c: &mut Criterion) {
    use p256::ecdsa::SigningKey;
    let sk = [0x11u8; 32];
    let signing = SigningKey::from_bytes(&sk.into()).unwrap();
    let pk = signing.verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let msg = b"benchmark message for ECDSA P-256 verification";
    let sig = signature::ecdsa_sign(SecuritySuite::Suite1, &sk, msg).unwrap();

    c.bench_function("ECDSA P-256 verify", |b| {
        b.iter(|| {
            signature::ecdsa_verify(black_box(SecuritySuite::Suite1), black_box(&pk), black_box(msg), black_box(&sig))
                .unwrap();
        });
    });
}

fn bench_kdf_tree(c: &mut Criterion) {
    let key = [0x11u8; 32];
    let label = b"test_label";
    let seed = [0x22u8; 8];

    c.bench_function("KDF_TREE_GOSTR3411_2012_256", |b| {
        b.iter(|| {
            gost3410::kdf_tree(black_box(&key), black_box(label), black_box(&seed), 96);
        });
    });
}

criterion_group!(
    benches,
    bench_gost3410_sign,
    bench_gost3410_verify,
    bench_gost3410_vko,
    bench_gost_cmac,
    bench_ecdsa_sign_p256,
    bench_ecdsa_verify_p256,
    bench_kdf_tree,
);
criterion_main!(benches);
