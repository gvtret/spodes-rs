use criterion::{black_box, criterion_group, criterion_main, Criterion};
use spodes_rs::classes::data::Data;
use spodes_rs::classes::register::Register;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::CosemDataType;

fn bench_data_serialize(c: &mut Criterion) {
    let obis = ObisCode::new(1, 0, 1, 8, 0, 0xFF);
    let data = Data::new(obis, CosemDataType::DoubleLongUnsigned(123_456));

    c.bench_function("Data serialize", |b| {
        b.iter(|| {
            serialize_object(black_box(&data)).unwrap();
        });
    });
}

fn bench_data_deserialize(c: &mut Criterion) {
    let obis = ObisCode::new(1, 0, 1, 8, 0, 0xFF);
    let data = Data::new(obis, CosemDataType::DoubleLongUnsigned(123_456));
    let encoded = serialize_object(&data).unwrap();

    c.bench_function("Data deserialize", |b| {
        b.iter(|| {
            let mut obj = Data::new(ObisCode::new(0, 0, 0, 0, 0, 0), CosemDataType::Null);
            deserialize_object(&mut obj, black_box(&encoded)).unwrap();
        });
    });
}

fn bench_register_serialize(c: &mut Criterion) {
    let obis = ObisCode::new(1, 0, 1, 8, 0, 0xFF);
    let reg = Register::new(obis, CosemDataType::DoubleLongUnsigned(123_456), CosemDataType::Long(0));

    c.bench_function("Register serialize", |b| {
        b.iter(|| {
            serialize_object(black_box(&reg)).unwrap();
        });
    });
}

fn bench_register_deserialize(c: &mut Criterion) {
    let obis = ObisCode::new(1, 0, 1, 8, 0, 0xFF);
    let reg = Register::new(obis, CosemDataType::DoubleLongUnsigned(123_456), CosemDataType::Long(0));
    let encoded = serialize_object(&reg).unwrap();

    c.bench_function("Register deserialize", |b| {
        b.iter(|| {
            let mut obj = Register::new(ObisCode::new(0, 0, 0, 0, 0, 0), CosemDataType::Null, CosemDataType::Null);
            deserialize_object(&mut obj, black_box(&encoded)).unwrap();
        });
    });
}

fn bench_obis_serialize(c: &mut Criterion) {
    let obis = ObisCode::new(1, 0, 1, 8, 0, 0xFF);

    c.bench_function("OBIS serialize", |b| {
        b.iter(|| {
            black_box(obis.to_bytes());
        });
    });
}

criterion_group!(
    benches,
    bench_data_serialize,
    bench_data_deserialize,
    bench_register_serialize,
    bench_register_deserialize,
    bench_obis_serialize,
);
criterion_main!(benches);
