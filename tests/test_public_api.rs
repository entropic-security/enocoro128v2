use enocoro128v2::Enocoro128;

static KEY: [u8; 16] = [
    0x4b, 0x8e, 0x29, 0x87, 0x80, 0x95, 0x96, 0xa3, 0xbb, 0x23, 0x82, 0x49, 0x9f, 0x1c, 0xe7, 0xc2,
];

static IV: [u8; 8] = [0x3c, 0x1d, 0xbb, 0x05, 0xe3, 0xca, 0x60, 0xd9];

#[test]
fn test_enc_dec_stateless() {
    let plaintext = [
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,
    ]; // "Hello world!"
    let mut msg: [u8; 12] = [
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,
    ]; // "Hello world!"

    // Encryption changes message
    Enocoro128::apply_keystream_static(&KEY, &IV, &mut msg);
    assert_ne!(msg, plaintext);

    // Decryption reverses encryption
    Enocoro128::apply_keystream_static(&KEY, &IV, &mut msg);
    assert_eq!(msg, plaintext);
}

#[test]
fn test_enc_dec_stateful() {
    let plaintext_1 = [0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"
    let plaintext_2 = [0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21]; // " world!"

    let mut msg_1 = [0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"
    let mut msg_2 = [0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21]; // " world!"

    let mut e128 = Enocoro128::new(&KEY, &IV);

    // Encryption changes messages/chunks of varying sizes
    e128.apply_keystream(&mut msg_1);
    e128.apply_keystream(&mut msg_2);
    assert_ne!(msg_1, plaintext_1);
    assert_ne!(msg_2, plaintext_2);

    // Decryption reverses encryption
    e128.init_keystream();
    e128.apply_keystream(&mut msg_1);
    e128.apply_keystream(&mut msg_2);
    assert_eq!(msg_1, plaintext_1);
    assert_eq!(msg_2, plaintext_2);
}

#[test]
fn test_rand() {
    let mut my_rand_buf = [0; 3];
    let mut my_rand_u8: u8 = 0;
    let mut my_rand_u16: u16 = 0;
    let mut my_rand_u32: u32 = 0;
    let mut my_rand_u64: u64 = 0;
    let mut my_rand_u128: u128 = 0;

    // Avoid warning about assigned value never being read
    assert!(my_rand_buf.iter().all(|&x| x == 0));
    assert_eq!(my_rand_u8, 0);
    assert_eq!(my_rand_u16, 0);
    assert_eq!(my_rand_u32, 0);
    assert_eq!(my_rand_u64, 0);
    assert_eq!(my_rand_u128, 0);

    let mut e128 = Enocoro128::new(&KEY, &IV);

    e128.rand_buf(&mut my_rand_buf);
    assert!(my_rand_buf.iter().all(|&x| x != 0));

    my_rand_u8 = e128.rand_u8();
    assert_ne!(my_rand_u8, 0);

    my_rand_u16 = e128.rand_u16();
    assert_ne!(my_rand_u16, 0);

    my_rand_u32 = e128.rand_u32();
    assert_ne!(my_rand_u32, 0);

    my_rand_u64 = e128.rand_u64();
    assert_ne!(my_rand_u64, 0);

    my_rand_u128 = e128.rand_u128();
    assert_ne!(my_rand_u128, 0);
}
