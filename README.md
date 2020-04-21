# enocoro128v2

![crates.io](https://img.shields.io/crates/v/enocoro128v2.svg)
![GitHub Actions](https://github.com/entropy-security/enocoro128v2/workflows/Test/badge.svg)

Safe Rust, `#![no_std]` implementation of Enocoro-128v2 [1], the updated variant [2] of a lightweight, CRYPTREC candidate [3] stream cipher.
No practical attacks against Enocoro-128v2 have been reported [4].

### Functionality

* Symmetric-key encryption
* Pseudo-Random Number Generator (PRNG)

### Implementation

* Operational in baremetal environments: no standard library dependencies, no dynamic memory allocation
* State securely wiped from memory on drop [5]
* Close mapping to Hitachi's C reference implementation [6] for audit-friendly code
* Verified using Hitachi's official test vectors [7]

### Considerations

* Encryption alone does *not* guarantee integrity or authenticity: depending on your usecase, this library may need to be combined with a Hash-based Message Authentication Code (HMAC)
* PRNG functions must be seeded from a platform-specific entropy source

### Usage

When the entirety of the plaintext or ciphertext is in-memory at once, a simplified API (associated functions) can be used:

```rust
use enocoro128v2::Enocoro128;

let key: [u8; 16] = [
    0x4b, 0x8e, 0x29, 0x87, 0x80, 0x95, 0x96, 0xa3,
    0xbb, 0x23, 0x82, 0x49, 0x9f, 0x1c, 0xe7, 0xc2,
];

let iv: [u8; 8] = [0x3c, 0x1d, 0xbb, 0x05, 0xe3, 0xca, 0x60, 0xd9];

let plaintext = [
    0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,
]; // "Hello world!"

let mut msg: [u8; 12] = plaintext.clone();

// Encrypt in-place
Enocoro128::apply_keystream_static(&key, &iv, &mut msg);
assert_ne!(msg, plaintext);

// Decrypt in-place
Enocoro128::apply_keystream_static(&key, &iv, &mut msg);
assert_eq!(msg, plaintext);
```

If entirety of the plaintext or ciphertext is never in memory at once (e.g. data received/transmitted in chunks, potentially of varying sizes), the instance API can be used:

```rust
use enocoro128v2::Enocoro128;

let key: [u8; 16] = [
    0x4b, 0x8e, 0x29, 0x87, 0x80, 0x95, 0x96, 0xa3,
    0xbb, 0x23, 0x82, 0x49, 0x9f, 0x1c, 0xe7, 0xc2,
];

let iv: [u8; 8] = [0x3c, 0x1d, 0xbb, 0x05, 0xe3, 0xca, 0x60, 0xd9];

let plaintext_1 = [0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"
let plaintext_2 = [0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21]; // " world!"

let mut msg_1 = plaintext_1.clone();
let mut msg_2 = plaintext_2.clone();

// Create an instance of the cipher
let mut e128 = Enocoro128::new(&key, &iv);

// Encrypt in-place
e128.apply_keystream(&mut msg_1);
e128.apply_keystream(&mut msg_2);
assert_ne!(msg_1, plaintext_1);
assert_ne!(msg_2, plaintext_2);

// Reset keystream prior to decryption
e128.init_keystream();

// Decrypt in-place
e128.apply_keystream(&mut msg_1);
e128.apply_keystream(&mut msg_2);
assert_eq!(msg_1, plaintext_1);
assert_eq!(msg_2, plaintext_2);
```

To generate random buffers or numbers from the keystream (note the caller is responsible for using a platform specific entropy source to
create the key and IV, these values seed the PRNG!):

```rust
use enocoro128v2::Enocoro128;

// Assuming bytes gathered from a reliable, platform-specific entropy source
let key: [u8; 16] = [
    0x4b, 0x8e, 0x29, 0x87, 0x80, 0x95, 0x96, 0xa3,
    0xbb, 0x23, 0x82, 0x49, 0x9f, 0x1c, 0xe7, 0xc2,
];

// Assuming bytes gathered from a reliable, platform-specific entropy source
let iv: [u8; 8] = [0x3c, 0x1d, 0xbb, 0x05, 0xe3, 0xca, 0x60, 0xd9];

let mut my_rand_buf = [0; 3];
let mut my_rand_u16: u16 = 0;
let mut my_rand_u64: u64 = 0;

let mut e128 = Enocoro128::new(&key, &iv);

e128.rand_buf(&mut my_rand_buf);
assert!(my_rand_buf.iter().all(|&x| x != 0));

my_rand_u16 = e128.rand_u16();
assert_ne!(my_rand_u16, 0);

my_rand_u64 = e128.rand_u64();
assert_ne!(my_rand_u64, 0);
```

### References
---

* [1] ["Pseudorandom Number Generator Enocoro", Hitachi Corporation (2010)](https://www.hitachi.com/rd/yrl/crypto/enocoro/index.html)
* [2] ["Update on Enocoro Stream Cipher", Dai Watanabe et. al. (2010)](https://ieeexplore.ieee.org/document/5649627)
* [3] ["Specifications of Ciphers in the Candidate Recommended Ciphers List", CRYPTREC (2013)](https://www.cryptrec.go.jp/en/method.html)
* [4] ["Security Evaluation of Stream Cipher Enocoro-128v2", Martin Hell and Thomas Johansson (2010)](https://www.cryptrec.go.jp/exreport/cryptrec-ex-2008-2010.pdf)
* [5] ["zeroize", Tony Arcieri (2019)](https://crates.io/crates/zeroize)
* [6] [enocoro_ref_20100222.zip, Hitachi Corporation (2010)](https://www.hitachi.com/rd/yrl/crypto/enocoro/enocoro_ref_20100222.zip)
* [7] [enocoro_tv_20100202.zip, Hitachi Corporation (2010)](https://www.hitachi.com/rd/yrl/crypto/enocoro/enocoro_ref_20100222.zip)