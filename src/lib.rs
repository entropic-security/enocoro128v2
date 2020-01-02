//! Safe Rust, `#![no_std]` implementation of Enocoro-128v2 \[1\], the updated variant \[2\] of a lightweight, CRYPTREC candidate \[3\] stream cipher.
//! No practical attacks against Enocoro-128v2 have been reported \[4\].
//!
//! ### Functionality
//!
//! * Symmetric-key encryption
//! * Pseudo-Random Number Generator (PRNG)
//!
//! ### Implementation
//!
//! * Operational in baremetal environments: no standard library dependencies, no dynamic memory allocation
//! * State securely wiped from memory on drop \[5\]
//! * Close mapping to Hitachi's C reference implementation \[6\] for audit-friendly code
//! * Verified using Hitachi's official test vectors \[7\]
//!
//! ### Usage
//!
//!
//! When the entirety of the plaintext or ciphertext is in-memory at once, a simplified API can be used:
//!
//! ```
//! use enocoro128v2::Enocoro128;
//!
//! let key: [u8; 16] = [
//!     0x4b, 0x8e, 0x29, 0x87, 0x80, 0x95, 0x96, 0xa3,
//!     0xbb, 0x23, 0x82, 0x49, 0x9f, 0x1c, 0xe7, 0xc2,
//! ];
//!
//! let iv: [u8; 8] = [0x3c, 0x1d, 0xbb, 0x05, 0xe3, 0xca, 0x60, 0xd9];
//!
//! let plaintext = [
//!     0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,
//! ]; // "Hello world!"
//!
//! let mut msg: [u8; 12] = plaintext.clone();
//!
//! // Encrypt in-place
//! Enocoro128::apply_keystream_static(&key, &iv, &mut msg);
//! assert_ne!(msg, plaintext);
//!
//! // Decrypt in-place
//! Enocoro128::apply_keystream_static(&key, &iv, &mut msg);
//! assert_eq!(msg, plaintext);
//! ```
//!
//! If entirety of the plaintext or ciphertext is never in memory at once (e.g. data received/transmitted in chunks, potentially of varying sizes):
//!
//! ```
//! use enocoro128v2::Enocoro128;
//!
//! let key: [u8; 16] = [
//!     0x4b, 0x8e, 0x29, 0x87, 0x80, 0x95, 0x96, 0xa3,
//!     0xbb, 0x23, 0x82, 0x49, 0x9f, 0x1c, 0xe7, 0xc2,
//! ];
//!
//! let iv: [u8; 8] = [0x3c, 0x1d, 0xbb, 0x05, 0xe3, 0xca, 0x60, 0xd9];
//!
//! let plaintext_1 = [0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"
//! let plaintext_2 = [0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21]; // " world!"
//!
//! let mut msg_1 = plaintext_1.clone();
//! let mut msg_2 = plaintext_2.clone();
//!
//! // Create an instance of the cipher
//! let mut e128 = Enocoro128::new(&key, &iv);
//!
//! // Encrypt in-place
//! e128.apply_keystream(&mut msg_1);
//! e128.apply_keystream(&mut msg_2);
//! assert_ne!(msg_1, plaintext_1);
//! assert_ne!(msg_2, plaintext_2);
//!
//! // Reset keystream prior to decryption
//! e128.init_keystream();
//!
//! // Decrypt in-place
//! e128.apply_keystream(&mut msg_1);
//! e128.apply_keystream(&mut msg_2);
//! assert_eq!(msg_1, plaintext_1);
//! assert_eq!(msg_2, plaintext_2);
//! ```
//!
//! To generate random buffers or numbers from the keystream (note the caller is responsible for using a platform specific entropy source to
//! create the key and IV, these values seed the PRNG!):
//!
//! ```
//! use enocoro128v2::Enocoro128;
//!
//! let key: [u8; 16] = [
//!     0x4b, 0x8e, 0x29, 0x87, 0x80, 0x95, 0x96, 0xa3,
//!     0xbb, 0x23, 0x82, 0x49, 0x9f, 0x1c, 0xe7, 0xc2,
//! ];
//!
//! let iv: [u8; 8] = [0x3c, 0x1d, 0xbb, 0x05, 0xe3, 0xca, 0x60, 0xd9];
//!
//! let mut my_rand_buf = [0; 3];
//! let mut my_rand_u16: u16 = 0;
//! let mut my_rand_u64: u64 = 0;
//!
//! let mut e128 = Enocoro128::new(&key, &iv);
//!
//! e128.rand_buf(&mut my_rand_buf);
//! assert!(my_rand_buf.iter().all(|&x| x != 0));
//!
//! my_rand_u16 = e128.rand_u16();
//! assert_ne!(my_rand_u16, 0);
//!
//! my_rand_u64 = e128.rand_u64();
//! assert_ne!(my_rand_u64, 0);
//! ```
//!
//! ### References
//!
//! * \[1\] ["Pseudorandom Number Generator Enocoro", Hitachi Corporation (2010)](https://www.hitachi.com/rd/yrl/crypto/enocoro/index.html)
//! * \[2\] ["Update on Enocoro Stream Cipher", Dai Watanabe et. al. (2010)](https://ieeexplore.ieee.org/document/5649627)
//! * \[3\] ["Specifications of Ciphers in the Candidate Recommended Ciphers List", CRYPTREC (2013)](https://www.cryptrec.go.jp/en/method.html)
//! * \[4\] ["Security Evaluation of Stream Cipher Enocoro-128v2", Martin Hell and Thomas Johansson (2010)](https://www.cryptrec.go.jp/exreport/cryptrec-ex-2008-2010.pdf)
//! * \[5\] ["zeroize", Tony Arcieri (2019)](https://crates.io/crates/zeroize)
//! * \[6\] [enocoro_ref_20100222.zip, Hitachi Corporation (2010)](https://www.hitachi.com/rd/yrl/crypto/enocoro/enocoro_ref_20100222.zip)
//! * \[7\] [enocoro_tv_20100202.zip, Hitachi Corporation (2010)](https://www.hitachi.com/rd/yrl/crypto/enocoro/enocoro_ref_20100222.zip)

#![no_std]
#![deny(warnings)]

use zeroize::Zeroize;
extern crate static_assertions as sa;

mod consts;
use consts::*;
pub use consts::{E128_IV_LEN, E128_KEY_LEN};

#[cfg(test)]
mod test;

// Verify reference config at compile time
sa::const_assert!(E128_KEY_LEN == 16);
sa::const_assert!(E128_IV_LEN == 8);
sa::const_assert!(K128_INIT_ROUND_NUM == 96);

/// Composition of reference implementation's context, state, and buffer structures.
/// Implements en/decryption and random (i.e. keystream getter) functions.
#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct Enocoro128 {
    key: [u8; E128_KEY_LEN],
    iv: [u8; E128_IV_LEN],
    state: [u8; E128_STATE_LEN],
    buf: [u8; E128_BUF_LEN],
    top: u8,
}

impl Enocoro128 {
    // Public APIs -----------------------------------------------------------------------------------------------------

    /// Constructor, note key and IV length are compile-time enforced.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn new(key: &[u8; E128_KEY_LEN], iv: &[u8; E128_IV_LEN]) -> Enocoro128 {
        let mut e128 = Enocoro128 {
            key: [0; E128_KEY_LEN],
            iv: [0; E128_IV_LEN],
            state: [0; E128_STATE_LEN],
            buf: [0; E128_BUF_LEN],
            top: 0,
        };

        e128.key[..].copy_from_slice(&key[..]);
        e128.iv[..].copy_from_slice(&iv[..]);
        e128.init_keystream();

        e128
    }

    /// Keystream initialization.
    pub fn init_keystream(&mut self) {
        let mut ctr = 0x1;

        // Verify safe initialization at compile time
        sa::const_assert!(E128_BUF_LEN == (E128_KEY_LEN + E128_IV_LEN + E128_BUF_TAIL_INIT.len()));
        sa::const_assert!(E128_STATE_LEN == E128_STATE_INIT.len());

        // Set starting buf
        self.buf[0..E128_KEY_LEN].copy_from_slice(&self.key);
        self.buf[E128_KEY_LEN..(E128_KEY_LEN + E128_IV_LEN)].copy_from_slice(&self.iv);
        self.buf[(E128_KEY_LEN + E128_IV_LEN)..].copy_from_slice(&E128_BUF_TAIL_INIT);

        // Set starting state
        self.state[..].copy_from_slice(&E128_STATE_INIT);

        // Init buf and state
        self.top = 0;
        for _ in 0..K128_INIT_ROUND_NUM {
            self.buf[(self.top.wrapping_add(K128_SHIFT) & 0x1f) as usize] ^= ctr;
            ctr = XTIME[ctr as usize];
            self.next128();
        }
    }

    /// Stateful, in-place en/decryption (current keystream XORed with data).
    /// Can be called repeatedly to continue applying keystream to data chunks of varying sizes.
    /// For usecases where the entirety of the plaintext or ciphertext is never in memory at once
    /// (e.g. data received/transmitted in chunks, potentially of varying sizes).
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for b_ptr in data {
            *b_ptr ^= self.state[1];
            self.next128();
        }
    }

    /// Stateless, in-place en/decryption (keystream XORed with data).
    /// Uses an ephemeral instance of the cipher, zeroed on function return.
    /// For usecases where the entirety of the plaintext or ciphertext is in-memory at once.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn apply_keystream_static(
        key: &[u8; E128_KEY_LEN],
        iv: &[u8; E128_IV_LEN],
        data: &mut [u8],
    ) {
        let mut e128 = Enocoro128::new(key, iv);
        e128.apply_keystream(data);
    }

    /// Fill arbitrary length buffer from keystream.
    pub fn rand_buf(&mut self, r: &mut [u8]) {
        for b_ptr in r {
            *b_ptr = self.state[1];
            self.next128();
        }
    }

    /// Get u8 from keystream.
    pub fn rand_u8(&mut self) -> u8 {
        let mut tmp_buf: [u8; 1] = [0x00; 1];
        self.rand_buf(&mut tmp_buf);

        tmp_buf[0]
    }

    /// Get u16 from keystream.
    pub fn rand_u16(&mut self) -> u16 {
        let mut tmp_buf: [u8; 2] = [0x00; 2];
        self.rand_buf(&mut tmp_buf);

        // Byte packing, no-std alternative to std::mem::transmute.
        u16::from(tmp_buf[0]) + (u16::from(tmp_buf[1]) << 8)
    }

    /// Get u32 from keystream.
    pub fn rand_u32(&mut self) -> u32 {
        let mut tmp_buf: [u8; 4] = [0x00; 4];
        self.rand_buf(&mut tmp_buf);

        // Byte packing, no-std alternative to std::mem::transmute.
        u32::from(tmp_buf[0])
            + (u32::from(tmp_buf[1]) << 8)
            + (u32::from(tmp_buf[2]) << 16)
            + (u32::from(tmp_buf[3]) << 24)
    }

    /// Get u64 from keystream.
    pub fn rand_u64(&mut self) -> u64 {
        let mut tmp_buf: [u8; 8] = [0x00; 8];
        self.rand_buf(&mut tmp_buf);

        // Byte packing, no-std alternative to std::mem::transmute.
        u64::from(tmp_buf[0])
            + (u64::from(tmp_buf[1]) << 8)
            + (u64::from(tmp_buf[2]) << 16)
            + (u64::from(tmp_buf[3]) << 24)
            + (u64::from(tmp_buf[4]) << 32)
            + (u64::from(tmp_buf[5]) << 40)
            + (u64::from(tmp_buf[6]) << 48)
            + (u64::from(tmp_buf[7]) << 56)
    }

    /// Get u128 from keystream.
    pub fn rand_u128(&mut self) -> u128 {
        let mut tmp_buf: [u8; 16] = [0x00; 16];
        self.rand_buf(&mut tmp_buf);

        // Byte packing, no-std alternative to std::mem::transmute.
        u128::from(tmp_buf[0])
            + (u128::from(tmp_buf[1]) << 8)
            + (u128::from(tmp_buf[2]) << 16)
            + (u128::from(tmp_buf[3]) << 24)
            + (u128::from(tmp_buf[4]) << 32)
            + (u128::from(tmp_buf[5]) << 40)
            + (u128::from(tmp_buf[6]) << 48)
            + (u128::from(tmp_buf[7]) << 56)
            + (u128::from(tmp_buf[8]) << 64)
            + (u128::from(tmp_buf[9]) << 72)
            + (u128::from(tmp_buf[10]) << 80)
            + (u128::from(tmp_buf[11]) << 88)
            + (u128::from(tmp_buf[12]) << 96)
            + (u128::from(tmp_buf[13]) << 104)
            + (u128::from(tmp_buf[14]) << 112)
            + (u128::from(tmp_buf[15]) << 120)
    }

    // Private APIs ----------------------------------------------------------------------------------------------------

    // Inlining means 3x code duplication (init, en/decrypt, rand)
    // but also removes per-byte function call overhead for tight loops.
    // TODO: make this configurable for the "small" profile once custom profiles are on Rust Stable
    /// Update cipher state.
    #[inline(always)]
    fn next128(&mut self) {
        let mut tmp: [u8; 3] = [0x0, 0x0, 0x0];

        let sbox_idx_1 = self.buf[(K128_1.wrapping_add(self.top) & 0x1f) as usize] as usize;
        let sbox_idx_2 = self.buf[(K128_2.wrapping_add(self.top) & 0x1f) as usize] as usize;
        let sbox_idx_3 = self.buf[(K128_3.wrapping_add(self.top) & 0x1f) as usize] as usize;
        let sbox_idx_4 = self.buf[(K128_4.wrapping_add(self.top) & 0x1f) as usize] as usize;

        let buf_idx_1 = (K128_1.wrapping_add(self.top) & 0x1f) as usize;
        let buf_idx_2 = (K128_2.wrapping_add(self.top) & 0x1f) as usize;
        let buf_idx_3 = (K128_3.wrapping_add(self.top) & 0x1f) as usize;

        let buf_idx_p1 = (K128_P1.wrapping_add(self.top) & 0x1f) as usize;
        let buf_idx_p2 = (K128_P2.wrapping_add(self.top) & 0x1f) as usize;
        let buf_idx_p3 = (K128_P3.wrapping_add(self.top) & 0x1f) as usize;

        // Copy state
        tmp[0] = self.state[0];

        // Update state
        tmp[1] = self.state[0] ^ SBOX[sbox_idx_1];
        tmp[2] = self.state[1] ^ SBOX[sbox_idx_2];
        self.state[0] = tmp[1] ^ tmp[2] ^ SBOX[sbox_idx_3];
        self.state[1] = tmp[1] ^ XTIME[tmp[2] as usize] ^ SBOX[sbox_idx_4];

        // Update buffer
        self.buf[buf_idx_1] ^= self.buf[buf_idx_p1];
        self.buf[buf_idx_2] ^= self.buf[buf_idx_p2];
        self.buf[buf_idx_3] ^= self.buf[buf_idx_p3];
        self.top = self.top.wrapping_add(K128_SHIFT) & 0x1f;
        self.buf[self.top as usize] ^= tmp[0];
    }
}
