# enocoro128v2

Safe Rust, `#![no_std]` implementation of enocoro-128v2 [1], the updated variant [2] of a lightweight, CRYPTREC candidate [3] stream cipher.
No practical attacks against enocoro-128v2 have been reported [4].

### Functionality

* Symmetric-key encryption
* Pseudo-Random Number Generator (PRNG)

### Design

* Operational in baremetal environments: no standard library dependencies, no dynamic memory
* State securely wiped from memory on drop [5]
* Close mapping to Hitachi's C reference implementation [6] for audit-friendly code
* Verified using Hitachi's official test vectors [7]

### Usage

TODO

### References
---

* [1] ["Pseudorandom Number Generator Enocoro", Hitachi Corporation (2010)](https://www.hitachi.com/rd/yrl/crypto/enocoro/index.html)
* [2] ["Update on Enocoro Stream Cipher", Dai Watanabe et. al. (2010)](https://ieeexplore.ieee.org/document/5649627)
* [3] ["Specifications of Ciphers in the Candidate Recommended Ciphers List", CRYPTREC (2013)](https://www.cryptrec.go.jp/en/method.html)
* [4] ["Security Evaluation of Stream Cipher Enocoro-128v2", Martin Hell and Thomas Johansson (2010)](https://www.cryptrec.go.jp/exreport/cryptrec-ex-2008-2010.pdf)
* [5] ["zeroize", Tony Arcieri (2019)](https://crates.io/crates/zeroize)
* [6] [enocoro_ref_20100222.zip, Hitachi Corporation (2010)](https://www.hitachi.com/rd/yrl/crypto/enocoro/enocoro_ref_20100222.zip)
* [7] [enocoro_tv_20100202.zip, Hitachi Corporation (2010)](https://www.hitachi.com/rd/yrl/crypto/enocoro/enocoro_ref_20100222.zip)