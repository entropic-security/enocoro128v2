# Test and Validation

### GitHub Actions CI

* [`test.yml`](../.github/workflows/test.yml): runs `cargo test` on push and PR.
* [`clippy.yml`](../.github/workflows/clippy.yml): runs `cargo clippy` on push and PR.

### Tests

* [`test_public_api.rs`](./test_public_api.rs): simple heuristics for API inputs/outputs, no validation of private fields.
* [`src/test.rs`](../src/test.rs): tests 10 sets of concrete, known-good input/output pairs. Verifies this implementation maintains "lock step" with the reference implementation for the sequence of 1120 internal states that produces each output. Validates private fields. Parses `official_test_vectors.txt` as input.

### Data

* [`official_test_vectors.txt`](./official_test_vectors.txt): Hitachi's official test vectors (not copyrighted and therefore distributed with this repository, [source](https://www.hitachi.com/rd/yrl/crypto/enocoro/enocoro_tv_20100202.zip)).

