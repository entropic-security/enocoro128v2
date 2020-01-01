# Test and Validation

### CI

TODO: Setup GHA CI

### Tests

* [`test_public_api.rs`](./test_public_api.rs): simple heuristics for API inputs/outputs, exercises error enums.
* [`src/test.rs`](../src/test.rs): concrete, known-good I/O pairs for all internal state given 10 sets of inputs, verifies this implementation maintains "lock step" with the reference implementation. Parses `official_test_vectors.txt` as input.

### Data

* [`official_test_vectors.txt`](./official_test_vectors.txt): Hitachi's official test vectors (not copyrighted, [source](https://www.hitachi.com/rd/yrl/crypto/enocoro/enocoro_tv_20100202.zip)):

