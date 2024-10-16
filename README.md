# Elisabeth
Elisabeth hybrid homomorphic encryption scheme based on TFHE.

## Prerequisite

To use elisabeth, you will need: 
- Rust: https://www.rust-lang.org/tools/install  
- FFTW library: can be installed using 
    - `brew install fftw` for MacOS, or
    - `sudo apt-get update && sudo apt-get install -y libfftw3-dev` for Debian-based Linux.


## Usage
First clone the project with
```bash
https://github.com/khoaguin/Elisabeth-HHE.git
```

Before running any test or benchmark, you should export the following RUSTFLAGS:
```
export RUSTFLAGS="-C target-cpu=native"
```
### Run
Simply run `cargo run` to run the code in `src/main.rs`


### Tests
To run a correctness test, run:
```bash
cargo test --release homomorphic -- *NUMBER_OF_NIBBLES*
```
Where *NUMBER_OF_NIBBLES* should be replaced by the actual number of nibbles over which you want the test to be run. For example:
```bash
cargo test --release homomorphic -- 10
```
Nota: the timings given by the tests are indicative and not precisely measured. To have precise time measurment, refer to the benchmark section.

### Benchmarks
To run an benchmark, use the following command:
```
cargo bench
```
### Optional features
By default, Elisabeth runs in multithreaded mode. To run in monothread, add `--no-default-features`.

