# Ultraplonk verifier

This is a verifier for the UltraPlonk zk-SNARK circuit. It is a wrapper around the `barretenberg` library, 
which is a C++ library for zk-SNARKs. The verifier is written in Rust and uses the `barretenberg` library 
through FFI (Foreign Function Interface).

## Usage

```rust
use ultraplonk_verifier::verify;
use ultraplonk_verifier::Proof;
use ultraplonk_verifier::PublicInput;
use ultraplonk_verifier::VerificationKey;

// Placeholder functions to simulate loading data
fn load_verification_key() -> VerificationKey {
    // Implement your logic to load the verification key
    unimplemented!()
}

fn load_proof_data() -> Proof {
    // Implement your logic to load proof data
    unimplemented!()
}

fn load_public_inputs() -> Vec<PublicInput> {
    // Implement your logic to load public inputs
    unimplemented!()
}

fn main() {
    let vk = load_verification_key();
    let proof = load_proof_data();
    let pubs = load_public_inputs();

    match verify(&vk, &proof, &pubs) {
        Ok(()) => println!("Proof is valid"),
        Err(e) => println!("Verification failed with error: {:?}", e),
    }
}
```

## Building

To build the verifier, run the following command:

```bash
cargo install cargo-make
cargo make ci
```

## Build cache support

This crate compilation is really expensive, so you can cache the native libraries to speed up the process:
the first time you build the library you can cache the static libraries that you find and later use them
by define environment variable.

You can find the library artifact in `target/<profile>/build/ultraplonk_verifier-<some_hash>/out/build/lib`
and save them in a folder. Later you can use `BARRETENBERG_LIB_DIR`s env to use them:

- profile = `debug` -> you can use `BARRETENBERG_LIB_DIR` or `BARRETENBERG_LIB_DIR_DEBUG` at you choice
- profile = `release` -> use `BARRETENBERG_LIB_DIR_RELEASE`

Example:

```sh
cargo build
cp -r target/debug/build/ultraplonk_verifier-fb3d068d3c03c1db/out/build/lib ../cache_dev
cargo clean
BARRETENBERG_LIB_DIR="../cache_dev" cargo test
```

## License

This project is licensed under the MIT License - see the [APACHE 2.0 license](LICENSE-APACHE2) file for details.
