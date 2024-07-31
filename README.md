# UltraPlonk zk-SNARK Verifier

The UltraPlonk zk-SNARK verifier is a Rust-based implementation that acts as a wrapper around the [`barretenberg`](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) library. This library, written in C++, specializes in zk-SNARKs (Zero-Knowledge Succinct Non-Interactive Argument of Knowledge) and provides efficient cryptographic primitives for constructing and verifying zero-knowledge proofs. The Rust verifier leverages `barretenberg` through Foreign Function Interface (FFI), allowing it to seamlessly call functions from the C++ library within the Rust environment.

The `barretenberg` library is part of the Aztec Protocol's suite of cryptographic tools. It is designed to support the needs of privacy-focused blockchain applications, providing tools for constructing complex zk-SNARK circuits. The UltraPlonk verifier specifically is built to work with the UltraPlonk protocol, a variant of the Plonk zero-knowledge proof protocol known for its efficiency and flexibility.

In addition, the [Noir language](http://noir-lang.org/) uses `barretenberg` as its cryptographic backend. Noir is a domain-specific language designed for creating and managing zero-knowledge circuits.

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

## Bins

The crate provides a binary that can be used to verify proofs. The binary reads the verification key, proof, and public inputs from files. The binary can be used as follows:

### Compile and install the binary

```bash
cargo install --features bins --path .
```

### Run the binary

```bash
noir-cli key --input ./resources/proves/verifier.sol --output ./target/vk.bin
noir-cli proof-data --input-json ./resources/proves/proof.json --output-proof ./target/proof.bin --output-pubs ./target/pubs.bin
noir-cli verify --key ./target/vk.bin --proof ./target/proof.bin --pubs ./target/pubs.bin
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
