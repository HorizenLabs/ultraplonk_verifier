# ultraplonk_verifier

This is a verifier for the UltraPlonk zk-SNARK circuit. It is a wrapper around the `barretenberg` library, 
which is a C++ library for zk-SNARKs. The verifier is written in Rust and uses the `barretenberg` library 
through FFI (Foreign Function Interface).

## Usage

```rust
use ultraplonk_verifier::verify;
use ultraplonk_verifier::PublicInput;
use ultraplonk_verifier::VerificationKey;

// Placeholder functions to simulate loading data
fn load_verification_key() -> VerificationKey {
    // Implement your logic to load the verification key
    unimplemented!()
}

fn load_proof_data() -> Vec<u8> {
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
        Ok(true) => println!("Proof is valid"),
        Ok(false) => println!("Proof is invalid"),
        Err(e) => println!("Verification failed with error: {:?}", e),
    }
}