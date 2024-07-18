# ultraplonk_verifier

This is a verifier for the UltraPlonk zk-SNARK circuit. It is a wrapper around the `barretenberg` library, which is a C++ library for zk-SNARKs. The verifier is written in Rust, and uses the `barretenberg` library through FFI.

# Usage

```rust
use ultraplonk_verifier::verify;

fn main() {
    let proof = vec![0u8; 2144]; // Proof bytes
    let public_inputs = vec![0u8; 32]; // Public inputs bytes
    let verification_key = vec![0u8; 1719]; // Verification key bytes

    let result = verify(&verification_key, &proof, &public_inputs);
    println!("Verification result: {}", result);
}
```
