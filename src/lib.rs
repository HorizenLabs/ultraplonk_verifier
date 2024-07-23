// Copyright 2024, The Horizen Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Suppress the flurry of warnings caused by using "C" naming conventions
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

mod acir;
mod key;

/// The verification key.
pub use key::VerificationKey;
/// The verification key error.
pub use key::VerificationKeyError;

// This matches bindgen::Builder output
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// `BackendError` enumerates all possible errors returned by the backend operations.
///
/// # Variants
///
/// - `BindingCallError(String)`: Represents an error that occurs during a binding call. The `String` contains the error message.
/// - `BindingCallPointerError(String)`: Represents an error that occurs if there is an issue with the output pointer during a binding call. The `String` contains the error message.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("Binding call error")]
    BindingCallError(String),
    #[error("Binding call output pointer error")]
    BindingCallPointerError(String),
}

// Expected sizes in bytes for proof.
pub const PROOF_SIZE: usize = 2144;

pub type PublicInput = [u8; 32];

/// Serializes a slice of bytes into a `Vec<u8>` with the first 4 bytes representing the length of the data slice in big-endian format, followed by the data itself.
///
/// # Arguments
///
/// * `data` - A slice of bytes (`&[u8]`) to be serialized.
///
/// # Returns
///
/// A `Vec<u8>` containing the serialized data.
///
/// # Examples
///
/// ```
/// use ultraplonk_verifier::serialize_slice;
///
/// let data = [1, 2, 3, 4];
/// let serialized = serialize_slice(&data);
/// assert_eq!(serialized, vec![0, 0, 0, 4, 1, 2, 3, 4]);
/// ```
pub fn serialize_slice(data: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buffer.extend_from_slice(data);
    buffer
}

/// Enum representing various errors that can occur during the verification process.
///
/// # Variants
///
/// * `BackendError` - An error that occurs in the backend. This variant wraps a `BackendError`.
/// * `VkError` - An error that occurs when handling the verification key. This variant contains a `VerificationKeyError`.
/// * `PublicInputError` - An error that occurs when the public input length does not match the verification key's expected length. This variant contains a descriptive `String`.
/// * `InvalidProofError` - An error that occurs when the proof length is invalid. This variant contains a descriptive `String`.
#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    #[error("BackendError")]
    BackendError(#[from] BackendError),

    #[error("VerificationKeyError")]
    VkError(VerificationKeyError),

    #[error("PublicInputError")]
    PublicInputError(String),

    #[error("InvalidProofError")]
    InvalidProofError(String),
}

/// Represents an ACIR composer with a pointer to the underlying C structure.
pub struct AcirComposer {
    composer_ptr: acir::AcirComposerPtr,
}

impl AcirComposer {
    /// Creates a new `AcirComposer` instance with a given size hint.
    ///
    /// # Arguments
    ///
    /// * `size_hint` - A hint for the size of the composer to optimize allocations.
    ///
    /// # Returns
    ///
    /// A result containing the new `AcirComposer` instance or an `AcirComposerError` on failure.
    pub fn new(size_hint: &u32) -> Result<Self, VerifyError> {
        Ok(acir::new_acir_composer(size_hint).map(|ptr| Self { composer_ptr: ptr })?)
    }

    /// Loads a verification key into the composer.
    ///
    /// # Arguments
    ///
    /// * `vk` - A byte slice containing the verification key.
    ///
    /// # Returns
    ///
    /// A result indicating success or an `AcirComposerError` on failure.
    pub fn load_verification_key(&self, vk: &[u8]) -> Result<(), VerifyError> {
        Ok(acir::load_verification_key(&self.composer_ptr, vk)?)
    }

    /// Verifies a proof using the composer.
    ///
    /// # Arguments
    ///
    /// * `proof` - A byte slice containing the proof to be verified.
    ///
    /// # Returns
    ///
    /// A result containing a boolean indicating the outcome of the verification or an `AcirComposerError` on failure.
    pub fn verify_proof(&self, proof: &[u8]) -> Result<bool, VerifyError> {
        Ok(acir::verify_proof(&self.composer_ptr, proof)?)
    }
}

/// Implements the Drop trait for `AcirComposer` to ensure proper resource cleanup.
impl Drop for AcirComposer {
    fn drop(&mut self) {
        let _ = acir::delete(self.composer_ptr);
    }
}

/// A constant byte slice representing BN254 G2 point. `noir-compiler` when installed will
/// downloads this data and stores it in ~/.nargo/backends/acvm-backend-barretenberg/crs/bn254_g2.dat
const G2_DATA: &[u8; 128] = &[
    1, 24, 196, 213, 184, 55, 188, 194, 188, 137, 181, 179, 152, 181, 151, 78, 159, 89, 68, 7, 59,
    50, 7, 139, 126, 35, 31, 236, 147, 136, 131, 176, 38, 14, 1, 178, 81, 246, 241, 199, 231, 255,
    78, 88, 7, 145, 222, 232, 234, 81, 216, 122, 53, 142, 3, 139, 78, 254, 48, 250, 192, 147, 131,
    193, 34, 254, 189, 163, 192, 192, 99, 42, 86, 71, 91, 66, 20, 229, 97, 94, 17, 230, 221, 63,
    150, 230, 206, 162, 133, 74, 135, 212, 218, 204, 94, 85, 4, 252, 99, 105, 247, 17, 15, 227,
    210, 81, 86, 193, 187, 154, 114, 133, 156, 242, 160, 70, 65, 249, 155, 164, 238, 65, 60, 128,
    218, 106, 95, 228,
];

/// Initializes the verifier by creating an `AcirComposer` instance and setting up the SRS (Structured Reference String).
///
/// # Returns
///
/// This function returns a `Result<AcirComposer, VerifyError>`, which is:
/// * `Ok(AcirComposer)` if the initialization is successful.
/// * `Err(VerifyErrorr)` if an error occurs during the initialization process.
pub fn verifier_init() -> Result<AcirComposer, VerifyError> {
    let acir_composer = AcirComposer::new(&0)?;
    acir::srs_init(&[], 0, G2_DATA)?;
    Ok(acir_composer)
}

/// Verifies a cryptographic proof using a verification key and public inputs.
///
/// # Arguments
///
/// * `vk_data` - A vector of bytes representing the verification key.
/// * `proof` - A vector of bytes representing the cryptographic proof.
/// * `pubs` - A vector of `PublicInput` representing the public inputs for the proof.
///
/// # Returns
///
/// This function returns a `Result<bool, VerifyError>`, which is:
/// * `Ok(true)` if the proof is valid.
/// * `Ok(false)` if the proof is invalid.
/// * `Err(VerifyError)` if an error occurs during verification.
///
/// # Errors
///
/// This function will return an error in the following cases:
/// * `VerifyError::InvalidProofError` if the length of the proof is not equal to the expected `PROOF_SIZE`.
/// * `VerifyError::VkError` if there is an error converting the verification key data to a `VerificationKey`.
/// * `VerifyError::PublicInputError` if the length of the public inputs does not match the expected length specified by the verification key.
/// * Any other error that occurs during the initialization of the verifier or the verification process.
///
/// # Example
///
/// ```rust
/// use ultraplonk_verifier::verify;
/// 
/// let vk_data = vec![/* verification key data */];
/// let proof = vec![/* proof data */];
/// let pubs = vec![/* public inputs */];
///
/// match verify(vk_data, proof, pubs) {
///     Ok(true) => println!("Proof is valid"),
///     Ok(false) => println!("Proof is invalid"),
///     Err(e) => println!("Verification failed with error: {:?}", e),
/// }
/// ```
///
/// # Implementation Details
///
/// The function performs the following steps:
/// 1. Checks if the length of the proof matches the expected `PROOF_SIZE`.
/// 2. Tries to convert the `vk_data` to a `VerificationKey`.
/// 3. Checks if the number of public inputs matches the expected number specified in the verification key.
/// 4. Concatenates the public inputs and the proof data into a single vector.
/// 5. Initializes the ACIR composer and loads the verification key.
/// 6. Uses the ACIR composer to verify the proof and returns the result.
pub fn verify(
    vk_data: Vec<u8>,
    proof: Vec<u8>,
    pubs: Vec<PublicInput>,
) -> Result<bool, VerifyError> {
    if proof.len() != PROOF_SIZE {
        return Err(VerifyError::InvalidProofError(format!(
            "Proof length is not {PROOF_SIZE} bytes"
        )));
    }

    let vk = key::VerificationKey::try_from(&vk_data[..]).map_err(VerifyError::VkError)?;

    if vk.num_public_inputs != pubs.len() as u32 {
        return Err(VerifyError::PublicInputError(
            "Public input length does not match the verification key".to_string(),
        ));
    }

    let mut proof_data = Vec::new();
    for pub_input in pubs.iter() {
        proof_data.extend_from_slice(pub_input);
    }
    proof_data.extend_from_slice(&proof);

    let acir_composer = verifier_init()?;
    acir_composer.load_verification_key(&vk_data)?;
    let verified = acir_composer.verify_proof(&proof_data)?;
    Ok(verified)
}

#[cfg(test)]
mod test {

    use super::*;

    use std::fs;

    #[test]
    fn test_verify() {
        let vk_data = fs::read("resources/proves/vk").unwrap();
        let proof_data = fs::read("resources/proves/proof").unwrap();
        let pub_inputs: Vec<PublicInput> = (0..2)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&proof_data[i * 32..(i + 1) * 32]);
                arr
            })
            .collect();

        let proof = proof_data[64..].to_vec();
        assert!(verify(vk_data, proof, pub_inputs).unwrap());
    }
}
