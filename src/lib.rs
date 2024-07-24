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

mod acir;
mod bindings;
mod key;
mod srs;

/// The backend error.
use acir::AcirBackendError;
/// The ACIR composer.
use acir::AcirComposer;
/// The verification key.
pub use key::VerificationKey;
/// The verification key error.
pub use key::VerificationKeyError;

/// Expected sizes in bytes for proof.
pub const PROOF_SIZE: usize = 2144;

/// The public input.
pub type PublicInput = [u8; 32];

/// Enum representing possible errors during the verification process.
#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    /// Error originating from the ACIR backend.
    #[error("BackendError")]
    BackendError(#[from] AcirBackendError),

    /// Error related to the verification key.
    #[error("VerificationKeyError")]
    VkError(VerificationKeyError),

    /// Error indicating an incorrect number of public inputs.
    ///
    /// # Fields
    /// - `expected`: The expected number of public inputs.
    /// - `actual`: The actual number of public inputs provided.
    #[error("Invalid public input length: {actual}, expected: {expected}")]
    PublicInputNumberError { expected: u32, actual: u32 },

    /// Error indicating an incorrect proof length.
    ///
    /// # Fields
    /// - `expected`: The expected length of the proof.
    /// - `actual`: The actual length of the proof provided.
    #[error("Invalid proof length: {actual}, expected: {expected}")]
    InvalidProofLengthError { expected: usize, actual: usize },
}

/// Verifies a cryptographic proof against a verification key and public inputs.
///
/// This function checks the length of the proof and the number of public inputs, concatenates the
/// proof data, initializes the ACIR composer, and performs the verification.
///
/// # Parameters
///
/// - `vk`: A reference to the `VerificationKey` used for verification.
/// - `proof`: A byte slice containing the proof data.
/// - `pubs`: A slice of public inputs used in the verification process.
///
/// # Returns
///
/// A `Result` which is:
/// - `Ok(true)` if the proof is valid.
/// - `Ok(false)` if the proof is invalid but the EC proof points are on the curve.
/// - `Err(VerifyError)` if an error occurs during verification.
///
/// # Errors
///
/// This function can return the following errors:
///
/// - `VerifyError::InvalidProofLengthError`: If the length of the proof does not match the expected length.
/// - `VerifyError::PublicInputNumberError`: If the number of public inputs does not match the expected number.
/// - `VerifyError::BackendError`: If there is an error originating from the backend.
/// - `VerifyError::VkError`: If there is an error related to the verification key.
///
/// # Examples
///
/// ```no_run
/// use ultraplonk_verifier::verify;
/// use ultraplonk_verifier::PublicInput;
/// use ultraplonk_verifier::VerificationKey;
///
/// // Placeholder functions to simulate loading data
/// fn load_verification_key() -> VerificationKey {
///     // Implement your logic to load the verification key
///     unimplemented!()
/// }
///
/// fn load_proof_data() -> Vec<u8> {
///     // Implement your logic to load proof data
///     unimplemented!()
/// }
///
/// fn load_public_inputs() -> Vec<PublicInput> {
///     // Implement your logic to load public inputs
///     unimplemented!()
/// }
///
/// let vk = load_verification_key();
/// let proof = load_proof_data();
/// let pubs = load_public_inputs();
///
/// match verify(&vk, &proof, &pubs) {
///     Ok(true) => println!("Proof is valid"),
///     Ok(false) => println!("Proof is invalid"),
///     Err(e) => println!("Verification failed with error: {:?}", e),
/// }
/// ```
pub fn verify(
    vk: &VerificationKey,
    proof: &[u8],
    pubs: &[PublicInput],
) -> Result<bool, VerifyError> {
    check_proof_length(proof)?;
    check_public_input_number(vk, pubs)?;

    let proof_data = concatenate_proof_data(pubs, proof);

    let acir_composer = verifier_init()?;
    acir_composer.load_verification_key(&vk.as_bytes())?;
    let verified = acir_composer.verify_proof(&proof_data)?;
    Ok(verified)
}

fn verifier_init() -> Result<AcirComposer, VerifyError> {
    let acir_composer = AcirComposer::new(&0)?;
    acir::srs_init(&[], 0, &srs::SRS_G2)?;
    Ok(acir_composer)
}

fn check_proof_length(proof: &[u8]) -> Result<(), VerifyError> {
    if proof.len() != PROOF_SIZE {
        Err(VerifyError::InvalidProofLengthError {
            expected: PROOF_SIZE,
            actual: proof.len(),
        })
    } else {
        Ok(())
    }
}

fn check_public_input_number(
    vk: &VerificationKey,
    pubs: &[PublicInput],
) -> Result<(), VerifyError> {
    if vk.num_public_inputs != pubs.len() as u32 {
        Err(VerifyError::PublicInputNumberError {
            expected: vk.num_public_inputs,
            actual: pubs.len() as u32,
        })
    } else {
        Ok(())
    }
}

fn concatenate_proof_data(pubs: &[PublicInput], proof: &[u8]) -> Vec<u8> {
    let mut proof_data = Vec::new();
    for pub_input in pubs.iter() {
        proof_data.extend_from_slice(pub_input);
    }
    proof_data.extend_from_slice(proof);
    proof_data
}

#[cfg(test)]
mod test {

    use super::*;

    use std::fs;

    fn read_file(path: &str) -> Vec<u8> {
        fs::read(path).expect(&format!("Failed to read file: {}", path))
    }

    fn extract_public_inputs(proof_data: &[u8], num_inputs: usize) -> Vec<PublicInput> {
        (0..num_inputs)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&proof_data[i * 32..(i + 1) * 32]);
                arr
            })
            .collect()
    }

    #[test]
    fn test_verify() {
        let vk_data = read_file("resources/proves/vk");
        let proof_data = read_file("resources/proves/proof");
        let pubs = extract_public_inputs(&proof_data, 2);
        let proof = proof_data[64..].to_vec();

        let vk = VerificationKey::try_from(vk_data.as_slice())
            .expect("Failed to parse verification key");

        assert!(verify(&vk, &proof, &pubs).expect("Verification failed"));
    }
}