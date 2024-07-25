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

/// The proof data.
pub type Proof = [u8; PROOF_SIZE];

/// The public input.
pub type PublicInput = [u8; 32];

/// Enum representing possible errors during the verification process.
#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    /// Error originating from the ACIR backend.
    #[error("Backend Error")]
    BackendError(#[from] AcirBackendError),

    /// Error related to the verification key.
    #[error("Key Error")]
    KeyError(VerificationKeyError),

    /// Error related to the public inputs.
    #[error("Invalid public input: {message}")]
    PublicInputError { message: String },

    /// Error indicating verification failed.
    #[error("Verification failed")]
    VerificationError,
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
/// - `Ok(())` if the proof is valid.
/// - `Err(VerifyError)` if an error occurs during verification.
///
/// # Errors
///
/// This function can return the following errors:
///
/// - `VerifyError::PublicInputError`: If there is an error related to public inputs.
/// - `VerifyError::BackendError`: If there is an error originating from the backend.
/// - `VerifyError::KeyError`: If there is an error related to the verification key.
///
/// # Examples
///
/// ```no_run
/// use ultraplonk_verifier::verify;
/// use ultraplonk_verifier::Proof;
/// use ultraplonk_verifier::PublicInput;
/// use ultraplonk_verifier::VerificationKey;
///
/// // Placeholder functions to simulate loading data
/// fn load_verification_key() -> VerificationKey {
///     // Implement your logic to load the verification key
///     unimplemented!()
/// }
///
/// fn load_proof_data() -> Proof {
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
///     Ok(()) => println!("Proof is valid"),
///     Err(e) => println!("Verification failed with error: {:?}", e),
/// }
/// ```
pub fn verify(
    vk: &VerificationKey,
    proof: &Proof,
    pubs: &[PublicInput],
) -> Result<(), VerifyError> {
    check_public_input_number(vk, pubs)?;

    let proof_data = concatenate_proof_data(pubs, proof);

    let acir_composer = verifier_init()?;
    acir_composer.load_verification_key(&vk.as_bytes())?;
    match acir_composer.verify_proof(&proof_data)? {
        true => Ok(()),
        false => Err(VerifyError::VerificationError),
    }
}

fn verifier_init() -> Result<AcirComposer, VerifyError> {
    let acir_composer = AcirComposer::new(&0)?;
    acir::srs_init(&[], 0, &srs::SRS_G2)?;
    Ok(acir_composer)
}

fn check_public_input_number(
    vk: &VerificationKey,
    pubs: &[PublicInput],
) -> Result<(), VerifyError> {
    if vk.num_public_inputs != pubs.len() as u32 {
        Err(VerifyError::PublicInputError {
            message: format!(
                "Invalid number of public inputs: expected {}, but got {}.",
                vk.num_public_inputs,
                pubs.len()
            ),
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

    fn extract_proof(proof_data: &[u8]) -> Proof {
        let slice = &proof_data[64..64 + PROOF_SIZE];
        let mut array = [0u8; PROOF_SIZE];
        array.copy_from_slice(slice);
        array
    }

    #[test]
    fn test_verify() {
        let vk_data = read_file("resources/proves/vk");
        let proof_data = read_file("resources/proves/proof");
        let pubs = extract_public_inputs(&proof_data, 2);
        let proof = extract_proof(&proof_data);

        let vk = VerificationKey::try_from(vk_data.as_slice())
            .expect("Failed to parse verification key");

        verify(&vk, &proof, &pubs).unwrap();
    }
}
