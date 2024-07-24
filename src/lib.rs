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
mod srs;

/// The backend error.
use acir::AcirBackendError;
/// The ACIR composer.
use acir::AcirComposer;
/// The verification key.
pub use key::VerificationKey;
/// The verification key error.
pub use key::VerificationKeyError;

// This matches bindgen::Builder output
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// Expected sizes in bytes for proof.
pub const PROOF_SIZE: usize = 2144;

pub type PublicInput = [u8; 32];

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
    BackendError(#[from] AcirBackendError),

    #[error("VerificationKeyError")]
    VkError(VerificationKeyError),

    #[error("PublicInputError")]
    PublicInputError(String),

    #[error("InvalidProofError")]
    InvalidProofError(String),
}

pub fn verifier_init() -> Result<AcirComposer, VerifyError> {
    let acir_composer = AcirComposer::new(&0)?;
    acir::srs_init(&[], 0, &srs::SRS_G2)?;
    Ok(acir_composer)
}

pub fn verify(
    vk: &VerificationKey,
    proof: Vec<u8>,
    pubs: Vec<PublicInput>,
) -> Result<bool, VerifyError> {
    if proof.len() != PROOF_SIZE {
        return Err(VerifyError::InvalidProofError(format!(
            "Proof length is not {PROOF_SIZE} bytes"
        )));
    }

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
    acir_composer.load_verification_key(&vk.as_bytes())?;
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
        let vk = VerificationKey::try_from(vk_data.as_slice()).unwrap();
        assert!(verify(&vk, proof, pub_inputs).unwrap());
    }
}
