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

pub fn verifier_init() -> Result<AcirComposer, VerifyError> {
    let acir_composer = AcirComposer::new(&0)?;
    acir::srs_init(&[], 0, G2_DATA)?;
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
