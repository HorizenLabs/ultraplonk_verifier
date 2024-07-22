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

use std::collections::HashMap;
use std::convert::TryInto;

mod acir;

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

#[derive(Debug, Clone, Copy)]
struct Commitment {
    x: [u8; 32],
    y: [u8; 32],
}

/// Simplified representation of a verification key for cryptographic verification processes.
#[derive(Debug, Copy, Clone)]
struct VerifierKey {
    circuit_type: u32, // Type of circuit
    #[allow(dead_code)]
    circuit_size: u32, // Size of the circuit, not used in verification
    num_public_inputs: u32, // Expected number of public inputs

    q_1: Commitment,
    q_2: Commitment,
    q_3: Commitment,
    q_4: Commitment,
    q_m: Commitment,
    q_c: Commitment,
    q_arith: Commitment,
    q_sort: Commitment,
    q_eliptic: Commitment,
    q_aux: Commitment,

    sigma_1: Commitment,
    sigma_2: Commitment,
    sigma_3: Commitment,
    sigma_4: Commitment,

    table_1: Commitment,
    table_2: Commitment,
    table_3: Commitment,
    table_4: Commitment,
    table_type: Commitment,

    id_1: Commitment,
    id_2: Commitment,
    id_3: Commitment,
    id_4: Commitment,
}

impl VerifierKey {
    fn deserialize(buffer: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let circuit_type = u32::from_le_bytes(buffer[0..4].try_into()?);
        let circuit_size = u32::from_le_bytes(buffer[4..8].try_into()?);
        let num_public_inputs = u32::from_le_bytes(buffer[8..12].try_into()?);

        let mut commitments_num = u32::from_le_bytes(buffer[12..16].try_into()?) as usize;
        let mut commitments = HashMap::new();
        let mut i = 16;
        while i < buffer.len() && commitments_num > 0 {
            let key_size = u32::from_le_bytes(buffer[i..i + 4].try_into()?) as usize;
            i += 4;
            let key = &buffer[i..i + key_size];
            i += key_size;
            let key = String::from_utf8(key)?;
            let value = Commitment {
                x: buffer[i..i + 32].try_into()?,
                y: buffer[i + 32..i + 64].try_into()?,
            };
            i += 64;
            commitments.insert(key, value);
            commitments_num -= 1;
        }

        if commitments_num != 0 {
            return Err("Failed to deserialize commitments".into());
        }

        Ok(Self {
            circuit_type,
            circuit_size,
            num_public_inputs,
            q_1: *commitments.get("Q_1")?,
            q_2: *commitments.get("Q_2")?,
            q_3: *commitments.get("Q_3")?,
            q_4: *commitments.get("Q_4")?,
            q_m: *commitments.get("Q_M")?,
            q_c: *commitments.get("Q_C")?,
            q_arith: *commitments.get("Q_ARITH")?,
            q_sort: *commitments.get("Q_SORT")?,
            q_eliptic: *commitments.get("Q_ELIPTIC")?,
            q_aux: *commitments.get("Q_AUX")?,
            sigma_1: *commitments.get("SIGMA_1")?,
            sigma_2: *commitments.get("SIGMA_2")?,
            sigma_3: *commitments.get("SIGMA_3")?,
            sigma_4: *commitments.get("SIGMA_4")?,
            table_1: *commitments.get("TABLE_1")?,
            table_2: *commitments.get("TABLE_2")?,
            table_3: *commitments.get("TABLE_3")?,
            table_4: *commitments.get("TABLE_4")?,
            table_type: *commitments.get("TABLE_TYPE")?,
            id_1: *commitments.get("ID_1")?,
            id_2: *commitments.get("ID_2")?,
            id_3: *commitments.get("ID_3")?,
            id_4: *commitments.get("ID_4")?,
        })
    }
}

// Expected sizes in bytes for proof.
pub const PROOF_SIZE: usize = 2144;

// Expected sizes in bytes for verification key.
pub const VK_SIZE: usize = 1719;

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

/// Enumerates possible errors within the ACIR composer.
///
/// This enum is leveraged for error handling across the ACIR composer, encapsulating various
/// error types that can arise during the composition and verification processes.
///
/// Variants:
///
/// - `BackendError`: Errors originating from the cryptographic backend. This includes issues
///   encountered during cryptographic operations such as hashing, encryption, etc.
///
/// - `VerifierKeyPartError`: Errors related to the verification key, such as issues with its
///   format, size, or content.
///
/// - `PublicInputError`: Errors associated with public inputs, including incorrect sizes or
///   formats that do not match expectations.
///
/// - `InvalidProofError`: Errors indicating that a proof is invalid. This could be due to
///   incorrect data, formatting, or failure to satisfy cryptographic verification.
#[derive(thiserror::Error, Debug)]
pub enum AcirComposerError {
    #[error("BackendError")]
    BackendError(#[from] BackendError),

    #[error("VerifierKeyPartError")]
    VerifierKeyPartError(String),

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
    pub fn new(size_hint: &u32) -> Result<Self, AcirComposerError> {
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
    pub fn load_verification_key(&self, vk: &[u8]) -> Result<(), AcirComposerError> {
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
    pub fn verify_proof(&self, proof: &[u8]) -> Result<bool, AcirComposerError> {
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

/// Initializes the verifier by creating a new `AcirComposer` and setting up the SRS.
///
/// # Returns
///
/// A result containing the `AcirComposer` or an `AcirComposerError` on failure.
pub fn verifier_init() -> Result<AcirComposer, AcirComposerError> {
    let acir_composer = AcirComposer::new(&0)?;
    acir::srs_init(&[], 0, G2_DATA)?;
    Ok(acir_composer)
}

/// Verifies a cryptographic proof against a set of public inputs and a verification key.
///
/// This function takes the verification key data (`vk_data`), the proof to be verified (`proof`),
/// and the public inputs (`pubs`) as parameters. It performs several checks to ensure the integrity
/// and correctness of the inputs before proceeding with the verification process.
///
/// # Arguments
///
/// * `vk_data` - A `Vec<u8>` containing the serialized data of the verification key.
/// * `proof` - A `Vec<u8>` containing the serialized proof to be verified.
/// * `pubs` - A `Vec<u8>` containing the serialized public inputs.
///
/// # Returns
///
/// A `Result<bool, AcirComposerError>` where:
/// - `Ok(true)` indicates that the proof is valid.
/// - `Ok(false)` indicates that the proof is invalid.
/// - `Err(AcirComposerError)` indicates that an error occurred during the verification process.
///
/// # Errors
///
/// This function can return an `AcirComposerError` in several cases, including:
/// - If the length of the verification key data does not match the expected size (`VK_SIZE`).
/// - If the length of the proof does not match the expected size (`PROOF_SIZE`).
/// - If the length of the public inputs is not a multiple of 32 bytes.
/// - If the public input size does not match the size specified in the verification key.
/// - If the circuit type specified in the verification key is not ULTRA-PLONK.
///
/// # Example
///
/// ```compile_fail
/// use ultraplonk_verifier::verify;
///
/// let vk_data = vec![...]; // Verification key data
/// let proof = vec![...]; // Proof to be verified
/// let pubs = vec![...]; // Public inputs
///
/// match verify(vk_data, proof, pubs) {
///     Ok(true) => println!("Proof is valid."),
///     Ok(false) => println!("Proof is invalid."),
///     Err(e) => println!("Verification error: {:?}", e),
/// }
/// ```
///
/// # Note
///
/// This function assumes that `VK_SIZE` and `PROOF_SIZE` are predefined constants that specify
/// the expected sizes of the verification key and proof, respectively.
pub fn verify(
    vk_data: Vec<u8>,
    proof: Vec<u8>,
    pubs: Vec<PublicInput>,
) -> Result<bool, AcirComposerError> {
    if proof.len() != PROOF_SIZE {
        return Err(AcirComposerError::InvalidProofError(
            "Proof length is not 2144 bytes".to_string(),
        ));
    }

    let vk_part = VerifierKey::deserialize(&vk_data).map_err(|e| {
        AcirComposerError::VerifierKeyPartError(format!(
            "Failed to deserialize verification key: {}",
            e
        ))
    })?;
    if vk_part.num_public_inputs != pubs.len() {
        return Err(AcirComposerError::PublicInputError(
            "Public input length does not match the verification key".to_string(),
        ));
    }
    // ULTRA-PLONK circuit type is 2
    if vk_part.circuit_type != 2 {
        return Err(AcirComposerError::VerifierKeyPartError(
            "Verification key circuit type is not ULTRA-PLONK".to_string(),
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

/// Converts a byte slice to a u32 value.
///
/// # Arguments
///
/// * `buffer` - A byte slice containing the data to be converted.
///
/// # Returns
///
/// A u32 value obtained by converting the byte slice.
fn to_u32(buffer: &[u8]) -> u32 {
    ((buffer[0] as u32) << 24)
        | ((buffer[1] as u32) << 16)
        | ((buffer[2] as u32) << 8)
        | (buffer[3] as u32)
}

#[cfg(test)]
mod test {

    use super::*;

    use std::fs;

    #[test]
    fn test_verify() {
        let vk_data = fs::read("resources/proves/vk").unwrap();
        let proof_data = fs::read("resources/proves/proof").unwrap();

        let pub_inputs = proof_data[..64].to_vec();
        let proof = proof_data[64..].to_vec();

        let verified = verify(vk_data, proof, pub_inputs).unwrap();
        assert!(verified);
    }
}
