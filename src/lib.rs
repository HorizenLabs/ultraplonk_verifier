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

/// `AcirComposerError` enumerates all possible errors returned by the ACIR composer.
///
/// # Variants
///
/// - `BackendError(BackendError)`: Wraps a `BackendError` indicating the error originated from the backend.
#[derive(thiserror::Error, Debug)]
pub enum AcirComposerError {
    #[error("BackendError")]
    BackendError(#[from] BackendError),
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

/// A constant byte slice representing BLS12-381 G2 point.
const G2_DATA: &[u8] = &[
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

/// Verifies a given proof using a verification key.
///
/// # Arguments
///
/// * `proof` - A vector of bytes representing the proof.
/// * `verification_key` - A vector of bytes representing the verification key.
///
/// # Returns
///
/// A result containing a boolean indicating the outcome of the verification or a string error message on failure.
pub fn verify(proof: Vec<u8>, verification_key: Vec<u8>) -> Result<bool, String> {
    let acir_composer = verifier_init().map_err(|e| e.to_string())?;
    acir_composer
        .load_verification_key(&verification_key)
        .map_err(|e| e.to_string())?;
    let verified = acir_composer
        .verify_proof(&proof)
        .map_err(|e| e.to_string())?;

    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::{self, Read};

    fn get_file_size(filename: &str) -> io::Result<u64> {
        let metadata = std::fs::metadata(filename)?;
        Ok(metadata.len())
    }

    fn read_file(filename: &str, bytes: Option<usize>) -> io::Result<Vec<u8>> {
        // Get the file size.
        let size = get_file_size(filename)?;
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("File is empty or there's an error reading it: {}", filename),
            ));
        }

        let to_read = bytes.unwrap_or(size as usize);

        let mut file = File::open(filename)?;
        let mut file_data = vec![0; to_read];

        // Read all its contents.
        file.read_exact(&mut file_data)?;

        Ok(file_data)
    }

    #[test]
    fn test_verify() {
        let proof = read_file("./assets/proof", None).unwrap();
        let vk = read_file("./assets/vk", None).unwrap();
        let verified = verify(proof, vk).unwrap();
        assert!(verified);
    }
}
