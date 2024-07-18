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

use std::fs::File;
use std::io::{self, Read};

use ultraplonk_verifier::{verify, AcirComposerError};

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
fn should_verify_proof() {
    let proof = read_file("./resources/proves/proof", None).unwrap();
    let vk = read_file("./resources/proves/vk", None).unwrap();
    let verified = verify(proof, vk).unwrap();
    assert!(verified);
}

#[test]
fn test_verify_invalid_pub_input() {
    let mut proof = read_file("./resources/proves/proof", None).unwrap();
    // Change the first byte of the proof data (pub input) to make it invalid
    proof[0] = 1;
    let vk = read_file("./resources/proves/vk", None).unwrap();
    let verified = verify(proof, vk).unwrap();
    assert!(!verified);
}

#[test]
fn test_verify_invalid_pub_input_length() {
    let mut proof = read_file("./resources/proves/proof", None).unwrap();
    // Remove first 32 bytes of the proof data (pub input) to make it invalid
    proof = proof[32..].to_vec();
    let vk = read_file("./resources/proves/vk", None).unwrap();
    let verified = verify(proof, vk).unwrap();
    assert!(!verified);
}

#[test]
fn test_verify_invalid_proof() {
    let mut proof = read_file("./resources/proves/proof", None).unwrap();
    let vk = read_file("./resources/proves/vk", None).unwrap();
    // Modify the proof to make it invalid
    proof[138] = 1;
    match verify(proof, vk) {
        // TODO: We have a very ambiguos situation here, if the proof points are on the curve and they are not valid
        // the result is Ok(false) but if the proof points are not on the curve the result is Err(BackendError)
        // Currently we are taking the easiest way to handle this situation, but we need to improve it
        Ok(_) => panic!("Verification should have failed"),
        Err(e) => match e {
            AcirComposerError::BackendError(e) => match e {
                ultraplonk_verifier::BackendError::BindingCallError(_) => {}
                _ => panic!("Verification should have failed"),
            },
        },
    }
}

#[test]
fn test_verify_invalid_vk() {
    let proof = read_file("./resources/proves/proof", None).unwrap();
    let mut vk = read_file("./resources/proves/vk", None).unwrap();
    // Modify the proof to make it invalid
    vk[138] = 1;
    match verify(proof, vk) {
        // TODO: We have a very ambiguos situation here, if the proof points are on the curve and they are not valid
        // the result is Ok(false) but if the proof points are not on the curve the result is Err(BackendError)
        // Currently we are taking the easiest way to handle this situation, but we need to improve it
        Ok(_) => panic!("Verification should have failed"),
        Err(e) => match e {
            AcirComposerError::BackendError(e) => match e {
                ultraplonk_verifier::BackendError::BindingCallError(_) => {}
                _ => panic!("Verification should have failed"),
            },
        },
    }
}
