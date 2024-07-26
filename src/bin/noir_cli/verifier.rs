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

use ultraplonk_verifier::{verify as verify_proof, Proof, PublicInput, VerificationKey};

use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::cli::Commands;

pub fn process_command(command: &Commands, verbose: bool) -> Result<()> {
    if let Commands::Verify { proof, pubs, key } = command {
        verify(key, proof, pubs, verbose)
    } else {
        Err(anyhow::anyhow!("Invalid command for verifier"))
    }
}

fn verify(key: &PathBuf, proof: &PathBuf, pubs: &PathBuf, verbose: bool) -> Result<()> {
    if verbose {
        println!("Reading key file: {:?}", key);
        println!("Reading proof file: {:?}", proof);
        println!("Reading pubs file: {:?}", pubs);
    }

    // Read and process the proof file
    let key_data =
        std::fs::read(key).with_context(|| format!("Failed to read proof file: {:?}", key))?;

    let vk = VerificationKey::try_from(&key_data[..])
        .with_context(|| format!("Failed to parse verification key from file: {:?}", key))?;

    // Read and process the input file
    let proof = read_proof_file(proof)
        .with_context(|| format!("Failed to read proof file: {:?}", proof))?;

    // Read and process the key file
    let pubs =
        std::fs::read(pubs).with_context(|| format!("Failed to read key file: {:?}", pubs))?;

    // Convert input data into a slice of [[u8; 32]]
    let pubs = convert_to_pub_inputs(&pubs)?;

    if verbose {
        println!("Verifying proof...");
    }

    // Perform verification logic (pseudo-code)
    match verify_proof(&vk, &proof, &pubs) {
        Ok(_) => {
            println!("Proof is valid");
            Ok(())
        }
        Err(e) => {
            println!("Verification failed with error: {:?}", e);
            Err(anyhow::anyhow!("Proof is invalid"))
        }
    }
}

fn convert_to_pub_inputs(data: &[u8]) -> Result<&[PublicInput]> {
    if data.len() % 32 != 0 {
        return Err(anyhow::anyhow!("Data length is not a multiple of 32"));
    }

    let pub_inputs =
        unsafe { std::slice::from_raw_parts(data.as_ptr() as *const PublicInput, data.len() / 32) };

    Ok(pub_inputs)
}

fn read_proof_file(path: &PathBuf) -> Result<Proof> {
    let data = std::fs::read(path).with_context(|| format!("Failed to read file: {:?}", path))?;

    if data.len() != ultraplonk_verifier::PROOF_SIZE {
        return Err(anyhow::anyhow!("File size is not 2144 bytes: {:?}", path));
    }

    let mut array = [0u8; ultraplonk_verifier::PROOF_SIZE];
    array.copy_from_slice(&data);
    Ok(array)
}
