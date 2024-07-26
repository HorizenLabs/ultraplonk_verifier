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

use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;

use crate::cli::Commands;
use crate::utils::{encode_hex, encode_pub_inputs, out_file};

#[derive(Deserialize, Debug)]
struct ProofData {
    proof: String,
    #[serde(rename = "verifyInputs")]
    verify_inputs: Vec<String>,
}

pub fn process_proof_data(command: &Commands, verbose: bool) -> Result<()> {
    if let Commands::ProofData {
        input_json,
        output_proof,
        output_pubs,
    } = command
    {
        parse_proof_data(input_json, output_proof, output_pubs, verbose)
    } else {
        return Err(anyhow::anyhow!("Invalid command"));
    }
}

fn parse_proof_data(
    input_json: &PathBuf,
    output_proof: &Option<PathBuf>,
    output_pubs: &Option<PathBuf>,
    verbose: bool,
) -> Result<()> {
    if verbose {
        println!("Reading input JSON file: {:?}", input_json);
    }

    let json_path = input_json;
    let proof_data = read_json_file(json_path)?;

    let mut proof_buf = vec![];
    let mut pub_inputs_buf = vec![];

    if verbose {
        println!("Encoding proof");
    }

    encode_hex(&proof_data.proof, &mut proof_buf)?;

    if verbose {
        println!("Encoding public inputs");
    }

    encode_pub_inputs(&proof_data.verify_inputs, &mut pub_inputs_buf)?;

    if verbose {
        println!("Writing output files");
    }

    out_file(output_proof.as_ref())?.write_all(&proof_buf)?;
    out_file(output_pubs.as_ref())?.write_all(&pub_inputs_buf)?;

    return Ok(());
}

fn read_json_file(path: &std::path::PathBuf) -> Result<ProofData> {
    let file = File::open(path).with_context(|| format!("Failed to open JSON file: {:?}", path))?;
    let reader = std::io::BufReader::new(file);
    let proof_data: ProofData = serde_json::from_reader(reader)
        .with_context(|| format!("Failed to parse JSON file: {:?}", path))?;
    Ok(proof_data)
}
