use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs::File;

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
    Err(anyhow::anyhow!("Invalid command"))
}

fn read_json_file(path: &std::path::PathBuf) -> Result<ProofData> {
    let file = File::open(path).with_context(|| format!("Failed to open JSON file: {:?}", path))?;
    let reader = std::io::BufReader::new(file);
    let proof_data: ProofData = serde_json::from_reader(reader)
        .with_context(|| format!("Failed to parse JSON file: {:?}", path))?;
    Ok(proof_data)
}
