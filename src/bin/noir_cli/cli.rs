use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "noir-cli")]
#[command(about = "Converts Solidity verification keys to binary format and processes proofs")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Convert Solidity verification key to binary format
    Key {
        /// Input file for verification key
        #[arg(long)]
        input: PathBuf,

        /// Output file for verification key [or stdout if not specified]
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Process proof data from JSON file
    ProofData {
        /// Input file for verification key
        #[arg(long)]
        input_json: PathBuf,

        /// Output file for proof data [or stdout if not specified]
        #[arg(long)]
        output_proof: Option<PathBuf>,

        /// Output file for verification key [or stdout if not specified]
        #[arg(long)]
        output_pubs: Option<PathBuf>,
    },
    /// Verify proof with key
    Verify {
        /// Proof file
        #[arg(long)]
        proof: PathBuf,

        /// Input file for verification key
        #[arg(long)]
        input: PathBuf,

        /// Key file
        #[arg(long)]
        key: PathBuf,
    },
}
