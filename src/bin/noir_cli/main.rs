use anyhow::Result;
use clap::Parser;

mod cli;
mod key_parser;
mod proof_parser;
mod utils;

fn main() -> Result<()> {
    let args = cli::Cli::parse();

    if args.verbose {
        println!("Running in verbose mode");
    }

    match args.command {
        cli::Commands::Key{ .. } => key_parser::process_verification_key(&args.command, args.verbose)?,
        cli::Commands::ProofData{ .. } => proof_parser::process_proof_data(&args.command, args.verbose)?,
        cli::Commands::Verify{ .. } => todo!(),
    }

    Ok(())
}
