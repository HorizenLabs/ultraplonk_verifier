use anyhow::{Context, Result};
use regex::Regex;
use std::fs::File;
use std::io::Write;

pub fn out_file(output: Option<&std::path::PathBuf>) -> Result<Box<dyn std::io::Write>> {
    // Attempt to create the file if a path is specified
    let from_path = output
        .map(|p| {
            // Try to create the file and add context to any error that occurs
            File::create(&p).with_context(|| format!("Failed to create output file {:?}", &p))
        })
        .transpose()?  // Convert Option<Result<File>> to Result<Option<File>>
        .map(|f| Box::new(f) as Box<dyn Write>); // Box the file writer

    // If no path is specified, default to stdout
    Ok(from_path.unwrap_or_else(|| Box::new(std::io::stdout()) as Box<dyn Write>))
}

pub fn encode_value_as_u32(
    value: &str,
    variable_part: &str,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<()> {
    encode_value(value, variable_part, buf, offset, 4)
}

pub fn encode_value_as_u256(
    value: &str,
    variable_part: &str,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<()> {
    encode_value(value, variable_part, buf, offset, 32)
}

pub fn encode_str(key: &str, buf: &mut [u8], offset: &mut usize) -> Result<()> {
    encode_u32(key.len() as u32, buf, offset);

    buf[*offset..*offset + key.len()].copy_from_slice(key.as_bytes());
    *offset += key.len();
    Ok(())
}

pub fn encode_u32(value: u32, buf: &mut [u8], offset: &mut usize) {
    buf[*offset..*offset + 4].copy_from_slice(&value.to_be_bytes());
    *offset += 4;
}

pub fn encode_value(
    value: &str,
    variable_part: &str,
    buf: &mut [u8],
    offset: &mut usize,
    length: usize,
) -> Result<()> {
    let pattern = format!(
        r"mstore\(add\(_vk, {}\), (0x[0-9a-fA-F]{{64}})\)",
        regex::escape(variable_part)
    );

    let re = Regex::new(&pattern)?;

    if let Some(cap) = re.captures(value) {
        let hex_value = &cap[1];
        let decoded_value = hex::decode(hex_value.strip_prefix("0x").unwrap_or(hex_value))?;
        let decoded_value = &decoded_value[32 - length..];

        if buf.len() < *offset + decoded_value.len() {
            return Err(anyhow::anyhow!("Buffer is too small"));
        }

        buf[*offset..*offset + decoded_value.len()].copy_from_slice(&decoded_value);
        *offset += decoded_value.len();
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Failed to extract value from: {:?}",
            variable_part
        ))
    }
}

pub fn encode_hex(hex_str: &str, buf: &mut Vec<u8>) -> Result<()> {
    let decoded_value = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))?;
    buf.extend_from_slice(&decoded_value);
    Ok(())
}

pub fn encode_pub_inputs(pub_inputs: &[String], buf: &mut Vec<u8>) -> Result<()> {
    for input in pub_inputs {
        let decoded_value = hex::decode(input.strip_prefix("0x").unwrap_or(input))?;
        buf.extend_from_slice(&decoded_value);
    }
    Ok(())
}

