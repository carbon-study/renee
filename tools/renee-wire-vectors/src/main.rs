//! Checked-in golden-vector maintenance command.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = parse_mode(std::env::args_os())?;
    let generated = renee_wire_vectors::generate()?;
    let path = vector_path();
    match mode {
        Mode::Check => {
            let checked_in = fs::read_to_string(path)?;
            if checked_in != generated {
                return Err(io::Error::other("wire vectors differ; run with --write").into());
            }
        }
        Mode::Write => fs::write(path, generated)?,
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Mode {
    Check,
    Write,
}

fn parse_mode(arguments: impl IntoIterator<Item = OsString>) -> io::Result<Mode> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let mode = match arguments.next().as_deref() {
        None => Mode::Check,
        Some(value) if value == "--check" => Mode::Check,
        Some(value) if value == "--write" => Mode::Write,
        Some(_unknown) => {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected --check or --write"));
        }
    };
    if arguments.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected exactly one optional mode",
        ));
    }
    Ok(mode)
}

fn vector_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join("wire-vectors").join("v1.json")
}
