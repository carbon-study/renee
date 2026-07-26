//! Idle connection-session daemon reserved for gateway-owned sessions.

#![forbid(unsafe_code)]

use std::error::Error;
use std::io;
use std::io::Write as _;

use tokio::io::AsyncReadExt as _;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    emit_readiness("READY sessiond")?;
    wait_for_supervisor().await?;
    Ok(())
}

fn emit_readiness(record: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{record}")?;
    output.flush()
}

async fn wait_for_supervisor() -> io::Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut byte = [0_u8; 1];
    stdin.read(&mut byte).await.map(|_bytes_read| ())
}
