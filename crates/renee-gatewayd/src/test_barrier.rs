//! Externally armed integration-test barriers.
//!
//! Production runs do not set `RENEE_TEST_BARRIER_DIRECTORY`, making every
//! checkpoint a no-op. The browser crash campaign arms one named checkpoint
//! with a file, waits for the daemon to atomically rename it to `reached-*`,
//! and then kills the daemon while it waits for release.

use std::env;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

const DIRECTORY_ENVIRONMENT_VARIABLE: &str = "RENEE_TEST_BARRIER_DIRECTORY";
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Stops at `name` only when the external harness has armed that checkpoint.
pub async fn checkpoint(name: &str) -> io::Result<()> {
    let Some(directory) = env::var_os(DIRECTORY_ENVIRONMENT_VARIABLE).map(PathBuf::from) else {
        return Ok(());
    };
    let armed = directory.join(format!("armed-{name}"));
    let reached = directory.join(format!("reached-{name}"));
    match tokio::fs::rename(armed, &reached).await {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    let release = directory.join(format!("release-{name}"));
    loop {
        match tokio::fs::metadata(&release).await {
            Ok(_metadata) => {
                drop(tokio::fs::remove_file(release).await);
                drop(tokio::fs::remove_file(reached).await);
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            Err(error) => return Err(error),
        }
    }
}
