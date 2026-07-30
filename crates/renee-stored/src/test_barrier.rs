//! Externally armed integration-test barriers.
//!
//! The synchronous store checkpoint can run inside a `SQLite` transaction. This
//! lets the browser crash campaign prove both rollback before commit and
//! byte-identical retry after a committed result whose response was lost.

use std::env;
use std::io;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const DIRECTORY_ENVIRONMENT_VARIABLE: &str = "RENEE_TEST_BARRIER_DIRECTORY";
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Stops at `name` only when the external harness has armed that checkpoint.
pub fn checkpoint(name: &str) -> io::Result<()> {
    let Some(directory) = env::var_os(DIRECTORY_ENVIRONMENT_VARIABLE).map(PathBuf::from) else {
        return Ok(());
    };
    let armed = directory.join(format!("armed-{name}"));
    let reached = directory.join(format!("reached-{name}"));
    match std::fs::rename(armed, &reached) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    let release = directory.join(format!("release-{name}"));
    loop {
        match release.metadata() {
            Ok(_metadata) => {
                drop(std::fs::remove_file(release));
                drop(std::fs::remove_file(reached));
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
}
