//! Black-box supervision and public-transport verification.

#![forbid(unsafe_code)]

use std::io;
use std::process::Stdio;

use renee_subject::{HarnessResult, PermanentDaemon, ServerHarness, daemon_path};
use tokio::process::Command;

#[tokio::test]
async fn supervisor_starts_permanent_processes_and_gateway_accepts_webtransport()
-> HarnessResult<()> {
    let mut server = ServerHarness::start().await?;
    let connection = server.connect_webtransport().await?;
    server.ensure_process_tree_is_running()?;
    connection.close();
    server.kill_and_wait_for_restart(PermanentDaemon::Store).await?;
    server.kill_and_wait_for_restart(PermanentDaemon::Gateway).await?;
    let replacement_connection = server.connect_webtransport().await?;
    replacement_connection.close();
    server.shutdown().await
}

#[tokio::test]
async fn malformed_supervisor_configuration_is_rejected_cleanly() -> HarnessResult<()> {
    let status = Command::new(daemon_path("renee-supervisord")?)
        .arg("--bind")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await?;
    if status.success() {
        return Err(io::Error::other("malformed configuration was accepted").into());
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn non_utf8_supervisor_arguments_are_rejected_without_panicking() -> HarnessResult<()> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    let status = Command::new(daemon_path("renee-supervisord")?)
        .arg(OsString::from_vec(vec![0xff]))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await?;
    if status.success() {
        return Err(io::Error::other("non-UTF-8 argument was accepted").into());
    }
    Ok(())
}

#[tokio::test]
async fn restart_intensity_exhaustion_restarts_the_whole_group() -> HarnessResult<()> {
    let mut server = ServerHarness::start().await?;
    for _restart in 0..5 {
        server.kill_and_wait_for_restart(PermanentDaemon::Store).await?;
    }
    server.kill_and_wait_for_group_restart(PermanentDaemon::Store).await?;
    let connection = server.connect_webtransport().await?;
    connection.close();
    server.shutdown().await
}
