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
async fn malformed_envelope_terminates_its_session_without_hanging() -> HarnessResult<()> {
    let server = ServerHarness::start().await?;
    let connection = server.connect_webtransport().await?;
    connection.reject_malformed_envelope().await?;
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

#[tokio::test]
async fn standalone_gateway_rejects_an_unavailable_sessiond_before_readiness() -> HarnessResult<()>
{
    let missing_sessiond = daemon_path("renee-sessiond-does-not-exist")?;
    let output = Command::new(daemon_path("renee-gatewayd")?)
        .arg("--sessiond")
        .arg(missing_sessiond)
        .stdin(Stdio::null())
        .output()
        .await?;
    if output.status.success() {
        return Err(io::Error::other("gateway accepted an unavailable sessiond").into());
    }
    if !output.stdout.is_empty() {
        return Err(io::Error::other("gateway emitted readiness before validating sessiond").into());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("sessiond executable is unavailable") {
        return Err(io::Error::other("gateway rejection did not identify sessiond").into());
    }
    Ok(())
}

#[tokio::test]
async fn gateway_rejects_non_loopback_deployment_without_authorization() -> HarnessResult<()> {
    let output = Command::new(daemon_path("renee-gatewayd")?)
        .args(["--bind", "0.0.0.0:0"])
        .arg("--sessiond")
        .arg(daemon_path("renee-sessiond")?)
        .stdin(Stdio::null())
        .output()
        .await?;
    if output.status.success() {
        return Err(io::Error::other("unauthorized non-loopback gateway was enabled").into());
    }
    if !output.stdout.is_empty() {
        return Err(io::Error::other("gateway emitted readiness before deployment gating").into());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("disabled until capability authorization is implemented") {
        return Err(io::Error::other("gateway rejection omitted the authorization gate").into());
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
