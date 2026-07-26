//! Black-box process and fault-injection harness for Renee.
//!
//! This crate drives the real Renee daemons as the subject under test. It owns
//! process lifecycle, transport clients, observable outcomes, and fault
//! injection, while `renee-model` remains an independent deterministic oracle.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};
use tokio::process::{Child, ChildStdout, Command};
use wtransport::endpoint::endpoint_side;
use wtransport::tls::{Sha256Digest, Sha256DigestFmt};
use wtransport::{ClientConfig, Connection, Endpoint};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);

/// A result produced by the Renee black-box test harness.
pub type HarnessResult<T> = Result<T, Box<dyn Error>>;

/// A running Renee process tree controlled through its top-level supervisor.
pub struct ServerHarness {
    address: String,
    certificate_hash: Sha256Digest,
    output: BufReader<ChildStdout>,
    permanent_child_pids: BTreeMap<&'static str, u32>,
    supervisor: Child,
}

/// A permanent Renee daemon that supervisord must restart after an unexpected exit.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PermanentDaemon {
    /// The public WebTransport gateway.
    Gateway,
    /// The authoritative store broker.
    Store,
}

/// A live test connection that keeps its client endpoint open.
pub struct WebTransportConnection {
    connection: Connection,
    _endpoint: Endpoint<endpoint_side::Client>,
}

impl ServerHarness {
    /// Starts every Renee daemon and waits for the complete process tree to be ready.
    pub async fn start() -> HarnessResult<Self> {
        let supervisor_path = daemon_path("renee-supervisord")?;
        let mut supervisor = Command::new(supervisor_path)
            .args(["--bind", "127.0.0.1:0", "--shutdown-on-stdin-eof"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let stdout = supervisor
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("supervisord stdout was not piped"))?;
        let mut output = BufReader::new(stdout);
        let mut readiness = String::new();

        let bytes_read =
            tokio::time::timeout(STARTUP_TIMEOUT, output.read_line(&mut readiness)).await??;
        if bytes_read == 0 {
            return Err(io::Error::other("supervisord exited before readiness").into());
        }

        let fields = parse_readiness(&readiness)?;
        let address = fields
            .get("address")
            .ok_or_else(|| io::Error::other("readiness omitted gateway address"))?
            .to_string();
        let certificate_hash = fields
            .get("certificate-sha256")
            .ok_or_else(|| io::Error::other("readiness omitted certificate hash"))?;
        let certificate_hash =
            Sha256Digest::from_str_fmt(certificate_hash, Sha256DigestFmt::DottedHex)?;
        let permanent_child_pids = [
            ("gatewayd", parse_pid(&fields, "gatewayd-pid")?),
            ("stored", parse_pid(&fields, "stored-pid")?),
        ]
        .into_iter()
        .collect();

        Ok(Self { address, certificate_hash, output, permanent_child_pids, supervisor })
    }

    /// Opens a certificate-pinned WebTransport connection to the running gateway.
    pub async fn connect_webtransport(&self) -> HarnessResult<WebTransportConnection> {
        let client_config = ClientConfig::builder()
            .with_bind_default()
            .with_server_certificate_hashes([self.certificate_hash.clone()])
            .build();
        let endpoint = Endpoint::client(client_config)?;
        let connection = tokio::time::timeout(
            STARTUP_TIMEOUT,
            endpoint.connect(&format!("https://{}/", self.address)),
        )
        .await??;

        Ok(WebTransportConnection { connection, _endpoint: endpoint })
    }

    /// Fails if the supervisor or any child has already exited.
    pub fn ensure_process_tree_is_running(&mut self) -> io::Result<()> {
        if let Some(status) = self.supervisor.try_wait()? {
            return Err(io::Error::other(format!(
                "supervisord or one of its children exited early with {status}"
            )));
        }
        Ok(())
    }

    /// Terminates one permanent daemon and waits for supervisord to replace it.
    pub async fn kill_and_wait_for_restart(
        &mut self,
        daemon: PermanentDaemon,
    ) -> HarnessResult<()> {
        let role = daemon.role();
        self.kill(daemon).await?;

        // EXITED and RESTARTED are separate observable events. Keeping both in
        // the contract lets later tests assert classification between them.
        let event = read_supervisor_event(&mut self.output).await?;
        let restart_prefix = format!("RESTARTED {role} ");
        let event = if event.starts_with(&restart_prefix) {
            event
        } else {
            let exit_prefix = format!("EXITED {role} ");
            if !event.starts_with(&exit_prefix) {
                return Err(
                    io::Error::other(format!("unexpected supervisor event: {event:?}")).into()
                );
            }
            read_supervisor_event(&mut self.output).await?
        };
        if !event.starts_with(&restart_prefix) {
            return Err(io::Error::other(format!("unexpected supervisor event: {event:?}")).into());
        }
        let fields = parse_restart(&event, role)?;
        let replacement_pid = parse_pid(&fields, &format!("{role}-pid"))?;
        self.permanent_child_pids.insert(role, replacement_pid);
        if daemon == PermanentDaemon::Gateway {
            self.update_gateway(&fields)?;
        }
        self.ensure_process_tree_is_running()?;
        Ok(())
    }

    /// Waits for the whole permanent-child group to restart after intensity exhaustion.
    pub async fn kill_and_wait_for_group_restart(
        &mut self,
        daemon: PermanentDaemon,
    ) -> HarnessResult<()> {
        self.kill(daemon).await?;
        let mut group_event = None;

        // Group shutdown adds ordered STOPPING/STOPPED events for both
        // permanent children before the replacement-group readiness event.
        for _event in 0..8 {
            let event = read_supervisor_event(&mut self.output).await?;
            if event.starts_with("RESTARTED supervisord-child-group ") {
                group_event = Some(event);
                break;
            }
        }

        let event =
            group_event.ok_or_else(|| io::Error::other("whole-group restart was not observed"))?;
        let fields = parse_group_restart(&event)?;
        self.permanent_child_pids.insert("gatewayd", parse_pid(&fields, "gatewayd-pid")?);
        self.permanent_child_pids.insert("stored", parse_pid(&fields, "stored-pid")?);
        self.update_gateway(&fields)?;
        self.ensure_process_tree_is_running()?;
        Ok(())
    }

    /// Requests clean shutdown and waits for the supervisor to exit.
    pub async fn shutdown(mut self) -> HarnessResult<()> {
        // Closing supervisord's parent-lifetime channel requests shutdown. We
        // then consume its remaining lifecycle stream to verify ordering rather
        // than merely accepting a zero exit status.
        drop(self.supervisor.stdin.take());
        let status = tokio::time::timeout(STARTUP_TIMEOUT, self.supervisor.wait()).await??;
        if !status.success() {
            return Err(io::Error::other(format!("supervisord exited with {status}")).into());
        }
        let mut events = String::new();
        self.output.read_to_string(&mut events).await?;
        verify_shutdown_order(&events)?;
        Ok(())
    }

    async fn kill(&self, daemon: PermanentDaemon) -> HarnessResult<()> {
        // This PID-based mechanism is test-only. Supervisord itself observes
        // owned `Child` handles; hardened Linux fault injection should replace
        // this external `kill` invocation with pidfds to avoid PID-reuse races.
        let role = daemon.role();
        let pid = self
            .permanent_child_pids
            .get(role)
            .copied()
            .ok_or_else(|| io::Error::other(format!("no recorded PID for {role}")))?;
        let pid_argument = pid.to_string();
        let status = Command::new("kill").args(["-KILL", pid_argument.as_str()]).status().await?;
        if !status.success() {
            return Err(io::Error::other(format!("failed to terminate {role}: {status}")).into());
        }
        Ok(())
    }

    fn update_gateway(&mut self, fields: &BTreeMap<&str, &str>) -> HarnessResult<()> {
        self.address = fields
            .get("address")
            .ok_or_else(|| io::Error::other("gateway event omitted address"))?
            .to_string();
        self.certificate_hash = Sha256Digest::from_str_fmt(
            fields
                .get("certificate-sha256")
                .ok_or_else(|| io::Error::other("gateway event omitted certificate hash"))?,
            Sha256DigestFmt::DottedHex,
        )?;
        Ok(())
    }
}

impl WebTransportConnection {
    /// Closes the test connection without defining an application close protocol.
    pub fn close(self) {
        self.connection.close(0_u32.into(), b"conformance connection complete");
    }
}

impl PermanentDaemon {
    const fn role(self) -> &'static str {
        match self {
            Self::Gateway => "gatewayd",
            Self::Store => "stored",
        }
    }
}

/// Locates one daemon built into the active Cargo profile directory.
pub fn daemon_path(name: &str) -> io::Result<PathBuf> {
    let test_executable = env::current_exe()?;
    let profile_directory = test_executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("test executable has no Cargo profile directory"))?;
    Ok(profile_directory.join(format!("{name}{}", env::consts::EXE_SUFFIX)))
}

fn parse_pid(fields: &BTreeMap<&str, &str>, name: &str) -> io::Result<u32> {
    fields
        .get(name)
        .ok_or_else(|| io::Error::other(format!("readiness omitted {name}")))?
        .parse()
        .map_err(|error| io::Error::other(format!("invalid {name}: {error}")))
}

async fn read_supervisor_event(output: &mut BufReader<ChildStdout>) -> io::Result<String> {
    let mut event = String::new();
    let bytes_read = tokio::time::timeout(STARTUP_TIMEOUT, output.read_line(&mut event))
        .await
        .map_err(|_timeout| io::Error::other("supervisor event timed out"))??;
    if bytes_read == 0 {
        return Err(io::Error::other("supervisord exited before event"));
    }
    Ok(event)
}

fn parse_restart<'a>(
    record: &'a str,
    expected_role: &'static str,
) -> io::Result<BTreeMap<&'a str, &'a str>> {
    let mut fields = record.split_whitespace();
    if fields.next() != Some("RESTARTED")
        || fields.next() != Some(expected_role)
        || fields.next() != Some("READY")
        || fields.next() != Some(expected_role)
    {
        return Err(io::Error::other(format!("unexpected supervisor event: {record:?}")));
    }
    fields
        .map(|field| {
            field
                .split_once('=')
                .ok_or_else(|| io::Error::other(format!("invalid restart field: {field}")))
        })
        .collect()
}

fn parse_group_restart(record: &str) -> io::Result<BTreeMap<&str, &str>> {
    let mut fields = record.split_whitespace();
    if fields.next() != Some("RESTARTED")
        || fields.next() != Some("supervisord-child-group")
        || fields.next() != Some("READY")
        || fields.next() != Some("gatewayd")
    {
        return Err(io::Error::other(format!("unexpected group restart event: {record:?}")));
    }
    fields
        .map(|field| {
            field
                .split_once('=')
                .ok_or_else(|| io::Error::other(format!("invalid group restart field: {field}")))
        })
        .collect()
}

fn verify_shutdown_order(events: &str) -> io::Result<()> {
    let gateway_stopping = event_position(events, "STOPPING gatewayd")?;
    let gateway_stopped = event_position(events, "STOPPED gatewayd")?;
    let store_stopping = event_position(events, "STOPPING stored")?;
    let store_stopped = event_position(events, "STOPPED stored")?;

    // Startup is stored -> gatewayd, so shutdown must fully complete gatewayd
    // before stored even begins its own independently timed grace period.
    if gateway_stopping < gateway_stopped
        && gateway_stopped < store_stopping
        && store_stopping < store_stopped
    {
        return Ok(());
    }
    Err(io::Error::other(format!("children did not stop in reverse startup order: {events:?}")))
}

fn event_position(events: &str, event: &'static str) -> io::Result<usize> {
    events.find(event).ok_or_else(|| io::Error::other(format!("shutdown omitted {event}")))
}

fn parse_readiness(record: &str) -> io::Result<BTreeMap<&str, &str>> {
    let mut fields = record.split_whitespace();
    if fields.next() != Some("READY")
        || fields.next() != Some("supervisord")
        || fields.next() != Some("READY")
        || fields.next() != Some("gatewayd")
    {
        return Err(io::Error::other(format!("unexpected readiness record: {record:?}")));
    }

    fields
        .map(|field| {
            field
                .split_once('=')
                .ok_or_else(|| io::Error::other(format!("invalid readiness field: {field}")))
        })
        .collect()
}
