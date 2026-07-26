//! Top-level process supervisor daemon for Renee.
//!
//! Supervisord owns process lifetime, not application or document state. Its
//! error policy is deliberately narrow: malformed startup configuration is a
//! controlled startup failure; child and dependency failures are contained by
//! restarting one permanent child or, after restart-intensity exhaustion, the
//! complete permanent-child group.
//!
//! Standard input is the parent-lifetime channel. Standard output carries
//! bounded machine-readable lifecycle events. Losing the output consumer after
//! startup must not become a new supervisor failure mode, so runtime events and
//! diagnostics are best-effort.

#![forbid(unsafe_code)]
#![deny(
    unconditional_panic,
    clippy::arithmetic_side_effects,
    clippy::exit,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::string_slice,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]

use std::collections::{BTreeMap, VecDeque};
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};
use tokio::process::{Child, ChildStdout, Command};

// `take` must permit one byte beyond the valid maximum so a full 4 KiB record
// without its newline is distinguishable from a correctly framed record.
const CHILD_READINESS_LIMIT: u64 = 4_097;
const CHILD_READINESS_MAX_BYTES: usize = 4_096;
const CHILD_READINESS_TIMEOUT: Duration = Duration::from_secs(10);
const CHILD_STATUS_INTERVAL: Duration = Duration::from_millis(25);

// MaxR/MaxT is currently five failures in thirty seconds. Exhaustion does not
// terminate supervisord: it drains the entire permanent-child group and starts
// a fresh group after this delay.
const GROUP_RESTART_DELAY: Duration = Duration::from_millis(500);
const MAX_RESTARTS: usize = 5;
const MAX_RESTART_TIME: Duration = Duration::from_secs(30);
const RESTART_DELAY: Duration = Duration::from_millis(100);

// This is a per-child deadline, not a budget shared by the group. Shutdown
// walks the group in reverse startup order and starts a fresh timer per child.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(2);

/// Immutable information needed to recreate one permanent child.
#[derive(Clone)]
struct ChildSpec {
    arguments: Vec<OsString>,
    executable: PathBuf,
    role: &'static str,
}

/// Validated operator configuration.
///
/// Paths remain `PathBuf`s so non-UTF-8 Unix paths are valid. Only values
/// consumed as protocol text, such as the bind address, require UTF-8.
struct Configuration {
    bind_address: String,
    certificate: Option<PathBuf>,
    gatewayd: PathBuf,
    private_key: Option<PathBuf>,
    sessiond: PathBuf,
    shutdown_on_stdin_eof: bool,
    stored: PathBuf,
}

/// One live child plus the restart history that follows that logical role.
struct ManagedChild {
    child: Option<Child>,
    restart_budget: RestartBudget,
    spec: ChildSpec,
}

/// Sliding-window failure history for one child role.
struct RestartBudget {
    failures: VecDeque<Instant>,
}

/// A complete generation of permanent Renee children.
struct RunningGroup {
    children: Vec<ManagedChild>,
    readiness: BTreeMap<&'static str, String>,
}

enum LifecycleEvent {
    RestartGroup,
    Shutdown(io::Result<()>),
}

enum RestartOutcome {
    Restarted,
    RestartGroup,
}

fn main() -> Result<(), Box<dyn Error>> {
    // Avoid `#[tokio::main]`: its generated runtime construction is outside
    // our visible fallible control flow. Runtime creation is an ordinary error.
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(run())
}

async fn run() -> Result<(), Box<dyn Error>> {
    let configuration = Configuration::from_args()?;
    configuration.validate()?;
    let specifications = configuration.child_specs();
    let shutdown = wait_for_shutdown(configuration.shutdown_on_stdin_eof);
    tokio::pin!(shutdown);
    let mut first_start = true;

    // One iteration owns exactly one child-group generation. Every path out of
    // the monitoring phase drains that generation before another can start.
    loop {
        let mut group = tokio::select! {
            shutdown_result = &mut shutdown => {
                return shutdown_result.map_err(Into::into);
            }
            group = start_group(&specifications) => group,
        };
        emit_group_readiness(&group, first_start);
        first_start = false;

        let event = tokio::select! {
            shutdown_result = &mut shutdown => LifecycleEvent::Shutdown(shutdown_result),
            monitor_result = monitor_children(&mut group.children) => monitor_result,
        };

        shutdown_children(&mut group.children).await;
        match event {
            LifecycleEvent::RestartGroup => {
                emit_event("RESTARTING supervisord-child-group");
                tokio::time::sleep(GROUP_RESTART_DELAY).await;
            }
            LifecycleEvent::Shutdown(result) => return result.map_err(Into::into),
        }
    }
}

impl Configuration {
    fn from_args() -> Result<Self, Box<dyn Error>> {
        let mut values = BTreeMap::new();
        let mut shutdown_on_stdin_eof = false;
        // `env::args()` panics on non-UTF-8 input. Option names are explicitly
        // converted and rejected; path-valued arguments remain `OsString`s.
        let mut arguments = env::args_os().skip(1);

        while let Some(argument) = arguments.next() {
            let argument = argument.into_string().map_err(|_argument| {
                io::Error::new(io::ErrorKind::InvalidInput, "argument name is not UTF-8")
            })?;
            if argument == "--shutdown-on-stdin-eof" {
                if shutdown_on_stdin_eof {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "duplicate argument --shutdown-on-stdin-eof",
                    )
                    .into());
                }
                shutdown_on_stdin_eof = true;
                continue;
            }

            let value = arguments.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("{argument} requires a value"))
            })?;
            if values.insert(argument.clone(), value).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("duplicate argument {argument}"),
                )
                .into());
            }
        }

        let sibling_directory = env::current_exe()?
            .parent()
            .ok_or_else(|| io::Error::other("supervisord executable has no parent directory"))?
            .to_owned();
        let gatewayd =
            take_path_or_sibling(&mut values, "--gatewayd", &sibling_directory, "renee-gatewayd");
        let stored =
            take_path_or_sibling(&mut values, "--stored", &sibling_directory, "renee-stored");
        let sessiond =
            take_path_or_sibling(&mut values, "--sessiond", &sibling_directory, "renee-sessiond");
        let bind_address = take_required_utf8_or_default(&mut values, "--bind", "127.0.0.1:4433")?;
        let certificate = take_optional_path(&mut values, "--certificate");
        let private_key = take_optional_path(&mut values, "--private-key");
        if let Some((unknown, _value)) = values.first_key_value() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown argument {unknown}"),
            )
            .into());
        }

        Ok(Self {
            bind_address,
            certificate,
            gatewayd,
            private_key,
            sessiond,
            shutdown_on_stdin_eof,
            stored,
        })
    }

    fn child_specs(&self) -> [ChildSpec; 2] {
        let mut gateway_arguments =
            vec![OsString::from("--bind"), OsString::from(&self.bind_address)];
        if let (Some(certificate), Some(private_key)) = (&self.certificate, &self.private_key) {
            gateway_arguments.extend([
                OsString::from("--certificate"),
                certificate.as_os_str().to_owned(),
                OsString::from("--private-key"),
                private_key.as_os_str().to_owned(),
            ]);
        }
        gateway_arguments
            .extend([OsString::from("--sessiond"), self.sessiond.as_os_str().to_owned()]);

        // Array order is startup order and therefore part of the lifecycle
        // contract. Shutdown iterates this collection in reverse: gatewayd
        // stops before stored, preventing new work while storage drains.
        //
        // sessiond is intentionally absent. Gatewayd receives its executable
        // path and creates one temporary child per connection.
        [
            ChildSpec { arguments: Vec::new(), executable: self.stored.clone(), role: "stored" },
            ChildSpec {
                arguments: gateway_arguments,
                executable: self.gatewayd.clone(),
                role: "gatewayd",
            },
        ]
    }

    fn validate(&self) -> io::Result<()> {
        validate_executable("gatewayd", &self.gatewayd)?;
        validate_executable("sessiond", &self.sessiond)?;
        validate_executable("stored", &self.stored)?;
        match (&self.certificate, &self.private_key) {
            (Some(certificate), Some(private_key)) => {
                validate_file("gateway certificate", certificate)?;
                validate_file("gateway private key", private_key)
            }
            (None, None) => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--certificate and --private-key must be provided together",
            )),
        }
    }
}

impl ManagedChild {
    fn from_started(spec: ChildSpec, child: Child, restart_budget: RestartBudget) -> Self {
        Self { child: Some(child), restart_budget, spec }
    }

    fn pid_field(&self) -> io::Result<String> {
        let pid = self
            .child
            .as_ref()
            .and_then(Child::id)
            .ok_or_else(|| io::Error::other(format!("{} has no process ID", self.spec.role)))?;
        Ok(format!("{}-pid={pid}", self.spec.role))
    }

    fn poll_exit(&mut self) -> io::Result<Option<ExitStatus>> {
        match self.child.as_mut() {
            Some(child) => child.try_wait(),
            None => Ok(None),
        }
    }

    async fn restart(&mut self, status: ExitStatus) -> RestartOutcome {
        self.child = None;
        emit_event(&format!("EXITED {} status={status}", self.spec.role));

        // Successful replacements retain this role's failure history. That is
        // what makes repeated short-lived replacements eventually cross MaxR
        // within MaxT instead of receiving a fresh budget every time.
        loop {
            if !self.restart_budget.record_failure() {
                write_diagnostic(
                    self.spec.role,
                    "restart-intensity-exceeded",
                    io::ErrorKind::Other,
                );
                return RestartOutcome::RestartGroup;
            }
            tokio::time::sleep(RESTART_DELAY).await;

            match spawn_ready_child(&self.spec).await {
                Ok((replacement, readiness)) => {
                    self.child = Some(replacement);
                    let pid_field = match self.pid_field() {
                        Ok(field) => field,
                        Err(error) => {
                            write_diagnostic(
                                self.spec.role,
                                "replacement-pid-unavailable",
                                error.kind(),
                            );
                            return RestartOutcome::RestartGroup;
                        }
                    };
                    emit_event(&format!("RESTARTED {} {readiness} {pid_field}", self.spec.role));
                    return RestartOutcome::Restarted;
                }
                Err(error) => {
                    write_diagnostic(self.spec.role, "restart-failed", error.kind());
                }
            }
        }
    }
}

impl RestartBudget {
    const fn new() -> Self {
        Self { failures: VecDeque::new() }
    }

    fn record_failure(&mut self) -> bool {
        let now = Instant::now();
        // Evict before testing the limit so failures outside MaxT never count
        // against the current restart-intensity decision.
        while self
            .failures
            .front()
            .is_some_and(|instant| now.duration_since(*instant) >= MAX_RESTART_TIME)
        {
            self.failures.pop_front();
        }
        if self.failures.len() >= MAX_RESTARTS {
            return false;
        }
        self.failures.push_back(now);
        true
    }
}

async fn start_group(specifications: &[ChildSpec]) -> RunningGroup {
    // Startup dependency failure is recoverable after configuration paths have
    // been validated. A role receives its normal retry budget; exhaustion
    // drains any already-started earlier roles and retries the complete group.
    loop {
        let mut children = Vec::new();
        let mut readiness = BTreeMap::new();
        let mut group_failed = false;

        for specification in specifications {
            let mut budget = RestartBudget::new();
            loop {
                match spawn_ready_child(specification).await {
                    Ok((child, record)) => {
                        let managed =
                            ManagedChild::from_started(specification.clone(), child, budget);
                        readiness.insert(specification.role, record);
                        children.push(managed);
                        break;
                    }
                    Err(error) => {
                        write_diagnostic(specification.role, "initial-start-failed", error.kind());
                        if !budget.record_failure() {
                            group_failed = true;
                            break;
                        }
                        tokio::time::sleep(RESTART_DELAY).await;
                    }
                }
            }
            if group_failed {
                break;
            }
        }

        if !group_failed {
            return RunningGroup { children, readiness };
        }

        shutdown_children(&mut children).await;
        emit_event("RESTARTING supervisord-child-group");
        tokio::time::sleep(GROUP_RESTART_DELAY).await;
    }
}

async fn monitor_children(children: &mut [ManagedChild]) -> LifecycleEvent {
    // `Child::try_wait` observes the owned child handle and reaps exits. PIDs
    // are emitted for conformance diagnostics but are never used here as the
    // authority for supervision.
    loop {
        for child in &mut *children {
            match child.poll_exit() {
                Ok(Some(status)) => {
                    let outcome = child.restart(status).await;
                    match outcome {
                        RestartOutcome::Restarted => {}
                        RestartOutcome::RestartGroup => return LifecycleEvent::RestartGroup,
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    write_diagnostic(child.spec.role, "child-observation-failed", error.kind());
                    return LifecycleEvent::RestartGroup;
                }
            }
        }
        tokio::time::sleep(CHILD_STATUS_INTERVAL).await;
    }
}

async fn spawn_ready_child(spec: &ChildSpec) -> io::Result<(Child, String)> {
    let mut command = Command::new(&spec.executable);
    command
        .args(&spec.arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        // If a partially started group is cancelled while supervisord handles
        // shutdown, dropping the process handle must not orphan that child.
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other(format!("{} stdout was not piped", spec.role)))?;
    let record = read_readiness(spec.role, stdout).await?;
    Ok((child, record))
}

async fn read_readiness(role: &'static str, stdout: ChildStdout) -> io::Result<String> {
    // `read_line` alone grows its String without a bound. The 4,097-byte `take`
    // cap limits allocation while retaining enough information to reject an
    // overlong or unterminated 4 KiB record.
    let mut output = BufReader::new(stdout).take(CHILD_READINESS_LIMIT);
    let mut record = String::new();
    let bytes_read = tokio::time::timeout(CHILD_READINESS_TIMEOUT, output.read_line(&mut record))
        .await
        .map_err(|_timeout| io::Error::other(format!("{role} readiness timed out")))??;

    if bytes_read == 0 {
        return Err(io::Error::other(format!("{role} exited before readiness")));
    }
    if bytes_read > CHILD_READINESS_MAX_BYTES || !record.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{role} readiness exceeded its framing limit"),
        ));
    }

    let record = record.trim_end().to_owned();
    let expected = format!("READY {role}");
    if record != expected && !record.starts_with(&format!("{expected} ")) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{role} emitted malformed readiness"),
        ));
    }
    Ok(record)
}

async fn shutdown_children(children: &mut [ManagedChild]) {
    // Reverse startup order is intentional: stop admission first, then the
    // authority it depends upon. Do not replace this with a simultaneous EOF
    // broadcast; the ordering is observable and safety-relevant.
    for child in children.iter_mut().rev() {
        shutdown_child(child).await;
    }
}

async fn shutdown_child(child: &mut ManagedChild) {
    emit_event(&format!("STOPPING {}", child.spec.role));
    let Some(mut process) = child.child.take() else {
        emit_event(&format!("STOPPED {} outcome=already-exited", child.spec.role));
        return;
    };

    // Closing only this child's parent-lifetime channel begins its graceful
    // period. The next child receives neither EOF nor a ticking deadline yet.
    drop(process.stdin.take());
    let shutdown_started = Instant::now();
    loop {
        match process.try_wait() {
            Ok(Some(status)) => {
                emit_event(&format!(
                    "STOPPED {} outcome=graceful status={status}",
                    child.spec.role
                ));
                return;
            }
            Ok(None) => {}
            Err(error) => {
                write_diagnostic(child.spec.role, "shutdown-observation-failed", error.kind());
                drop(process.kill().await);
                emit_event(&format!(
                    "STOPPED {} outcome=forced-after-observation-error",
                    child.spec.role
                ));
                return;
            }
        }
        if shutdown_started.elapsed() >= SHUTDOWN_DEADLINE {
            // Escalation is scoped to the child whose independent deadline
            // expired. Later children still receive their full grace period.
            drop(process.kill().await);
            emit_event(&format!("STOPPED {} outcome=forced-after-deadline", child.spec.role));
            return;
        }
        tokio::time::sleep(CHILD_STATUS_INTERVAL).await;
    }
}

async fn wait_for_shutdown(shutdown_on_stdin_eof: bool) -> io::Result<()> {
    if !shutdown_on_stdin_eof {
        return tokio::signal::ctrl_c().await;
    }

    // EOF shutdown is used by the conformance harness and by a parent process
    // that treats an inherited pipe as the lifetime authority.
    let mut stdin = tokio::io::stdin();
    let mut parent_byte = [0_u8; 1];
    tokio::select! {
        signal = tokio::signal::ctrl_c() => signal,
        read = stdin.read(&mut parent_byte) => read.map(|_bytes_read| ()),
    }
}

fn emit_group_readiness(group: &RunningGroup, first_start: bool) {
    let gateway_readiness =
        group.readiness.get("gatewayd").map_or("READY gatewayd unavailable", String::as_str);
    let process_fields = group
        .children
        .iter()
        .filter_map(|child| child.pid_field().ok())
        .collect::<Vec<_>>()
        .join(" ");
    let event = if first_start {
        format!("READY supervisord {gateway_readiness} {process_fields}")
    } else {
        format!("RESTARTED supervisord-child-group {gateway_readiness} {process_fields}")
    };
    emit_event(&event);
}

fn emit_event(record: &str) {
    // After startup, a closed observer pipe must not take down supervisord or
    // prevent recovery. Conformance keeps this pipe open and verifies events.
    let stdout = io::stdout();
    let mut output = stdout.lock();
    drop(writeln!(output, "{record}"));
    drop(output.flush());
}

fn take_path_or_sibling(
    values: &mut BTreeMap<String, OsString>,
    name: &'static str,
    sibling_directory: &Path,
    sibling_name: &'static str,
) -> PathBuf {
    values.remove(name).map_or_else(|| sibling_directory.join(sibling_name), PathBuf::from)
}

fn take_optional_path(
    values: &mut BTreeMap<String, OsString>,
    name: &'static str,
) -> Option<PathBuf> {
    values.remove(name).map(PathBuf::from)
}

fn take_required_utf8_or_default(
    values: &mut BTreeMap<String, OsString>,
    name: &'static str,
    default: &'static str,
) -> io::Result<String> {
    match values.remove(name) {
        Some(value) => value.into_string().map_err(|_value| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("{name} value is not UTF-8"))
        }),
        None => Ok(default.to_owned()),
    }
}

fn validate_executable(role: &'static str, executable: &Path) -> io::Result<()> {
    validate_file(&format!("{role} executable"), executable)
}

fn validate_file(description: &str, path: &Path) -> io::Result<()> {
    // Validation separates malformed operator configuration from transient
    // spawn/readiness failures handled by the restart state machine.
    let metadata = path.metadata().map_err(|error| {
        io::Error::new(error.kind(), format!("{description} is unavailable: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(io::Error::other(format!("{description} is not a file")));
    }
    Ok(())
}

fn write_diagnostic(role: &'static str, message: &'static str, error_kind: io::ErrorKind) {
    // Only trusted role/event vocabulary and an `ErrorKind` are emitted. Child
    // output and raw attacker-controlled values are deliberately excluded.
    let stderr = io::stderr();
    let mut output = stderr.lock();
    drop(writeln!(output, "supervisord role={role} event={message} error-kind={error_kind}"));
    drop(output.flush());
}
