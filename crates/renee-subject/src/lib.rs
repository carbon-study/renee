//! Black-box process and fault-injection harness for Renee.
//!
//! This crate drives the real Renee daemons as the subject under test. It owns
//! process lifecycle, transport clients, observable outcomes, and fault
//! injection.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use renee_types::{DocumentId, UpdateId};
use renee_wire::{
    ACCEPT_UPDATE, ACCEPT_UPDATE_RESPONSE, AcceptUpdateOutcome, AuthorizedUpdateRequest,
    CAPABILITY_ERROR, CLIENT_HELLO, CREATE_DOCUMENT, CREATE_DOCUMENT_RESPONSE, CapabilityAuthority,
    CapabilityErrorCode, ControlMutationOutcome, CreateDocumentOutcome, CreateDocumentRequest,
    ENUMERATE_UPDATES, ENUMERATE_UPDATES_RESPONSE, ERROR_ALREADY_NEGOTIATED, ERROR_EXPECTED_HELLO,
    ERROR_UNSUPPORTED_PROFILE, ERROR_UNSUPPORTED_VERSION, EnumerateRequest, EnumerateResponse,
    EnumerateStart, Envelope, FETCH_UPDATE, FETCH_UPDATE_RESPONSE, GRANT_CAPABILITY,
    GRANT_CAPABILITY_RESPONSE, GrantCapabilityRequest, PROFILE, PROTOCOL_ERROR, REVOKE_CAPABILITY,
    REVOKE_CAPABILITY_RESPONSE, RevokeCapabilityRequest, SERVER_HELLO, UPDATE_ERROR,
    UpdateErrorCode, VERSION, decode_accept_response, decode_body, decode_capability_error,
    decode_control_mutation_response, decode_create_document_response, decode_enumerate_response,
    decode_fetch_response, decode_greeting, decode_update_error, encode_authorized_update_request,
    encode_body, encode_create_document_request, encode_enumerate_request, encode_fetch_request,
    encode_grant_capability_request, encode_greeting, encode_revoke_capability_request, read_body,
    write_body,
};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};
use tokio::process::{Child, ChildStdout, Command};
use wtransport::endpoint::endpoint_side;
use wtransport::tls::{Sha256Digest, Sha256DigestFmt};
use wtransport::{ClientConfig, Connection, Endpoint};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
/// The greeting sent by the Carbon client represented by this subject harness.
pub const CARBON_BANNER: &str = "I couldn't stay away";

/// A result produced by the Renee black-box test harness.
pub type HarnessResult<T> = Result<T, Box<dyn Error>>;

/// A running Renee process tree controlled through its top-level supervisor.
pub struct ServerHarness {
    address: String,
    barrier_directory: PathBuf,
    certificate_hash: Sha256Digest,
    output: BufReader<ChildStdout>,
    permanent_child_pids: BTreeMap<&'static str, u32>,
    _state_directory: TemporaryDirectory,
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

/// A normalized negotiation observation from the real subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegotiationObservation {
    /// The requested profile was selected.
    Selected {
        /// Informational greeting returned by the real server.
        server_banner: String,
    },
    /// The envelope version is unsupported.
    UnsupportedVersion,
    /// The named profile is unsupported.
    UnsupportedProfile,
    /// The first message was not a hello.
    ExpectedHello,
    /// Negotiation was repeated after success.
    AlreadyNegotiated,
}

/// Subject observation for immutable accept.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptObservation {
    /// A new idempotency key was inserted.
    Inserted,
    /// The exact same immutable bytes were already present.
    AlreadyPresent,
    /// The document-scoped update ID named different immutable input.
    IdentifierConflict,
    /// Renee rejected the record structure.
    Malformed,
    /// Renee denied the indistinguishable document capability authority.
    AuthorizationDenied,
}

/// Subject observation for root document creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateDocumentObservation {
    /// The document and root capability were inserted.
    Inserted,
    /// The exact document and root authority were already durable.
    AlreadyPresent,
    /// The document identifier named different root input.
    IdentifierConflict,
    /// Renee rejected malformed creation input.
    Malformed,
}

/// Subject observation for grant and revoke control mutations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlMutationObservation {
    /// A new control mutation was committed.
    Inserted,
    /// The exact issuer-scoped request was already durable.
    AlreadyPresent,
    /// Authority was denied without disclosing its cause.
    AuthorizationDenied,
    /// A client-selected capability identifier names different input.
    IdentifierConflict,
    /// The request identifier names different input.
    RequestConflict,
    /// The control revision cannot advance.
    CounterExhausted,
    /// Renee rejected malformed control input.
    Malformed,
}

/// Subject observation for an authorized fetch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FetchObservation {
    /// Renee returned the exact opaque encrypted bytes.
    Found(Vec<u8>),
    /// No update exists under the complete idempotency key.
    NotFound,
}

/// Subject observation for one finite metadata read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnumerateObservation {
    /// Renee returned a bounded page and an opaque continuation cursor.
    Page(EnumerateResponse),
    /// The cursor was malformed or bound to another document.
    InvalidCursor,
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl ServerHarness {
    /// Starts every Renee daemon and waits for the complete process tree to be ready.
    pub async fn start() -> HarnessResult<Self> {
        let supervisor_path = daemon_path("renee-supervisord")?;
        Self::start_with_supervisor(supervisor_path).await
    }

    /// Starts Renee from an explicitly built daemon directory.
    ///
    /// Cross-repository conformance uses this entry point so Carbon can build
    /// Renee into a dedicated target directory without coupling either Cargo
    /// workspace to the other's production crates.
    pub async fn start_with_daemon_directory(daemon_directory: &Path) -> HarnessResult<Self> {
        Self::start_with_supervisor(
            daemon_directory.join(format!("renee-supervisord{}", env::consts::EXE_SUFFIX)),
        )
        .await
    }

    async fn start_with_supervisor(supervisor_path: PathBuf) -> HarnessResult<Self> {
        let state_directory = TemporaryDirectory::create()?;
        let store_database = state_directory.path.join("renee.sqlite3");
        let barrier_directory = state_directory.path.join("barriers");
        fs::create_dir_all(&barrier_directory)?;
        let mut supervisor = Command::new(supervisor_path)
            .args(["--bind", "127.0.0.1:0", "--shutdown-on-stdin-eof"])
            .arg("--store-database")
            .arg(store_database)
            .env("RENEE_TEST_BARRIER_DIRECTORY", &barrier_directory)
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

        Ok(Self {
            address,
            barrier_directory,
            certificate_hash,
            output,
            permanent_child_pids,
            _state_directory: state_directory,
            supervisor,
        })
    }

    /// Arms one externally acknowledged store transaction barrier.
    pub fn arm_store_barrier(&self, name: &'static str) -> io::Result<()> {
        fs::write(self.barrier_directory.join(format!("armed-{name}")), [])
    }

    /// Waits for an armed store barrier, kills stored there, and observes replacement.
    pub async fn crash_store_at_barrier(&mut self, name: &'static str) -> HarnessResult<()> {
        let reached = self.barrier_directory.join(format!("reached-{name}"));
        tokio::time::timeout(STARTUP_TIMEOUT, async {
            loop {
                match reached.metadata() {
                    Ok(_metadata) => break Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    Err(error) => break Err(error),
                }
            }
        })
        .await??;
        self.kill_and_wait_for_restart(PermanentDaemon::Store).await?;
        drop(fs::remove_file(reached));
        Ok(())
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
            self.verify_gateway(&fields)?;
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
        self.verify_gateway(&fields)?;
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

    fn verify_gateway(&self, fields: &BTreeMap<&str, &str>) -> HarnessResult<()> {
        let address = fields
            .get("address")
            .ok_or_else(|| io::Error::other("gateway event omitted address"))?
            .to_string();
        let certificate_hash = Sha256Digest::from_str_fmt(
            fields
                .get("certificate-sha256")
                .ok_or_else(|| io::Error::other("gateway event omitted certificate hash"))?,
            Sha256DigestFmt::DottedHex,
        )?;
        if address != self.address || certificate_hash != self.certificate_hash {
            return Err(io::Error::other(
                "gateway restart changed its public endpoint or TLS identity",
            )
            .into());
        }
        Ok(())
    }
}

impl WebTransportConnection {
    /// Sends a structurally invalid envelope and verifies prompt session termination.
    pub async fn reject_malformed_envelope(&self) -> HarnessResult<()> {
        let mut stream =
            wtransport::stream::BiStream::join(self.connection.open_bi().await?.await?);
        write_body(&mut stream, b"not-an-envelope").await?;
        tokio::io::AsyncWriteExt::shutdown(&mut stream).await?;

        let response =
            tokio::time::timeout(Duration::from_secs(2), read_body(&mut stream)).await.map_err(
                |_elapsed| io::Error::other("malformed envelope left client stream hanging"),
            )?;
        match response {
            Ok(None) | Err(_) => Ok(()),
            Ok(Some(_body)) => {
                Err(io::Error::other("malformed envelope received an unexpected response").into())
            }
        }
    }

    /// Negotiates Renee's experimental profile over one reliable stream.
    pub async fn negotiate(&self) -> HarnessResult<NegotiationObservation> {
        self.hello(VERSION, PROFILE, CARBON_BANNER).await
    }

    /// Sends one experimental hello with caller-selected negotiation values.
    pub async fn hello(
        &self,
        version: u16,
        profile: &str,
        banner: &str,
    ) -> HarnessResult<NegotiationObservation> {
        let correlation_id = [0x11; 16];
        let request = Envelope {
            correlation_id,
            message_type: CLIENT_HELLO,
            payload: encode_greeting(profile, banner)?,
            version,
        };
        let mut stream =
            wtransport::stream::BiStream::join(self.connection.open_bi().await?.await?);
        write_body(&mut stream, &encode_body(&request)?).await?;
        tokio::io::AsyncWriteExt::shutdown(&mut stream).await?;
        let response_body = read_body(&mut stream)
            .await?
            .ok_or_else(|| io::Error::other("gateway closed before negotiation response"))?;
        let response = decode_body(&response_body)?;
        if response.correlation_id != correlation_id {
            return Err(io::Error::other("negotiation correlation ID changed").into());
        }
        if response.message_type == SERVER_HELLO && response.version == VERSION {
            let greeting = decode_greeting(&response.payload)?;
            if greeting.profile != PROFILE {
                return Err(io::Error::other("server selected an unexpected profile").into());
            }
            return Ok(NegotiationObservation::Selected {
                server_banner: greeting.banner.to_owned(),
            });
        }
        if response.message_type == PROTOCOL_ERROR {
            return match response.payload.as_slice() {
                ERROR_UNSUPPORTED_VERSION => Ok(NegotiationObservation::UnsupportedVersion),
                ERROR_UNSUPPORTED_PROFILE => Ok(NegotiationObservation::UnsupportedProfile),
                ERROR_EXPECTED_HELLO => Ok(NegotiationObservation::ExpectedHello),
                ERROR_ALREADY_NEGOTIATED => Ok(NegotiationObservation::AlreadyNegotiated),
                _ => Err(io::Error::other("unknown negotiation rejection").into()),
            };
        }
        Err(io::Error::other("unexpected negotiation response").into())
    }

    /// Creates one document and its full-operation root capability.
    pub async fn create_document(
        &self,
        request: &CreateDocumentRequest,
    ) -> HarnessResult<CreateDocumentObservation> {
        let response =
            self.exchange(CREATE_DOCUMENT, encode_create_document_request(request)).await?;
        match response.message_type {
            CREATE_DOCUMENT_RESPONSE => match decode_create_document_response(&response.payload)? {
                CreateDocumentOutcome::Inserted => Ok(CreateDocumentObservation::Inserted),
                CreateDocumentOutcome::AlreadyPresent => {
                    Ok(CreateDocumentObservation::AlreadyPresent)
                }
            },
            CAPABILITY_ERROR => match decode_capability_error(&response.payload)? {
                CapabilityErrorCode::IdentifierConflict => {
                    Ok(CreateDocumentObservation::IdentifierConflict)
                }
                CapabilityErrorCode::Malformed => Ok(CreateDocumentObservation::Malformed),
                CapabilityErrorCode::AuthorizationDenied => {
                    Err(io::Error::other("unexpected create authorization denial").into())
                }
                CapabilityErrorCode::RequestConflict | CapabilityErrorCode::CounterExhausted => {
                    Err(io::Error::other("unexpected create control rejection").into())
                }
            },
            _unexpected => Err(io::Error::other("unexpected create response").into()),
        }
    }

    /// Grants one attenuated descendant capability.
    pub async fn grant_capability(
        &self,
        request: &GrantCapabilityRequest,
    ) -> HarnessResult<ControlMutationObservation> {
        let response =
            self.exchange(GRANT_CAPABILITY, encode_grant_capability_request(request)).await?;
        control_observation(&response, GRANT_CAPABILITY_RESPONSE)
    }

    /// Revokes one capability subtree.
    pub async fn revoke_capability(
        &self,
        request: &RevokeCapabilityRequest,
    ) -> HarnessResult<ControlMutationObservation> {
        let response =
            self.exchange(REVOKE_CAPABILITY, encode_revoke_capability_request(request)).await?;
        control_observation(&response, REVOKE_CAPABILITY_RESPONSE)
    }

    /// Submits one exact canonical record under current update authority.
    pub async fn accept_update(
        &self,
        authority: &CapabilityAuthority,
        encoded_record: &[u8],
    ) -> HarnessResult<AcceptObservation> {
        let payload = encode_authorized_update_request(&AuthorizedUpdateRequest {
            authority: authority.clone(),
            encoded_record,
        })?;
        let response = self.exchange(ACCEPT_UPDATE, payload).await?;
        match response.message_type {
            ACCEPT_UPDATE_RESPONSE => match decode_accept_response(&response.payload)? {
                AcceptUpdateOutcome::Inserted => Ok(AcceptObservation::Inserted),
                AcceptUpdateOutcome::AlreadyPresent => Ok(AcceptObservation::AlreadyPresent),
            },
            UPDATE_ERROR => match decode_update_error(&response.payload)? {
                UpdateErrorCode::IdentifierConflict => Ok(AcceptObservation::IdentifierConflict),
                UpdateErrorCode::Malformed => Ok(AcceptObservation::Malformed),
                UpdateErrorCode::AuthorizationDenied => Ok(AcceptObservation::AuthorizationDenied),
                UpdateErrorCode::NotFound
                | UpdateErrorCode::NotNegotiated
                | UpdateErrorCode::InvalidCursor
                | UpdateErrorCode::CounterExhausted => {
                    Err(io::Error::other("unexpected accept rejection").into())
                }
            },
            unexpected => Err(io::Error::other(format!(
                "unexpected accept response type {unexpected} payload {:?}",
                response.payload
            ))
            .into()),
        }
    }

    /// Enumerates one bounded page of public update metadata.
    pub async fn enumerate_updates(
        &self,
        document_id: DocumentId,
        cursor: Option<Vec<u8>>,
    ) -> HarnessResult<EnumerateResponse> {
        match self.enumerate_updates_observation(document_id, cursor).await? {
            EnumerateObservation::Page(page) => Ok(page),
            EnumerateObservation::InvalidCursor => {
                Err(io::Error::other("valid enumerate request received invalid-cursor").into())
            }
        }
    }

    /// Enumerates while preserving an invalid-cursor protocol observation.
    pub async fn enumerate_updates_observation(
        &self,
        document_id: DocumentId,
        cursor: Option<Vec<u8>>,
    ) -> HarnessResult<EnumerateObservation> {
        let start = cursor.map_or(EnumerateStart::Origin, EnumerateStart::Continue);
        self.enumerate_updates_start_observation(document_id, start).await
    }

    /// Captures a new finite read strictly after one completed tail cursor.
    pub async fn enumerate_updates_after_tail(
        &self,
        document_id: DocumentId,
        cursor: Vec<u8>,
    ) -> HarnessResult<EnumerateResponse> {
        match self
            .enumerate_updates_start_observation(document_id, EnumerateStart::AfterTail(cursor))
            .await?
        {
            EnumerateObservation::Page(page) => Ok(page),
            EnumerateObservation::InvalidCursor => {
                Err(io::Error::other("valid tail cursor received invalid-cursor").into())
            }
        }
    }

    async fn enumerate_updates_start_observation(
        &self,
        document_id: DocumentId,
        start: EnumerateStart,
    ) -> HarnessResult<EnumerateObservation> {
        let response = self
            .exchange(
                ENUMERATE_UPDATES,
                encode_enumerate_request(&EnumerateRequest { document_id, start })?,
            )
            .await?;
        match response.message_type {
            ENUMERATE_UPDATES_RESPONSE => {
                Ok(EnumerateObservation::Page(decode_enumerate_response(&response.payload)?))
            }
            UPDATE_ERROR
                if decode_update_error(&response.payload)? == UpdateErrorCode::InvalidCursor =>
            {
                Ok(EnumerateObservation::InvalidCursor)
            }
            _unexpected => Err(io::Error::other("unexpected enumerate response").into()),
        }
    }

    /// Fetches one exact opaque encrypted payload.
    pub async fn fetch_update(
        &self,
        document_id: DocumentId,
        update_id: UpdateId,
    ) -> HarnessResult<FetchObservation> {
        let response =
            self.exchange(FETCH_UPDATE, encode_fetch_request(document_id, update_id)).await?;
        match response.message_type {
            FETCH_UPDATE_RESPONSE => {
                Ok(FetchObservation::Found(decode_fetch_response(&response.payload)?.to_vec()))
            }
            UPDATE_ERROR
                if decode_update_error(&response.payload)? == UpdateErrorCode::NotFound =>
            {
                Ok(FetchObservation::NotFound)
            }
            _unexpected => Err(io::Error::other("unexpected fetch response").into()),
        }
    }

    /// Closes the test connection without defining an application close protocol.
    pub fn close(self) {
        self.connection.close(0_u32.into(), b"conformance connection complete");
    }

    async fn exchange(&self, message_type: u16, payload: Vec<u8>) -> HarnessResult<Envelope> {
        let correlation_id = [0x22_u8; 16];
        let request = Envelope { correlation_id, message_type, payload, version: VERSION };
        let mut stream =
            wtransport::stream::BiStream::join(self.connection.open_bi().await?.await?);
        write_body(&mut stream, &encode_body(&request)?).await?;
        tokio::io::AsyncWriteExt::shutdown(&mut stream).await?;
        let response_body = read_body(&mut stream)
            .await?
            .ok_or_else(|| io::Error::other("gateway closed before application response"))?;
        let response = decode_body(&response_body)?;
        if response.correlation_id != correlation_id || response.version != VERSION {
            return Err(io::Error::other("application response envelope changed").into());
        }
        Ok(response)
    }
}

fn control_observation(
    response: &Envelope,
    success_message_type: u16,
) -> HarnessResult<ControlMutationObservation> {
    if response.message_type == success_message_type {
        return Ok(match decode_control_mutation_response(&response.payload)? {
            ControlMutationOutcome::Inserted => ControlMutationObservation::Inserted,
            ControlMutationOutcome::AlreadyPresent => ControlMutationObservation::AlreadyPresent,
        });
    }
    if response.message_type == CAPABILITY_ERROR {
        return Ok(match decode_capability_error(&response.payload)? {
            CapabilityErrorCode::Malformed => ControlMutationObservation::Malformed,
            CapabilityErrorCode::AuthorizationDenied => {
                ControlMutationObservation::AuthorizationDenied
            }
            CapabilityErrorCode::IdentifierConflict => {
                ControlMutationObservation::IdentifierConflict
            }
            CapabilityErrorCode::RequestConflict => ControlMutationObservation::RequestConflict,
            CapabilityErrorCode::CounterExhausted => ControlMutationObservation::CounterExhausted,
        });
    }
    Err(io::Error::other("unexpected control mutation response").into())
}

impl PermanentDaemon {
    const fn role(self) -> &'static str {
        match self {
            Self::Gateway => "gatewayd",
            Self::Store => "stored",
        }
    }
}

impl TemporaryDirectory {
    // Atomic reservation specifically requires `create_dir`: `create_dir_all`
    // would report success when a colliding directory already existed.
    #[expect(
        clippy::create_dir,
        reason = "atomic exclusive reservation must reject an already existing directory"
    )]
    fn create() -> io::Result<Self> {
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

        let base = env::temp_dir();
        let process_id = std::process::id();
        for _attempt in 0..100 {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("renee-subject-{process_id}-{sequence}"));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not reserve a unique Renee subject state directory",
        ))
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        // This exact directory was atomically created and exclusively owned by
        // the harness. Best-effort cleanup must never obscure test outcomes.
        drop(fs::remove_dir_all(&self.path));
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
