//! Public WebTransport gateway daemon for Renee.
//!
//! The gateway owns transport admission and connection lifetime. Application
//! envelopes remain opaque while it relays them through one session process.

#![forbid(unsafe_code)]

#[cfg(debug_assertions)]
mod identity;
#[cfg(debug_assertions)]
mod test_barrier;

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

#[cfg(debug_assertions)]
use renee_wire::{CERTIFICATE_MANIFEST, CERTIFICATE_MANIFEST_RESPONSE, VERSION, encode_body};
use renee_wire::{Envelope, SUBSCRIBE_UPDATES_ACK, decode_body, is_update_subscription_event};
use renee_wire::{read_body, write_body};
#[cfg(debug_assertions)]
use std::sync::Arc;
#[cfg(debug_assertions)]
use time::OffsetDateTime;
use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWriteExt as _, BufReader,
};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use wtransport::endpoint::IncomingSession;
use wtransport::{Connection, Endpoint, Identity, ServerConfig};

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:4433";
const DEFAULT_STORE_ADDRESS: &str = "127.0.0.1:4434";
const STREAM_EOF_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CONNECTION_REQUESTS: usize = 64;

struct GatewayRequest {
    body: Vec<u8>,
    response: oneshot::Sender<GatewayResponse>,
}

struct GatewayResponse {
    body: Vec<u8>,
    delivered: Option<oneshot::Sender<()>>,
}

enum SessionOutput {
    Frame(Vec<u8>),
    Closed,
    Error(io::Error),
}

struct PublicRequestStream {
    complete: bool,
    streams: Option<(wtransport::SendStream, wtransport::RecvStream)>,
}

impl PublicRequestStream {
    fn new(streams: (wtransport::SendStream, wtransport::RecvStream)) -> Self {
        Self { complete: false, streams: Some(streams) }
    }

    fn streams(&mut self) -> (&mut wtransport::SendStream, &mut wtransport::RecvStream) {
        let (send, receive) = self.streams.as_mut().expect("request stream is present until drop");
        (send, receive)
    }

    fn complete(&mut self) {
        self.complete = true;
    }
}

impl Drop for PublicRequestStream {
    fn drop(&mut self) {
        if self.complete {
            return;
        }
        if let Some((mut send, receive)) = self.streams.take() {
            let _reset_result = send.reset(1_u32.into());
            receive.stop(1_u32.into());
        }
    }
}

struct Configuration {
    bind_address: SocketAddr,
    certificate: Option<PathBuf>,
    local_identity: Option<PathBuf>,
    private_key: Option<PathBuf>,
    sessiond: PathBuf,
    store_address: SocketAddr,
}

struct GatewayIdentity {
    transport: Identity,
    rotation_delay: Option<Duration>,
    #[cfg(debug_assertions)]
    control_public_key: [u8; 32],
    #[cfg(debug_assertions)]
    manifest: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let configuration = Configuration::from_args()?;
    configuration.validate()?;
    let prepared = configuration.identity().await?;
    #[cfg(debug_assertions)]
    let debug_readiness = format!(
        " certificate-sha256={} control-public-key={} certificate-manifest={}",
        identity::certificate_hash(&prepared.transport)?,
        identity::encode_hex(&prepared.control_public_key),
        identity::encode_hex(&prepared.manifest),
    );
    #[cfg(debug_assertions)]
    let manifest = Arc::<[u8]>::from(prepared.manifest);
    let rotation_delay = prepared.rotation_delay;
    let config = ServerConfig::builder()
        .with_bind_address(configuration.bind_address)
        .with_identity(prepared.transport)
        .build();
    let endpoint = Endpoint::server(config)?;
    let local_address = endpoint.local_addr()?;

    #[cfg(debug_assertions)]
    emit_readiness(&format!("READY gatewayd address={local_address}{debug_readiness}"))?;
    #[cfg(not(debug_assertions))]
    emit_readiness(&format!("READY gatewayd address={local_address}"))?;

    let rotation = wait_for_rotation(rotation_delay);
    tokio::pin!(rotation);
    let mut stdin = tokio::io::stdin();
    let mut parent_byte = [0_u8; 1];

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let sessiond = configuration.sessiond.clone();
                let store_address = configuration.store_address;
                #[cfg(debug_assertions)]
                let manifest = Arc::clone(&manifest);
                tokio::spawn(async move {
                    let _session_result =
                        hold_session(
                            incoming,
                            sessiond,
                            store_address,
                            #[cfg(debug_assertions)]
                            manifest,
                        ).await;
                });
            }
            read = stdin.read(&mut parent_byte) => {
                read?;
                break;
            }
            signal = tokio::signal::ctrl_c() => {
                signal?;
                break;
            }
            () = &mut rotation => {
                // The replacement process loads the already-advertised next
                // leaf and publishes a newly signed successor manifest.
                break;
            }
        }
    }

    Ok(())
}

impl Configuration {
    fn from_args() -> Result<Self, Box<dyn Error>> {
        let mut arguments = env::args_os().skip(1);
        let mut bind_address = OsString::from(DEFAULT_BIND_ADDRESS);
        let mut certificate = None;
        let mut local_identity = None;
        let mut private_key = None;
        let mut sessiond = None;
        let mut store_address = OsString::from(DEFAULT_STORE_ADDRESS);

        while let Some(argument) = arguments.next() {
            let argument = argument.into_string().map_err(|_argument| {
                io::Error::new(io::ErrorKind::InvalidInput, "argument name is not UTF-8")
            })?;
            let value = arguments.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("{argument} requires a value"))
            })?;
            match argument.as_str() {
                "--bind" => bind_address = value,
                "--certificate" => certificate = Some(PathBuf::from(value)),
                "--local-identity" => local_identity = Some(PathBuf::from(value)),
                "--private-key" => private_key = Some(PathBuf::from(value)),
                "--sessiond" => sessiond = Some(PathBuf::from(value)),
                "--store" => store_address = value,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unknown argument: {argument}"),
                    )
                    .into());
                }
            }
        }

        let bind_address = bind_address
            .into_string()
            .map_err(|_address| {
                io::Error::new(io::ErrorKind::InvalidInput, "--bind value is not UTF-8")
            })?
            .parse()?;
        match (&certificate, &private_key, &local_identity) {
            (Some(_), Some(_), None) | (None, None, Some(_) | None) => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "use either --certificate with --private-key or --local-identity",
                )
                .into());
            }
        }

        let sessiond = sessiond.unwrap_or_else(|| {
            env::current_exe()
                .ok()
                .and_then(|path| path.parent().map(|parent| parent.join("renee-sessiond")))
                .unwrap_or_else(|| PathBuf::from("renee-sessiond"))
        });
        let store_address = store_address
            .into_string()
            .map_err(|_address| {
                io::Error::new(io::ErrorKind::InvalidInput, "--store value is not UTF-8")
            })?
            .parse()?;
        Ok(Self { bind_address, certificate, local_identity, private_key, sessiond, store_address })
    }

    fn validate(&self) -> io::Result<()> {
        if !self.bind_address.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "non-loopback gateway binding is disabled until capability authorization is implemented",
            ));
        }
        validate_executable("sessiond", &self.sessiond)
    }

    async fn identity(&self) -> Result<GatewayIdentity, Box<dyn Error>> {
        match (&self.certificate, &self.private_key, &self.local_identity) {
            #[cfg(debug_assertions)]
            (Some(_), Some(_), None) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "debug gateways use --local-identity certificate advertising",
            )
            .into()),
            #[cfg(not(debug_assertions))]
            (Some(certificate), Some(private_key), None) => Ok(GatewayIdentity {
                rotation_delay: None,
                transport: Identity::load_pemfiles(certificate, private_key).await?,
            }),
            #[cfg(debug_assertions)]
            (None, None, Some(local_identity)) => {
                let prepared = identity::prepare(local_identity, OffsetDateTime::now_utc()).await?;
                Ok(GatewayIdentity {
                    control_public_key: prepared.control_public_key,
                    manifest: prepared.manifest,
                    rotation_delay: Some(prepared.rotation_delay),
                    transport: prepared.transport,
                })
            }
            #[cfg(not(debug_assertions))]
            (None, None, Some(_)) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "--local-identity is available only in debug builds",
            )
            .into()),
            (None, None, None) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gateway requires a configured TLS identity",
            )
            .into()),
            _ => Err(io::Error::other("gateway identity configuration is inconsistent").into()),
        }
    }
}

fn validate_executable(role: &'static str, executable: &Path) -> io::Result<()> {
    let description = format!("{role} executable");
    let metadata = executable.metadata().map_err(|error| {
        io::Error::new(error.kind(), format!("{description} is unavailable: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(io::Error::other(format!("{description} is not a file")));
    }
    Ok(())
}

fn emit_readiness(record: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{record}")?;
    output.flush()
}

struct SessionProcess {
    child: Child,
    input: ChildStdin,
    output: Option<BufReader<ChildStdout>>,
}

async fn hold_session(
    incoming: IncomingSession,
    sessiond: PathBuf,
    store_address: SocketAddr,
    #[cfg(debug_assertions)] manifest: Arc<[u8]>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let request = incoming.await?;
    let connection = request.accept().await?;
    let mut session = spawn_session(sessiond, store_address).await?;

    let relay_result = relay_session(
        &connection,
        &mut session,
        #[cfg(debug_assertions)]
        &manifest,
    )
    .await;
    // Relay failure can leave request streams owned by dispatcher tasks. Close
    // the WebTransport session explicitly so every such stream unblocks before
    // the per-connection worker is reaped.
    connection.close(1_u32.into(), b"session relay ended");
    let shutdown_result = shutdown_session(session).await;
    // Teardown was already attempted above. Preserve the relay failure as the
    // primary cause when both the session and its cleanup fail.
    relay_result?;
    shutdown_result
}

#[expect(
    clippy::too_many_lines,
    reason = "one bounded dispatcher makes correlation and event routing auditable together"
)]
async fn relay_session(
    connection: &Connection,
    session: &mut SessionProcess,
    #[cfg(debug_assertions)] manifest: &[u8],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (request_sender, mut request_receiver) = mpsc::channel(MAX_CONNECTION_REQUESTS);
    let mut request_tasks = JoinSet::new();
    let (session_output_sender, mut session_output_receiver) =
        mpsc::channel(MAX_CONNECTION_REQUESTS);
    let session_output = session
        .output
        .take()
        .ok_or_else(|| io::Error::other("sessiond output is already being relayed"))?;
    let mut session_output_tasks = JoinSet::new();
    session_output_tasks.spawn(read_session_output(session_output, session_output_sender));
    let mut pending = HashMap::<[u8; 16], oneshot::Sender<GatewayResponse>>::new();
    loop {
        tokio::select! {
            stream = connection.accept_bi() => {
                // `closed()` and `accept_bi()` can become ready together. An
                // accept error therefore marks the end of this connection,
                // rather than bypassing the sessiond teardown path.
                let Ok(stream) = stream else {
                    break;
                };
                if request_tasks.len() >= MAX_CONNECTION_REQUESTS {
                    return Err(io::Error::other("connection request limit exceeded").into());
                }
                request_tasks.spawn(relay_public_request(stream, request_sender.clone()));
            }
            request = request_receiver.recv() => {
                let Some(request) = request else {
                    return Err(io::Error::other("gateway request queue closed").into());
                };
                let envelope = decode_body(&request.body)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                #[cfg(debug_assertions)]
                if let Some(response) = certificate_manifest_response(&request.body, manifest)? {
                    let _response_result = request.response.send(GatewayResponse {
                        body: response,
                        delivered: None,
                    });
                    continue;
                }
                if pending.len() >= MAX_CONNECTION_REQUESTS {
                    return Err(io::Error::other("connection correlation limit exceeded").into());
                }
                if pending.contains_key(&envelope.correlation_id) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "duplicate active correlation identifier",
                    ).into());
                }
                pending.insert(envelope.correlation_id, request.response);
                write_body(&mut session.input, &request.body).await?;
            }
            response = session_output_receiver.recv() => {
                let response = match response {
                    Some(SessionOutput::Frame(response)) => response,
                    Some(SessionOutput::Closed) | None => {
                        return Err(io::Error::other("sessiond closed before response").into());
                    }
                    Some(SessionOutput::Error(error)) => return Err(error.into()),
                };
                let envelope = decode_body(&response)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                if is_update_subscription_event(envelope.message_type) {
                    let mut stream = connection.open_uni().await?.await?;
                    write_body(&mut stream, &response).await?;
                    stream.shutdown().await?;
                    continue;
                }
                let responder = pending.remove(&envelope.correlation_id).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sessiond returned an impossible correlation identifier",
                    )
                })?;
                if envelope.message_type == SUBSCRIBE_UPDATES_ACK {
                    let (delivered, delivery) = oneshot::channel();
                    responder
                        .send(GatewayResponse {
                            body: response,
                            delivered: Some(delivered),
                        })
                        .map_err(|_response| {
                            io::Error::other("subscription client closed before acknowledgement")
                        })?;
                    delivery.await.map_err(|_error| {
                        io::Error::other("subscription acknowledgement stream closed early")
                    })?;
                } else {
                    let _response_result = responder.send(GatewayResponse {
                        body: response,
                        delivered: None,
                    });
                }
            }
            task = request_tasks.join_next(), if !request_tasks.is_empty() => {
                match task {
                    Some(Ok(Ok(()))) | None => {}
                    Some(Ok(Err(error))) => return Err(error),
                    Some(Err(error)) => return Err(error.into()),
                }
            }
            _closed = connection.closed() => break,
        }
    }
    request_tasks.abort_all();
    Ok(())
}

async fn read_session_output(
    mut output: BufReader<ChildStdout>,
    sender: mpsc::Sender<SessionOutput>,
) {
    loop {
        let output = match read_body(&mut output).await {
            Ok(Some(frame)) => SessionOutput::Frame(frame),
            Ok(None) => SessionOutput::Closed,
            Err(error) => SessionOutput::Error(error),
        };
        let terminal = !matches!(output, SessionOutput::Frame(_));
        if sender.send(output).await.is_err() || terminal {
            return;
        }
    }
}

async fn relay_public_request(
    stream: (wtransport::SendStream, wtransport::RecvStream),
    request_sender: mpsc::Sender<GatewayRequest>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut stream = PublicRequestStream::new(stream);
    let (_, receive) = stream.streams();
    let Some(body) = read_body(receive).await? else {
        stream.complete();
        return Ok(());
    };
    let (_, trailing_receive) = stream.streams();
    require_request_eof(trailing_receive).await?;
    #[cfg(debug_assertions)]
    test_barrier::checkpoint("gateway-request-admitted").await?;
    let (response_sender, receive_response) = oneshot::channel();
    request_sender
        .send(GatewayRequest { body, response: response_sender })
        .await
        .map_err(|_error| io::Error::other("gateway request dispatcher closed"))?;
    let routed_response = receive_response
        .await
        .map_err(|_error| io::Error::other("gateway response dispatcher closed"))?;
    let (send, _) = stream.streams();
    write_body(send, &routed_response.body).await?;
    send.shutdown().await?;
    if let Some(delivered) = routed_response.delivered {
        let _delivery_result = delivered.send(());
    }
    stream.complete();
    Ok(())
}

#[cfg(debug_assertions)]
fn certificate_manifest_response(body: &[u8], manifest: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let Ok(request) = decode_body(body) else {
        return Ok(None);
    };
    if request.version != VERSION || request.message_type != CERTIFICATE_MANIFEST {
        return Ok(None);
    }
    encode_body(&Envelope {
        correlation_id: request.correlation_id,
        message_type: CERTIFICATE_MANIFEST_RESPONSE,
        payload: manifest.to_vec(),
        version: VERSION,
    })
    .map(Some)
}

async fn wait_for_rotation(delay: Option<Duration>) {
    match delay {
        Some(delay) => tokio::time::sleep(delay).await,
        None => std::future::pending::<()>().await,
    }
}

async fn require_request_eof<R>(stream: &mut R) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut trailing = [0_u8; 1];
    let bytes_read =
        match tokio::time::timeout(STREAM_EOF_TIMEOUT, stream.read(&mut trailing)).await {
            Ok(result) => result?,
            Err(_elapsed) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "request stream did not finish after its frame",
                ));
            }
        };
    if bytes_read != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request stream contains trailing bytes",
        ));
    }
    Ok(())
}

async fn shutdown_session(mut session: SessionProcess) -> Result<(), Box<dyn Error + Send + Sync>> {
    // EOF gives sessiond its normal opportunity to finish. A connection-scoped
    // deadline prevents a wedged child from retaining gateway resources.
    drop(session.input);
    match tokio::time::timeout(Duration::from_secs(2), session.child.wait()).await {
        Ok(wait_result) => {
            let _exit_status = wait_result?;
        }
        Err(_elapsed) => {
            session.child.kill().await?;
        }
    }
    Ok(())
}

async fn spawn_session(
    executable: PathBuf,
    store_address: SocketAddr,
) -> Result<SessionProcess, Box<dyn Error + Send + Sync>> {
    let mut child = Command::new(executable)
        .args(["--store", &store_address.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let input =
        child.stdin.take().ok_or_else(|| io::Error::other("sessiond stdin was not piped"))?;
    let stdout =
        child.stdout.take().ok_or_else(|| io::Error::other("sessiond stdout was not piped"))?;
    let mut output = BufReader::new(stdout);
    let mut readiness = String::new();
    tokio::time::timeout(Duration::from_secs(10), output.read_line(&mut readiness)).await??;
    if readiness.trim_end() != "READY sessiond" {
        return Err(io::Error::other("sessiond emitted malformed readiness").into());
    }
    Ok(SessionProcess { child, input, output: Some(output) })
}
