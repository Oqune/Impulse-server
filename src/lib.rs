pub mod config;
pub mod console;

use bcrypt::{DEFAULT_COST, hash, verify};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::tungstenite::Message;

const MAX_CLIENTS: usize = 100;
const MAX_MSG_SIZE: usize = 4096;
const CHANNEL_CAP: usize = 16;
const MAX_NAME_LEN: usize = 32;
const HEARTBEAT_INTERVAL_SECS: u64 = 30;
const CLIENT_TIMEOUT_SECS: u64 = 60;

fn log_debug(component: &str, msg: &str) {
    crate::console::log(crate::console::LogLevel::Debug, component, msg);
}

fn log_info(component: &str, msg: &str) {
    crate::console::log(crate::console::LogLevel::Info, component, msg);
}

fn log_warn(component: &str, msg: &str) {
    crate::console::log(crate::console::LogLevel::Warning, component, msg);
}

fn log_error(component: &str, msg: &str) {
    crate::console::log(crate::console::LogLevel::Error, component, msg);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u8,
    pub timestamp: u64,
    #[serde(flatten)]
    pub body: MessageBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum MessageBody {
    Auth(AuthRequest),
    AuthResult(AuthResult),
    Chat(ChatMessage),
    Event(EventMessage),
    Error(ErrorMessage),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub name: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub success: bool,
    pub client_id: u32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMessage {
    #[serde(rename = "event")]
    pub kind: EventKind,
    pub user_id: u32,
    pub user_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Joined,
    Left,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMessage {
    pub code: u16,
    pub message: String,
}

#[derive(Debug)]
pub struct ClientInfo {
    pub id: u32,
    pub name: String,
    pub sender: tokio::sync::mpsc::Sender<Message>,
    pub last_seen: Arc<Mutex<std::time::Instant>>,
}

type ClientsMap = Arc<Mutex<HashMap<u32, ClientInfo>>>;

/// Allocates client IDs from a free-list, reusing IDs of disconnected clients.
struct ClientIdPool {
    next: u32,
    free: VecDeque<u32>,
}

impl ClientIdPool {
    fn new() -> Self {
        Self {
            next: 1,
            free: VecDeque::new(),
        }
    }

    fn acquire(&mut self) -> Option<u32> {
        if let Some(id) = self.free.pop_front() {
            return Some(id);
        }
        if self.next == u32::MAX {
            return None;
        }
        let id = self.next;
        self.next += 1;
        Some(id)
    }

    fn release(&mut self, id: u32) {
        self.free.push_back(id);
    }
}

pub struct WsServer {
    config: config::ServerSettings,
    clients: ClientsMap,
    id_pool: Arc<Mutex<ClientIdPool>>,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    tls_acceptor: TlsAcceptor,
}

impl WsServer {
    pub fn new() -> Self {
        Self::with_config(config::ServerSettings::default())
    }

    pub fn with_config(config: config::ServerSettings) -> Self {
        let tls_acceptor = load_tls_acceptor(&config).unwrap_or_else(|e| {
            log_error("SERVER", &format!("Failed to load TLS certificate: {}", e));
            std::process::exit(1);
        });

        Self {
            config,
            clients: Arc::new(Mutex::new(HashMap::new())),
            id_pool: Arc::new(Mutex::new(ClientIdPool::new())),
            shutdown_tx: None,
            tls_acceptor,
        }
    }

    pub fn address(&self) -> &str {
        &self.config.address
    }

    pub async fn client_count(&self) -> usize {
        self.clients.lock().await.len()
    }

    pub async fn connected_clients(&self) -> Vec<u32> {
        self.clients.lock().await.keys().cloned().collect()
    }

    pub async fn broadcast(&self, message: &Envelope) {
        broadcast_message(&self.clients, message, None).await;
    }

    pub async fn send_to_client(&self, client_id: u32, message: &Envelope) -> Result<(), String> {
        let clients_map = self.clients.lock().await;
        if let Some(client_info) = clients_map.get(&client_id) {
            if let Ok(json_msg) = serde_json::to_string(message) {
                if let Err(e) = client_info
                    .sender
                    .send(Message::Text(json_msg.into()))
                    .await
                {
                    return Err(format!("Failed to send to client {}: {}", client_id, e));
                }
                Ok(())
            } else {
                Err(format!(
                    "Failed to serialize message for client {}",
                    client_id
                ))
            }
        } else {
            Err(format!("Client {} not found", client_id))
        }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.config.address).await?;
        log_info(
            "SERVER",
            &format!(
                "Secure WebSocket (WSS) listening on {}",
                self.config.address
            ),
        );

        let hashed_password = hash(&self.config.password, DEFAULT_COST)?;
        log_info("SERVER", "Authentication enabled");

        let clients = self.clients.clone();
        let id_pool = self.id_pool.clone();
        let auth_message = self.config.auth_message.clone();
        let acceptor = self.tls_acceptor.clone();

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, addr)) => {
                            log_debug("SERVER", &format!("New secure connection from {}", addr));
                            let acceptor = acceptor.clone();
                            let clients = clients.clone();
                            let id_pool = id_pool.clone();
                            let hashed_password = hashed_password.clone();
                            let auth_message = auth_message.clone();

                            tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        handle_client(tls_stream, addr, id_pool, clients, hashed_password, auth_message).await;
                                    }
                                    Err(e) => {
                                        log_error("WS", &format!("TLS handshake error from {}: {}", addr, e));
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            log_error("SERVER", &format!("Accept error: {}", e));
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        log_info("SERVER", "Shutdown signal received");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
    }
}

impl Default for WsServer {
    fn default() -> Self {
        Self::new()
    }
}

fn sanitize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len().min(MAX_NAME_LEN));
    for c in name.chars() {
        if c.is_control() || c == '"' || c == '\\' {
            continue;
        }
        if out.len() >= MAX_NAME_LEN {
            break;
        }
        out.push(c);
    }
    if out.is_empty() {
        "Anonymous".to_string()
    } else {
        out
    }
}

fn make_envelope(body: MessageBody) -> Envelope {
    Envelope {
        version: 1,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        body,
    }
}

async fn send_error(ws_tx: &mut (impl SinkExt<Message> + Unpin), code: u16, message: &str) {
    let env = make_envelope(MessageBody::Error(ErrorMessage {
        code,
        message: message.to_string(),
    }));
    if let Ok(json) = serde_json::to_string(&env) {
        let _ = ws_tx.send(Message::Text(json.into())).await;
    }
}

async fn handle_client(
    stream: TlsStream<TcpStream>,
    peer_addr: std::net::SocketAddr,
    id_pool: Arc<Mutex<ClientIdPool>>,
    clients: ClientsMap,
    hashed_password: String,
    auth_success_message: String,
) {
    let client_id = {
        let mut pool = id_pool.lock().await;
        match pool.acquire() {
            Some(id) => id,
            None => {
                log_warn("WS", "Client ID pool exhausted");
                return;
            }
        }
    };

    log_debug(
        "WS",
        &format!("Client {} connecting from {:?}", client_id, peer_addr),
    );

    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(s) => s,
        Err(e) => {
            log_error(
                "WS",
                &format!("Handshake error for client {}: {}", client_id, e),
            );
            id_pool.lock().await.release(client_id);
            return;
        }
    };

    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    let auth_message = match ws_rx.next().await {
        Some(Ok(Message::Text(text))) => {
            log_debug(
                "WS",
                &format!("Client {} auth payload: {}", client_id, text),
            );
            text
        }
        Some(Ok(Message::Binary(_))) => {
            log_warn(
                "WS",
                &format!("Client {} sent binary instead of auth text", client_id),
            );
            let _ = ws_tx.send(Message::Close(None)).await;
            id_pool.lock().await.release(client_id);
            return;
        }
        Some(Ok(Message::Close(_))) | None => {
            log_debug(
                "WS",
                &format!("Client {} disconnected before auth", client_id),
            );
            id_pool.lock().await.release(client_id);
            return;
        }
        Some(Err(e)) => {
            log_error(
                "WS",
                &format!("Client {} receive error during auth: {}", client_id, e),
            );
            id_pool.lock().await.release(client_id);
            return;
        }
        _ => {
            log_warn(
                "WS",
                &format!("Client {} unexpected message type during auth", client_id),
            );
            let _ = ws_tx.send(Message::Close(None)).await;
            id_pool.lock().await.release(client_id);
            return;
        }
    };

    let mut client_name = "Anonymous".to_string();
    let authenticated = match serde_json::from_str::<Envelope>(&auth_message) {
        Ok(env) if env.version == 1 => match env.body {
            MessageBody::Auth(req) => {
                log_debug(
                    "WS",
                    &format!("Client {} auth attempt: name={}", client_id, req.name),
                );
                match verify(&req.password, &hashed_password) {
                    Ok(valid) => {
                        if valid {
                            client_name = sanitize_name(&req.name);
                        }
                        log_info(
                            "WS",
                            &format!(
                                "Client {} auth result: {} (name={})",
                                client_id,
                                if valid { "success" } else { "failed" },
                                client_name
                            ),
                        );
                        valid
                    }
                    Err(e) => {
                        log_error(
                            "WS",
                            &format!("Client {} bcrypt verify error: {}", client_id, e),
                        );
                        false
                    }
                }
            }
            _ => {
                log_warn(
                    "WS",
                    &format!("Client {} invalid auth message type", client_id),
                );
                false
            }
        },
        Ok(_) => {
            log_warn("WS", &format!("Client {} bad protocol version", client_id));
            false
        }
        Err(e) => {
            log_warn(
                "WS",
                &format!("Client {} invalid JSON in auth: {}", client_id, e),
            );
            false
        }
    };

    if !authenticated {
        let _ = ws_tx.send(Message::Close(None)).await;
        id_pool.lock().await.release(client_id);
        return;
    }

    let auth_response = make_envelope(MessageBody::AuthResult(AuthResult {
        success: true,
        client_id,
        message: auth_success_message,
    }));

    if let Ok(json_msg) = serde_json::to_string(&auth_response) {
        let _ = ws_tx.send(Message::Text(json_msg.into())).await;
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel(CHANNEL_CAP);
    let last_seen = Arc::new(Mutex::new(std::time::Instant::now()));

    {
        let mut clients_map = clients.lock().await;
        let current_count = clients_map.len();
        if current_count >= MAX_CLIENTS {
            drop(clients_map);
            send_error(&mut ws_tx, 429, "Server full").await;
            log_warn(
                "WS",
                &format!(
                    "Rejected client {}: server full ({}/{})",
                    client_id, current_count, MAX_CLIENTS
                ),
            );
            id_pool.lock().await.release(client_id);
            return;
        }
        clients_map.insert(
            client_id,
            ClientInfo {
                id: client_id,
                name: client_name.clone(),
                sender: tx,
                last_seen: last_seen.clone(),
            },
        );
        log_info(
            "WS",
            &format!(
                "Client {} ({}) connected [total: {}]",
                client_id,
                client_name,
                clients_map.len()
            ),
        );
    }

    let event = make_envelope(MessageBody::Event(EventMessage {
        kind: EventKind::Joined,
        user_id: client_id,
        user_name: client_name.clone(),
    }));
    if let Ok(json_msg) = serde_json::to_string(&event) {
        broadcast_raw_message(&clients, &json_msg, Some(client_id)).await;
    }

    let mut heartbeat =
        tokio::time::interval(std::time::Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
    let mut last_pong = std::time::Instant::now();

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(message) => {
                        if let Err(e) = ws_tx.send(message).await {
                            log_error("WS", &format!("Send error for client {}: {}", client_id, e));
                            break;
                        }
                    }
                    None => {
                        log_debug("WS", &format!("Client {} rx channel closed", client_id));
                        break;
                    }
                }
            }
            _ = heartbeat.tick() => {
                if last_pong.elapsed() > std::time::Duration::from_secs(CLIENT_TIMEOUT_SECS) {
                    log_warn("WS", &format!("Client {} timed out (no pong)", client_id));
                    let _ = ws_tx.send(Message::Close(None)).await;
                    break;
                }
                let _ = ws_tx.send(Message::Ping(Vec::new().into())).await;
            }
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        *last_seen.lock().await = std::time::Instant::now();
                        log_debug("WS", &format!("Client {} recv: {}", client_id, text));
                        if text.len() > MAX_MSG_SIZE {
                            log_warn("WS", &format!("Message too large from client {}: {} bytes", client_id, text.len()));
                            continue;
                        }
                        match serde_json::from_str::<Envelope>(&text) {
                            Ok(env) if env.version == 1 => match env.body {
                                MessageBody::Chat(chat) => {
                                    log_debug("WS", &format!("Client {} chat: {} bytes", client_id, chat.content.len()));
                                    let clients_map = clients.lock().await;
                                    let sender_name = clients_map.get(&client_id)
                                        .map(|c| c.name.clone())
                                        .unwrap_or_else(|| "Unknown".to_string());
                                    drop(clients_map);
                                    let server_msg = make_envelope(MessageBody::Chat(ChatMessage {
                                        content: chat.content,
                                        sender_id: Some(client_id),
                                        sender_name: Some(sender_name),
                                    }));
                                    broadcast_message(&clients, &server_msg, Some(client_id)).await;
                                }
                                MessageBody::Error(err) => {
                                    log_warn("WS", &format!("Client {} sent error: code={} msg={}", client_id, err.code, err.message));
                                }
                                MessageBody::Auth(_) => {
                                    log_warn("WS", &format!("Client {} sent duplicate auth", client_id));
                                }
                                MessageBody::Event(_) => {
                                    log_warn("WS", &format!("Client {} sent event (not allowed)", client_id));
                                }
                                MessageBody::AuthResult(_) => {
                                    log_warn("WS", &format!("Client {} sent auth_result (not allowed)", client_id));
                                }
                            },
                            Ok(_) => {
                                log_warn("WS", &format!("Bad protocol version from client {}", client_id));
                            }
                            Err(e) => {
                                log_warn("WS", &format!("Bad JSON from client {}: {}", client_id, e));
                            }
                        }
                    }
                    Some(Ok(Message::Close(reason))) => {
                        log_info("WS", &format!("Client {} close frame: {:?}", client_id, reason));
                        break;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        log_debug("WS", &format!("Client {} ping: {} bytes", client_id, data.len()));
                        let _ = ws_tx.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {
                        log_debug("WS", &format!("Client {} pong", client_id));
                        last_pong = std::time::Instant::now();
                    }
                    Some(Ok(Message::Binary(data))) => {
                        log_debug("WS", &format!("Client {} binary: {} bytes", client_id, data.len()));
                    }
                    Some(Ok(Message::Frame(_))) => {}
                    Some(Err(e)) => {
                        log_error("WS", &format!("Receive error for client {}: {}", client_id, e));
                        break;
                    }
                    None => {
                        log_debug("WS", &format!("Client {} stream ended", client_id));
                        break;
                    }
                }
            }
        }
    }

    log_info(
        "WS",
        &format!("Client {} ({}) disconnecting", client_id, client_name),
    );

    let leave = make_envelope(MessageBody::Event(EventMessage {
        kind: EventKind::Left,
        user_id: client_id,
        user_name: client_name.clone(),
    }));
    if let Ok(json_msg) = serde_json::to_string(&leave) {
        broadcast_raw_message(&clients, &json_msg, Some(client_id)).await;
    }

    {
        let mut clients_map = clients.lock().await;
        clients_map.remove(&client_id);
        log_info(
            "WS",
            &format!(
                "Client {} ({}) disconnected [remaining: {}]",
                client_id,
                client_name,
                clients_map.len()
            ),
        );
    }

    id_pool.lock().await.release(client_id);
}

fn load_tls_acceptor(
    config: &config::ServerSettings,
) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    if config.tls_cert.is_empty() || config.tls_key.is_empty() {
        return Err(
            "TLS certificate/key not provided. Start the server with --tls-cert <path> and --tls-key <path> \
             (e.g. --tls-cert cert.pem --tls-key key.pem)"
                .into(),
        );
    }

    let cert_path = &config.tls_cert;
    let key_path = &config.tls_key;

    if !std::path::Path::new(cert_path).exists() || !std::path::Path::new(key_path).exists() {
        log_warn(
            "SERVER",
            "TLS certificate or key not found, generating a self-signed certificate",
        );
        generate_self_signed_cert(cert_path, key_path, &config.tls_san)?;
    }

    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| format!("Failed to open cert {}: {}", cert_path, e))?;
    let key_file = std::fs::File::open(key_path)
        .map_err(|e| format!("Failed to open key {}: {}", key_path, e))?;

    let mut reader = std::io::BufReader::new(cert_file);
    let certs: Vec<rustls::pki_types::CertificateDer> =
        rustls_pemfile::certs(&mut reader).collect::<Result<_, _>>()?;

    let mut reader = std::io::BufReader::new(key_file);
    let key =
        rustls_pemfile::private_key(&mut reader)?.ok_or("No private key found in TLS key file")?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Generate a self-signed certificate/key pair (PEM) and write it to disk.
/// Used as a fallback when no certificate is provided, so the server can start
/// out of the box. The certificate is valid for `localhost`, the machine
/// hostname, and any extra SANs supplied via `--tls-san` (e.g. a public IP).
fn generate_self_signed_cert(
    cert_path: &str,
    key_path: &str,
    extra_sans: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    use rcgen::{CertificateParams, Ia5String, KeyPair, SanType};

    let mut sans: Vec<SanType> = Vec::new();
    sans.push(SanType::DnsName(Ia5String::try_from(
        "localhost".to_string(),
    )?));
    sans.push(SanType::IpAddress("127.0.0.1".parse()?));
    if let Ok(hostname) = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME"))
        && !hostname.is_empty()
        && let Ok(ia5) = Ia5String::try_from(hostname)
    {
        sans.push(SanType::DnsName(ia5));
    }
    for iface in if_addrs::get_if_addrs().into_iter().flatten() {
        sans.push(SanType::IpAddress(iface.ip()));
    }
    for san in extra_sans {
        if let Ok(ip) = san.parse::<std::net::IpAddr>() {
            sans.push(SanType::IpAddress(ip));
        } else if let Ok(ia5) = Ia5String::try_from(san.clone()) {
            sans.push(SanType::DnsName(ia5));
        }
    }

    let mut params = CertificateParams::new(vec!["localhost".to_string()])?;
    params.subject_alt_names = sans;

    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;

    let pem_cert = cert.pem();
    let pem_key = key.serialize_pem();

    if let Some(parent) = std::path::Path::new(cert_path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(cert_path, pem_cert)
        .map_err(|e| format!("Failed to write cert {}: {}", cert_path, e))?;
    std::fs::write(key_path, pem_key)
        .map_err(|e| format!("Failed to write key {}: {}", key_path, e))?;

    log_info(
        "SERVER",
        &format!(
            "Self-signed certificate written to {} and {}",
            cert_path, key_path
        ),
    );
    Ok(())
}

async fn broadcast_message(clients: &ClientsMap, message: &Envelope, exclude_id: Option<u32>) {
    if let Ok(json_msg) = serde_json::to_string(message) {
        broadcast_raw_message(clients, &json_msg, exclude_id).await;
    }
}

async fn broadcast_raw_message(clients: &ClientsMap, message: &str, exclude_id: Option<u32>) {
    let mut clients_map = clients.lock().await;
    let mut dead: Vec<u32> = Vec::new();
    for (id, client_info) in clients_map.iter() {
        if exclude_id == Some(*id) {
            continue;
        }
        if client_info
            .sender
            .send(Message::Text(message.to_string().into()))
            .await
            .is_err()
        {
            dead.push(*id);
        }
    }
    for id in dead {
        log_warn("WS", &format!("Removing dead client {}", id));
        clients_map.remove(&id);
    }
}
