pub mod config;
pub mod console;

use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};

const MAX_CLIENTS: usize = 100;
const MAX_MSG_SIZE: usize = 4096;
const CHANNEL_CAP: usize = 16;
const MAX_NAME_LEN: usize = 32;

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
    pub sender: tokio::sync::mpsc::Sender<Message>,
}

type ClientsMap = Arc<Mutex<HashMap<u32, ClientInfo>>>;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub address: String,
    pub password: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0:8087".to_string(),
            password: "your_secure_password_here".to_string(),
        }
    }
}

pub struct WsServer {
    config: ServerConfig,
    clients: ClientsMap,
    client_id_counter: Arc<Mutex<u32>>,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
}

impl WsServer {
    pub fn new() -> Self {
        Self::with_config(ServerConfig::default())
    }

    pub fn with_config(config: ServerConfig) -> Self {
        Self {
            config,
            clients: Arc::new(Mutex::new(HashMap::new())),
            client_id_counter: Arc::new(Mutex::new(0u32)),
            shutdown_tx: None,
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
                if let Err(e) = client_info.sender.send(Message::Text(json_msg.into())).await {
                    return Err(format!("Failed to send to client {}: {}", client_id, e));
                }
                Ok(())
            } else {
                Err(format!("Failed to serialize message for client {}", client_id))
            }
        } else {
            Err(format!("Client {} not found", client_id))
        }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.config.address).await?;
        crate::console::log(
            crate::console::LogLevel::Info,
            "SERVER",
            &format!("WebSocket server listening on {}", self.config.address),
        );

        let hashed_password = hash(&self.config.password, DEFAULT_COST)?;
        crate::console::log(
            crate::console::LogLevel::Info,
            "SERVER",
            "Authentication enabled",
        );

        let clients = self.clients.clone();
        let client_id_counter = self.client_id_counter.clone();

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _addr)) => {
                            let clients = clients.clone();
                            let client_id_counter = client_id_counter.clone();
                            let hashed_password = hashed_password.clone();

                            tokio::spawn(async move {
                                handle_client(stream, client_id_counter, clients, hashed_password).await;
                            });
                        }
                        Err(e) => {
                            crate::console::log(crate::console::LogLevel::Error, "SERVER", &format!("Accept error: {}", e));
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        crate::console::log(crate::console::LogLevel::Info, "SERVER", "Shutdown signal received");
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
        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
        body,
    }
}

async fn send_error(ws_tx: &mut (impl SinkExt<Message> + Unpin), code: u16, message: &str) {
    let env = make_envelope(MessageBody::Error(ErrorMessage { code, message: message.to_string() }));
    if let Ok(json) = serde_json::to_string(&env) {
        let _ = ws_tx.send(Message::Text(json.into())).await;
    }
}

async fn handle_client(
    stream: tokio::net::TcpStream,
    client_id_counter: Arc<Mutex<u32>>,
    clients: ClientsMap,
    hashed_password: String,
) {
    let client_id = {
        let mut counter = client_id_counter.lock().await;
        if *counter >= u32::MAX - 1 {
            return;
        }
        *counter += 1;
        *counter
    };

    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(s) => s,
        Err(_) => {
            crate::console::log(crate::console::LogLevel::Error, "WS", &format!("Handshake error: client {}", client_id));
            return;
        }
    };

    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    let auth_message = match ws_rx.next().await {
        Some(Ok(Message::Text(text))) => text,
        _ => {
            let _ = ws_tx.send(Message::Close(None)).await;
            return;
        }
    };

    let mut client_name = "Anonymous".to_string();
    let authenticated = match serde_json::from_str::<Envelope>(&auth_message) {
        Ok(env) if env.version == 1 => match env.body {
            MessageBody::Auth(req) => {
                match verify(&req.password, &hashed_password) {
                    Ok(valid) => {
                        if valid {
                            client_name = sanitize_name(&req.name);
                        }
                        valid
                    }
                    Err(_) => false,
                }
            }
            _ => false,
        }
        _ => false,
    };

    if !authenticated {
        let _ = ws_tx.send(Message::Close(None)).await;
        crate::console::log(crate::console::LogLevel::Warning, "WS", &format!("Auth failed: client {}", client_id));
        return;
    }

    let auth_response = make_envelope(MessageBody::AuthResult(AuthResult {
        success: true,
        client_id,
        message: "Аутентификация успешна".to_string(),
    }));

    if let Ok(json_msg) = serde_json::to_string(&auth_response) {
        let _ = ws_tx.send(Message::Text(json_msg.into())).await;
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel(CHANNEL_CAP);

    {
        let mut clients_map = clients.lock().await;
        if clients_map.len() >= MAX_CLIENTS {
            drop(clients_map);
            send_error(&mut ws_tx, 429, "Server full").await;
            crate::console::log(crate::console::LogLevel::Warning, "WS", &format!("Rejected: server full, client {}", client_id));
            return;
        }
        clients_map.insert(client_id, ClientInfo { id: client_id, sender: tx });
        crate::console::log(crate::console::LogLevel::Info, "WS", &format!("Client {} ({}) connected", client_id, client_name));
    }

    let event = make_envelope(MessageBody::Event(EventMessage {
        kind: EventKind::Joined,
        user_id: client_id,
        user_name: client_name.clone(),
    }));
    if let Ok(json_msg) = serde_json::to_string(&event) {
        broadcast_raw_message(&clients, &json_msg, Some(client_id)).await;
    }

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(message) => {
                        if let Err(e) = ws_tx.send(message).await {
                            crate::console::log(crate::console::LogLevel::Error, "WS", &format!("Send error: client {}, {}", client_id, e));
                            break;
                        }
                    }
                    None => break,
                }
            }
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if text.len() > MAX_MSG_SIZE {
                            crate::console::log(crate::console::LogLevel::Warning, "WS", &format!("Message too large: client {}", client_id));
                            continue;
                        }
                        match serde_json::from_str::<Envelope>(&text) {
                            Ok(env) if env.version == 1 => match env.body {
                                MessageBody::Chat(chat) => {
                                    let server_msg = make_envelope(MessageBody::Chat(ChatMessage {
                                        content: chat.content,
                                    }));
                                    broadcast_message(&clients, &server_msg, Some(client_id)).await;
                                }
                                MessageBody::Error(_) => {}
                                _ => {}
                            },
                            Ok(_) => {
                                crate::console::log(crate::console::LogLevel::Warning, "WS", &format!("Bad protocol version: client {}", client_id));
                            }
                            Err(_) => {
                                crate::console::log(crate::console::LogLevel::Warning, "WS", &format!("Bad JSON: client {}", client_id));
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        crate::console::log(crate::console::LogLevel::Error, "WS", &format!("Receive error: client {}, {}", client_id, e));
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

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
        crate::console::log(crate::console::LogLevel::Info, "WS", &format!("Client {} ({}) disconnected", client_id, client_name));
    }
}

async fn broadcast_message(clients: &ClientsMap, message: &Envelope, exclude_id: Option<u32>) {
    if let Ok(json_msg) = serde_json::to_string(message) {
        broadcast_raw_message(clients, &json_msg, exclude_id).await;
    }
}

async fn broadcast_raw_message(clients: &ClientsMap, message: &str, exclude_id: Option<u32>) {
    let clients_map = clients.lock().await;
    for (_, client_info) in clients_map.iter() {
        if let Some(exclude) = exclude_id && client_info.id == exclude {
            continue;
        }
        let _ = client_info.sender.send(Message::Text(message.to_string().into())).await;
    }
}
