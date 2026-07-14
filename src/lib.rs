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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
    Technical,
    Informational,
    Content,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedMessage {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub payload: serde_json::Value,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub name: String,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub success: bool,
    pub message: String,
    pub client_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientContentMessage {
    pub sender_name: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerContentMessage {
    pub sender_id: u32,
    pub sender_name: String,
    pub message: String,
    #[serde(default)]
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub event: String,
    pub user_id: u32,
    pub user_name: String,
}

#[derive(Debug)]
pub struct ClientInfo {
    pub id: u32,
    pub sender: tokio::sync::mpsc::UnboundedSender<Message>,
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
            address: "0.0.0.0:8080".to_string(),
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

    pub async fn broadcast(&self, message: &UnifiedMessage) {
        broadcast_message(&self.clients, message, None).await;
    }

    pub async fn send_to_client(&self, client_id: u32, message: &UnifiedMessage) -> Result<(), String> {
        let clients_map = self.clients.lock().await;
        if let Some(client_info) = clients_map.get(&client_id) {
            if let Ok(json_msg) = serde_json::to_string(message) {
                if let Err(e) = client_info.sender.send(Message::Text(json_msg.into())) {
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

async fn handle_client(
    stream: tokio::net::TcpStream,
    client_id_counter: Arc<Mutex<u32>>,
    clients: ClientsMap,
    hashed_password: String,
) {
    let client_id = {
        let mut counter = client_id_counter.lock().await;
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
            crate::console::log(crate::console::LogLevel::Error, "WS", &format!("Auth failed: no message, client {}", client_id));
            let _ = ws_tx.send(Message::Close(None)).await;
            return;
        }
    };

    let mut client_name = "Клиент".to_string();
    let authenticated = match serde_json::from_str::<UnifiedMessage>(&auth_message) {
        Ok(unified_msg) if unified_msg.msg_type == MessageType::Technical => {
            match serde_json::from_value::<AuthRequest>(unified_msg.payload) {
                Ok(auth_req) => {
                    let password_verified = auth_req.password.as_deref().map_or(true, |pwd| verify(pwd, &hashed_password).unwrap_or(false));
                    if password_verified {
                        client_name = auth_req.name;
                    }
                    password_verified
                }
                Err(_) => false,
            }
        }
        _ => false,
    };

    if !authenticated {
        let _ = ws_tx.send(Message::Close(None)).await;
        crate::console::log(crate::console::LogLevel::Error, "WS", &format!("Auth failed: client {}", client_id));
        return;
    }

    let auth_response = AuthResponse {
        msg_type: "auth_response".to_string(),
        success: true,
        message: "Аутентификация успешна".to_string(),
        client_id,
    };

    if let Ok(json_msg) = serde_json::to_string(&auth_response) {
        let _ = ws_tx.send(Message::Text(json_msg.into())).await;
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    {
        let mut clients_map = clients.lock().await;
        clients_map.insert(client_id, ClientInfo { id: client_id, sender: tx });
        crate::console::log(crate::console::LogLevel::Info, "WS", &format!("Client {} ({}) connected", client_id, client_name));
    }

    let info_msg = InfoMessage {
        msg_type: "info".to_string(),
        event: "joined".to_string(),
        user_id: client_id,
        user_name: client_name.clone(),
    };

    if let Ok(json_msg) = serde_json::to_string(&info_msg) {
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
                        match serde_json::from_str::<UnifiedMessage>(&text) {
                            Ok(unified_msg) if unified_msg.msg_type == MessageType::Content => {
                                if let Ok(cm) = serde_json::from_value::<ClientContentMessage>(unified_msg.payload) {
                                    let server_msg = ServerContentMessage {
                                        sender_id: client_id,
                                        sender_name: cm.sender_name.clone(),
                                        message: cm.content,
                                        encrypted: false,
                                    };
                                    let unified = UnifiedMessage {
                                        msg_type: MessageType::Content,
                                        payload: serde_json::to_value(server_msg).unwrap(),
                                        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                                    };
                                    broadcast_message(&clients, &unified, Some(client_id)).await;
                                }
                            }
                            _ => {}
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

    let leave_msg = InfoMessage {
        msg_type: "informational".to_string(),
        event: "left".to_string(),
        user_id: client_id,
        user_name: client_name.clone(),
    };

    if let Ok(json_msg) = serde_json::to_string(&leave_msg) {
        broadcast_raw_message(&clients, &json_msg, Some(client_id)).await;
    }

    {
        let mut clients_map = clients.lock().await;
        clients_map.remove(&client_id);
        crate::console::log(crate::console::LogLevel::Info, "WS", &format!("Client {} ({}) disconnected", client_id, client_name));
    }
}

async fn broadcast_message(clients: &ClientsMap, message: &UnifiedMessage, exclude_id: Option<u32>) {
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
        let _ = client_info.sender.send(Message::Text(message.to_string().into()));
    }
}
