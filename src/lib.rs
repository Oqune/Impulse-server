pub mod config;
pub mod config_api;
pub mod console;
pub mod ws_logging;

use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};

// Типы сообщений для классификации
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
    Technical,
    Informational,
    Content,
    System,
}

// Унифицированная структура сообщения
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedMessage {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub payload: serde_json::Value,
    pub timestamp: u64,
}

// Структуры для технических сообщений (аутентификация)
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

// Структура для контентных сообщений от клиента
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientContentMessage {
    pub sender_name: String,
    pub content: String,
}

// Структура для контентных сообщений сервера
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerContentMessage {
    pub sender_id: u32,
    pub sender_name: String,
    pub message: String,
    #[serde(default)]
    pub encrypted: bool,
}

// Структуры для информационных сообщений
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub event: String, // "joined" или "left"
    pub user_id: u32,
    pub user_name: String,
}

// Информация о клиенте
#[derive(Debug)]
pub struct ClientInfo {
    pub id: u32,
    pub sender: tokio::sync::mpsc::UnboundedSender<Message>,
}

type ClientsMap = Arc<Mutex<HashMap<u32, ClientInfo>>>;

/// Configuration for the WebSocket server
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub address: String,
    pub password: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0:8080".to_string(),  // Listen on all interfaces for external access
            password: "your_secure_password_here".to_string(),
        }
    }
}

/// WebSocket server instance that can be controlled externally
pub struct WsServer {
    config: ServerConfig,
    clients: ClientsMap,
    client_id_counter: Arc<Mutex<u32>>,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
}

impl WsServer {
    /// Create a new server with default configuration
    pub fn new() -> Self {
        Self::with_config(ServerConfig::default())
    }

    /// Create a new server with custom configuration
    pub fn with_config(config: ServerConfig) -> Self {
        Self {
            config,
            clients: Arc::new(Mutex::new(HashMap::new())),
            client_id_counter: Arc::new(Mutex::new(0u32)),
            shutdown_tx: None,
        }
    }

    /// Get the server address
    pub fn address(&self) -> &str {
        &self.config.address
    }

    /// Get the number of connected clients
    pub async fn client_count(&self) -> usize {
        self.clients.lock().await.len()
    }

    /// Get list of connected client IDs
    pub async fn connected_clients(&self) -> Vec<u32> {
        self.clients.lock().await.keys().cloned().collect()
    }

    /// Broadcast a message to all connected clients
    pub async fn broadcast(&self, message: &UnifiedMessage) {
        broadcast_message(&self.clients, message, None).await;
    }

    /// Send a message to a specific client
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

    /// Start the server and listen for connections
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.config.address).await?;
        crate::console::log(
            crate::console::LogLevel::Info,
            "SERVER",
            &format!("WebSocket server listening on {}", self.config.address),
        );

        // Хешируем пароль при запуске сервера
        let hashed_password = hash(&self.config.password, DEFAULT_COST)?;
        crate::console::log(
            crate::console::LogLevel::Info,
            "SERVER",
            "Authentication enabled, ready to accept connections",
        );

        let clients = self.clients.clone();
        let client_id_counter = self.client_id_counter.clone();

        // Create shutdown channel using watch for better control
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            println!("[WS]  New connection from: {}", addr);

                            let clients = clients.clone();
                            let client_id_counter = client_id_counter.clone();
                            let hashed_password = hashed_password.clone();

                            tokio::spawn(async move {
                                handle_client(stream, client_id_counter, clients, hashed_password).await;
                            });
                        }
                        Err(e) => {
                            eprintln!("[WS]  Error accepting connection: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        println!("[WS]  Shutdown signal received");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Shutdown the server gracefully
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

/// Handle a single client connection
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

    if let Ok(ws_stream) = tokio_tungstenite::accept_async(stream).await {
        let (mut ws_tx, mut ws_rx) = ws_stream.split();
        println!("[WS]  WebSocket connection established for client {}", client_id);

        // Ожидаем сообщение аутентификации от клиента
        let auth_message = ws_rx.next().await;
        let mut client_name = "Клиент".to_string();
        let authenticated = match auth_message {
            Some(Ok(Message::Text(text))) => {
                if let Ok(unified_msg) = serde_json::from_str::<UnifiedMessage>(&text) {
                    if unified_msg.msg_type == MessageType::Technical {
                        if let Ok(auth_req) = serde_json::from_value::<AuthRequest>(unified_msg.payload) {
                            let password_verified = if let Some(pwd) = &auth_req.password {
                                verify(pwd, &hashed_password).unwrap_or(false)
                            } else {
                                true
                            };

                            if password_verified {
                                client_name = auth_req.name.clone();
                            }

                            password_verified
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        };

        if !authenticated {
            println!("[WS]  Client {} failed authentication", client_id);
            let _ = ws_tx.send(Message::Close(None)).await;
            return;
        }

        // Отправляем ответ об успешной аутентификации
        let auth_response = AuthResponse {
            msg_type: "auth_response".to_string(),
            success: true,
            message: "Аутентификация успешна".to_string(),
            client_id,
        };

        if let Ok(json_msg) = serde_json::to_string(&auth_response)
            && ws_tx.send(Message::Text(json_msg.into())).await.is_err()
        {
            eprintln!("[WS]  Error sending auth response to client {}: connection closed", client_id);
            return;
        }

        println!("[WS]  Client {} ({}) authenticated successfully", client_id, client_name);

        // Создаем канал для отправки сообщений этому клиенту
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Добавляем клиента в карту
        let client_info = ClientInfo {
            id: client_id,
            sender: tx.clone(),
        };

        {
            let mut clients_map = clients.lock().await;
            clients_map.insert(client_id, client_info);
            println!("[WS]  Client {} added. Total clients: {}", client_id, clients_map.len());
        }

        // Отправляем информационное сообщение о новом клиенте
        let info_msg = InfoMessage {
            msg_type: "info".to_string(),
            event: "joined".to_string(),
            user_id: client_id,
            user_name: client_name.clone(),
        };

        if let Ok(json_msg) = serde_json::to_string(&info_msg) {
            broadcast_raw_message(&clients, &json_msg, Some(client_id)).await;
        }

        // Задача для отправки сообщений клиенту
        let send_task = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let Err(e) = ws_tx.send(message).await {
                    eprintln!("[WS]  Error sending to client {}: {}", client_id, e);
                    break;
                }
            }
        });

        // Задача для получения сообщений от клиента
        let clients_recv = clients.clone();
        let client_name_for_recv = client_name.clone();
        let recv_task = tokio::spawn(async move {
            while let Some(message) = ws_rx.next().await {
                match message {
                    Ok(Message::Text(text)) => {
                        // Пытаемся распарсить как унифицированное сообщение
                        if let Ok(unified_msg) = serde_json::from_str::<UnifiedMessage>(&text) {
                            match unified_msg.msg_type {
                                MessageType::Content => {
                                    // Обрабатываем контентные сообщения от клиента
                                    if let Ok(client_content_msg) = serde_json::from_value::<ClientContentMessage>(unified_msg.payload) {
                                        println!("[WS]  Message from client {}: {}", client_content_msg.sender_name, client_content_msg.content);

                                        // Создаем серверное контентное сообщение для рассылки
                                        let server_content_msg = ServerContentMessage {
                                            sender_id: client_id,
                                            sender_name: client_content_msg.sender_name.clone(),
                                            message: client_content_msg.content,
                                            encrypted: false,
                                        };

                                        let unified_server_msg = UnifiedMessage {
                                            msg_type: MessageType::Content,
                                            payload: serde_json::to_value(server_content_msg).unwrap(),
                                            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                                        };

                                        broadcast_message(&clients_recv, &unified_server_msg, Some(client_id)).await;
                                    }
                                }
                                MessageType::Technical => {
                                    // Обрабатываем технические сообщения
                                    println!("[WS]  Technical message from client {}", client_id);
                                }
                                MessageType::System => {
                                    // Обрабатываем системные сообщения
                                    println!("[WS]  System message from client {}", client_id);
                                }
                                MessageType::Informational => {
                                    // Обрабатываем информационные сообщения
                                    println!("[WS]  Informational message from client {}", client_id);
                                }
                            }
                        } else {
                            eprintln!("[WS]  Unknown message format from client {}: {}", client_id, text);
                        }
                    }
                    Ok(Message::Close(_)) => {
                        println!("[WS]  Client {} ({}) disconnected", client_id, client_name_for_recv);
                        break;
                    }
                    Err(e) => {
                        eprintln!("[WS]  Error receiving message from client {} ({}): {}", client_id, client_name_for_recv, e);
                        break;
                    }
                    _ => {}
                }
            }
        });

        // Ждем завершения одной из задач
        tokio::select! {
            _ = send_task => {},
            _ = recv_task => {},
        }

        // Отправляем информационное сообщение об отключении клиента
        let leave_info_msg = InfoMessage {
            msg_type: "informational".to_string(),
            event: "left".to_string(),
            user_id: client_id,
            user_name: client_name.clone(),
        };

        if let Ok(json_msg) = serde_json::to_string(&leave_info_msg) {
            broadcast_raw_message(&clients, &json_msg, Some(client_id)).await;
        }

        // Удаляем клиента из карты при отключении
        {
            let mut clients_map = clients.lock().await;
            clients_map.remove(&client_id);
            println!("[WS]  Client {} removed. Total clients: {}", client_id, clients_map.len());
        }
    } else {
        eprintln!("[WS]  WebSocket handshake error for client {}", client_id);
    }
}

// Функция для широковещательной рассылки унифицированных сообщений
async fn broadcast_message(clients: &ClientsMap, message: &UnifiedMessage, exclude_id: Option<u32>) {
    if let Ok(json_msg) = serde_json::to_string(message) {
        broadcast_raw_message(clients, &json_msg, exclude_id).await;
    }
}

// Базовая функция для широковещательной рассылки
async fn broadcast_raw_message(clients: &ClientsMap, message: &str, exclude_id: Option<u32>) {
    let clients_map = clients.lock().await;
    for (_, client_info) in clients_map.iter() {
        // Пропускаем клиента, если он в списке исключений
        if let Some(exclude) = exclude_id && client_info.id == exclude {
            continue;
        }

        // Пытаемся отправить сообщение
        if let Err(e) = client_info.sender.send(Message::Text(message.to_string().into())) {
            eprintln!("[WS]  Error sending to client {}: {}", client_info.id, e);
        }
    }
}
