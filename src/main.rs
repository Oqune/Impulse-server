use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const SERVER_ADDRESS: &str = "192.168.1.50:8080";
const SECRET_PASSWORD: &str = "your_secure_password_here";

// Типы сообщений для классификации
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum MessageType {
    Technical,
    Informational,
    Content,
    System,
}

// Унифицированная структура сообщения
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnifiedMessage {
    #[serde(rename = "type")]
    msg_type: MessageType,
    payload: serde_json::Value,
    timestamp: u64,
}

// Структуры для технических сообщений (аутентификация)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthRequest {
    name: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthResponse {
    #[serde(rename = "type")]
    msg_type: String,
    success: bool,
    message: String,
    client_id: u32,
}

// Структура для контентных сообщений от клиента
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientContentMessage {
    sender_name: String,
    content: String,
}

// Структура для контентных сообщений сервера
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerContentMessage {
    sender_id: u32,
    sender_name: String,
    message: String,
    #[serde(default)]
    encrypted: bool,
}

// Структуры для информационных сообщений
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InfoMessage {
    #[serde(rename = "type")]
    msg_type: String,
    event: String, // "joined" или "left"
    user_id: u32,
    user_name: String,
}

// Информация о клиенте
#[derive(Debug)]
struct ClientInfo {
    id: u32,
    name: String,
    sender: tokio::sync::mpsc::UnboundedSender<Message>,
    public_key: Option<String>,
    user_id: Option<String>,
}

type ClientsMap = Arc<Mutex<HashMap<u32, ClientInfo>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(SERVER_ADDRESS).await?;
    println!("WebSocket сервер запущен на {}", SERVER_ADDRESS);

    // Хешируем пароль при запуске сервера
    let hashed_password = hash(SECRET_PASSWORD, DEFAULT_COST)?;
    println!("Сервер готов принимать соединения с аутентификацией");

    let clients: ClientsMap = Arc::new(Mutex::new(HashMap::new()));
    let client_id_counter = Arc::new(Mutex::new(0u32));

    while let Ok((stream, addr)) = listener.accept().await {
        println!("Новое соединение с: {}", addr);

        let clients = clients.clone();
        let client_id_counter = client_id_counter.clone();
        let hashed_password = hashed_password.clone();

        tokio::spawn(async move {
            let client_id = {
                let mut counter = client_id_counter.lock().await;
                *counter += 1;
                *counter
            };

            if let Ok(ws_stream) = tokio_tungstenite::accept_async(stream).await {
                let (mut ws_tx, mut ws_rx) = ws_stream.split();
                println!("WebSocket соединение установлено для клиента {}", client_id);

                // Ожидаем сообщение аутентификации от клиента
                let auth_message = ws_rx.next().await;
                let mut client_name = "Клиент".to_string();
                let mut client_public_key = None;
                let mut client_user_id = None;
                let authenticated = match auth_message {
                    Some(Ok(Message::Text(text))) => {
                        // Пытаемся сначала распарсить как унифицированное сообщение
                        if let Ok(unified_msg) = serde_json::from_str::<UnifiedMessage>(&text) {
                            if unified_msg.msg_type == MessageType::Technical {
                                if let Ok(auth_req) = serde_json::from_value::<AuthRequest>(unified_msg.payload.clone()) {
                                    let password_verified = if let Some(pwd) = &auth_req.password {
                                        verify(pwd, &hashed_password).unwrap_or(false)
                                    } else {
                                        true
                                    };

                                    if password_verified {
                                        client_name = auth_req.name.clone();
                                        client_public_key = auth_req.public_key.clone();
                                    }

                                    password_verified
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        } else {
                            // Если не удалось распарсить как унифицированное, пробуем как простой AuthRequest
                            if let Ok(auth_req) = serde_json::from_str::<AuthRequest>(&text) {
                                let password_verified = if let Some(pwd) = &auth_req.password {
                                    verify(pwd, &hashed_password).unwrap_or(false)
                                } else {
                                    true
                                };

                                if password_verified {
                                    client_name = auth_req.name.clone();
                                    client_public_key = auth_req.public_key.clone();
                                }

                                password_verified
                            } else {
                                false
                            }
                        }
                    }
                    _ => false,
                };

                if !authenticated {
                    println!("Клиент {} не прошел аутентификацию", client_id);
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

                if let Ok(json_msg) = serde_json::to_string(&auth_response) {
                    if let Err(e) = ws_tx.send(Message::Text(json_msg.into())).await {
                        eprintln!("Ошибка отправки сигнала аутентификации клиенту {}: {}", client_id, e);
                        return;
                    }
                }

                println!("Клиент {} ({}) успешно аутентифицирован", client_id, client_name);

                // Создаем канал для отправки сообщений этому клиенту
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

                // Добавляем клиента в карту
                let client_info = ClientInfo {
                    id: client_id,
                    name: client_name.clone(),
                    sender: tx.clone(),
                    public_key: client_public_key.clone(),
                    user_id: client_user_id.clone(),
                };

                {
                    let mut clients_map = clients.lock().await;
                    clients_map.insert(client_id, client_info);
                    println!("Клиент {} добавлен. Всего клиентов: {}", client_id, clients_map.len());
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
                            eprintln!("Ошибка отправки клиенту {}: {}", client_id, e);
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
                                            if let Ok(client_content_msg) = serde_json::from_value::<ClientContentMessage>(unified_msg.payload.clone()) {
                                                println!("Получено сообщение от клиента {}: {}", client_content_msg.sender_name, client_content_msg.content);

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
                                            println!("Получено техническое сообщение от клиента {}", client_id);
                                        }
                                        MessageType::System => {
                                            // Обрабатываем системные сообщения
                                            println!("Получено системное сообщение от клиента {}", client_id);
                                        }
                                        MessageType::Informational => {
                                            // Обрабатываем информационные сообщения
                                            println!("Получено информационное сообщение от клиента {}", client_id);
                                        }
                                    }
                                } else {
                                    // Пытаемся распарсить как простое JSON сообщение
                                    if let Ok(value) = serde_json::from_str::<Value>(&text) {
                                        if let Some(msg_type) = value.get("type").and_then(|v| v.as_str()) {
                                            match msg_type {
                                                "content" => {
                                                    if let Some(payload) = value.get("payload") {
                                                        if let Ok(client_content_msg) = serde_json::from_value::<ClientContentMessage>(payload.clone()) {
                                                            println!("Получено сообщение от клиента {}: {}", client_content_msg.sender_name, client_content_msg.content);

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
                                                }
                                                "auth" | "authentication" => {
                                                    println!("Получено повторное сообщение аутентификации от клиента {}", client_id);
                                                }
                                                _ => {
                                                    eprintln!("Получено сообщение неизвестного типа '{}' от клиента {}: {}", msg_type, client_id, text);
                                                }
                                            }
                                        } else {
                                            eprintln!("Получено сообщение без типа от клиента {}: {}", client_id, text);
                                        }
                                    } else {
                                        eprintln!("Получено сообщение неизвестного формата от клиента {}: {}", client_id, text);
                                    }
                                }
                            }
                            Ok(Message::Close(_)) => {
                                println!("Клиент {} ({}) отключился", client_id, client_name_for_recv);
                                break;
                            }
                            Err(e) => {
                                eprintln!("Ошибка получения сообщения от клиента {} ({}): {}", client_id, client_name_for_recv, e);
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
                    println!("Клиент {} удален. Всего клиентов: {}", client_id, clients_map.len());
                }
            } else {
                eprintln!("Ошибка во время WebSocket handshake для клиента {}", client_id);
            }
        });
    }
    Ok(())
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
        if let Some(exclude) = exclude_id {
            if client_info.id == exclude {
                continue;
            }
        }

        // Пытаемся отправить сообщение
        if let Err(e) = client_info.sender.send(Message::Text(message.to_string().into())) {
            eprintln!("Ошибка отправки клиенту {}: {}", client_info.id, e);
        }
    }
}