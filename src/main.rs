use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};

const SERVER_ADDRESS: &str = "192.168.1.50:8080";
const SECRET_PASSWORD: &str = "your_secure_password_here";

// Типы сообщений
#[derive(Debug, Clone, Serialize, Deserialize)]
enum MessageType {
    Auth,
    System,
    Content,
}

// Структура сообщения
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    msg_type: MessageType,
    sender_id: usize,
    sender_name: String,
    content: String,
}

// Структура для аутентификации
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthData {
    password: String,
    name: Option<String>,
}

// Информация о клиенте
#[derive(Debug)]
struct ClientInfo {
    id: usize,
    name: String,
    sender: tokio::sync::mpsc::UnboundedSender<Message>,
}

// Типы для хранения состояния
type ClientsMap = Arc<Mutex<HashMap<usize, ClientInfo>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(SERVER_ADDRESS).await?;
    println!("WebSocket сервер запущен на {}", SERVER_ADDRESS);

    // Хешируем пароль при запуске сервера
    let hashed_password = hash(SECRET_PASSWORD, DEFAULT_COST)?;
    println!("Сервер готов принимать соединения с аутентификацией");

    let clients: ClientsMap = Arc::new(Mutex::new(HashMap::new()));
    let client_id_counter = Arc::new(Mutex::new(0usize));

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

                // Ожидаем сообщение с паролем и именем от клиента
                let auth_message = ws_rx.next().await;
                let mut client_name = "Клиент".to_string();
                let authenticated = match auth_message {
                    Some(Ok(Message::Text(text))) => {
                        // Парсим JSON с аутентификацией
                        if let Ok(auth_data) = serde_json::from_str::<AuthData>(&text) {
                            let verified = verify(&auth_data.password, &hashed_password).unwrap_or(false);

                            // Получаем имя клиента, если указано
                            if let Some(name) = auth_data.name {
                                if !name.is_empty() {
                                    client_name = name;
                                }
                            }

                            verified
                        } else {
                            false
                        }
                    },
                    _ => false,
                };

                if !authenticated {
                    println!("Клиент {} не прошел аутентификацию", client_id);
                    let _ = ws_tx.send(Message::Close(None)).await;
                    return;
                }

                // Отправляем сигнал об успешной аутентификации
                let auth_success_msg = ChatMessage {
                    msg_type: MessageType::Auth,
                    sender_id: 0,
                    sender_name: "SERVER".to_string(),
                    content: "AUTH_SUCCESS".to_string(),
                };

                if let Ok(json_msg) = serde_json::to_string(&auth_success_msg) {
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
                };

                {
                    let mut clients_map = clients.lock().await;
                    clients_map.insert(client_id, client_info);
                    println!("Клиент {} добавлен. Всего клиентов: {}", client_id, clients_map.len());
                }

                // Отправляем системное сообщение о новом клиенте (не отправителю)
                let join_msg = ChatMessage {
                    msg_type: MessageType::System,
                    sender_id: client_id,
                    sender_name: client_name.clone(),
                    content: "присоединился к чату".to_string(),
                };

                broadcast_message(&clients, &join_msg, Some(client_id)).await;

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
                                // Обрабатываем текстовые сообщения как контент
                                let content_msg = ChatMessage {
                                    msg_type: MessageType::Content,
                                    sender_id: client_id,
                                    sender_name: client_name_for_recv.clone(),
                                    content: text.to_string(),
                                };

                                println!("Получено сообщение от клиента {}: {}", client_name_for_recv, content_msg.content);
                                // Отправляем сообщение всем клиентам, кроме отправителя
                                broadcast_message(&clients_recv, &content_msg, Some(client_id)).await;
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

                // Отправляем системное сообщение об отключении клиента (не отправителю)
                let leave_msg = ChatMessage {
                    msg_type: MessageType::System,
                    sender_id: client_id,
                    sender_name: client_name.clone(),
                    content: "покинул чат".to_string(),
                };

                broadcast_message(&clients, &leave_msg, Some(client_id)).await;

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

// Функция для широковещательной рассылки сообщений
async fn broadcast_message(clients: &ClientsMap, message: &ChatMessage, exclude_id: Option<usize>) {
    if let Ok(json_msg) = serde_json::to_string(message) {
        let clients_map = clients.lock().await;
        for (_, client_info) in clients_map.iter() {
            // Пропускаем клиента, если он в списке исключений
            if let Some(exclude) = exclude_id {
                if client_info.id == exclude {
                    continue;
                }
            }

            // Пытаемся отправить сообщение
            if let Err(e) = client_info.sender.send(Message::Text(json_msg.clone().into())) {
                eprintln!("Ошибка отправки клиенту {}: {}", client_info.id, e);
            }
        }
    }
}