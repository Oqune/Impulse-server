use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use bcrypt::{hash, verify, DEFAULT_COST};

const SERVER_ADDRESS: &str = "192.168.1.50:8080";
const SECRET_PASSWORD: &str = "your_secure_password_here";

// Типы для хранения состояния
type ClientMap = Arc<Mutex<HashMap<usize, tokio::sync::mpsc::UnboundedSender<Message>>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(SERVER_ADDRESS).await?;
    println!("WebSocket сервер запущен на {}", SERVER_ADDRESS);

    // Хешируем пароль при запуске сервера
    let hashed_password = hash(SECRET_PASSWORD, DEFAULT_COST)?;
    println!("Сервер готов принимать соединения с аутентификацией");

    let clients: ClientMap = Arc::new(Mutex::new(HashMap::new()));
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

                // Ожидаем сообщение с паролем от клиента
                let auth_message = ws_rx.next().await;
                let authenticated = match auth_message {
                    Some(Ok(Message::Text(text))) => {
                        verify(&text, &hashed_password).unwrap_or_else(|_| false)
                    },
                    _ => false,
                };

                if !authenticated {
                    println!("Клиент {} не прошел аутентификацию", client_id);
                    let _ = ws_tx.send(Message::Close(None)).await;
                    return;
                }

                // Отправляем сигнал об успешной аутентификации
                if let Err(e) = ws_tx.send(Message::Text("AUTH_SUCCESS".to_string().into())).await {
                    eprintln!("Ошибка отправки сигнала аутентификации клиенту {}: {}", client_id, e);
                    return;
                }
                println!("Клиент {} успешно аутентифицирован", client_id);

                // Создаем канал для отправки сообщений этому клиенту
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

                // Добавляем клиента в карту
                {
                    let mut clients_map = clients.lock().await;
                    clients_map.insert(client_id, tx);
                    println!("Клиент {} добавлен. Всего клиентов: {}", client_id, clients_map.len());
                }

                // Задача для отправки сообщений клиенту
                let mut ws_tx = ws_tx;
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
                let recv_task = tokio::spawn(async move {
                    while let Some(message) = ws_rx.next().await {
                        match message {
                            Ok(Message::Text(text)) => {
                                println!("Получено сообщение от клиента {}: {}", client_id, text);

                                // Формируем сообщение для рассылки
                                let broadcast_msg = Message::Text(format!("Клиент {}: {}", client_id, text).into());

                                // Рассылаем сообщение всем клиентам
                                let clients_map = clients_recv.lock().await;
                                for (&id, client_tx) in clients_map.iter() {
                                    if id != client_id { // Не отправляем обратно отправителю
                                        if let Err(e) = client_tx.send(broadcast_msg.clone()) {
                                            eprintln!("Ошибка отправки клиенту {}: {}", id, e);
                                        }
                                    }
                                }
                            }
                            Ok(Message::Close(_)) => {
                                println!("Клиент {} отключился", client_id);
                                break;
                            }
                            Err(e) => {
                                eprintln!("Ошибка получения сообщения от клиента {}: {}", client_id, e);
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