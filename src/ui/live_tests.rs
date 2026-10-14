//! Real loopback WebTransport smoke test of the production relay path.
use super::*;
use crate::cert::CertManager;
use crate::config::ServerSettings;
use crate::protocol::{Opcode, PacketWriter};
use crate::relay::RelayServer;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use wtransport::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};

struct TestCertificates(std::path::PathBuf);
impl Drop for TestCertificates {
    fn drop(&mut self) {
        // Only the two known files in this freshly-created test directory.
        for name in ["impulse_cert.pem", "impulse_key.pem"] {
            let _ = std::fs::remove_file(self.0.join(name));
        }
        let _ = std::fs::remove_dir(&self.0);
    }
}

async fn read_bytes(recv: &mut RecvStream, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut bytes)).await.unwrap().unwrap();
    bytes
}

async fn authenticate(connection: &Connection, key: &[u8]) -> (SendStream, RecvStream) {
    let (mut send, mut recv) = connection.open_bi().await.unwrap().await.unwrap();
    // Stream creation transmits its WT header before application data.
    let challenge = read_bytes(&mut recv, 17).await;
    assert_eq!(challenge[0], Opcode::AuthChallenge.as_u8());
    for _ in 0..2 {
        let len = u32::from_le_bytes(read_bytes(&mut recv, 4).await.try_into().unwrap());
        read_bytes(&mut recv, len as usize).await;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(&challenge[1..]);
    let mut packet = PacketWriter::with_opcode(Opcode::Auth);
    packet.write_len_prefixed(&mac.finalize().into_bytes());
    send.write_all(&packet.into_bytes()).await.unwrap();
    assert_eq!(read_bytes(&mut recv, 2).await, [Opcode::AuthResult.as_u8(), 1]);
    (send, recv)
}

async fn open_unauthenticated_stream(connection: &Connection) -> (SendStream, RecvStream) {
    let (send, mut recv) = connection.open_bi().await.unwrap().await.unwrap();
    let challenge = read_bytes(&mut recv, 17).await;
    assert_eq!(challenge[0], Opcode::AuthChallenge.as_u8());
    for _ in 0..2 {
        let len = u32::from_le_bytes(read_bytes(&mut recv, 4).await.try_into().unwrap());
        read_bytes(&mut recv, len as usize).await;
    }
    (send, recv)
}

#[tokio::test]
async fn live_pinned_quic_auth_heartbeat_relay_and_sync() {
    let directory = std::env::temp_dir().join(format!("impulse-live-test-{}-{:016x}", std::process::id(), rand::random::<u64>()));
    std::fs::create_dir(&directory).unwrap();
    let _certificates = TestCertificates(directory.clone());
    let manager = CertManager::load_or_create(&directory, vec!["localhost".into()]).unwrap();
    let pin: [u8; 32] = hex::decode(&manager.current().fingerprint).unwrap().try_into().unwrap();
    let hash = crate::crypto::argon2_hash("test-only-loopback-password").unwrap();
    let key = crate::crypto::hmac_key_from_stored_hash(&hash).unwrap();
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let (log_tx, _log_rx) = crossbeam_channel::bounded(MAX_LOG_LINES);
    let tui = TuiHandle {
        log_tx, cert: Arc::new(Mutex::new(CertView::default())),
        info: Arc::new(Mutex::new(ServerInfo::default())), stats: Arc::new(ServerStats::new()),
        sessions: Arc::new(Mutex::new(Vec::new())), users: Arc::new(Mutex::new(Vec::new())), shutdown: shutdown.clone(),
    };
    let relay = Arc::new(RelayServer::new(ServerSettings {
        address: "127.0.0.1:0".into(), password_hash: hash,
        cert_dir: directory.to_string_lossy().into_owned(), ..Default::default()
    }, Arc::new(tokio::sync::Mutex::new(manager)), tui.clone()).await.unwrap());

    // A full direct-response channel can block an authenticated Heartbeat
    // handler even though the packet itself is small. Exercise the production
    // handler and the same deadline wrapper used by the session reader.
    let (direct_tx, mut direct_rx) = tokio::sync::mpsc::channel::<crate::relay::DirectResponse>(1);
    direct_tx.send(crate::relay::DirectResponse::plain(vec![0])).await.unwrap();
    let mut heartbeat_session = crate::relay::session::Session::new(
        0xfeed,
        "127.0.0.1".parse().unwrap(),
    );
    heartbeat_session.authenticated = true;
    let heartbeat_packet = crate::protocol::encode_heartbeat(123);
    let heartbeat_processing = crate::relay::auth::process_packet(
        &relay, &mut heartbeat_session, &direct_tx, &heartbeat_packet,
    );
    let deadline = crate::relay::session::timeout_packet_processing(
        Duration::from_millis(50),
        heartbeat_processing,
    ).await;
    assert!(deadline.is_err(), "Heartbeat processing must not wait indefinitely for the writer channel");
    assert!(direct_rx.try_recv().is_ok(), "the already-queued response remains owned by the writer side");
    assert!(direct_rx.try_recv().is_err(), "timed-out Heartbeat response must not remain queued");

    let address = tui.info.lock().unwrap().address.clone();
    let task = tokio::spawn(relay.run(shutdown.clone()));
    let endpoint = Endpoint::client(ClientConfig::builder().with_bind_default()
        .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(pin)]).build()).unwrap();
    let url = format!("https://{address}");
    let wrong_pin_endpoint = Endpoint::client(ClientConfig::builder().with_bind_default()
        .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new([0; 32])]).build()).unwrap();
    let rejected = tokio::time::timeout(Duration::from_secs(5), wrong_pin_endpoint.connect(url.as_str())).await.unwrap();
    assert!(rejected.is_err(), "a mismatched certificate pin must fail closed");
    let first = tokio::time::timeout(Duration::from_secs(5), endpoint.connect(url.as_str())).await.unwrap().unwrap();
    let (mut send_a, mut recv_a) = authenticate(&first, &key).await;
    let second = tokio::time::timeout(Duration::from_secs(5), endpoint.connect(url.as_str())).await.unwrap().unwrap();
    let (mut send_b, mut recv_b) = authenticate(&second, &key).await;
    assert_eq!(tui.stats.sessions.load(Ordering::Relaxed), 2);

    // Auth's 30-second deadline must stop applying after the transition to
    // authenticated. Keep one real QUIC session active beyond that boundary.
    let heartbeat_start = tokio::time::Instant::now();
    while heartbeat_start.elapsed() < Duration::from_secs(31) {
        let heartbeat = crate::protocol::encode_heartbeat(heartbeat_start.elapsed().as_millis() as u64);
        send_a.write_all(&heartbeat).await.unwrap();
        assert_eq!(read_bytes(&mut recv_a, heartbeat.len()).await, heartbeat);
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    // Valid framing with a pre-auth application opcode must close the session.
    let unauthenticated = tokio::time::timeout(Duration::from_secs(5), endpoint.connect(url.as_str())).await.unwrap().unwrap();
    let (mut unauth_send, mut unauth_recv) = open_unauthenticated_stream(&unauthenticated).await;
    let mut forbidden = PacketWriter::with_opcode(Opcode::Data);
    forbidden.write_len_prefixed(b"must not be accepted");
    unauth_send.write_all(&forbidden.into_bytes()).await.unwrap();
    let mut one = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(5), unauth_recv.read(&mut one)).await;
    assert!(matches!(closed, Ok(Ok(None)) | Ok(Err(_))), "unauthenticated packet must close the session: {closed:?}");
    unauthenticated.close(0u32.into(), b"fail-closed regression");

    // Heartbeat is not an auth bypass and must not produce a pre-auth response.
    let unauth_heartbeat = tokio::time::timeout(Duration::from_secs(5), endpoint.connect(url.as_str())).await.unwrap().unwrap();
    let (mut heartbeat_send, mut heartbeat_recv) = open_unauthenticated_stream(&unauth_heartbeat).await;
    heartbeat_send.write_all(&crate::protocol::encode_heartbeat(123)).await.unwrap();
    let mut one = [0u8; 1];
    let heartbeat_closed = tokio::time::timeout(Duration::from_secs(5), heartbeat_recv.read(&mut one)).await;
    assert!(matches!(heartbeat_closed, Ok(Ok(None)) | Ok(Err(_))), "pre-auth Heartbeat must not keep the session alive: {heartbeat_closed:?}");
    unauth_heartbeat.close(0u32.into(), b"pre-auth heartbeat regression");
    tokio::time::timeout(Duration::from_secs(5), async {
        while tui.stats.sessions.load(Ordering::Relaxed) != 2 {
            tokio::task::yield_now().await;
        }
    }).await.unwrap();

    let heartbeat = crate::protocol::encode_heartbeat(12345);
    send_a.write_all(&heartbeat).await.unwrap();
    assert_eq!(read_bytes(&mut recv_a, 9).await, heartbeat);
    let opaque = [0xA5, 0x00, 0xFF, 0x72, 0x10];
    let mut data = PacketWriter::with_opcode(Opcode::Data);
    data.write_len_prefixed(&opaque);
    send_a.write_all(&data.into_bytes()).await.unwrap();
    let header = read_bytes(&mut recv_b, 21).await;
    assert_eq!(header[0], Opcode::Data.as_u8());
    let id = u64::from_le_bytes(header[1..9].try_into().unwrap());
    assert!(id > 0);
    assert_eq!(u32::from_le_bytes(header[17..21].try_into().unwrap()), opaque.len() as u32);
    assert_eq!(read_bytes(&mut recv_b, opaque.len()).await, opaque);

    let mut sync = PacketWriter::with_opcode(Opcode::Sync);
    sync.write_u64(0);
    send_b.write_all(&sync.into_bytes()).await.unwrap();
    let replay = read_bytes(&mut recv_b, 25).await;
    assert_eq!(replay[0], Opcode::SyncResponse.as_u8());
    assert_eq!(u32::from_le_bytes(replay[1..5].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(replay[5..13].try_into().unwrap()), id);
    assert_eq!(read_bytes(&mut recv_b, opaque.len()).await, opaque);

    // Exercise the production Sync encoder/pager above one 4 MiB response.
    // Five maximum-sized opaque payloads require at least two bounded frames.
    let large_payload = vec![0x5A; crate::protocol::limits::MAX_PAYLOAD_BYTES];
    for _ in 0..5 {
        let mut data = PacketWriter::with_opcode(Opcode::Data);
        data.write_len_prefixed(&large_payload);
        send_a.write_all(&data.into_bytes()).await.unwrap();
    }
    for _ in 0..5 {
        let header = read_bytes(&mut recv_b, 21).await;
        assert_eq!(header[0], Opcode::Data.as_u8());
        assert_eq!(u32::from_le_bytes(header[17..21].try_into().unwrap()) as usize, large_payload.len());
        assert_eq!(read_bytes(&mut recv_b, large_payload.len()).await, large_payload);
    }
    let mut sync = PacketWriter::with_opcode(Opcode::Sync);
    sync.write_u64(id);
    send_b.write_all(&sync.into_bytes()).await.unwrap();
    let mut synced = 0usize;
    let mut frames = 0usize;
    while synced < 5 {
        let mut frame_bytes = 5usize;
        let frame_header = read_bytes(&mut recv_b, 5).await;
        assert_eq!(frame_header[0], Opcode::SyncResponse.as_u8());
        let count = u32::from_le_bytes(frame_header[1..5].try_into().unwrap()) as usize;
        assert!(count > 0 && count < 500);
        for _ in 0..count {
            let record = read_bytes(&mut recv_b, 20).await;
            frame_bytes += 20;
            let payload_len = u32::from_le_bytes(record[16..20].try_into().unwrap()) as usize;
            frame_bytes += payload_len;
            assert_eq!(payload_len, large_payload.len());
            let payload = read_bytes(&mut recv_b, payload_len).await;
            assert_eq!(payload, large_payload);
        }
        assert!(frame_bytes <= crate::protocol::limits::MAX_SYNC_RESPONSE_BYTES);
        synced += count;
        frames += 1;
    }
    assert!(frames >= 2, "more than 4 MiB of Sync data must be paged");

    first.close(0u32.into(), b"test complete");
    second.close(0u32.into(), b"test complete");
    endpoint.wait_idle().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while tui.stats.sessions.load(Ordering::Relaxed) != 0 {
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    // Reconnect and recover the stored opaque message through the actual stream.
    let third = tokio::time::timeout(Duration::from_secs(5), endpoint.connect(url.as_str())).await.unwrap().unwrap();
    let (mut send_c, mut recv_c) = authenticate(&third, &key).await;
    let mut sync = PacketWriter::with_opcode(Opcode::Sync);
    sync.write_u64(0);
    send_c.write_all(&sync.into_bytes()).await.unwrap();
    let replay = read_bytes(&mut recv_c, 25).await;
    assert_eq!(replay[0], Opcode::SyncResponse.as_u8());
    assert_eq!(u64::from_le_bytes(replay[5..13].try_into().unwrap()), id);
    assert_eq!(read_bytes(&mut recv_c, opaque.len()).await, opaque);
    third.close(0u32.into(), b"reconnect test complete");
    endpoint.wait_idle().await;
    shutdown.notify_one();
    tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap().unwrap();
}
