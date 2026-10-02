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
