use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use nostr::event::{EventBuilder, Kind, Tag};
use nostr::filter::SingleLetterTag;
use nostr::key::Keys;
use nostr::message::ClientMessage;
use nostr::util::{hex, JsonUtil};
use nostr_sdk::Client;

use super::Error;

pub type BoxSendSyncError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub(crate) struct Db {
    child: Arc<tokio::process::Child>,
    port: u16,
    temp_dir: Arc<tempfile::TempDir>,
}

impl Db {
    pub(crate) async fn new() -> Result<Self, BoxSendSyncError> {
        let (port, child, temp_dir) = init_nostr_relay().await?;

        Ok(Self { child: Arc::new(child), port, temp_dir: Arc::new(temp_dir) })
    }

    pub(crate) fn nostr_relay_url(&self) -> String { format!("ws://127.0.0.1:{}", self.port) }

    pub(crate) async fn push_v2_nostr_payload(
        &self,
        mailbox_id: &payjoin::directory::ShortId,
        data: Vec<u8>,
    ) -> Result<(), NostrBackendError> {
        let hex_data = hex::encode(data);
        let hex_mailbox_id = hex::encode(mailbox_id.as_bytes());
        let ephemeral_key = Keys::generate();
        let ephemeral_pubkey = ephemeral_key.public_key();

        let event = EventBuilder::new(Kind::GiftWrap, hex_data)
            .tag(Tag::custom(
                nostr::event::TagKind::SingleLetter(SingleLetterTag::from_char('h').unwrap()),
                hex_mailbox_id.chars().map(|c| c.to_string()),
            ))
            .build(ephemeral_pubkey)
            .sign(&ephemeral_key)
            .await
            .unwrap();

        let client = Client::new(ephemeral_key);
        client.add_relay(self.nostr_relay_url()).await.unwrap();

        client.connect().await;
        client.send_event(&event).await.unwrap();
        client.disconnect().await;

        Ok(())
    }
}

impl super::Db for Db {
    type OperationalError = NostrBackendError;

    async fn post_v2_payload(
        &self,
        mailbox_id: &payjoin::directory::ShortId,
        data: Vec<u8>,
    ) -> Result<(), Error<Self::OperationalError>> {
        self.push_v2_nostr_payload(mailbox_id, data).await?;
        Ok(())
    }

    async fn wait_for_v2_payload(
        &self,
        mailbox_id: &payjoin::directory::ShortId,
    ) -> Result<Vec<u8>, Error<Self::OperationalError>> {
        unimplemented!()
    }

    async fn post_v1_response(
        &self,
        _mailbox_id: &payjoin::directory::ShortId,
        _data: Vec<u8>,
    ) -> Result<(), Error<Self::OperationalError>> {
        unimplemented!()
    }

    async fn post_v1_request_and_wait_for_response(
        &self,
        _mailbox_id: &payjoin::directory::ShortId,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, Error<Self::OperationalError>> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub(crate) enum NostrBackendError {}

impl crate::db::SendableError for NostrBackendError {}

impl std::error::Error for NostrBackendError {}

impl std::fmt::Display for NostrBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { todo!() }
}

/// Find the nostr-rs-relay binary
fn find_nostr_relay_binary() -> Option<String> {
    // First check environment variable (similar to BITCOIND_EXE pattern)
    if let Ok(path) = std::env::var("NOSTR_RELAY_EXE") {
        return Some(path);
    }

    // Check if nostr-rs-relay is in PATH (this will find cargo-installed binaries)
    if let Ok(output) = std::process::Command::new("which").arg("nostr-rs-relay").output() {
        if output.status.success() {
            if let Ok(path) = String::from_utf8(output.stdout) {
                return Some(path.trim().to_string());
            }
        }
    }

    // Fallback: just try "nostr-rs-relay" directly (will work if it's in PATH)
    Some("nostr-rs-relay".to_string())
}

/// Initialize a nostr-rs-relay instance for testing
/// Returns (port, child_process, temp_directory)
pub async fn init_nostr_relay(
) -> Result<(u16, tokio::process::Child, tempfile::TempDir), BoxSendSyncError> {
    use std::process::Stdio;

    use tempfile::TempDir;
    use tokio::process::Command;

    // Create a temporary directory for the relay data
    let temp_dir = TempDir::new().map_err(|e| format!("Failed to create temp dir: {}", e))?;
    let data_dir = temp_dir.path().join("nostr_data");
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("Failed to create data dir: {}", e))?;

    // Find a free port
    let listener =
        bind_free_port().await.map_err(|e| format!("Failed to bind free port: {}", e))?;
    let port =
        listener.local_addr().map_err(|e| format!("Failed to get local addr: {}", e))?.port();
    drop(listener); // Release the port for nostr-rs-relay to use

    // Create minimal config file
    let config_path = temp_dir.path().join("config.toml");
    let config_content = format!(
        r#"
[info]
relay_url = "ws://127.0.0.1:{}/"
name = "Test Nostr Relay"
description = "A test instance of nostr-rs-relay for payjoin testing"

[database]
data_directory = "{}"

[network]
address = "127.0.0.1"
port = {}

[limits]
# Allow generous limits for testing
max_ws_connections = 1000
max_event_bytes = 1048576

[authorization]
# No authorization required for testing
pubkey_whitelist = []

[verified_users]
# No verified users required for testing

[log]
# Simple logging for tests
"#,
        port,
        data_dir.display(),
        port
    );

    std::fs::write(&config_path, config_content)
        .map_err(|e| format!("Failed to write config: {}", e))?;

    // Get the nostr relay binary
    let nostr_relay_exe = find_nostr_relay_binary()
        .ok_or("nostr-rs-relay binary not found. Please install it with 'cargo install nostr-rs-relay' or set NOSTR_RELAY_EXE environment variable")?;

    // Start the nostr relay process
    let child = Command::new(nostr_relay_exe)
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start nostr-rs-relay: {}", e))?;

    // Give it a moment to start up
    tokio::time::sleep(Duration::from_millis(500)).await;

    Ok((port, child, temp_dir))
}

async fn bind_free_port() -> Result<tokio::net::TcpListener, std::io::Error> {
    let bind_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    tokio::net::TcpListener::bind(bind_addr).await
}

mod test {
    use super::*;

    #[tokio::test]
    async fn test_nostr_directory() -> Result<(), BoxSendSyncError> {
        let (port, mut child, _temp_dir) = init_nostr_relay().await?;

        // Simple test: connect via WebSocket and send a basic REQ
        let relay_url = format!("ws://127.0.0.1:{}", port);

        // Give the relay a moment to fully start
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

        // Test WebSocket connection
        match tokio_tungstenite::connect_async(&relay_url).await {
            Ok((mut ws_stream, _response)) => {
                use futures_util::{SinkExt, StreamExt};
                use tokio_tungstenite::tungstenite::Message;

                // Send a basic REQ message (request events with limit 1)
                let req_msg = r#"["REQ","test_sub",{"limit":1}]"#;
                ws_stream.send(Message::Text(req_msg.into())).await?;

                // Read response (should get EOSE - End Of Stored Events)
                if let Some(msg) = ws_stream.next().await {
                    match msg? {
                        Message::Text(text) => {
                            println!("Received from nostr relay: {}", text);
                            // Should receive something like: ["EOSE","test_sub"]
                            assert!(text.contains("EOSE") || text.contains("test_sub"));
                        }
                        _ => panic!("Expected text message from nostr relay"),
                    }
                }

                println!("✓ Nostr relay is operational at {}", relay_url);
            }
            Err(e) => {
                panic!("Failed to connect to nostr relay: {}", e);
            }
        }

        // Clean up
        child.kill().await?;

        Ok(())
    }
}
