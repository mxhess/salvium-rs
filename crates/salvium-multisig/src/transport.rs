//! TCP transport layer for multisig message exchange.
//!
//! Star topology: one signer runs as coordinator (server), others connect as clients.
//!
//! ## Wire protocol (length-delimited framing)
//!
//! ```text
//! [u32 LE: payload length] [u8: msg_type] [payload bytes]
//! ```
//!
//! Maximum payload size: 16 MiB.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Maximum payload size: 16 MiB.
const MAX_PAYLOAD: u32 = 16 * 1024 * 1024;

/// Wire message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    Kex = 0x01,
    TxSet = 0x02,
    PartialSig = 0x03,
    Ready = 0x04,
    Error = 0xFF,
}

impl MsgType {
    fn from_u8(b: u8) -> Result<Self, String> {
        match b {
            0x01 => Ok(MsgType::Kex),
            0x02 => Ok(MsgType::TxSet),
            0x03 => Ok(MsgType::PartialSig),
            0x04 => Ok(MsgType::Ready),
            0xFF => Ok(MsgType::Error),
            other => Err(format!("unknown message type: 0x{:02x}", other)),
        }
    }
}

/// A framed wire message.
#[derive(Debug, Clone)]
pub struct WireMessage {
    pub msg_type: MsgType,
    pub payload: Vec<u8>,
}

impl WireMessage {
    pub fn new(msg_type: MsgType, payload: Vec<u8>) -> Self {
        Self { msg_type, payload }
    }

    /// Encode to wire format: `[u32 LE: payload_len] [u8: msg_type] [payload]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(5 + self.payload.len());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.push(self.msg_type as u8);
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode from wire format bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 5 {
            return Err("message too short".to_string());
        }
        let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if len > MAX_PAYLOAD {
            return Err(format!("payload too large: {} bytes", len));
        }
        let msg_type = MsgType::from_u8(data[4])?;
        let expected_total = 5 + len as usize;
        if data.len() < expected_total {
            return Err(format!(
                "incomplete message: have {} bytes, need {}",
                data.len(),
                expected_total
            ));
        }
        let payload = data[5..expected_total].to_vec();
        Ok(Self { msg_type, payload })
    }
}

/// Send a framed message over a TCP stream.
async fn send_message(stream: &mut TcpStream, msg: &WireMessage) -> Result<(), String> {
    let len = msg.payload.len() as u32;
    if len > MAX_PAYLOAD {
        return Err("payload exceeds maximum size".to_string());
    }
    stream
        .write_all(&len.to_le_bytes())
        .await
        .map_err(|e| format!("write length failed: {}", e))?;
    stream.write_u8(msg.msg_type as u8).await.map_err(|e| format!("write type failed: {}", e))?;
    stream.write_all(&msg.payload).await.map_err(|e| format!("write payload failed: {}", e))?;
    stream.flush().await.map_err(|e| format!("flush failed: {}", e))?;
    Ok(())
}

/// Receive a framed message from a TCP stream.
async fn recv_message(stream: &mut TcpStream) -> Result<WireMessage, String> {
    let len = stream.read_u32_le().await.map_err(|e| format!("read length failed: {}", e))?;
    if len > MAX_PAYLOAD {
        return Err(format!("payload too large: {} bytes", len));
    }
    let type_byte = stream.read_u8().await.map_err(|e| format!("read type failed: {}", e))?;
    let msg_type = MsgType::from_u8(type_byte)?;
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload).await.map_err(|e| format!("read payload failed: {}", e))?;
    Ok(WireMessage { msg_type, payload })
}

/// Configuration for the coordinator.
pub struct CoordinatorConfig {
    /// Address to bind on (e.g. "0.0.0.0:7777").
    pub bind_addr: String,
    /// Number of expected signers (including the coordinator itself if it participates).
    pub expected_signers: usize,
    /// Timeout for waiting for all signers to connect/respond.
    pub timeout: Duration,
}

/// Coordinator (server) for multisig message exchange.
///
/// Runs as a star-topology hub: accepts connections from `expected_signers - 1`
/// clients, then orchestrates message exchange rounds.
pub struct Coordinator {
    config: CoordinatorConfig,
}

impl Coordinator {
    pub fn new(config: CoordinatorConfig) -> Self {
        Self { config }
    }

    /// Accept connections from `expected_signers - 1` clients.
    ///
    /// Returns the listener and the connected streams.
    pub async fn accept_signers(&self) -> Result<(TcpListener, Vec<TcpStream>), String> {
        let listener = TcpListener::bind(&self.config.bind_addr)
            .await
            .map_err(|e| format!("bind failed: {}", e))?;

        let needed = self.config.expected_signers - 1;
        let mut streams = Vec::with_capacity(needed);

        let accept_all = async {
            for _ in 0..needed {
                let (stream, _addr) =
                    listener.accept().await.map_err(|e| format!("accept failed: {}", e))?;
                streams.push(stream);
            }
            Ok::<_, String>(())
        };

        tokio::time::timeout(self.config.timeout, accept_all)
            .await
            .map_err(|_| "timed out waiting for signers".to_string())?
            .map_err(|e| format!("accept error: {}", e))?;

        Ok((listener, streams))
    }

    /// Collect one KEX message from each connected signer, then broadcast all
    /// collected messages to every signer.
    ///
    /// `local_msg` is the coordinator's own KEX message (if participating).
    /// Returns the collected messages (including local).
    pub async fn collect_kex_round(
        streams: &mut [TcpStream],
        local_msg: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Vec<Vec<u8>>, String> {
        let mut messages = Vec::new();

        // Add the coordinator's own message first if present
        if let Some(msg) = local_msg {
            messages.push(msg.to_vec());
        }

        // Collect from all connected signers
        let collect = async {
            for stream in streams.iter_mut() {
                let wire_msg = recv_message(stream).await?;
                if wire_msg.msg_type != MsgType::Kex {
                    return Err(format!("expected Kex message, got {:?}", wire_msg.msg_type));
                }
                messages.push(wire_msg.payload);
            }
            Ok::<_, String>(())
        };

        tokio::time::timeout(timeout, collect)
            .await
            .map_err(|_| "timed out collecting KEX messages".to_string())?
            .map_err(|e| format!("collect error: {}", e))?;

        // Broadcast all collected messages to each signer
        for stream in streams.iter_mut() {
            // Send count then each message
            let count_msg =
                WireMessage::new(MsgType::Ready, (messages.len() as u32).to_le_bytes().to_vec());
            send_message(stream, &count_msg).await?;
            for msg_payload in &messages {
                let wire = WireMessage::new(MsgType::Kex, msg_payload.clone());
                send_message(stream, &wire).await?;
            }
        }

        Ok(messages)
    }

    /// Run all KEX rounds end-to-end.
    ///
    /// For each round, collects messages from all signers, broadcasts to all,
    /// and returns the collected messages per round.
    pub async fn run_kex(
        streams: &mut [TcpStream],
        total_rounds: usize,
        local_msgs: &[Vec<u8>],
        timeout: Duration,
    ) -> Result<Vec<Vec<Vec<u8>>>, String> {
        let mut all_rounds = Vec::new();
        for round in 0..total_rounds {
            let local = local_msgs.get(round).map(|v| v.as_slice());
            let messages = Self::collect_kex_round(streams, local, timeout).await?;
            all_rounds.push(messages);
        }
        Ok(all_rounds)
    }

    /// Exchange a TX set: receive from proposer, broadcast to all signers.
    pub async fn exchange_tx_set(
        streams: &mut [TcpStream],
        proposer_index: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        // Receive TX set from the proposer
        let collect = async {
            let wire_msg = recv_message(&mut streams[proposer_index]).await?;
            if wire_msg.msg_type != MsgType::TxSet {
                return Err(format!("expected TxSet message, got {:?}", wire_msg.msg_type));
            }
            Ok::<_, String>(wire_msg.payload)
        };

        let tx_set_data = tokio::time::timeout(timeout, collect)
            .await
            .map_err(|_| "timed out waiting for TX set".to_string())?
            .map_err(|e| format!("tx set error: {}", e))?;

        // Broadcast to all signers
        for stream in streams.iter_mut() {
            let wire = WireMessage::new(MsgType::TxSet, tx_set_data.clone());
            send_message(stream, &wire).await?;
        }

        Ok(tx_set_data)
    }

    /// Collect partial signatures from all connected signers.
    pub async fn collect_partials(
        streams: &mut [TcpStream],
        local_partial: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Vec<Vec<u8>>, String> {
        let mut partials = Vec::new();

        if let Some(p) = local_partial {
            partials.push(p.to_vec());
        }

        let collect = async {
            for stream in streams.iter_mut() {
                let wire_msg = recv_message(stream).await?;
                if wire_msg.msg_type != MsgType::PartialSig {
                    return Err(format!(
                        "expected PartialSig message, got {:?}",
                        wire_msg.msg_type
                    ));
                }
                partials.push(wire_msg.payload);
            }
            Ok::<_, String>(())
        };

        tokio::time::timeout(timeout, collect)
            .await
            .map_err(|_| "timed out collecting partial signatures".to_string())?
            .map_err(|e| format!("collect partials error: {}", e))?;

        Ok(partials)
    }
}

/// Client for connecting to a multisig coordinator.
pub struct SignerClient {
    stream: TcpStream,
}

impl SignerClient {
    /// Connect to a coordinator at the given address.
    pub async fn connect(addr: &str) -> Result<Self, String> {
        let stream =
            TcpStream::connect(addr).await.map_err(|e| format!("connect failed: {}", e))?;
        Ok(Self { stream })
    }

    /// Send a KEX message to the coordinator.
    pub async fn send_kex(&mut self, payload: &[u8]) -> Result<(), String> {
        let msg = WireMessage::new(MsgType::Kex, payload.to_vec());
        send_message(&mut self.stream, &msg).await
    }

    /// Receive all KEX messages for the current round from the coordinator.
    ///
    /// The coordinator first sends a Ready message with the count, then
    /// sends each KEX message.
    pub async fn receive_kex_round(&mut self) -> Result<Vec<Vec<u8>>, String> {
        // First receive the Ready message with count
        let ready = recv_message(&mut self.stream).await?;
        if ready.msg_type != MsgType::Ready {
            return Err(format!("expected Ready message, got {:?}", ready.msg_type));
        }
        if ready.payload.len() < 4 {
            return Err("Ready message payload too short".to_string());
        }
        let count = u32::from_le_bytes([
            ready.payload[0],
            ready.payload[1],
            ready.payload[2],
            ready.payload[3],
        ]) as usize;

        // Receive each KEX message
        let mut messages = Vec::with_capacity(count);
        for _ in 0..count {
            let wire_msg = recv_message(&mut self.stream).await?;
            if wire_msg.msg_type != MsgType::Kex {
                return Err(format!("expected Kex message, got {:?}", wire_msg.msg_type));
            }
            messages.push(wire_msg.payload);
        }

        Ok(messages)
    }

    /// Send a TX set to the coordinator.
    pub async fn send_tx_set(&mut self, payload: &[u8]) -> Result<(), String> {
        let msg = WireMessage::new(MsgType::TxSet, payload.to_vec());
        send_message(&mut self.stream, &msg).await
    }

    /// Receive a TX set from the coordinator.
    pub async fn receive_tx_set(&mut self) -> Result<Vec<u8>, String> {
        let wire_msg = recv_message(&mut self.stream).await?;
        if wire_msg.msg_type != MsgType::TxSet {
            return Err(format!("expected TxSet message, got {:?}", wire_msg.msg_type));
        }
        Ok(wire_msg.payload)
    }

    /// Send a partial signature to the coordinator.
    pub async fn send_partial(&mut self, payload: &[u8]) -> Result<(), String> {
        let msg = WireMessage::new(MsgType::PartialSig, payload.to_vec());
        send_message(&mut self.stream, &msg).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_message_roundtrip() {
        let msg = WireMessage::new(MsgType::Kex, b"hello world".to_vec());
        let bytes = msg.to_bytes();
        let decoded = WireMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.msg_type, MsgType::Kex);
        assert_eq!(decoded.payload, b"hello world");
    }

    #[test]
    fn wire_message_all_types() {
        for (t, expected) in [
            (MsgType::Kex, 0x01),
            (MsgType::TxSet, 0x02),
            (MsgType::PartialSig, 0x03),
            (MsgType::Ready, 0x04),
            (MsgType::Error, 0xFF),
        ] {
            let msg = WireMessage::new(t, vec![0xAB]);
            let bytes = msg.to_bytes();
            assert_eq!(bytes[4], expected);
            let decoded = WireMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.msg_type, t);
        }
    }

    #[test]
    fn wire_message_empty_payload() {
        let msg = WireMessage::new(MsgType::Ready, vec![]);
        let bytes = msg.to_bytes();
        assert_eq!(bytes.len(), 5); // 4 bytes length + 1 byte type
        let decoded = WireMessage::from_bytes(&bytes).unwrap();
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn wire_message_reject_too_short() {
        assert!(WireMessage::from_bytes(&[0, 0]).is_err());
        assert!(WireMessage::from_bytes(&[]).is_err());
    }

    #[test]
    fn wire_message_reject_unknown_type() {
        let mut bytes = WireMessage::new(MsgType::Kex, vec![1]).to_bytes();
        bytes[4] = 0x42; // Invalid type
        assert!(WireMessage::from_bytes(&bytes).is_err());
    }

    #[test]
    fn wire_message_reject_truncated_payload() {
        // Claim 100 bytes but only provide 5
        let bytes = vec![100, 0, 0, 0, 0x01, 1, 2, 3, 4, 5];
        assert!(WireMessage::from_bytes(&bytes).is_err());
    }

    #[tokio::test]
    async fn coordinator_two_clients_kex_round() {
        // Start coordinator on a random port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            // Accept 2 clients
            let (stream1, _) = listener.accept().await.unwrap();
            let (stream2, _) = listener.accept().await.unwrap();
            let mut streams = vec![stream1, stream2];

            // Coordinator's own message
            let local = b"coordinator_kex_data".to_vec();
            let messages =
                Coordinator::collect_kex_round(&mut streams, Some(&local), Duration::from_secs(5))
                    .await
                    .unwrap();

            assert_eq!(messages.len(), 3); // 1 local + 2 clients
            messages
        });

        // Give the server a moment to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Client 1
        let addr_str = addr.to_string();
        let client1 = tokio::spawn({
            let addr = addr_str.clone();
            async move {
                let mut client = SignerClient::connect(&addr).await.unwrap();
                client.send_kex(b"client1_kex_data").await.unwrap();
                let round_msgs = client.receive_kex_round().await.unwrap();
                assert_eq!(round_msgs.len(), 3);
                round_msgs
            }
        });

        // Client 2
        let client2 = tokio::spawn({
            let addr = addr_str;
            async move {
                let mut client = SignerClient::connect(&addr).await.unwrap();
                client.send_kex(b"client2_kex_data").await.unwrap();
                let round_msgs = client.receive_kex_round().await.unwrap();
                assert_eq!(round_msgs.len(), 3);
                round_msgs
            }
        });

        let server_msgs = server.await.unwrap();
        let client1_msgs = client1.await.unwrap();
        let client2_msgs = client2.await.unwrap();

        // All participants see the same messages
        assert_eq!(client1_msgs, client2_msgs);
        // Server collected 3 messages
        assert_eq!(server_msgs.len(), 3);
    }

    #[tokio::test]
    async fn coordinator_tx_set_exchange() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream1, _) = listener.accept().await.unwrap();
            let (stream2, _) = listener.accept().await.unwrap();
            let mut streams = vec![stream1, stream2];

            // Client 0 (index 0) is the proposer
            let tx_data = Coordinator::exchange_tx_set(&mut streams, 0, Duration::from_secs(5))
                .await
                .unwrap();

            assert_eq!(tx_data, b"test_tx_set_binary_data");
            tx_data
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let addr_str = addr.to_string();

        // Client 1 (proposer) sends TX set
        let proposer = tokio::spawn({
            let addr = addr_str.clone();
            async move {
                let mut client = SignerClient::connect(&addr).await.unwrap();
                client.send_tx_set(b"test_tx_set_binary_data").await.unwrap();
                // Proposer also receives the broadcast
                let received = client.receive_tx_set().await.unwrap();
                assert_eq!(received, b"test_tx_set_binary_data");
            }
        });

        // Client 2 receives TX set
        let signer = tokio::spawn({
            let addr = addr_str;
            async move {
                let mut client = SignerClient::connect(&addr).await.unwrap();
                let received = client.receive_tx_set().await.unwrap();
                assert_eq!(received, b"test_tx_set_binary_data");
            }
        });

        server.await.unwrap();
        proposer.await.unwrap();
        signer.await.unwrap();
    }

    #[tokio::test]
    async fn coordinator_timeout() {
        let config = CoordinatorConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            expected_signers: 5, // Expect 4 clients, but none will connect
            timeout: Duration::from_millis(100),
        };
        let coordinator = Coordinator::new(config);
        let result = coordinator.accept_signers().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timed out"));
    }
}
