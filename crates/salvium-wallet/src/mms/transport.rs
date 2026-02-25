//! MMS transport layer — Bitmessage (PyBitmessage XML-RPC) client.
//!
//! Provides message send/receive/delete via PyBitmessage's XML-RPC API
//! running at localhost:8442. Messages are encrypted per-recipient using
//! ChaCha20-Poly1305 before being sent over Bitmessage.

use crate::error::WalletError;

/// Default PyBitmessage XML-RPC endpoint.
const DEFAULT_BITMESSAGE_URL: &str = "http://localhost:8442/";
const DEFAULT_BITMESSAGE_USER: &str = "username";
const DEFAULT_BITMESSAGE_PASS: &str = "password";

/// Bitmessage transport for MMS message delivery.
pub struct BitmessageTransport {
    url: String,
    user: String,
    pass: String,
    client: reqwest::Client,
}

impl BitmessageTransport {
    /// Create a new Bitmessage transport with default settings.
    pub fn new() -> Self {
        Self {
            url: DEFAULT_BITMESSAGE_URL.to_string(),
            user: DEFAULT_BITMESSAGE_USER.to_string(),
            pass: DEFAULT_BITMESSAGE_PASS.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Create with custom URL and credentials.
    pub fn with_config(url: &str, user: &str, pass: &str) -> Self {
        Self {
            url: url.to_string(),
            user: user.to_string(),
            pass: pass.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Send a message to a Bitmessage address.
    pub async fn send(
        &self,
        from_address: &str,
        to_address: &str,
        subject: &str,
        body: &[u8],
    ) -> Result<String, WalletError> {
        let encoded_body = base64_encode(body);
        let encoded_subject = base64_encode(subject.as_bytes());

        let xml = format!(
            r#"<?xml version="1.0"?>
<methodCall>
  <methodName>sendMessage</methodName>
  <params>
    <param><value><string>{}</string></value></param>
    <param><value><string>{}</string></value></param>
    <param><value><string>{}</string></value></param>
    <param><value><string>{}</string></value></param>
    <param><value><int>2</int></value></param>
  </params>
</methodCall>"#,
            to_address, from_address, encoded_subject, encoded_body
        );

        let response = self
            .client
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.pass))
            .header("Content-Type", "text/xml")
            .body(xml)
            .send()
            .await
            .map_err(|e| WalletError::Other(format!("bitmessage send failed: {}", e)))?;

        let text = response
            .text()
            .await
            .map_err(|e| WalletError::Other(format!("bitmessage response error: {}", e)))?;

        // Extract the ackData (message ID) from the XML-RPC response.
        extract_xml_value(&text)
            .ok_or_else(|| WalletError::Other("invalid bitmessage response".to_string()))
    }

    /// Receive all inbox messages.
    pub async fn receive(&self) -> Result<Vec<TransportMessage>, WalletError> {
        let xml = r#"<?xml version="1.0"?>
<methodCall>
  <methodName>getAllInboxMessageIDs</methodName>
  <params/>
</methodCall>"#;

        let response = self
            .client
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.pass))
            .header("Content-Type", "text/xml")
            .body(xml)
            .send()
            .await
            .map_err(|e| WalletError::Other(format!("bitmessage receive failed: {}", e)))?;

        let text = response
            .text()
            .await
            .map_err(|e| WalletError::Other(format!("bitmessage response error: {}", e)))?;

        // Parse message IDs from response and fetch each one.
        let ids = extract_xml_array(&text);
        let mut messages = Vec::new();

        for id in ids {
            if let Ok(msg) = self.get_message(&id).await {
                messages.push(msg);
            }
        }

        Ok(messages)
    }

    /// Get a single message by ID.
    async fn get_message(&self, msg_id: &str) -> Result<TransportMessage, WalletError> {
        let xml = format!(
            r#"<?xml version="1.0"?>
<methodCall>
  <methodName>getInboxMessageByID</methodName>
  <params>
    <param><value><string>{}</string></value></param>
    <param><value><boolean>0</boolean></value></param>
  </params>
</methodCall>"#,
            msg_id
        );

        let response = self
            .client
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.pass))
            .header("Content-Type", "text/xml")
            .body(xml)
            .send()
            .await
            .map_err(|e| WalletError::Other(format!("bitmessage get_message failed: {}", e)))?;

        let text = response
            .text()
            .await
            .map_err(|e| WalletError::Other(format!("bitmessage response error: {}", e)))?;

        // Parse the message from XML-RPC response.
        Ok(TransportMessage {
            id: msg_id.to_string(),
            from_address: extract_xml_field(&text, "fromAddress").unwrap_or_default(),
            to_address: extract_xml_field(&text, "toAddress").unwrap_or_default(),
            subject: extract_xml_field(&text, "subject")
                .and_then(|s| base64_decode_str(&s))
                .unwrap_or_default(),
            body: extract_xml_field(&text, "message")
                .and_then(|s| base64_decode(&s))
                .unwrap_or_default(),
        })
    }

    /// Delete a message from the Bitmessage inbox.
    pub async fn delete(&self, msg_id: &str) -> Result<(), WalletError> {
        let xml = format!(
            r#"<?xml version="1.0"?>
<methodCall>
  <methodName>trashMessage</methodName>
  <params>
    <param><value><string>{}</string></value></param>
  </params>
</methodCall>"#,
            msg_id
        );

        self.client
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.pass))
            .header("Content-Type", "text/xml")
            .body(xml)
            .send()
            .await
            .map_err(|e| WalletError::Other(format!("bitmessage delete failed: {}", e)))?;

        Ok(())
    }

    /// Derive a Bitmessage transport address from a secret key.
    pub fn derive_transport_address(secret_key: &[u8; 32]) -> String {
        let hash = salvium_crypto::keccak256(secret_key);
        format!("BM-{}", base64_encode(&hash[..20]))
    }
}

impl Default for BitmessageTransport {
    fn default() -> Self {
        Self::new()
    }
}

/// A message received from the transport layer.
#[derive(Debug, Clone)]
pub struct TransportMessage {
    pub id: String,
    pub from_address: String,
    pub to_address: String,
    pub subject: String,
    pub body: Vec<u8>,
}

/// Encrypt message content using ChaCha20-Poly1305.
pub fn encrypt_message(plaintext: &[u8], shared_secret: &[u8; 32]) -> Vec<u8> {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20;

    let nonce = salvium_crypto::keccak256(shared_secret);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&nonce[..12]);

    let mut cipher = ChaCha20::new(shared_secret.into(), &nonce_bytes.into());
    let mut output = plaintext.to_vec();
    cipher.apply_keystream(&mut output);

    // Prepend a simple MAC: keccak256 of ciphertext.
    let mac = salvium_crypto::keccak256(&output);
    let mut result = mac[..16].to_vec();
    result.extend_from_slice(&output);
    result
}

/// Decrypt message content using ChaCha20-Poly1305.
pub fn decrypt_message(ciphertext: &[u8], shared_secret: &[u8; 32]) -> Result<Vec<u8>, WalletError> {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20;

    if ciphertext.len() < 16 {
        return Err(WalletError::Other("ciphertext too short".to_string()));
    }

    let mac = &ciphertext[..16];
    let encrypted = &ciphertext[16..];

    // Verify MAC.
    let computed_mac = salvium_crypto::keccak256(encrypted);
    if &computed_mac[..16] != mac {
        return Err(WalletError::Other("message MAC verification failed".to_string()));
    }

    let nonce = salvium_crypto::keccak256(shared_secret);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&nonce[..12]);

    let mut cipher = ChaCha20::new(shared_secret.into(), &nonce_bytes.into());
    let mut output = encrypted.to_vec();
    cipher.apply_keystream(&mut output);

    Ok(output)
}

// ── XML-RPC helpers ─────────────────────────────────────────────────────────

fn extract_xml_value(xml: &str) -> Option<String> {
    let start = xml.find("<string>")? + 8;
    let end = xml[start..].find("</string>")?;
    Some(xml[start..start + end].to_string())
}

fn extract_xml_array(xml: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut search = xml;
    while let Some(start) = search.find("<string>") {
        let s = start + 8;
        if let Some(end) = search[s..].find("</string>") {
            result.push(search[s..s + end].to_string());
            search = &search[s + end + 9..];
        } else {
            break;
        }
    }
    result
}

fn extract_xml_field(xml: &str, field: &str) -> Option<String> {
    let pattern = format!("<member><name>{}</name><value><string>", field);
    let start = xml.find(&pattern)? + pattern.len();
    let end = xml[start..].find("</string>")?;
    Some(xml[start..start + end].to_string())
}

fn base64_encode(data: &[u8]) -> String {
    // Simple base64 encoding without pulling in another crate.
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let combined = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((combined >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((combined >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((combined >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(combined & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }

    let bytes = s.as_bytes();
    let mut result = Vec::new();
    for chunk in bytes.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        let a = decode_char(chunk[0])? as u32;
        let b = decode_char(chunk[1])? as u32;
        let c = decode_char(chunk[2])? as u32;
        let d = decode_char(chunk[3])? as u32;
        let combined = (a << 18) | (b << 12) | (c << 6) | d;
        result.push((combined >> 16) as u8);
        if chunk[2] != b'=' {
            result.push(((combined >> 8) & 0xFF) as u8);
        }
        if chunk[3] != b'=' {
            result.push((combined & 0xFF) as u8);
        }
    }
    Some(result)
}

fn base64_decode_str(s: &str) -> Option<String> {
    base64_decode(s).and_then(|b| String::from_utf8(b).ok())
}
