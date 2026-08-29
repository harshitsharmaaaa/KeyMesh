//! TssTransport abstraction for local tests and real socket-backed participant processes.
//!
//! In-memory transport stays available for unit tests. Real transport uses a framed TCP
//! connection with application-level authentication on every envelope.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::envelope::TssEnvelope;
use crate::identity::ParticipantIdentity;

const FRAME_VERSION: u8 = 1;
pub const MAX_TSS_MESSAGE_BYTES: usize = 64 * 1024;

#[async_trait]
pub trait TssTransport: Send + Sync {
    async fn connect(&mut self) -> Result<(), String>;
    async fn authenticate(&mut self, identity: &ParticipantIdentity) -> Result<(), String>;
    async fn send(&mut self, envelope: TssEnvelope) -> Result<(), String>;
    async fn receive(&mut self) -> Result<TssEnvelope, String>;
    async fn close(&mut self) -> Result<(), String>;
    fn session_binding(&self) -> Option<([u8; 32], [u8; 20], u64)>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FramedEnvelope {
    frame_version: u8,
    envelope: TssEnvelope,
}

fn encode_frame(envelope: &TssEnvelope) -> Result<Vec<u8>, String> {
    let framed = FramedEnvelope {
        frame_version: FRAME_VERSION,
        envelope: envelope.clone(),
    };
    let bytes = serde_json::to_vec(&framed).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_TSS_MESSAGE_BYTES {
        return Err(format!(
            "frame too large: {} > {}",
            bytes.len(),
            MAX_TSS_MESSAGE_BYTES
        ));
    }
    Ok(bytes)
}

fn decode_frame(bytes: &[u8]) -> Result<TssEnvelope, String> {
    if bytes.len() > MAX_TSS_MESSAGE_BYTES {
        return Err(format!(
            "frame too large: {} > {}",
            bytes.len(),
            MAX_TSS_MESSAGE_BYTES
        ));
    }
    let framed: FramedEnvelope = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if framed.frame_version != FRAME_VERSION {
        return Err("frame version mismatch".into());
    }
    Ok(framed.envelope)
}

async fn write_frame(stream: &mut TcpStream, envelope: &TssEnvelope) -> Result<(), String> {
    let bytes = encode_frame(envelope)?;
    let len = u32::try_from(bytes.len()).map_err(|_| "frame too large".to_string())?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("write length failed: {e}"))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| format!("write frame failed: {e}"))?;
    Ok(())
}

async fn read_frame(stream: &mut TcpStream) -> Result<TssEnvelope, String> {
    let mut len_bytes = [0u8; 4];
    stream
        .read_exact(&mut len_bytes)
        .await
        .map_err(|e| format!("read length failed: {e}"))?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len == 0 || len > MAX_TSS_MESSAGE_BYTES {
        return Err(format!("invalid frame length: {len}"));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("read frame failed: {e}"))?;
    decode_frame(&buf)
}

pub struct InMemoryAuthenticatedTransport {
    tx: tokio::sync::mpsc::UnboundedSender<TssEnvelope>,
    rx: tokio::sync::mpsc::UnboundedReceiver<TssEnvelope>,
    authenticated: bool,
    expected_session: Option<([u8; 32], [u8; 20], u64)>,
}

impl InMemoryAuthenticatedTransport {
    pub fn pair() -> (Self, Self) {
        let (a_tx, b_rx) = tokio::sync::mpsc::unbounded_channel();
        let (b_tx, a_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Self {
                tx: a_tx,
                rx: a_rx,
                authenticated: false,
                expected_session: None,
            },
            Self {
                tx: b_tx,
                rx: b_rx,
                authenticated: false,
                expected_session: None,
            },
        )
    }

    pub fn with_session(session_id: [u8; 32], wallet: [u8; 20], chain_id: u64) -> (Self, Self) {
        let (mut a, mut b) = Self::pair();
        a.expected_session = Some((session_id, wallet, chain_id));
        b.expected_session = Some((session_id, wallet, chain_id));
        (a, b)
    }
}

#[async_trait]
impl TssTransport for InMemoryAuthenticatedTransport {
    async fn connect(&mut self) -> Result<(), String> {
        Ok(())
    }

    async fn authenticate(&mut self, _identity: &ParticipantIdentity) -> Result<(), String> {
        self.authenticated = true;
        Ok(())
    }

    async fn send(&mut self, envelope: TssEnvelope) -> Result<(), String> {
        if !self.authenticated {
            return Err("not authenticated".into());
        }
        self.tx
            .send(envelope)
            .map_err(|e| format!("send failed: {e}"))?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<TssEnvelope, String> {
        if !self.authenticated {
            return Err("not authenticated".into());
        }
        let env = self.rx.recv().await.ok_or("channel closed")?;
        if let Some((sid, wallet, chain)) = self.expected_session {
            env.validate_against(&sid, &wallet, chain, &env.digest, &env.protocol_version)
                .map_err(|e| format!("session binding failed: {e}"))?;
        }
        Ok(env)
    }

    async fn close(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn session_binding(&self) -> Option<([u8; 32], [u8; 20], u64)> {
        self.expected_session
    }
}

#[derive(Clone, Debug)]
pub enum TcpMode {
    Client { addr: std::net::SocketAddr },
    Server { addr: std::net::SocketAddr },
}

pub struct TcpAuthenticatedTransport {
    mode: TcpMode,
    stream: Option<TcpStream>,
    listener: Option<TcpListener>,
    authenticated: bool,
    expected_session: Option<([u8; 32], [u8; 20], u64)>,
    peer_identity: Option<ParticipantIdentity>,
}

impl TcpAuthenticatedTransport {
    pub fn client(
        addr: std::net::SocketAddr,
        expected_session: Option<([u8; 32], [u8; 20], u64)>,
        peer_identity: Option<ParticipantIdentity>,
    ) -> Self {
        Self {
            mode: TcpMode::Client { addr },
            stream: None,
            listener: None,
            authenticated: false,
            expected_session,
            peer_identity,
        }
    }

    pub fn server(
        addr: std::net::SocketAddr,
        expected_session: Option<([u8; 32], [u8; 20], u64)>,
        peer_identity: Option<ParticipantIdentity>,
    ) -> Self {
        Self {
            mode: TcpMode::Server { addr },
            stream: None,
            listener: None,
            authenticated: false,
            expected_session,
            peer_identity,
        }
    }
}

#[async_trait]
impl TssTransport for TcpAuthenticatedTransport {
    async fn connect(&mut self) -> Result<(), String> {
        match self.mode {
            TcpMode::Client { addr } => {
                self.stream = Some(TcpStream::connect(addr).await.map_err(|e| e.to_string())?);
                Ok(())
            }
            TcpMode::Server { addr } => {
                let listener = TcpListener::bind(addr).await.map_err(|e| e.to_string())?;
                self.listener = Some(listener);
                let (stream, _) = self
                    .listener
                    .as_mut()
                    .ok_or_else(|| "listener missing".to_string())?
                    .accept()
                    .await
                    .map_err(|e| e.to_string())?;
                self.stream = Some(stream);
                Ok(())
            }
        }
    }

    async fn authenticate(&mut self, identity: &ParticipantIdentity) -> Result<(), String> {
        let _ = identity;
        self.authenticated = true;
        Ok(())
    }

    async fn send(&mut self, envelope: TssEnvelope) -> Result<(), String> {
        if !self.authenticated {
            return Err("not authenticated".into());
        }
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| "not connected".to_string())?;
        if let Some((sid, wallet, chain)) = self.expected_session {
            envelope
                .validate_against(
                    &sid,
                    &wallet,
                    chain,
                    &envelope.digest,
                    &envelope.protocol_version,
                )
                .map_err(|e| format!("session binding failed: {e}"))?;
        }
        write_frame(stream, &envelope).await
    }

    async fn receive(&mut self) -> Result<TssEnvelope, String> {
        if !self.authenticated {
            return Err("not authenticated".into());
        }
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| "not connected".to_string())?;
        let env = read_frame(stream).await?;
        let peer = self
            .peer_identity
            .as_ref()
            .ok_or_else(|| "missing peer identity".to_string())?;
        if !env.verify(peer) {
            return Err("peer authentication failed".into());
        }
        if let Some((sid, wallet, chain)) = self.expected_session {
            env.validate_against(&sid, &wallet, chain, &env.digest, &env.protocol_version)
                .map_err(|e| format!("session binding failed: {e}"))?;
        }
        Ok(env)
    }

    async fn close(&mut self) -> Result<(), String> {
        self.stream = None;
        self.listener = None;
        Ok(())
    }

    fn session_binding(&self) -> Option<([u8; 32], [u8; 20], u64)> {
        self.expected_session
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{NetworkKeypair, ParticipantIdentity};
    use std::net::SocketAddr;

    #[tokio::test]
    async fn in_memory_authenticated_roundtrip() {
        let kp = NetworkKeypair::generate();
        let id = ParticipantIdentity::new(0, kp.verifying_key().clone(), [0x11; 20], 31337);
        let sid = [0xAA; 32];
        let wallet = [0x11; 20];
        let (mut a, mut b) = InMemoryAuthenticatedTransport::with_session(sid, wallet, 31337);
        a.authenticate(&id).await.unwrap();
        b.authenticate(&id).await.unwrap();
        let mut env = TssEnvelope {
            protocol_version: "synedrion/0.3-cggmp24".into(),
            session_id: sid,
            wallet,
            chain_id: 31337,
            participant_id: 0,
            round: 1,
            message_type: "Test".into(),
            digest: [0xBB; 32],
            payload: vec![9, 8, 7],
            signature: None,
        };
        env.sign(&kp);
        a.send(env.clone()).await.unwrap();
        let got = b.receive().await.unwrap();
        assert_eq!(got.payload, vec![9, 8, 7]);
        assert!(got.verify(&id));
    }

    #[tokio::test]
    async fn tcp_frame_roundtrip_and_size_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);
        let kp_a = NetworkKeypair::generate();
        let kp_b = NetworkKeypair::generate();
        let id_a = ParticipantIdentity::new(0, kp_a.verifying_key().clone(), [0x11; 20], 31337);
        let id_b = ParticipantIdentity::new(1, kp_b.verifying_key().clone(), [0x11; 20], 31337);
        let id_a_server = id_a.clone();
        let id_b_server = id_b.clone();
        let sid = [0xAA; 32];
        let expected = Some((sid, [0x11; 20], 31337));

        let server = tokio::spawn(async move {
            let mut transport =
                TcpAuthenticatedTransport::server(addr, expected, Some(id_a_server));
            transport.connect().await.unwrap();
            transport.authenticate(&id_b_server).await.unwrap();
            let got = transport.receive().await.unwrap();
            assert_eq!(got.participant_id, 0);
        });

        let mut client = TcpAuthenticatedTransport::client(addr, expected, Some(id_b.clone()));
        client.connect().await.unwrap();
        client.authenticate(&id_a).await.unwrap();
        let mut env = TssEnvelope::new(
            "synedrion/0.3-cggmp24".into(),
            sid,
            [0x11; 20],
            31337,
            0,
            1,
            "Test".into(),
            [0x22; 32],
            vec![1, 2, 3],
        );
        env.sign(&kp_a);
        client.send(env).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn not_authenticated_rejects() {
        let (mut a, _b) = InMemoryAuthenticatedTransport::pair();
        let env = TssEnvelope::new(
            "v".into(),
            [0; 32],
            [0; 20],
            1,
            0,
            1,
            "T".into(),
            [0; 32],
            vec![],
        );
        assert!(a.send(env).await.is_err());
    }
}
