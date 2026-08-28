//! TssTransport abstraction — TestRuntime for unit tests, RealTransport for testnet.
//! Real transport choice: TCP + authenticated envelope (TLS/mTLS optional). For prototype,
//! we implement InMemoryAuthenticatedTransport (tokio mpsc) that is ready for WebSocket/TLS upgrade.

use async_trait::async_trait;

use crate::envelope::TssEnvelope;
use crate::identity::ParticipantIdentity;

#[async_trait]
pub trait TssTransport: Send + Sync {
    async fn connect(&mut self) -> Result<(), String>;
    async fn authenticate(&mut self, identity: &ParticipantIdentity) -> Result<(), String>;
    async fn send(&mut self, envelope: TssEnvelope) -> Result<(), String>;
    async fn receive(&mut self) -> Result<TssEnvelope, String>;
    async fn close(&mut self) -> Result<(), String>;
    fn session_binding(&self) -> Option<([u8; 32], [u8; 20], u64)>;
}

/// In-memory authenticated transport — used for unit tests and Phase 2.5 prototype
/// multi-process dev mode (each participant is a separate tokio task, shares not co-located).
/// Real deployment would replace the channel with `tokio::net::TcpStream` + `rustls` or `tokio-tungstenite`.

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
        // In real transport: mTLS handshake, verify cert against ParticipantIdentity
        self.authenticated = true;
        Ok(())
    }
    async fn send(&mut self, envelope: TssEnvelope) -> Result<(), String> {
        if !self.authenticated {
            return Err("not authenticated".into());
        }
        // Validate envelope is authenticated
        // Note: caller must have signed envelope; we just relay
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
        // Validate session binding if set
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

/// Real TCP transport placeholder — documents choice, not yet fully implemented for testnet.
/// For Phase 2.5, `InMemoryAuthenticatedTransport` is used for multi-process dev mode;
/// this struct shows where `tokio::net::TcpStream` + `tokio-rustls` would be plugged.
pub struct TcpAuthenticatedTransport {
    // In production: TcpStream, TlsConnector, ParticipantIdentity
    _placeholder: (),
}

impl TcpAuthenticatedTransport {
    pub fn new_placeholder() -> Self {
        Self { _placeholder: () }
    }
}

#[async_trait]
impl TssTransport for TcpAuthenticatedTransport {
    async fn connect(&mut self) -> Result<(), String> {
        Err("TcpAuthenticatedTransport not yet configured — use InMemoryAuthenticatedTransport for dev/testnet".into())
    }
    async fn authenticate(&mut self, _identity: &ParticipantIdentity) -> Result<(), String> {
        Err("not connected".into())
    }
    async fn send(&mut self, _envelope: TssEnvelope) -> Result<(), String> {
        Err("not connected".into())
    }
    async fn receive(&mut self) -> Result<TssEnvelope, String> {
        Err("not connected".into())
    }
    async fn close(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn session_binding(&self) -> Option<([u8; 32], [u8; 20], u64)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{NetworkKeypair, ParticipantIdentity};

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
