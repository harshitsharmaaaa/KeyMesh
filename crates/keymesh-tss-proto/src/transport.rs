//! In-process transport simulator — allows delay/drop/duplicate/reorder/modify.
//! For Phase 2.2 failure injection; not a production networking layer.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportMessage {
    pub session_id: [u8; 32],
    pub sender: u8,
    pub round: u8,
    pub payload: Vec<u8>,
    pub digest: [u8; 32],
}

pub struct SimulatedTransport {
    messages: Vec<TransportMessage>,
}

impl SimulatedTransport {
    pub fn new() -> Self {
        Self { messages: vec![] }
    }
    pub fn send(&mut self, msg: TransportMessage) {
        self.messages.push(msg);
    }
    /// Drop all messages from sender
    pub fn drop_from(&mut self, sender: u8) {
        self.messages.retain(|m| m.sender != sender);
    }
    /// Duplicate first message
    pub fn duplicate_first(&mut self) {
        if let Some(first) = self.messages.first().cloned() {
            self.messages.push(first);
        }
    }
    /// Reorder: swap first two
    pub fn reorder(&mut self) {
        if self.messages.len() >= 2 {
            self.messages.swap(0, 1);
        }
    }
    /// Modify digest (simulates substitution attack)
    pub fn modify_first_digest(&mut self, new_digest: [u8; 32]) {
        if let Some(first) = self.messages.first_mut() {
            first.digest = new_digest;
        }
    }
    /// Verify all messages belong to expected session and digest; detect mismatches
    pub fn verify_binding(
        &self,
        expected_session: &[u8; 32],
        expected_digest: &[u8; 32],
    ) -> Result<(), String> {
        for m in &self.messages {
            if &m.session_id != expected_session {
                return Err(format!("session mismatch from {}", m.sender));
            }
            if &m.digest != expected_digest {
                return Err(format!("digest mismatch from {}", m.sender));
            }
        }
        Ok(())
    }
    /// Check no duplicate (sender,round)
    pub fn check_no_duplicate(&self) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        for m in &self.messages {
            let key = (m.sender, m.round);
            if !seen.insert(key) {
                return Err(format!("duplicate round {} from {}", m.round, m.sender));
            }
        }
        Ok(())
    }
    /// Check round ordering 1..n
    pub fn check_round_order(&self) -> Result<(), String> {
        for m in &self.messages {
            if m.round == 0 || m.round > 3 {
                return Err(format!("invalid round {}", m.round));
            }
        }
        Ok(())
    }
    pub fn len(&self) -> usize {
        self.messages.len()
    }
}
