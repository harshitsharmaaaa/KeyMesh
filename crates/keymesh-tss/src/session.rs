use tiny_keccak::{Hasher, Keccak};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionBinding {
    pub wallet: [u8; 20],
    pub chain_id: u64,
    pub nonce: u64,
    pub digest: [u8; 32],
    pub policy_version: u64,
    pub signing_protocol_version: String,
    pub random: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn write_u256_be(out: &mut Vec<u8>, v: u64) {
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&v.to_be_bytes());
    out.extend_from_slice(&buf);
}

pub fn derive_session_id(binding: &SessionBinding) -> SessionId {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&binding.wallet);
    write_u256_be(&mut preimage, binding.chain_id);
    write_u256_be(&mut preimage, binding.nonce);
    preimage.extend_from_slice(&binding.digest);
    write_u256_be(&mut preimage, binding.policy_version);
    preimage.extend_from_slice(binding.signing_protocol_version.as_bytes());
    preimage.extend_from_slice(&binding.random);
    let mut hasher = Keccak::v256();
    hasher.update(&preimage);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    SessionId(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigningSessionStatus {
    Started,
    Completed,
    Aborted,
    Failed,
}

#[derive(Clone, Debug)]
pub struct SigningSession {
    pub session_id: SessionId,
    pub binding: SessionBinding,
    pub participants: Vec<u8>,
    pub threshold: usize,
    pub status: SigningSessionStatus,
}

impl SigningSession {
    pub fn new(binding: SessionBinding, participants: Vec<u8>, threshold: usize) -> Self {
        let session_id = derive_session_id(&binding);
        Self {
            session_id,
            binding,
            participants,
            threshold,
            status: SigningSessionStatus::Started,
        }
    }
    pub fn transition(&mut self, to: SigningSessionStatus) -> Result<(), &'static str> {
        if self.status != SigningSessionStatus::Started {
            return Err("cannot transition from terminal");
        }
        if to == SigningSessionStatus::Started {
            return Err("cannot transition back to Started");
        }
        self.status = to;
        Ok(())
    }
}
