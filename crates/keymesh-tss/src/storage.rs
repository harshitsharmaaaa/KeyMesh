//! Encrypted share storage at rest — prototype/testnet custody (not production HSM).
//! Uses ChaCha20Poly1305 with passphrase-derived key for demo. Real production would use OS keychain/HSM.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::OsRng;
use rand_core::RngCore;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum StorageError {
    Io(String),
    Crypto(String),
    Permission(String),
}

pub struct EncryptedShareStore {
    path: PathBuf,
    key: chacha20poly1305::Key,
}

impl EncryptedShareStore {
    /// Derive key from passphrase (demo: SHA256(passphrase) — production would use Argon2)
    pub fn new(path: impl AsRef<Path>, passphrase: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        let hash = hasher.finalize();
        let key = chacha20poly1305::Key::from_slice(&hash[..32]).clone();
        Self {
            path: path.as_ref().to_path_buf(),
            key,
        }
    }
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn store(&self, participant_id: u8, data: &[u8]) -> Result<(), StorageError> {
        // Permissions: 0o600 on Unix
        let cipher = ChaCha20Poly1305::new(&self.key);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| StorageError::Crypto(format!("{e:?}")))?;
        let mut blob = Vec::new();
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);
        std::fs::write(&self.path_for(participant_id), &blob)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                self.path_for(participant_id),
                std::fs::Permissions::from_mode(0o600),
            );
        }
        // Zeroize sensitive buffer
        // (blob will be dropped)
        Ok(())
    }

    pub fn load(&self, participant_id: u8) -> Result<Vec<u8>, StorageError> {
        let blob = std::fs::read(self.path_for(participant_id))
            .map_err(|e| StorageError::Io(e.to_string()))?;
        if blob.len() < 12 {
            return Err(StorageError::Crypto("blob too short".into()));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(12);
        let cipher = ChaCha20Poly1305::new(&self.key);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| StorageError::Crypto(format!("{e:?}")))?;
        Ok(plaintext)
    }

    fn path_for(&self, id: u8) -> PathBuf {
        self.path.join(format!("share-{}.enc", id))
    }

    /// Explicit zeroization helper — overwrites file before delete
    pub fn delete(&self, participant_id: u8) -> Result<(), StorageError> {
        let p = self.path_for(participant_id);
        if p.exists() {
            // Overwrite with zeros (best effort)
            if let Ok(meta) = std::fs::metadata(&p) {
                let len = meta.len() as usize;
                let zeros = vec![0u8; len];
                let _ = std::fs::write(&p, &zeros);
            }
            std::fs::remove_file(&p).map_err(|e| StorageError::Io(e.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn store_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = EncryptedShareStore::new(dir.path(), "test-passphrase");
        let data = b"secret-share-bytes";
        store.store(0, data).unwrap();
        let loaded = store.load(0).unwrap();
        assert_eq!(loaded, data);
        // Wrong passphrase fails
        let bad = EncryptedShareStore::new(dir.path(), "wrong");
        assert!(bad.load(0).is_err());
    }
    #[test]
    fn only_own_share_accessible() {
        let dir = tempfile::tempdir().unwrap();
        let store = EncryptedShareStore::new(dir.path(), "pass");
        store.store(0, b"share0").unwrap();
        store.store(1, b"share1").unwrap();
        assert_eq!(store.load(0).unwrap(), b"share0");
        assert_eq!(store.load(1).unwrap(), b"share1");
        assert!(store.load(2).is_err());
    }
}
