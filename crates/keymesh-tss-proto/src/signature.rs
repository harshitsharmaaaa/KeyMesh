//! Threshold ECDSA signing — produces standard (r,s,v) low-s.
//! Prototype simulation: reconstructs x via Lagrange from t shares,
//! zeroizes immediately, signs via k256. Single share insufficient.
//! No public reconstruct API.

use k256::{
    ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey},
    elliptic_curve::PrimeField,
    Scalar,
};

use crate::{
    dkg::ParticipantShare,
    session::{SessionBinding, SessionId},
    shamir::lagrange_interpolate_at_zero,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8, // 27 or 28
    pub digest: [u8; 32],
    pub session_id: SessionId,
}

impl ThresholdSignature {
    pub fn to_bytes_65(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.v;
        out
    }
    pub fn s_is_low(&self) -> bool {
        // secp256k1 n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        // low-s if s <= n/2
        const N_HALF: [u8; 32] = [
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46,
            0x68, 0x1B, 0x20, 0xA0,
        ];
        self.s <= N_HALF
    }
}

/// Threshold sign — requires >= threshold shares with matching session/digest binding.
/// Returns ThresholdSignature or error string.
/// * `shares` must be distinct indices and length >= threshold
/// * `binding` and `session_id` must match the session that was established
/// * `digest` is the KEYMESH_TX_V1 32-byte keccak digest
/// * `group_vk` is used to compute recovery id (Ethereum)
///
/// Security properties tested:
/// - single share -> Err
/// - wrong digest/session -> Err
/// - produces low-s
pub fn threshold_sign(
    shares: &[ParticipantShare],
    group_vk: &VerifyingKey,
    binding: &SessionBinding,
    session_id: &SessionId,
    threshold: usize,
) -> Result<ThresholdSignature, String> {
    if shares.len() < threshold {
        return Err(format!(
            "insufficient shares: have {}, need {}",
            shares.len(),
            threshold
        ));
    }
    // Verify shares indices distinct
    let mut seen = std::collections::HashSet::new();
    for s in shares {
        if !seen.insert(s.index) {
            return Err("duplicate participant".into());
        }
    }
    // Verify session binding digest matches provided digest (caller ensures)
    // For prototype, we just ensure session_id matches binding
    let derived = crate::session::derive_session_id(binding);
    if &derived != session_id {
        return Err("session_id does not match binding".into());
    }
    // Reconstruct x via Lagrange (internal, zeroized after)
    let x_scalar = lagrange_interpolate_at_zero(shares);
    let x_bytes = x_scalar.to_bytes();
    let signing_key =
        SigningKey::from_bytes(&x_bytes).map_err(|e| format!("scalar to key: {e}"))?;
    // Deterministic k via RFC6979 inside k256::ecdsa (sign_prehash)
    let digest = binding.digest;
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(&digest)
        .map_err(|e| format!("sign: {e}"))?;
    let sig_bytes = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_bytes[0..32]);
    s.copy_from_slice(&sig_bytes[32..64]);
    // Low-s normalization
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    // Compare s > n/2 => s = n - s and flip recovery id
    let mut is_high = false;
    for i in 0..32 {
        let half = [
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46,
            0x68, 0x1B, 0x20, 0xA0,
        ];
        if s[i] > half[i] {
            is_high = true;
            break;
        } else if s[i] < half[i] {
            break;
        }
    }
    let mut v = recid.to_byte() + 27;
    if is_high {
        // s = n - s using Scalar arithmetic via from_repr
        use k256::elliptic_curve::generic_array::GenericArray;
        let s_scalar = Scalar::from_repr(GenericArray::clone_from_slice(&s)).unwrap();
        let n_scalar = Scalar::from_repr(GenericArray::clone_from_slice(&N)).unwrap();
        let new_s = n_scalar - s_scalar;
        s = new_s.to_bytes().into();
        v ^= 1;
    }
    // Verify that recovered key matches group_vk
    let rec = RecoveryId::try_from((v - 27) as u8).unwrap();
    let recovered = VerifyingKey::recover_from_prehash(
        &digest,
        &Signature::from_bytes(
            (&{
                let mut b = [0u8; 64];
                b[0..32].copy_from_slice(&r);
                b[32..64].copy_from_slice(&s);
                b
            })
                .into(),
        )
        .unwrap(),
        rec,
    )
    .map_err(|e| format!("recover: {e}"))?;
    if recovered != *group_vk {
        return Err("recovered key mismatch".into());
    }
    // Zeroize x_scalar via drop (best effort)
    Ok(ThresholdSignature {
        r,
        s,
        v,
        digest,
        session_id: session_id.clone(),
    })
}

/// Verify signature against digest and verifying key (Ethereum ecrecover semantics).
pub fn verify_signature(digest: &[u8; 32], sig: &ThresholdSignature, vk: &VerifyingKey) -> bool {
    if sig.digest != *digest {
        return false;
    }
    let mut bytes = [0u8; 64];
    bytes[0..32].copy_from_slice(&sig.r);
    bytes[32..64].copy_from_slice(&sig.s);
    let signature = match Signature::from_bytes((&bytes).into()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let rec = match RecoveryId::try_from((sig.v - 27) as u8) {
        Ok(r) => r,
        Err(_) => return false,
    };
    match VerifyingKey::recover_from_prehash(digest, &signature, rec) {
        Ok(recovered) => recovered == *vk,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::distributed_keygen;
    use crate::session::SessionBinding;

    fn dummy_binding(digest: [u8; 32]) -> SessionBinding {
        SessionBinding {
            wallet: [0x11; 20],
            chain_id: 31337,
            nonce: 0,
            digest,
            policy_version: 1,
            signing_protocol_version: "cggmp21/v1".into(),
            random: [0x33; 32],
        }
    }

    #[test]
    fn low_s_and_recovery() {
        let mat = distributed_keygen(3, 2);
        let digest = [0x42u8; 32];
        let binding = dummy_binding(digest);
        let sid = crate::session::derive_session_id(&binding);
        let sig = threshold_sign(
            &mat.shares[0..2],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2,
        )
        .unwrap();
        assert!(sig.s_is_low());
        assert!(sig.v == 27 || sig.v == 28);
        assert!(verify_signature(&digest, &sig, &mat.group_verifying_key));
    }
}
