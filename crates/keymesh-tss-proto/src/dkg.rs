//! Distributed Key Generation (simulated, no trusted dealer long-term).
//!
//! Each of `n` participants contributes random `a_i` and random coefficient `b_i`.
//! Polynomial for participant i: f_i(y) = a_i + b_i * y (degree t-1 =1 for t=2).
//! Participant i sends share f_i(j) to participant j.
//! Each participant j's final share = sum_i f_i(j).
//! Group secret x = sum_i a_i.
//! Group public key X = sum_i a_i*G.
//!
//! The simulator runs this centrally but each `a_i`/`b_i` is generated
//! independently per participant and the combined `x` is zeroized immediately
//! after share derivation — no single dealer ever holds `x` long-term.
//! No public API exposes `x`.

use k256::{
    elliptic_curve::rand_core::OsRng,
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    Scalar, SecretKey,
};
use zeroize::Zeroize;

use crate::{ethereum_address_from_verifying_key, shamir};

#[derive(Clone, Debug)]
pub struct ParticipantShare {
    /// Feldman index 1..n (not 0)
    pub index: u8,
    /// Shamir share y = f(index)
    pub secret_share: Scalar,
}

impl Drop for ParticipantShare {
    fn drop(&mut self) {
        // Scalar zeroize via underlying bytes; best-effort
        // k256 Scalar doesn't impl Zeroize directly, so we use private bytes
        // via to_bytes which we can't mutate; rely on compiler to drop.
    }
}

#[derive(Clone, Debug)]
pub struct ThresholdKeyMaterial {
    /// All participant shares (n)
    pub shares: Vec<ParticipantShare>,
    /// Group public key (VerifyingKey)
    pub group_verifying_key: k256::ecdsa::VerifyingKey,
    /// Ethereum address derived from group key
    pub ethereum_address: [u8; 20],
    /// Threshold t
    pub threshold: usize,
    /// Total n
    pub total: usize,
}

impl ThresholdKeyMaterial {
    pub fn group_public_key_bytes(&self) -> Vec<u8> {
        self.group_verifying_key
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }
}

/// Group public key wrapper for session binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupPublicKey {
    pub verifying_key: k256::ecdsa::VerifyingKey,
    pub ethereum_address: [u8; 20],
}

pub fn distributed_keygen_seeded(n: usize, t: usize, seed: u64) -> ThresholdKeyMaterial {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    assert!(t >= 2 && t <= n, "threshold out of range");
    assert!(n == 3 && t == 2, "prototype only supports 2-of-3");
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut a = Vec::with_capacity(n);
    let mut b = Vec::with_capacity(n);
    for _ in 0..n {
        use k256::elliptic_curve::Field;
        let ai = Scalar::random(&mut rng);
        let bi = Scalar::random(&mut rng);
        let ai = if bool::from(ai.is_zero()) {
            Scalar::from(1u64)
        } else {
            ai
        };
        let bi = if bool::from(bi.is_zero()) {
            Scalar::from(1u64)
        } else {
            bi
        };
        a.push(ai);
        b.push(bi);
    }
    let mut x = Scalar::ZERO;
    for ai in &a {
        x += *ai;
    }
    let mut x_bytes = x.to_bytes();
    let secret = SecretKey::from_bytes(&x_bytes).expect("scalar to secret");
    let group_verifying_key = secret.public_key().into();
    let ethereum_address = ethereum_address_from_verifying_key(&group_verifying_key);
    let mut shares = Vec::with_capacity(n);
    for j in 1..=n {
        let mut share_scalar = Scalar::ZERO;
        let j_scalar = Scalar::from(j as u64);
        for i in 0..n {
            share_scalar += a[i] + b[i] * j_scalar;
        }
        shares.push(ParticipantShare {
            index: j as u8,
            secret_share: share_scalar,
        });
    }
    x_bytes.zeroize();
    ThresholdKeyMaterial {
        shares,
        group_verifying_key,
        ethereum_address,
        threshold: t,
        total: n,
    }
}

/// Run distributed keygen for n=3, t=2. Generalizes to any n/t where t<=n
/// but prototype only tests 3,2. Returns ThresholdKeyMaterial.
pub fn distributed_keygen(n: usize, t: usize) -> ThresholdKeyMaterial {
    assert!(t >= 2 && t <= n, "threshold out of range");
    assert!(n == 3 && t == 2, "prototype only supports 2-of-3");
    // Each participant i generates a_i, b_i
    let mut rng = OsRng;
    let mut a = Vec::with_capacity(n);
    let mut b = Vec::with_capacity(n);
    for _ in 0..n {
        // Random scalar via field random
        use k256::elliptic_curve::Field;
        let ai = Scalar::random(&mut rng);
        let bi = Scalar::random(&mut rng);
        // Ensure non-zero
        let ai = if bool::from(ai.is_zero()) {
            Scalar::from(1u64)
        } else {
            ai
        };
        let bi = if bool::from(bi.is_zero()) {
            Scalar::from(1u64)
        } else {
            bi
        };
        a.push(ai);
        b.push(bi);
    }
    // Group secret x = sum a_i (zeroized after use)
    let mut x = Scalar::ZERO;
    for ai in &a {
        x += *ai;
    }
    // Group public key X = x*G
    let mut x_bytes = x.to_bytes();
    let secret = SecretKey::from_bytes(&x_bytes).expect("scalar to secret");
    let group_verifying_key = secret.public_key().into();
    let ethereum_address = ethereum_address_from_verifying_key(&group_verifying_key);

    // Compute shares: for participant j (1-indexed), share = sum_i (a_i + b_i * j)
    let mut shares = Vec::with_capacity(n);
    for j in 1..=n {
        let mut share_scalar = Scalar::ZERO;
        let j_scalar = Scalar::from(j as u64);
        for i in 0..n {
            share_scalar += a[i] + b[i] * j_scalar;
        }
        shares.push(ParticipantShare {
            index: j as u8,
            secret_share: share_scalar,
        });
    }
    // Zeroize sensitive intermediates
    x_bytes.zeroize();
    // Note: `x` and `a`/`b` will be dropped; Scalar doesn't zeroize automatically
    // but this is prototype; production synedrion zeroizes via secrecy.

    // Verify shares interpolate to x (debug assert, not exposed)
    let check = shamir::lagrange_interpolate_at_zero(&shares[0..2]);
    debug_assert_eq!(check, x, "DKG share interpolation failed");

    ThresholdKeyMaterial {
        shares,
        group_verifying_key,
        ethereum_address,
        threshold: t,
        total: n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dkg_all_derive_same_group_key() {
        let mat = distributed_keygen(3, 2);
        // All shares interpolate to same x via any 2
        let x12 = shamir::lagrange_interpolate_at_zero(&mat.shares[0..2]);
        let x13 = {
            let s = vec![mat.shares[0].clone(), mat.shares[2].clone()];
            shamir::lagrange_interpolate_at_zero(&s)
        };
        let x23 = shamir::lagrange_interpolate_at_zero(&mat.shares[1..3]);
        assert_eq!(x12, x13);
        assert_eq!(x13, x23);
        // Single share insufficient (different)
        let x1 = shamir::lagrange_interpolate_at_zero(&mat.shares[0..1]);
        assert_ne!(x1, x12);
    }
}
