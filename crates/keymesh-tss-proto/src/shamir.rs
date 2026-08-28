//! Shamir 2-of-3 over secp256k1 scalar field.
//! For prototype only — not constant-time hardened.

use k256::Scalar;

use crate::dkg::ParticipantShare;

/// Lagrange interpolation at x=0 for given shares (x_i, y_i) where x_i = participant index (1..n).
/// Shares are assumed distinct x.
pub fn lagrange_interpolate_at_zero(shares: &[ParticipantShare]) -> Scalar {
    // x = 0
    let mut result = Scalar::ZERO;
    for (i, share) in shares.iter().enumerate() {
        let xi = Scalar::from(share.index as u64);
        // Lagrange basis l_i(0) = product_{j != i} (0 - xj) / (xi - xj) = product (-xj)/(xi - xj)
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for (j, other) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = Scalar::from(other.index as u64);
            numerator *= -xj;
            denominator *= xi - xj;
        }
        // denominator.invert() via invert().unwrap() — field element guaranteed non-zero for distinct indices
        let inv = denominator.invert().unwrap();
        let lagrange = numerator * inv;
        result += lagrange * share.secret_share;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::rand_core::OsRng;
    use rand::RngCore;

    #[test]
    fn shamir_2of3_reconstruct() {
        // Quick sanity: create polynomial f(y)=x + a*y, shares at 1,2,3
        let x = Scalar::from(42u64);
        let a = Scalar::from(7u64);
        let shares = vec![
            ParticipantShare {
                index: 1,
                secret_share: x + a * Scalar::from(1u64),
            },
            ParticipantShare {
                index: 2,
                secret_share: x + a * Scalar::from(2u64),
            },
            ParticipantShare {
                index: 3,
                secret_share: x + a * Scalar::from(3u64),
            },
        ];
        // Any 2 should reconstruct
        let r12 = lagrange_interpolate_at_zero(&shares[0..2]);
        let r13 = lagrange_interpolate_at_zero(&[shares[0].clone(), shares[2].clone()]);
        let r23 = lagrange_interpolate_at_zero(&shares[1..3]);
        assert_eq!(r12, x);
        assert_eq!(r13, x);
        assert_eq!(r23, x);
        // Single share should NOT reconstruct (generally different)
        let r1 = lagrange_interpolate_at_zero(&shares[0..1]);
        assert_ne!(r1, x);
    }
}
