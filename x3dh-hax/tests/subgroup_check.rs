//! The input check `subgroup::is_subgroup_point` against curve25519-dalek.
//!
//! The reference predicate is computed with curve25519-dalek: a canonical
//! string `u` (number below `p = 2^255 - 19`) is the encoding of a point of
//! the prime-order subgroup when it is `0` (the identity) or when
//! `MontgomeryPoint(u).to_edwards(0)` is a point and that point is torsion
//! free (`[l] P = O`). The tests check
//!
//! - acceptance of the multiples `s B` of the base point, of X25519 public
//!   keys and of the identity;
//! - rejection of `s B + T` for every point `T` of order 2, 4 or 8, of the
//!   u-coordinates of the eight torsion points other than `0`, of twist
//!   points and of non-canonical strings;
//! - agreement with the reference predicate on random strings, and agreement
//!   of `is_on_curve` with the decompression of curve25519-dalek;
//! - for the input check `subgroup::valid_pub`: agreement with the reference
//!   predicate with the identity excluded, rejection of the identity, and
//!   acceptance of X25519 public keys.

use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::{EdwardsPoint, Scalar};
use proptest::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};
use x3dh_hax::subgroup::{is_on_curve, is_subgroup_point, valid_pub};

/// `p = 2^255 - 19`, little-endian.
const P: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x7f,
];

/// Whether the little-endian number of `u` is below `p`.
fn canonical(u: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if u[i] != P[i] {
            return u[i] < P[i];
        }
    }
    false
}

/// The reference predicate, from curve25519-dalek.
fn reference(u: &[u8; 32]) -> bool {
    if !canonical(u) {
        return false;
    }
    if *u == [0u8; 32] {
        return true;
    }
    match MontgomeryPoint(*u).to_edwards(0) {
        Some(e) => e.is_torsion_free(),
        None => false,
    }
}

fn u_of(e: &EdwardsPoint) -> [u8; 32] {
    e.to_montgomery().to_bytes()
}

#[test]
fn base_point_and_identity_accepted() {
    let mut nine = [0u8; 32];
    nine[0] = 9;
    assert!(is_subgroup_point(&nine));
    assert!(is_subgroup_point(&[0u8; 32]));
}

#[test]
fn torsion_points_rejected() {
    for t in EIGHT_TORSION.iter() {
        let u = u_of(t);
        // The identity and the point of order 2 both have u-coordinate 0, the
        // encoding of the identity.
        let expected = u == [0u8; 32];
        assert_eq!(is_subgroup_point(&u), expected, "torsion point {:?}", u);
        assert_eq!(reference(&u), expected);
    }
}

#[test]
fn non_canonical_rejected() {
    // u = p + 9 and u = 9 + 2^255 both reduce to the base point.
    let mut p9 = P;
    p9[0] = 0xf6;
    assert!(!is_subgroup_point(&p9));
    let mut nine_high = [0u8; 32];
    nine_high[0] = 9;
    nine_high[31] = 0x80;
    assert!(!is_subgroup_point(&nine_high));
    assert!(!is_subgroup_point(&P));
}

proptest! {
    #[test]
    fn prop_base_point_multiples_accepted(seed in any::<[u8; 32]>()) {
        let s = Scalar::from_bytes_mod_order(seed);
        let u = u_of(&EdwardsPoint::mul_base(&s));
        prop_assert!(is_subgroup_point(&u));
        prop_assert!(reference(&u));
    }

    #[test]
    fn prop_x25519_public_keys_accepted(sk in any::<[u8; 32]>()) {
        let pk = *PublicKey::from(&StaticSecret::from(sk)).as_bytes();
        prop_assert!(is_subgroup_point(&pk));
    }

    #[test]
    fn prop_torsion_components_rejected(seed in any::<[u8; 32]>(), k in 1usize..8) {
        let s = Scalar::from_bytes_mod_order(seed);
        let q = EdwardsPoint::mul_base(&s);
        prop_assume!(!q.is_identity());
        let u = u_of(&(q + EIGHT_TORSION[k]));
        prop_assert!(!is_subgroup_point(&u));
        prop_assert!(!reference(&u));
    }

    #[test]
    fn prop_agrees_with_reference(u in any::<[u8; 32]>(), top in 0u8..3) {
        // Bias the top byte so that canonical strings near p are sampled too.
        let mut u = u;
        match top {
            0 => u[31] &= 0x7f,
            1 => u[31] |= 0x80,
            _ => {}
        }
        prop_assert_eq!(is_subgroup_point(&u), reference(&u));
    }

    #[test]
    fn prop_on_curve_agrees_with_decompression(u in any::<[u8; 32]>()) {
        let mut u = u;
        u[31] &= 0x3f;
        // u = p - 1 is not below 2^254, so `to_edwards` fails only off the curve.
        prop_assert_eq!(is_on_curve(&u), MontgomeryPoint(u).to_edwards(0).is_some());
    }

    #[test]
    fn prop_subgroup_points_with_random_s(seed in any::<[u8; 32]>(), k in 0usize..8) {
        // Every point of the curve is s B + T for a point T of the 8-torsion; it
        // is accepted exactly when T is the identity (or the result encodes 0).
        let s = Scalar::from_bytes_mod_order(seed);
        let u = u_of(&(EdwardsPoint::mul_base(&s) + EIGHT_TORSION[k]));
        prop_assert_eq!(is_subgroup_point(&u), reference(&u));
        if k == 0 {
            prop_assert!(is_subgroup_point(&u));
        }
    }

    /// The input check `valid_pub` is the reference predicate with the
    /// identity `0` excluded.
    #[test]
    fn prop_valid_pub_agrees_with_reference(u in any::<[u8; 32]>(), top in 0u8..3) {
        let mut u = u;
        match top {
            0 => u[31] &= 0x7f,
            1 => u[31] |= 0x80,
            _ => {}
        }
        prop_assert_eq!(valid_pub(&u), reference(&u) && u != [0u8; 32]);
    }

    /// X25519 public keys pass the input check.
    #[test]
    fn prop_x25519_public_keys_valid(sk in any::<[u8; 32]>()) {
        let pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();
        prop_assert!(valid_pub(&pk));
    }
}

/// The identity is a point of the subgroup and fails the input check.
#[test]
fn identity_rejected_by_valid_pub() {
    assert!(reference(&[0u8; 32]));
    assert!(is_subgroup_point(&[0u8; 32]));
    assert!(!valid_pub(&[0u8; 32]));
}
