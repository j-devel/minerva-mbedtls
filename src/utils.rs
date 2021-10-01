#[cfg(feature = "std")]
use std::{vec, vec::Vec};
#[cfg(not(feature = "std"))]
use mcu_if::{alloc::{vec, vec::Vec}};

pub fn asn1_from_signature(signature: &[u8]) -> Vec<u8> {
    let half = signature.len() / 2;
    let h = half as u8;
    let mut asn1 = vec![];
    asn1.extend_from_slice(&[48, 2 * h + 6, 2, h + 1, 0]);
    asn1.extend_from_slice(&signature[..half]); // r
    asn1.extend_from_slice(&[2, h + 1, 0]);
    asn1.extend_from_slice(&signature[half..]); // s

    asn1
}
