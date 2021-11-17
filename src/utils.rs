#[cfg(feature = "std")]
use std::{vec, vec::Vec};
#[cfg(not(feature = "std"))]
use mcu_if::{alloc::{vec, vec::Vec}};

pub fn asn1_signature_from(signature: &[u8]) -> Vec<u8> {
    let half = signature.len() / 2;
    let h = half as u8;
    let mut asn1 = vec![];
    asn1.extend_from_slice(&[48, 2 * h + 6, 2, h + 1, 0]);
    asn1.extend_from_slice(&signature[..half]); // r
    asn1.extend_from_slice(&[2, h + 1, 0]);
    asn1.extend_from_slice(&signature[half..]); // s

    asn1
}

pub fn is_asn1_signature(sig: &[u8]) -> bool {
    let sig_len = sig.len();
    let seq_len = sig_len - 2;
    let int_len = seq_len / 2 - 2;

    sig[0] == 48 &&
        sig[1] as usize == seq_len &&
        sig[2] == 2 &&
        sig[3] as usize == int_len &&
        sig[sig_len - int_len - 2] == 2 &&
        sig[sig_len - int_len - 1] as usize == int_len
}