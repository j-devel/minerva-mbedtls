#[cfg(feature = "std")]
use std::{vec, vec::Vec, io::{self, Cursor, Write}};
#[cfg(not(feature = "std"))]
use mcu_if::{alloc::{vec, vec::Vec}, core2::io::{self as io, Cursor, Write}};

pub fn asn1_signature_from(sig: &[u8]) -> io::Result<Vec<u8>> {
    let sig_len = sig.len();
    let half = sig_len / 2;
    let h = half as u8;

    let mut asn1 = vec![0u8; sig_len + 8];
    let mut writer = Cursor::new(&mut asn1[..]);
    writer.write(&[48, 2 * h + 6, 2, h + 1, 0])?;
    writer.write(&sig[..half])?; // r
    writer.write(&[2, h + 1, 0])?;
    writer.write(&sig[half..])?; // s

    Ok(asn1)
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