use crate::{vec, Vec, io::{self, Cursor, Write}};

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

    let int1_pos = 2;
    let int1_len = sig.get(int1_pos + 1);
    if int1_len.is_none() { return false; }
    let int1_len = *int1_len.unwrap() as usize;
    //crate::println!("int1_len: {}", int1_len);

    let int2_pos = int1_pos + 1 + int1_len + 1;
    let int2_len = sig.get(int2_pos + 1);
    if int2_len.is_none() { return false; }
    let int2_len = *int2_len.unwrap() as usize;
    //crate::println!("int2_len: {}", int2_len);

    sig[0] == 48 &&
        sig[1] as usize == seq_len &&
        sig[int1_pos] == 2 &&
        sig[int2_pos] == 2 &&
        int1_len + int2_len + 4 == seq_len
}

#[test]
fn test_is_asn1_signature() {
    assert_eq!(is_asn1_signature(&[ // len=64; product=F2_00_02
        99, 204, 130, 58, 52, 185, 100, 173, 200, 53, 181, 142, 46, 225, 231, 227, 0, 136, 173, 230, 137, 111, 148, 177, 58, 199, 48, 100, 62, 150, 96, 181, 169, 52, 83, 243, 201, 216, 160, 154, 181, 122, 1, 19, 164, 6, 114, 120, 132, 118, 58, 42, 208, 75, 79, 171, 79, 111, 184, 188, 179, 46, 250, 71
    ]), false);

    assert_eq!(is_asn1_signature(&[ // len=72; product=02_00_2E; sidhash: Map({Integer(1001154): Map({})})
        48, 70, 2, 33, 0, 207, 108, 40, 154, 180, 93, 219, 99, 88, 85, 28, 106, 253, 2, 206, 174, 5, 173, 169, 237, 87, 55, 52, 221, 140, 157, 195, 235, 48, 33, 104, 200, 2, 33, 0, 222, 162, 96, 5, 154, 133, 186, 60, 156, 254, 101, 61, 63, 157, 87, 33, 113, 38, 236, 114, 99, 79, 149, 7, 131, 88, 193, 26, 27, 124, 54, 230
    ]), true);

    assert_eq!(is_asn1_signature(&[ // len=71; product=02_00_2E; sidhash: Map({Integer(1): Map({})})
        48, 69, 2, 33, 0, 152, 82, 125, 36, 97, 213, 158, 38, 8, 68, 14, 194, 99, 237, 119, 120, 106, 11, 51, 153, 151, 187, 19, 189, 52, 137, 8, 86, 218, 247, 111, 220, 2, 32, 39, 131, 155, 58, 236, 211, 16, 142, 139, 129, 22, 124, 70, 214, 168, 71, 12, 83, 62, 248, 57, 2, 152, 23, 4, 163, 170, 80, 127, 137, 35, 52
    ]), true);
}