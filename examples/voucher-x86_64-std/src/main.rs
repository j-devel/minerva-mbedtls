use minerva_mbedtls::{psa_crypto, ifce::psa_crypto_ffi};

fn main() -> Result<(), VoucherError> {
    psa_crypto::init().unwrap();
    psa_crypto::initialized().unwrap();

    let res = Voucher::try_from(VOUCHER_F2_00_02)?
        .validate(Some(MASA_PEM_F2_00_02))
        .is_ok();
    println!("voucher validation: {}", if res { "SUCCESS" } else { "FAIL" });

    Ok(())
}

static MASA_PEM_F2_00_02: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIByzCCAVKgAwIBAgIESltVuTAKBggqhkjOPQQDAjBTMRIwEAYKCZImiZPyLGQB
GRYCY2ExGTAXBgoJkiaJk/IsZAEZFglzYW5kZWxtYW4xIjAgBgNVBAMMGWhpZ2h3
YXktdGVzdC5zYW5kZWxtYW4uY2EwHhcNMTgxMTIyMTg1MjAxWhcNMjAxMTIxMTg1
MjAxWjBXMRIwEAYKCZImiZPyLGQBGRYCY2ExGTAXBgoJkiaJk/IsZAEZFglzYW5k
ZWxtYW4xJjAkBgNVBAMMHWhpZ2h3YXktdGVzdC5leGFtcGxlLmNvbSBNQVNBMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqgQVo0S54kT4yfkbBxumdHOcHrpsqbOp
MKmiMln3oB1HAW25MJV+gqi4tMFfSJ0iEwt8kszfWXK4rLgJS2mnpaMQMA4wDAYD
VR0TAQH/BAIwADAKBggqhkjOPQQDAgNnADBkAjBkuTwpIGSZTJ3cDNv3RkZ9xR5F
F+msNgl8HH50lTF47uRVn/FrY3S8GS1TjP9RGhoCMC8lEKi0zeSya9yYDdXuxUVy
G5/TRupdVlCjPz1+tm/iA9ykx/sazZsuPgw14YulLw==
-----END CERTIFICATE-----
";
static VOUCHER_F2_00_02: &[u8] = &[210, 132, 67, 161, 1, 38, 160, 89, 2, 183, 161, 25, 9, 147, 165, 1, 102, 108, 111, 103, 103, 101, 100, 2, 193, 26, 95, 86, 209, 119, 11, 113, 48, 48, 45, 68, 48, 45, 69, 53, 45, 70, 50, 45, 48, 48, 45, 48, 50, 7, 118, 88, 83, 121, 70, 52, 76, 76, 73, 105, 113, 85, 50, 45, 79, 71, 107, 54, 108, 70, 67, 65, 103, 8, 121, 2, 116, 77, 73, 73, 66, 48, 84, 67, 67, 65, 86, 97, 103, 65, 119, 73, 66, 65, 103, 73, 66, 65, 106, 65, 75, 66, 103, 103, 113, 104, 107, 106, 79, 80, 81, 81, 68, 65, 122, 66, 120, 77, 82, 73, 119, 69, 65, 89, 75, 67, 90, 73, 109, 105, 90, 80, 121, 76, 71, 81, 66, 71, 82, 89, 67, 89, 50, 69, 120, 71, 84, 65, 88, 66, 103, 111, 74, 107, 105, 97, 74, 107, 47, 73, 115, 90, 65, 69, 90, 70, 103, 108, 122, 89, 87, 53, 107, 90, 87, 120, 116, 89, 87, 52, 120, 81, 68, 65, 43, 66, 103, 78, 86, 66, 65, 77, 77, 78, 121, 77, 56, 85, 51, 108, 122, 100, 71, 86, 116, 86, 109, 70, 121, 97, 87, 70, 105, 98, 71, 85, 54, 77, 72, 103, 119, 77, 68, 65, 119, 77, 68, 65, 119, 78, 71, 89, 53, 77, 84, 70, 104, 77, 68, 52, 103, 86, 87, 53, 122, 100, 72, 74, 49, 98, 109, 99, 103, 82, 109, 57, 49, 98, 110, 82, 104, 97, 87, 52, 103, 81, 48, 69, 119, 72, 104, 99, 78, 77, 84, 99, 120, 77, 84, 65, 51, 77, 106, 77, 48, 78, 84, 73, 52, 87, 104, 99, 78, 77, 84, 107, 120, 77, 84, 65, 51, 77, 106, 77, 48, 78, 84, 73, 52, 87, 106, 66, 68, 77, 82, 73, 119, 69, 65, 89, 75, 67, 90, 73, 109, 105, 90, 80, 121, 76, 71, 81, 66, 71, 82, 89, 67, 89, 50, 69, 120, 71, 84, 65, 88, 66, 103, 111, 74, 107, 105, 97, 74, 107, 47, 73, 115, 90, 65, 69, 90, 70, 103, 108, 122, 89, 87, 53, 107, 90, 87, 120, 116, 89, 87, 52, 120, 69, 106, 65, 81, 66, 103, 78, 86, 66, 65, 77, 77, 67, 87, 120, 118, 89, 50, 70, 115, 97, 71, 57, 122, 100, 68, 66, 90, 77, 66, 77, 71, 66, 121, 113, 71, 83, 77, 52, 57, 65, 103, 69, 71, 67, 67, 113, 71, 83, 77, 52, 57, 65, 119, 69, 72, 65, 48, 73, 65, 66, 74, 90, 108, 85, 72, 73, 48, 117, 112, 47, 108, 51, 101, 90, 102, 57, 118, 67, 66, 98, 43, 108, 73, 110, 111, 69, 77, 69, 103, 99, 55, 82, 111, 43, 88, 90, 67, 116, 106, 65, 73, 48, 67, 68, 49, 102, 74, 102, 74, 82, 47, 104, 73, 121, 121, 68, 109, 72, 87, 121, 89, 105, 78, 70, 98, 82, 67, 72, 57, 102, 121, 97, 114, 102, 107, 122, 103, 88, 52, 112, 48, 122, 84, 105, 122, 113, 106, 68, 84, 65, 76, 77, 65, 107, 71, 65, 49, 85, 100, 69, 119, 81, 67, 77, 65, 65, 119, 67, 103, 89, 73, 75, 111, 90, 73, 122, 106, 48, 69, 65, 119, 77, 68, 97, 81, 65, 119, 90, 103, 73, 120, 65, 76, 81, 77, 78, 117, 114, 102, 56, 116, 118, 53, 48, 108, 82, 79, 68, 53, 68, 81, 88, 72, 69, 79, 74, 74, 78, 87, 51, 81, 86, 50, 103, 57, 81, 69, 100, 68, 83, 107, 50, 77, 89, 43, 65, 111, 83, 114, 66, 83, 109, 71, 83, 78, 106, 104, 52, 111, 108, 69, 79, 104, 69, 117, 76, 103, 73, 120, 65, 74, 52, 110, 87, 102, 78, 119, 43, 66, 106, 98, 90, 109, 75, 105, 73, 105, 85, 69, 99, 84, 119, 72, 77, 104, 71, 86, 88, 97, 77, 72, 89, 47, 70, 55, 110, 51, 57, 119, 119, 75, 99, 66, 66, 83, 79, 110, 100, 78, 80, 113, 67, 112, 79, 69, 76, 108, 54, 98, 113, 51, 67, 90, 113, 81, 61, 61, 88, 64, 99, 204, 130, 58, 52, 185, 100, 173, 200, 53, 181, 142, 46, 225, 231, 227, 0, 136, 173, 230, 137, 111, 148, 177, 58, 199, 48, 100, 62, 150, 96, 181, 169, 52, 83, 243, 201, 216, 160, 154, 181, 122, 1, 19, 164, 6, 114, 120, 132, 118, 58, 42, 208, 75, 79, 171, 79, 111, 184, 188, 179, 46, 250, 71];

//

use minerva_voucher::{Voucher as BaseVoucher, Validate, VoucherError};
use std::convert::TryFrom;

struct Voucher(BaseVoucher);

impl TryFrom<&[u8]> for Voucher {
    type Error = VoucherError;
    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(BaseVoucher::try_from(raw)?))
    }
}

impl Validate for Voucher {
    fn validate(&self, masa_pem: Option<&[u8]>) -> Result<&Self, VoucherError> {
        let (_, sig_alg, to_verify) = self.0.to_validate();
        let (signature, _) = sig_alg.unwrap();

        use psa_crypto_ffi::{md_info, MD_SHA256/* TODO: , x509_crt */};
        use minerva_mbedtls::ifce::{md_type, x509_crt}; // TODO: migrate to `ifce::psa_crypto_ffi::*`

        let hash = &md_info::from_type(MD_SHA256).md(to_verify);
        let err = Err(VoucherError::ValidationFailed);

        x509_crt::new()
            .parse(masa_pem.unwrap()).unwrap()
            .info().unwrap() // debug
            .pk_mut()
            .verify(md_type::MBEDTLS_MD_SHA256, hash, signature)
            .map_or(err, |x| if x { Ok(self) } else { err })
    }
}