use super::glue;

#[cfg(feature = "std")]
use std::os::raw::*;
#[cfg(not(feature = "std"))]
use mcu_if::c_types::*;

pub type size_t = c_uint;

#[repr(C)]
pub struct mbedtls_pk_context {
    pub pk_info: *const mbedtls_pk_info,
    pub pk_ctx: *mut c_void,
}

impl mbedtls_pk_context {
    pub fn new() -> Self {
        //unsafe { glue::glue_debug_sizeof(); } // debug
        Self {
            pk_info: core::ptr::null(),
            pk_ctx: core::ptr::null_mut(),
        }
    }

    pub fn free(&mut self) {
        unsafe { mbedtls_pk_free(self); }
    }

    pub fn init(&mut self) {
        unsafe { mbedtls_pk_init(self); }
    }

    pub fn setup(&mut self, ty: mbedtls_pk_type_t) {
        unsafe { mbedtls_pk_setup(self, mbedtls_pk_info_from_type(ty)); }
    }

    pub fn verify(
        &mut self,
        ty: mbedtls_md_type_t,
        hash: &[u8],
        sig: &[u8],
    ) -> c_int {
        unsafe { mbedtls_pk_verify(
            self, ty,
            hash.as_ptr(), hash.len() as size_t,
            sig.as_ptr(), sig.len() as size_t) }
    }
}

//

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum mbedtls_pk_type_t {
    MBEDTLS_PK_NONE = 0,
    MBEDTLS_PK_RSA = 1,
    MBEDTLS_PK_ECKEY = 2,
    MBEDTLS_PK_ECKEY_DH = 3,
    MBEDTLS_PK_ECDSA = 4,
    MBEDTLS_PK_RSA_ALT = 5,
    MBEDTLS_PK_RSASSA_PSS = 6,
}

//

#[repr(C)]
pub struct mbedtls_pk_info(glue::OpaqueStruct);

extern "C" { // library/pk.c
    pub fn mbedtls_pk_info_from_type(pk_type: mbedtls_pk_type_t) -> *const mbedtls_pk_info;
    pub fn mbedtls_pk_init(ctx: *mut mbedtls_pk_context);
    pub fn mbedtls_pk_free(ctx: *mut mbedtls_pk_context);
    pub fn mbedtls_pk_setup(
        ctx: *mut mbedtls_pk_context,
        info: *const mbedtls_pk_info,
    ) -> c_int;
    pub fn mbedtls_pk_verify(
        ctx: *mut mbedtls_pk_context,
        md_alg: mbedtls_md_type_t,
        hash: *const c_uchar,
        hash_len: size_t,
        sig: *const c_uchar,
        sig_len: size_t,
    ) -> c_int;
}

//

#[repr(C)]
pub struct mbedtls_ecp_keypair {
    pub grp: mbedtls_ecp_group,
    pub d: mbedtls_mpi,
    pub q: mbedtls_ecp_point,
}

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum mbedtls_ecp_group_id {
    MBEDTLS_ECP_DP_NONE = 0,
    MBEDTLS_ECP_DP_SECP192R1 = 1,
    MBEDTLS_ECP_DP_SECP224R1 = 2,
    MBEDTLS_ECP_DP_SECP256R1 = 3,
    MBEDTLS_ECP_DP_SECP384R1 = 4,
    MBEDTLS_ECP_DP_SECP521R1 = 5,
    MBEDTLS_ECP_DP_BP256R1 = 6,
    MBEDTLS_ECP_DP_BP384R1 = 7,
    MBEDTLS_ECP_DP_BP512R1 = 8,
    MBEDTLS_ECP_DP_CURVE25519 = 9,
    MBEDTLS_ECP_DP_SECP192K1 = 10,
    MBEDTLS_ECP_DP_SECP224K1 = 11,
    MBEDTLS_ECP_DP_SECP256K1 = 12,
    MBEDTLS_ECP_DP_CURVE448 = 13,
}

//

#[repr(C)]
pub struct mbedtls_ecp_group([u8; glue::size_struct::MBEDTLS_ECP_GROUP]);

impl mbedtls_ecp_group {
    pub fn new() -> mbedtls_ecp_group {
        mbedtls_ecp_group([0; glue::size_struct::MBEDTLS_ECP_GROUP])
    }
}

extern "C" { // library/ecp_curves.c
    pub fn mbedtls_ecp_group_load(
        grp: *mut mbedtls_ecp_group,
        id: mbedtls_ecp_group_id,
    ) -> c_int;
}

//

#[repr(C)]
pub struct mbedtls_ecp_point {
    pub x: mbedtls_mpi,
    pub y: mbedtls_mpi,
    pub z: mbedtls_mpi,
}

extern "C" { // library/ecp.c
    pub fn mbedtls_ecp_point_read_binary(
        grp: *const mbedtls_ecp_group,
        pt: *mut mbedtls_ecp_point,
        buf: *const c_uchar,
        ilen: size_t,
    ) -> c_int;
}

//

#[repr(C)]
pub struct mbedtls_mpi([u8; glue::size_struct::MBEDTLS_MPI]);

impl mbedtls_mpi {
    pub fn new() -> mbedtls_mpi {
        mbedtls_mpi([0; glue::size_struct::MBEDTLS_MPI])
    }
}

extern "C" { // library/bignum.c
    pub fn mbedtls_mpi_write_binary(
        mpi: *const mbedtls_mpi,
        buf: *mut c_uchar,
        buflen: size_t,
    ) -> c_int;
    pub fn mbedtls_mpi_size(mpi: *const mbedtls_mpi) -> size_t;
}

#[cfg(feature = "v3")]
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum mbedtls_md_type_t {
    MBEDTLS_MD_NONE=0,
    MBEDTLS_MD_MD5=1,
    MBEDTLS_MD_SHA1=2,
    MBEDTLS_MD_SHA224=3,
    MBEDTLS_MD_SHA256=4,
    MBEDTLS_MD_SHA384=5,
    MBEDTLS_MD_SHA512=6,
    MBEDTLS_MD_RIPEMD160=7,
}
#[cfg(not(feature = "v3"))]
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum mbedtls_md_type_t {
    MBEDTLS_MD_NONE=0,
    MBEDTLS_MD_MD2=1,
    MBEDTLS_MD_MD4=2,
    MBEDTLS_MD_MD5=3,
    MBEDTLS_MD_SHA1=4,
    MBEDTLS_MD_SHA224=5,
    MBEDTLS_MD_SHA256=6,
    MBEDTLS_MD_SHA384=7,
    MBEDTLS_MD_SHA512=8,
    MBEDTLS_MD_RIPEMD160=9,
}

//

#[repr(C)]
pub struct mbedtls_md_info(glue::OpaqueStruct);

extern "C" { // library/md.c
    pub fn mbedtls_md_info_from_string(md_name: *const c_char) -> *const mbedtls_md_info;
    pub fn mbedtls_md_info_from_type(md_type: mbedtls_md_type_t) -> *const mbedtls_md_info;
    pub fn mbedtls_md_get_type(md_info: *const mbedtls_md_info) -> mbedtls_md_type_t;
    pub fn mbedtls_md(
        md_info: *const mbedtls_md_info,
        input: *const c_uchar,
        ilen: size_t,
        output: *mut c_uchar,
    ) -> c_int;
}

//

#[repr(C)]
pub struct mbedtls_x509_crt([u8; glue::size_struct::MBEDTLS_X509_CRT]);

impl mbedtls_x509_crt {
    pub fn new() -> mbedtls_x509_crt {
        mbedtls_x509_crt([0; glue::size_struct::MBEDTLS_X509_CRT])
    }

    pub fn free(&mut self) {
        unsafe { mbedtls_x509_crt_free(self as *mut Self) }
    }

    pub fn init(&mut self) {
        unsafe { mbedtls_x509_crt_init(self as *mut Self) }
    }

    pub fn pk_ptr(&self) -> *const c_void {
        unsafe { glue::glue_get_pk_of(self as *const Self as *const c_void) }
    }

    pub fn parse(&mut self, buf: &[u8]) -> c_int {
        unsafe { mbedtls_x509_crt_parse(self as *mut Self, buf.as_ptr(), buf.len() as size_t) }
    }

    pub fn info(&self, buf: &mut[u8], prefix: &str) -> c_int {
        unsafe { mbedtls_x509_crt_info(
            buf.as_mut_ptr(), buf.len() as size_t, crate::cstr_from!(prefix), self as *const Self) }
    }
}

extern "C" {
    fn mbedtls_x509_crt_free(crt: *mut mbedtls_x509_crt);
    fn mbedtls_x509_crt_init(crt: *mut mbedtls_x509_crt);
    fn mbedtls_x509_crt_parse(
        chain: *mut mbedtls_x509_crt,
        buf: *const c_uchar,
        buf_len: size_t,
    ) -> c_int;
    fn mbedtls_x509_crt_info(
        buf: *mut c_uchar,
        size: size_t,
        prefix: *const c_char,
        crt: *const mbedtls_x509_crt,
    ) -> c_int;
}

#[test]
fn test_mbedtls_x509_crt() {
    #[cfg(feature = "std")]
    use std::println;
    #[cfg(not(feature = "std"))]
    use mcu_if::println;

    assert_eq!(core::mem::size_of::<mbedtls_x509_crt>(), glue::size_struct::MBEDTLS_X509_CRT);

    let crt = mbedtls_x509_crt::new();
    let pk = crt.pk_ptr();
    println!("crt: {:p} pk: {:p}", &crt, pk);
    //assert!(false); // debug
}

//

#[cfg(feature = "v3")]
pub mod sys_v3 {
    use super::*;

    extern "C" {
        pub fn psa_crypto_init() -> c_int;
    }
}
