
pub const SIZE_STRUCT_OPAQUE: usize = 0;
pub type OpaqueStruct = [u8; SIZE_STRUCT_OPAQUE];

#[cfg(all(feature = "v3", target_arch = "x86_64"))]
pub mod size_struct {
    pub const MBEDTLS_ECP_GROUP: usize = 248;
    pub const MBEDTLS_MPI: usize = 24;
    pub const MBEDTLS_X509_CRT: usize = 616;
}
#[cfg(all(feature = "v3", target_arch = "x86"))]
pub mod size_struct {
    // pub const MBEDTLS_ECP_GROUP: usize = ;
    // pub const MBEDTLS_MPI: usize = ;
    // pub const MBEDTLS_X509_CRT: usize = ;
}
#[cfg(all(feature = "v3", target_arch = "xtensa"))]
pub mod size_struct {
    // pub const MBEDTLS_ECP_GROUP: usize = ;
    // pub const MBEDTLS_MPI: usize = ;
    // pub const MBEDTLS_X509_CRT: usize = ;
}


#[cfg(all(not(feature = "v3"), target_arch = "x86_64"))]
pub mod size_struct {
    pub const MBEDTLS_ECP_GROUP: usize = 248;
    pub const MBEDTLS_MPI: usize = 24;
    pub const MBEDTLS_X509_CRT: usize = 552;
}
#[cfg(all(not(feature = "v3"), target_arch = "x86"))]
pub mod size_struct {
    pub const MBEDTLS_ECP_GROUP: usize = 124;
    pub const MBEDTLS_MPI: usize = 12;
    pub const MBEDTLS_X509_CRT: usize = 312;
}
#[cfg(all(not(feature = "v3"), target_arch = "xtensa"))]
pub mod size_struct {
    // pub const MBEDTLS_ECP_GROUP: usize = ;
    // pub const MBEDTLS_MPI: usize = ;
    // pub const MBEDTLS_X509_CRT: usize = ;
}

extern "C" {
    pub fn glue_get_pk_of(crt: *const core::ffi::c_void) -> *const core::ffi::c_void;

    fn glue_debug_sizeof();

    fn glue_sizeof_mbedtls_ecp_group() -> usize;
    fn glue_sizeof_mbedtls_mpi() -> usize;
    fn glue_sizeof_mbedtls_x509_crt() -> usize;
}

#[test]
fn test_glue() {
    unsafe { glue_debug_sizeof() }
    // assert!(false); // debug

    assert_eq!(unsafe { glue_sizeof_mbedtls_ecp_group() }, size_struct::MBEDTLS_ECP_GROUP);
    assert_eq!(unsafe { glue_sizeof_mbedtls_mpi() }, size_struct::MBEDTLS_MPI);
    assert_eq!(unsafe { glue_sizeof_mbedtls_x509_crt() }, size_struct::MBEDTLS_X509_CRT);
}
