
pub const SIZE_STRUCT_OPAQUE: usize = 0;
pub type OpaqueStruct = [u8; SIZE_STRUCT_OPAQUE];

#[cfg(feature = "v3")]
pub mod size_struct {
    //==== x86_64
    pub const MBEDTLS_ECP_GROUP: usize = 248;
    pub const MBEDTLS_MPI: usize = 24;
    pub const MBEDTLS_X509_CRT: usize = 616;
    //==== x86 TODO
    // pub const MBEDTLS_ECP_GROUP: usize = ;
    // pub const MBEDTLS_MPI: usize = ;
    // pub const MBEDTLS_X509_CRT: usize = ;
    //==== xtensa  TODO
    // pub const MBEDTLS_ECP_GROUP: usize = ;
    // pub const MBEDTLS_MPI: usize = ;
    // pub const MBEDTLS_X509_CRT: usize = ;
}
#[cfg(not(feature = "v3"))]
pub mod size_struct {
    //==== x86_64
    pub const MBEDTLS_ECP_GROUP: usize = 248;
    pub const MBEDTLS_MPI: usize = 24;
    pub const MBEDTLS_X509_CRT: usize = 552;
    //==== x86 TODO
    // pub const MBEDTLS_ECP_GROUP: usize = ;
    // pub const MBEDTLS_MPI: usize = ;
    // pub const MBEDTLS_X509_CRT: usize = ;
    //==== xtensa  TODO
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
