#![no_std]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(feature = "std")]
use std::{println, vec, vec::Vec, io};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc::{vec, vec::Vec}, core2::io};

use mcu_if::{cstr_from, null_terminate_str, null_terminate_bytes};

#[cfg(feature = "v3")]
pub use psa_crypto;

#[cfg(feature = "v3")]
pub mod psa_ifce;

pub mod utils;
