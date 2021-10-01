#![no_std]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

use mcu_if::{cstr_from, null_terminate_str, null_terminate_bytes};

mod glue;

pub mod sys;

pub mod r#if;
pub use r#if as ifce;

#[cfg(feature = "v3")]
pub use psa_crypto;

pub mod utils;
