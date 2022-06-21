use std::path::Path;
use std::process::Command;
use std::env;

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");

    let is_v3 = cfg!(feature = "v3");
    let ver = if is_v3 { "v3" } else { "lts" };

    let out_dir = env::var("OUT_DIR").unwrap();
    let target = env::var("TARGET").unwrap();

    let branch = if is_v3 { "v3.0.0" } else { "v2.16.11" };
    let mbedtls = format!("{}/mbedtls-{}-{}", out_dir, ver, target);
    let out_mk_target = format!("{}-{}", ver, match target.as_str() {
        "xtensa-esp32-none-elf" => "xtensa",
        "i686-unknown-linux-gnu" => "x86",
        _ => "x86_64",
    });

    if !Path::new(&mbedtls).exists() {
        Command::new("git")
            .args(&["clone", "-b", branch, "https://github.com/ARMmbed/mbedtls", &mbedtls]).status()?;
        Command::new("cp")
            .args(&["out.mk", &out_dir]).status()?;
        Command::new("make")
            .args(&["-C", &mbedtls, "-f", "../out.mk", &out_mk_target]).status()?;
    }

    let lib_dir = format!("{}/library", mbedtls);
    println!("cargo:rerun-if-changed={}", lib_dir);
    println!("cargo:rustc-link-search=native={}", lib_dir);
    println!("cargo:rustc-link-lib=static=mbedtls");
    println!("cargo:rustc-link-lib=static=mbedx509");
    println!("cargo:rustc-link-lib=static=mbedcrypto");

    Ok(())
}
