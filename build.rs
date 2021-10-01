use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");

    let is_v3 = cfg!(feature = "v3");
    let ver = if is_v3 { "v3" } else { "lts" };

    let arch = "x86_64"; // TODO auto detect arch

    // TODO cross build -- https://developer.trustedfirmware.org/w/mbed-tls/testing/ci/
    //   e.g. `make -j CC=gcc CFLAGS="-m32 -O2 -DMBEDTLS_ARIA_C=ON" LDFLAGS="-m32" lib`

    let mbedtls = format!("mbedtls-{}-{}", ver, arch);
    let branch = if is_v3 { "v3.0.0" } else { "v2.16.11" };
    let cflags = if is_v3 {
        "CFLAGS='-O2 -DMBEDTLS_USE_PSA_CRYPTO=ON'"
    } else {
        "CFLAGS='-O2 -DMBEDTLS_ARIA_C=ON'"
    };

    let local = format!("{}/__local", mbedtls);
    let lib_dir = format!("{}/lib", local);
    let include_dir = format!("{}/include", local);

    //

    if !Path::new(&mbedtls).exists() {
        Command::new("git")
            .args(&["clone", "-b", branch, "https://github.com/ARMmbed/mbedtls", &mbedtls])
            .status()
            .unwrap();
        Command::new("make")
            .args(&["-C", &mbedtls, "-j", cflags, "lib"])
            .status()
            .unwrap();
        Command::new("mkdir")
            .args(&[&local])
            .status()
            .unwrap();
        Command::new("make")
            .args(&["-C", &mbedtls, "-j", "DESTDIR=./__local", "install"])
            .status()
            .unwrap();
    }

    //

    println!("cargo:rerun-if-changed={}", lib_dir);
    println!("cargo:rustc-link-search=native={}", lib_dir);
    println!("cargo:rustc-link-lib=static=mbedtls");
    println!("cargo:rustc-link-lib=static=mbedx509");
    println!("cargo:rustc-link-lib=static=mbedcrypto");

    //

    println!("cargo:rerun-if-changed=src/glue.c");
    let mut cfg = cc::Build::new();
    if is_v3 {
        cfg.define("MINERVA_MBEDTLS_GLUE_V3", None);
    }
    cfg.include(include_dir)
        .file("src/glue.c")
        .compile("libglue-mbedtls.a");
}
