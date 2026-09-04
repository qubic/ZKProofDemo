//! Builds crypto/ via its Makefile (libstock_qubic.a + libriscv_qubic.a) and links both. See host/README.md.
use std::process::Command;

#[path = "../methods/guest/identity.rs"]
mod identity;

fn main() {
    // Same config the guest bakes in; image_id prints it next to the IMAGE_ID.
    let config = concat!(env!("CARGO_MANIFEST_DIR"), "/../config/deploy.env");
    println!("cargo:rerun-if-changed={config}");
    let (id, pk) = identity::arbitrator_from_config(config).unwrap_or_else(|e| panic!("config: {e}"));
    println!("cargo:rustc-env=ZKQ_ARBITRATOR_IDENTITY={id}");
    println!("cargo:rustc-env=ZKQ_ARBITRATOR_PUBKEY_HEX={}", identity::hex32(&pk));
    let crypto = concat!(env!("CARGO_MANIFEST_DIR"), "/../crypto");
    println!("cargo:rerun-if-changed={crypto}/src");
    println!("cargo:rerun-if-changed={crypto}/include");
    println!("cargo:rerun-if-changed={crypto}/Makefile");
    let args = ["-C", crypto, "-j", "build/libstock_qubic.a", "build/libriscv_qubic.a"];
    let status = Command::new("make").args(args).status().expect("make not found");
    assert!(status.success(), "make {:?} failed", args);
    println!("cargo:rustc-link-search=native={crypto}/build");
    println!("cargo:rustc-link-lib=static=stock_qubic");
    println!("cargo:rustc-link-lib=static=riscv_qubic");
    println!("cargo:rustc-link-lib=dylib=stdc++");
}
