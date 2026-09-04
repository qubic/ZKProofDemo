//! Compiles crypto/src C into the guest; arbitrator pubkey from config/deploy.env is baked into IMAGE_ID.
#[path = "identity.rs"]
mod identity;

fn main() {
    let config = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/deploy.env");
    println!("cargo:rerun-if-changed={config}");
    let (id, pk) = identity::arbitrator_from_config(config).unwrap_or_else(|e| panic!("config: {e}"));
    println!("cargo:rustc-env=ZKQ_ARBITRATOR_IDENTITY={id}");
    println!("cargo:rustc-env=ZKQ_ARBITRATOR_PUBKEY_HEX={}", identity::hex32(&pk));
    let crypto = concat!(env!("CARGO_MANIFEST_DIR"), "/../../crypto");
    let sources = ["riscv_fourq_verify.c", "riscv_tables.c"];
    println!("cargo:rerun-if-changed={crypto}/include/riscv_qubic_crypto.h");
    // User CFLAGS would change the ELF => IMAGE_ID drift.
    for v in ["CFLAGS", "TARGET_CFLAGS", "CFLAGS_riscv32im_risc0_zkvm_elf", "CC"] {
        println!("cargo:rerun-if-env-changed={v}");
    }
    for v in ["CFLAGS", "TARGET_CFLAGS"] {
        assert!(std::env::var_os(v).is_none(), "{v} is set: refusing non-reproducible guest build");
    }
    // risc0-build sets these two itself; anything else means a foreign compiler/flags.
    if let Ok(f) = std::env::var("CFLAGS_riscv32im_risc0_zkvm_elf") {
        assert_eq!(f, "-march=rv32im -nostdlib", "unexpected guest CFLAGS");
    }
    if let Ok(cc) = std::env::var("CC") {
        assert!(cc.ends_with("riscv32-unknown-elf-gcc"), "unexpected guest CC: {cc}");
    }
    let mut build = cc::Build::new();
    for s in sources {
        let path = format!("{crypto}/src/{s}");
        println!("cargo:rerun-if-changed={path}");
        build.file(path);
    }
    build
        .include(format!("{crypto}/include"))
        .define("ZKQ_BIGINT2", None)    // field mul/inv via bigint2 precompile (src/bigint2.rs)
        .flag("-O3")                    // zkVM cycle count
        .flag("-fno-strict-aliasing")   // REQUIRED: port type-puns through pointers
        .flag("-fsigned-char")          // REQUIRED: signed wNAF digits stored in char
        .flag("-Wno-stringop-overflow") // 32-bit gcc false positive
        .flag("-Wno-error")
        .warnings(false)
        .compile("riscv_qubic");
}
