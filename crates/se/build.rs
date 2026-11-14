fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "macos") {
        // Keep archive rebuilds stable without removing host proc-macro UUIDs.
        println!("cargo::rustc-link-arg-bin=se=-Wl,-no_uuid");
    }
}
