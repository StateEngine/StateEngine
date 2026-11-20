fn main() {
    // The local CLI uses a named pipe. Network authentication, certificate
    // verification and profile lookup belong to other command paths.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        for dll in ["ws2_32.dll", "crypt32.dll", "secur32.dll", "userenv.dll"] {
            println!("cargo:rustc-link-arg-bin=se=/DELAYLOAD:{dll}");
        }
        println!("cargo:rustc-link-arg-bin=se=delayimp.lib");
    }
}
