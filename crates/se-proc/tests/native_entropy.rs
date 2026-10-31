//! Invoke --expect-native-failure with the Linux short-read/error interposer.
//! Never emit a secret, seed, digest, or credential publication.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).as_deref() == Some("--expect-native-failure") {
        let error = match se_proc::random_secret() {
            Ok(_) => {
                return Err(
                    "native failure silently returned a secret or used fallback entropy".into(),
                );
            }
            Err(error) => error,
        };
        assert_eq!(error.operation, "getrandom");
        assert_eq!(error.native_code, Some(5));
        println!("1 passed; 0 failed; partial native fill followed by EIO returns no Secret");
        return Ok(());
    }
    let first = se_proc::random_secret()?;
    let second = se_proc::random_secret()?;
    assert_eq!(first.expose().len(), 32);
    assert_eq!(second.expose().len(), 32);
    assert_eq!(format!("{first:?}"), "[redacted]");
    assert_eq!(format!("{second:?}"), "[redacted]");
    // A deterministic repeated output would violate the actual fresh allocation
    // consumer. Statistical entropy comes from the OS API, not this assertion.
    assert!(
        first.expose() != second.expose(),
        "consecutive native allocations repeated"
    );
    println!(
        "1 passed; 0 failed; native allocation length/freshness/redaction; init publication NOT GRADED"
    );
    Ok(())
}
