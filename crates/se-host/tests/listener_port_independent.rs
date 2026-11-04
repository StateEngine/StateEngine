//! Exercises actual native binds shared by standalone and embedded hosts.

#[test]
fn busy_explicit_port_refuses_with_configuration_repair() -> Result<(), Box<dyn std::error::Error>>
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    let _entered = runtime.enter();
    let first = se_host::HttpListener::bind(None)?;
    let other = se_host::HttpListener::bind(None)?;
    assert_ne!(first.port(), other.port());
    let error = match se_host::HttpListener::bind(Some(first.port())) {
        Err(error) => error,
        Ok(_) => return Err("two listeners claimed the same explicit port".into()),
    };
    assert_eq!(error.code(), se_types::Code::ListenerUnavailable);
    assert!(error.body.message().contains(&first.port().to_string()));
    let remedy = error.body.remedy(&se_types::RenderCx::default())?;
    assert!(remedy.text.contains("runtime.listen_port"));
    assert!(remedy.text.contains("20000..29999"));
    assert!(remedy.text.contains("config.toml"));
    // Refusal must leave the incumbent socket alive, not silently rebind it.
    let _first_connection =
        std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, first.port()))?;
    let _other_connection =
        std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, other.port()))?;
    Ok(())
}
