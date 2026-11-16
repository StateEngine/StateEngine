//! Controlled forwarding child for the native pipe-lifetime witness.
//! It accepts exactly the loopback liveness probes used by Forwards::activate.
//! No remote protocol, authentication or application data is simulated.
use std::{error::Error, net::TcpListener, path::PathBuf};

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.last().map(String::as_str) != Some("forward-witness")
        || !args.iter().any(|v| v == "-N")
        || !args.iter().any(|v| v == "-T")
        || !args.iter().any(|v| v == "ExitOnForwardFailure=yes")
    {
        return Err("unexpected controlled forward invocation".into());
    }
    let mapping = args
        .windows(2)
        .find(|pair| pair[0] == "-L")
        .ok_or("missing loopback mapping")?[1]
        .clone();
    let fields: Vec<_> = mapping.split(':').collect();
    if fields.len() != 4 || fields[0] != "127.0.0.1" || fields[2] != "127.0.0.1" || fields[3] != "9"
    {
        return Err("unexpected loopback mapping".into());
    }
    let port: u16 = fields[1].parse()?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
    let receipts = PathBuf::from(
        std::env::var_os("SE_FORWARD_WITNESS_DIR")
            .ok_or("private witness receipt directory absent")?,
    );
    let pid = std::process::id();
    std::fs::write(
        receipts.join(format!("forward-{pid}.json")),
        format!("{{\"pid\":{pid},\"port\":{port},\"mode\":\"quiet-forward\"}}\n"),
    )?;
    // Keep stderr open and silent, like an established healthy SSH forward.
    // Only the public Forwards owner stops and joins this exact direct child.
    for stream in listener.incoming() {
        drop(stream?);
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("controlled forward setup failed: {error}");
        std::process::exit(1);
    }
}
