//! Persist the initial listener choice through the shared native file adapter.
//! A competing edit refuses its original digest rather than replacing new data.
use super::files::Files;
use crate::{bootstrap::Bootstrap, config::Origin};
use se_config::config_policy::ConfigFile;
use se_core::{scope, store_error::store_error};
use se_store::StateFiles;
use se_types::{Result, SeError};
use sha2::{Digest, Sha256};

#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub fn listener_port(
    cx: &Bootstrap,
    files: &Files,
    owner: &str,
    desired: &ConfigFile,
) -> Result<(u16, bool)> {
    let path = match &cx.config.origin {
        Origin::File(path) => path.clone(),
        Origin::BuiltIn => cx.home.join("config.toml"),
    };
    let mut pin = se_proc::OwnedFile::open(&path)
        .map_err(|e| scope::unreadable("setup configuration", &e.to_string()))?;
    let prior = pin
        .as_mut()
        .map(|p| p.read(1024 * 1024))
        .transpose()
        .map_err(|e| scope::unreadable("setup configuration", &e.to_string()))?;
    let observed = match &prior {
        Some(bytes) => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| SeError::invalid("configuration", "UTF-8 TOML"))?;
            toml::from_str::<ConfigFile>(text)
                .map_err(|e| scope::unreadable("setup configuration", &e.to_string()))?
        }
        None => ConfigFile::default(),
    };
    observed.validate()?;
    if serde_json::to_value(&observed)
        .map_err(|e| scope::unreadable("configuration identity", &e.to_string()))?
        != serde_json::to_value(&cx.config.value)
            .map_err(|e| scope::unreadable("configuration identity", &e.to_string()))?
    {
        return Err(scope::unreadable(
            "setup configuration",
            "selected configuration changed after bootstrap; retry without overwriting it",
        ));
    }
    let mut updated = desired.clone();
    let (port, _reservation) = match observed.runtime.listen_port {
        Some(port) => (port, None),
        None => {
            // Dormant homes owned by the same OS user must not all start their search
            // at the same port. A later external collision still refuses at bind time.
            let mut seed = Sha256::new();
            seed.update(owner.as_bytes());
            seed.update([0]);
            seed.update(cx.home.as_os_str().as_encoded_bytes());
            let hash = seed.finalize();
            let first = u16::from_le_bytes([hash[0], hash[1]]) % 10000;
            let mut selected = None;
            for step in 0..10000u16 {
                let port = 20000 + (first + step) % 10000;
                match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)) {
                    Ok(listener) => {
                        selected = Some((port, listener));
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => (),
                    Err(error) => {
                        return Err(scope::unreadable(
                            "initial loopback listener port",
                            &error.to_string(),
                        ));
                    }
                }
            }
            let (port, reservation) = selected.ok_or_else(|| {
                scope::unreadable(
                    "initial loopback listener port",
                    "all ports in 20000–29999 are already in use",
                )
            })?;
            (port, Some(reservation))
        }
    };
    updated.runtime.listen_port = Some(port);
    updated.validate()?;
    if serde_json::to_value(&updated)
        .map_err(|e| scope::unreadable("configuration identity", &e.to_string()))?
        == serde_json::to_value(&observed)
            .map_err(|e| scope::unreadable("configuration identity", &e.to_string()))?
    {
        return Ok((port, false));
    }
    let bytes = toml::to_string_pretty(&updated)
        .map_err(|e| scope::unreadable("setup configuration encoding", &e.to_string()))?
        .into_bytes();
    match pin {
        Some(pin) => pin
            .replace(
                Sha256::digest(prior.as_deref().ok_or_else(|| {
                    SeError::invalid("configuration identity", "the retained prior bytes")
                })?)
                .into(),
                &bytes,
            )
            .map_err(|e| scope::unreadable("setup configuration publication", &e.to_string()))?,
        None => files
            .replace_owned(&path, None, &bytes)
            .map_err(|e| store_error(&e))?,
    }
    let mut readback = se_proc::OwnedFile::open(&path)
        .map_err(|e| scope::unreadable("setup configuration readback", &e.to_string()))?
        .ok_or_else(|| {
            scope::unreadable(
                "setup configuration readback",
                "published configuration is absent",
            )
        })?;
    if readback
        .read(1024 * 1024)
        .map_err(|e| scope::unreadable("setup configuration readback", &e.to_string()))?
        != bytes
    {
        return Err(scope::unreadable(
            "setup configuration readback",
            "the independently reopened bytes differ",
        ));
    }
    Ok((port, true))
}
