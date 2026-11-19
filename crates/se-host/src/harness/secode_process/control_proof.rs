//! Possession proof for a restarted service's control connection.
use super::unreadable;
use hmac::{Hmac, Mac};
use se_types::{Result, Secret};
use sha2::Sha256;

const DOMAIN: &[u8] = b"stateengine.rebind.control/v1";

fn error() -> se_types::SeError {
    unreadable(
        "SE Code control proof",
        "the service did not prove its current restart capability; retry the original endpoint",
    )
}

pub(super) fn verify(
    capability: &Secret,
    restart: &[u8; 32],
    challenge: &[u8; 32],
    response: &str,
) -> Result<()> {
    let mut mac = Hmac::<Sha256>::new_from_slice(capability.expose()).map_err(|_| error())?;
    mac.update(DOMAIN);
    mac.update(restart);
    mac.update(challenge);
    verify_mac(mac, response)
}

fn verify_mac(mac: Hmac<Sha256>, response: &str) -> Result<()> {
    if response.len() != 64
        || !response
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(error());
    }
    let mut value = [0u8; 32];
    for (index, part) in response.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        value[index] = (digit(part[0]) << 4) | digit(part[1]);
    }
    mac.verify_slice(&value).map_err(|_| error())
}

pub(super) fn release_mac(
    capability: &Secret,
    restart: &[u8; 32],
    nonce: &[u8; 32],
    project: &str,
    agent: &str,
) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(capability.expose()).map_err(|_| error())?;
    mac.update(b"stateengine.rebind.release/v1");
    mac.update(restart);
    mac.update(nonce);
    mac.update(project.as_bytes());
    mac.update(&[0]);
    mac.update(agent.as_bytes());
    Ok(se_types::hex_lower(&mac.finalize().into_bytes()))
}

pub(super) fn verify_release(
    capability: &Secret,
    restart: &[u8; 32],
    nonce: &[u8; 32],
    response: &str,
) -> Result<()> {
    let mut mac = Hmac::<Sha256>::new_from_slice(capability.expose()).map_err(|_| error())?;
    mac.update(b"stateengine.rebind.released/v1");
    mac.update(restart);
    mac.update(nonce);
    verify_mac(mac, response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_restart_challenge_vector() -> Result<()> {
        let capability = Secret::new(b"synthetic-capability-for-test-only".to_vec())?;
        let mut restart = [0u8; 32];
        let mut challenge = [0u8; 32];
        for (index, byte) in restart.iter_mut().enumerate() {
            *byte = index as u8;
        }
        for (index, byte) in challenge.iter_mut().enumerate() {
            *byte = index as u8 + 32;
        }
        verify(
            &capability,
            &restart,
            &challenge,
            "ad4eb8e09b9604facdf15c33a5c808614f1b226eca54cf04e947f16f8ef50315",
        )?;
        assert!(verify(&capability, &restart, &challenge, &"0".repeat(64)).is_err());
        assert_eq!(
            release_mac(
                &capability,
                &restart,
                &challenge,
                "project-example",
                "agent-example"
            )?,
            "2ed0427df889ae94a466b1f76b26c77bf928c3056952e08833cefc630a4ccc82"
        );
        verify_release(
            &capability,
            &restart,
            &challenge,
            "9541b02ebe01e55ac03d5c45e6710a349bd13d3e34f1649ff71501e0123db50c",
        )?;
        Ok(())
    }
}
