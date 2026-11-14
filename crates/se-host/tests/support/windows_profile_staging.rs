//! A disposable local Windows account supplies the real native profile path.
use super::{Check, require, staging};
use base64::Engine as _;
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn profile_paths_and_shells() -> Check {
    let nonce = format!(
        "{:x}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    );
    let name = format!("se Ω 测 {}", &nonce[nonce.len() - 8..]);
    let root = PathBuf::from(std::env::var_os("PUBLIC").ok_or("native public profile absent")?)
        .join(format!("se-staging-{nonce}"));
    std::fs::create_dir(&root)?;
    let result = (|| -> Check {
        let bytes: Vec<_> = (0..=u8::MAX).cycle().take(32768).collect();
        use sha2::{Digest, Sha256};
        let digest = se_types::hex_lower(&Sha256::digest(&bytes));
        let directory = format!(".stateengine-runtime/{digest}");
        let image = format!("{directory}/se.exe");
        let upload = format!("{image}.upload-profile");
        let payload = serde_json::json!({
            "prepare":staging::prepare(&directory,true,false),
            "receive":staging::receive(&upload,true),
            "verify_upload":staging::verify(&upload,&digest,true,false),
            "publish":staging::publish(&upload,&image,true),
            "verify":staging::verify(&image,&digest,true,false),
            "remove_upload":staging::remove(&upload,true),
            "remove_image":staging::remove(&image,true),
            "bytes":base64::engine::general_purpose::STANDARD.encode(&bytes),
            "directory":directory,"image":image,"upload":upload,"name":name
        });
        std::fs::write(root.join("payload.json"), serde_json::to_vec(&payload)?)?;
        let mut worker = vec![0xef, 0xbb, 0xbf];
        worker.extend_from_slice(include_bytes!("windows_profile_worker.ps1"));
        std::fs::write(root.join("worker.ps1"), worker)?;
        let parent = include_str!("windows_profile_account.ps1")
            .replace(
                "@ROOT@",
                &root
                    .to_str()
                    .ok_or("native path UTF-8")?
                    .replace('\'', "''"),
            )
            .replace("@NAME@", &name);
        // Account setup and two shell traversals require a longer outer bound.
        let output = run_profile(&staging::powershell(&parent))?;
        require(
            output.status.success(),
            &format!(
                "profile control refused: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        )?;
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("result.json"))?)?;
        require(
            report["shells"]
                .as_array()
                .is_some_and(|rows| rows.len() == 2),
            "both native shells were not exercised",
        )?;
        let cleanup: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("cleanup.json"))?)?;
        require(
            cleanup["account_absent"] == true && cleanup["profile_absent"] == true,
            "owned account/profile cleanup unproved",
        )
    })();
    // Remove only this invocation's public fixture leaf; profile deletion is
    // independently performed by the OS account fixture, keyed by its SID.
    let removed = std::fs::remove_dir_all(&root);
    removed?;
    result
}

fn run_profile(
    command: &str,
) -> Result<std::process::Output, Box<dyn std::error::Error + Send + Sync>> {
    // run() has a fixed 15s bound for single staging commands. The outer
    // account control uses the same owned-child implementation with 95s.
    super::run_bounded(command, None, std::time::Duration::from_secs(95))
}
