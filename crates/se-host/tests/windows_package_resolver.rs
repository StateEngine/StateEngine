//! Exercise the production package lookup on each host; these fixtures are not executed.
#![cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[path = "../../test-support/directory.rs"]
mod directory;
#[path = "../src/process/windows_executable.rs"]
mod windows_executable;

use se_types::Provider;
use std::{fs, io, path::Path};

type Check = Result<(), Box<dyn std::error::Error>>;

fn fixture(check: impl FnOnce(&Path) -> Check) -> Check {
    let root = directory::private_directory()?;
    check(&root)?;
    fs::remove_dir_all(root)?;
    Ok(())
}

fn put(root: &Path, relative: &str, bytes: &[u8]) -> io::Result<std::path::PathBuf> {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().ok_or_else(|| io::Error::other("no parent"))?)?;
    fs::write(&path, bytes)?;
    Ok(path)
}

fn package(root: &Path) -> io::Result<()> {
    put(
        root,
        "node_modules/@openai/codex/package.json",
        br#"{"name":"@openai/codex","version":"0.0.0-test"}"#,
    )?;
    Ok(())
}

fn target() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64-pc-windows-msvc"
    } else {
        "x86_64-pc-windows-msvc"
    }
}

fn platform() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "codex-win32-arm64"
    } else {
        "codex-win32-x64"
    }
}

#[test]
fn extensionless_package_launcher_selects_native_payload() -> Check {
    fixture(|root| {
        package(root)?;
        let launcher = put(root, "codex", b"#!/bin/sh\nexec node launcher.js\n")?;
        let payload = put(
            root,
            &format!(
                "node_modules/@openai/codex/node_modules/@openai/{}/vendor/{}/bin/codex.exe",
                platform(),
                target()
            ),
            b"MZ native-header fixture",
        )?;
        assert_eq!(
            windows_executable::resolve(&launcher, Some(Provider::Codex))?,
            Some(payload)
        );
        Ok(())
    })
}

#[test]
fn command_and_powershell_shims_find_hoisted_payloads() -> Check {
    fixture(|root| {
        package(root)?;
        let payload = put(
            root,
            &format!(
                "node_modules/@openai/{}/vendor/{}/bin/codex.exe",
                platform(),
                target()
            ),
            b"MZ native-header fixture",
        )?;
        for extension in ["cmd", "ps1"] {
            let shim = put(
                root,
                &format!("codex.{extension}"),
                b"synthetic script launcher",
            )?;
            assert_eq!(
                windows_executable::resolve(&shim, Some(Provider::Codex))?,
                Some(payload.clone())
            );
            assert_eq!(
                windows_executable::resolve(&root.join("codex"), Some(Provider::Codex))?,
                Some(payload.clone())
            );
            fs::remove_file(shim)?;
        }
        Ok(())
    })
}

#[test]
fn embedded_vendor_payload_is_available_to_an_explicit_shim() -> Check {
    fixture(|root| {
        package(root)?;
        let launcher = put(root, "codex.cmd", b"@echo off\n")?;
        let payload = put(
            root,
            &format!(
                "node_modules/@openai/codex/vendor/{}/bin/codex.exe",
                target()
            ),
            b"MZ native-header fixture",
        )?;
        assert_eq!(
            windows_executable::resolve(&launcher, Some(Provider::Codex))?,
            Some(payload)
        );
        Ok(())
    })
}

#[test]
fn native_executable_takes_precedence_over_a_script() -> Check {
    fixture(|root| {
        put(root, "codex", b"#!/bin/sh\n")?;
        let image = put(root, "codex.exe", b"MZ native-header fixture")?;
        for provider in [None, Some(Provider::Claude), Some(Provider::Codex)] {
            assert_eq!(
                windows_executable::resolve(&root.join("codex"), provider)?,
                Some(image.clone())
            );
            assert_eq!(
                windows_executable::resolve(&image, provider)?,
                Some(image.clone())
            );
        }
        Ok(())
    })
}

#[test]
fn scripts_and_missing_images_are_not_native_executables() -> Check {
    fixture(|root| {
        let launcher = put(root, "codex", b"#!/bin/sh\n")?;
        for provider in [None, Some(Provider::Claude), Some(Provider::Codex)] {
            assert_eq!(windows_executable::resolve(&launcher, provider)?, None);
        }
        assert_eq!(
            windows_executable::resolve(&root.join("absent"), None)?,
            None
        );
        let invalid = put(root, "broken.exe", b"script")?;
        assert_eq!(
            windows_executable::resolve(&invalid, None)
                .err()
                .ok_or("invalid image accepted")?
                .kind(),
            io::ErrorKind::InvalidData
        );
        Ok(())
    })
}

#[test]
fn package_lookup_requires_both_the_launcher_and_provider() -> Check {
    fixture(|root| {
        package(root)?;
        put(
            root,
            &format!(
                "node_modules/@openai/codex/vendor/{}/bin/codex.exe",
                target()
            ),
            b"MZ native-header fixture",
        )?;
        let launcher = root.join("codex");
        assert_eq!(
            windows_executable::resolve(&launcher, Some(Provider::Codex))?,
            None
        );
        put(root, "codex.cmd", b"synthetic script launcher")?;
        assert_eq!(
            windows_executable::resolve(&launcher, Some(Provider::Claude))?,
            None
        );
        assert_eq!(windows_executable::resolve(&launcher, None)?, None);
        Ok(())
    })
}

#[test]
fn unreadable_package_metadata_is_not_reported_absent() -> Check {
    fixture(|root| {
        let launcher = put(root, "codex.cmd", b"synthetic script launcher")?;
        for metadata in [
            b"{".to_vec(),
            br#"{"name":"different-package"}"#.to_vec(),
            vec![b' '; 65537],
        ] {
            put(root, "node_modules/@openai/codex/package.json", &metadata)?;
            assert_eq!(
                windows_executable::resolve(&launcher, Some(Provider::Codex))
                    .err()
                    .ok_or("bad metadata accepted")?
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        Ok(())
    })
}
