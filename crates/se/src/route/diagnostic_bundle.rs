//! Owner-only, bounded diagnostic export. No host startup, repairs or credentials are collected.
mod logs;
mod redact;

use crate::bootstrap::Bootstrap;
use redact::Redactor;
use se_core::{
    ops::{
        AnyOp, AnyOutput, DiagnosticBundle, DiagnosticBundleOutput, DoctorInspect, ProjectStatus,
    },
    scope,
};
use se_types::{Result, SeError};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

const SECTION_BYTES: usize = 256 * 1024;
const BUNDLE_BYTES: usize = 2 * 1024 * 1024;

/// Serialization stops before allocating more than the section's bounded buffer.
struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > SECTION_BYTES {
            return Err(std::io::Error::other(
                "diagnostic section exceeds its byte bound",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn section(result: Result<AnyOutput>) -> Value {
    match result {
        Ok(output) => {
            let mut bounded = Bounded(Vec::new());
            if serde_json::to_writer(&mut bounded, &output).is_err() {
                return json!({"state":"oversized", "max_bytes":SECTION_BYTES,
                    "reason":"The observation could not be serialized within the export bound; no partial data is included"});
            }
            match serde_json::from_slice::<Value>(&bounded.0) {
                Ok(data) => {
                    let exit_code = output.exit_code();
                    // An unhealthy diagnosis is collected; a partial/unreadable
                    // source is not. In particular status can contain a page cursor.
                    let complete = exit_code == 0
                        || (matches!(&output, AnyOutput::DoctorInspect(_)) && exit_code == 1);
                    json!({"state":"observed", "exit_code":exit_code, "complete":complete, "data":data})
                }
                Err(_) => {
                    json!({"state":"unreadable", "reason":"The typed observation could not be decoded for export"})
                }
            }
        }
        // Never export a partial error string: a cut can split a quoted secret.
        // Private causes are not part of the diagnostic surface.
        Err(error) => {
            let message = error.body.message();
            if message.len() > 4096 {
                json!({"state":"unreadable", "code":error.code().as_str(),
                    "reason":"Public error message exceeds the 4096-byte bound and is omitted in full",
                    "reason_omitted":true, "reason_bytes":message.len()})
            } else {
                json!({"state":"unreadable", "code":error.code().as_str(),
                    "reason":message, "reason_omitted":false})
            }
        }
    }
}
fn observed(value: &Value) -> bool {
    value["state"] == "observed"
}
fn collected(value: &Value) -> bool {
    observed(value) && value["complete"] == true
}
fn status(cx: &Bootstrap) -> Result<AnyOutput> {
    // Reuse normal status configuration handling, separately from doctor's recovery mode.
    let op = AnyOp::ProjectStatus(ProjectStatus { all: true });
    let mut status = Bootstrap::resolve(Some(cx.home.clone()), None, true, true, &op)?;
    status.project = None;
    status.selections.status_all = true;
    super::execute::dispatch(&status, op, &mut |_| Ok(()))
}

pub(super) fn execute(cx: &Bootstrap, _: DiagnosticBundle) -> Result<AnyOutput> {
    let op = AnyOp::DiagnosticBundle(DiagnosticBundle {});
    crate::bootstrap::check_session_route(&op)?;
    if cx.session.is_some() {
        return Err(SeError::new(se_types::Detail::OwnerRequired(
            se_types::details::OwnerRequired {
                op: "diagnostic.bundle".into(),
            },
        )));
    }
    let redactor = Redactor::new(cx)?;
    let version = section(
        se_core::ops::metadata_output(&AnyOp::MetaVersion(se_core::ops::MetaVersion {}))?
            .ok_or_else(|| {
                scope::unreadable("diagnostic version", "build metadata is unavailable")
            }),
    );
    let status = section(status(cx));
    let doctor = section(super::execute::dispatch(
        cx,
        AnyOp::DoctorInspect(DoctorInspect {}),
        &mut |_| Ok(()),
    ));
    let logs = logs::collect(&cx.home);
    let complete = collected(&version)
        && collected(&status)
        && collected(&doctor)
        && logs["inventory_complete"] == true
        && logs["omitted"] == 0
        && logs["state"] != "unreadable"
        && logs["entries"]
            .as_array()
            .is_some_and(|entries| entries.iter().all(observed));
    let mut bundle = json!({
        "schema":"se.diagnostic-bundle-file/v1",
        "generated_at":se_core::ops::receipt::timestamp(super::execute::now_us()?)?,
        "platform":std::env::consts::OS, "architecture":std::env::consts::ARCH,
        "complete":complete,
        "redaction":"Credential fields, credential-shaped text and home paths are removed. Review before sharing; arbitrary user text cannot be certified secret-free.",
        "version":version, "status":status, "doctor":doctor, "logs":logs,
    });
    redactor.value(&mut bundle);
    let mut bytes = serde_json::to_vec_pretty(&bundle)
        .map_err(|error| scope::unreadable("diagnostic serialization", &error.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() > BUNDLE_BYTES {
        return Err(scope::unreadable(
            "diagnostic bundle",
            "redacted export exceeds the 2 MiB bound; no file was published",
        ));
    }
    publish(&bytes, complete)
}
fn publish(bytes: &[u8], complete: bool) -> Result<AnyOutput> {
    // Native creation supplies owner-only mode/DACL on every supported platform.
    // A fresh directory avoids demanding that a damaged state home be repaired first.
    let directory = std::env::temp_dir().join(format!("se-diagnostic-{}", uuid::Uuid::new_v4()));
    let files = se_proc::NativeStateFiles::create(&directory)
        .map_err(|error| scope::unreadable("private diagnostic directory", &error.to_string()))?;
    let path = directory.join("bundle.json");
    let mut staged = files
        .create_staging(&directory)
        .map_err(|error| scope::unreadable("diagnostic staging", &error.to_string()))?;
    staged
        .file
        .write_all(bytes)
        .map_err(|error| scope::unreadable("diagnostic write", &error.to_string()))?;
    drop(staged.file);
    files
        .publish_no_replace(&staged.path, &path)
        .map_err(|error| scope::unreadable("diagnostic publication", &error.to_string()))?;
    let mut readback = Vec::new();
    files
        .readback(&path)
        .map_err(|error| scope::unreadable("diagnostic readback", &error.to_string()))?
        .ok_or_else(|| scope::unreadable("diagnostic readback", "published file is absent"))?
        .take(BUNDLE_BYTES as u64 + 1)
        .read_to_end(&mut readback)
        .map_err(|error| scope::unreadable("diagnostic readback", &error.to_string()))?;
    if readback != bytes {
        return Err(scope::unreadable(
            "diagnostic readback",
            "published bytes differ; no verified receipt is available",
        ));
    }
    Ok(DiagnosticBundleOutput {
        path: path
            .to_str()
            .ok_or_else(|| {
                scope::unreadable(
                    "diagnostic path",
                    "private temporary directory must have a lossless UTF-8 path",
                )
            })?
            .into(),
        bytes: bytes.len() as u64,
        sha256: se_types::hex_lower(&Sha256::digest(bytes)),
        complete,
    }
    .into())
}
