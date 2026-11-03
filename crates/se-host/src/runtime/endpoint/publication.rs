//! Protected endpoint bytes and their compare-and-remove retirement.
use super::super::{BlockingPool, HostLease, recovery};
use crate::{EndpointRecord, client::endpoint as codec};
use se_core::store_error::store_error;
use se_store::RuntimeLease;
use se_types::{Read, Result, SeError};
use std::{
    io::{Read as ByteRead, Write},
    path::PathBuf,
    sync::Arc,
};

pub(crate) struct EndpointPublication {
    lease: Arc<HostLease>,
    path: PathBuf,
    pub(super) record: EndpointRecord,
    pub(super) recovery: Option<se_core::ops::EndpointRecovery>,
}
impl EndpointPublication {
    pub(super) fn publish(
        lease: Arc<HostLease>,
        directory: PathBuf,
        record: EndpointRecord,
        recovery: Option<se_core::ops::EndpointRecovery>,
    ) -> Result<Self> {
        let bytes = codec::encode_endpoint(&record)?;
        let path = directory.join("endpoint.json");
        let staged = lease
            .files()
            .create_staging(&directory)
            .map_err(|e| store_error(&e))?;
        let mut file = staged.file;
        file.write_all(bytes.as_bytes())
            .map_err(|e| io_error("write staged endpoint", e))?;
        file.sync_all()
            .map_err(|e| io_error("sync staged endpoint", e))?;
        drop(file);
        lease
            .files()
            .publish_no_replace(&staged.path, &path)
            .map_err(|e| store_error(&e))?;
        let published = Self {
            lease,
            path,
            record,
            recovery,
        };
        published.verify()?;
        Ok(published)
    }
    pub(super) fn retire_stale(
        lease: &HostLease,
        directory: &std::path::Path,
        expected_address: &crate::IpcEndpoint,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<Option<se_core::ops::EndpointRecovery>> {
        let path = directory.join("endpoint.json");
        let mut recovery = None;
        let previous = match lease.files().readback(&path).map_err(|e| store_error(&e))? {
            Read::Absent { .. } => None,
            Read::Present { value: mut prior } => {
                let mut bytes = Vec::new();
                (&mut prior)
                    .take(crate::client::wire::MAX_ENDPOINT_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| io_error("read stale endpoint", e))?;
                drop(prior);
                let record = codec::decode_endpoint(&bytes)?;
                if &record.address != expected_address {
                    recovery = Some(recovery::retain(&lease.files.0, &bytes)?);
                    None
                } else {
                    Some(bytes)
                }
            }
            Read::Unreadable { reason, .. } => {
                return Err(se_core::scope::unreadable("stale endpoint", &reason));
            }
            Read::Unknown { what } => {
                return Err(se_core::scope::unreadable("stale endpoint", &what));
            }
        };
        let cleanup = (|| -> Result<()> {
            deadline.remaining()?;
            #[cfg(unix)]
            {
                let crate::IpcEndpoint::UnixSocket(socket) = expected_address else {
                    return Err(SeError::invalid(
                        "stale endpoint",
                        "the native Unix socket address",
                    ));
                };
                let bound = deadline.native_bound();
                if let Some(stale) = se_proc::native_ipc::NativeUnixSocketCleanup::observe(
                    &socket.to_local()?,
                    &bound,
                )
                .map_err(crate::client::lease::native_error)?
                {
                    stale
                        .compare_remove(&bound)
                        .map_err(crate::client::lease::native_error)?;
                }
            }
            if let Some(previous) = previous {
                use sha2::Digest;
                lease
                    .files()
                    .remove_owned(&path, sha2::Sha256::digest(&previous).into())
                    .map_err(|e| store_error(&e))?;
            }
            Ok(())
        })();
        cleanup.map_err(|error| recovery::after_retention(directory, recovery.as_ref(), error))?;
        Ok(recovery)
    }
    pub(super) fn verify(&self) -> Result<()> {
        let mut file = match self
            .lease
            .files()
            .readback(&self.path)
            .map_err(|e| store_error(&e))?
        {
            Read::Present { value } => value,
            _ => {
                return Err(SeError::invalid(
                    "published endpoint",
                    "the present protected file owned by this runtime",
                ));
            }
        };
        let mut bytes = Vec::new();
        (&mut file)
            .take(crate::client::wire::MAX_ENDPOINT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| io_error("read published endpoint", e))?;
        let expected = codec::encode_endpoint(&self.record)?;
        if bytes != expected.as_bytes() {
            return Err(SeError::invalid(
                "published endpoint",
                "the exact bytes published by this epoch/generation",
            ));
        }
        Ok(())
    }
}
/// Native transport is closed; protected endpoint retirement still belongs to
/// the compare-and-remove native effect port. This value retains the OS lease
/// until that effect is independently read back as absent.
pub struct RetainedEndpoint {
    pub(super) publication: EndpointPublication,
}
impl RetainedEndpoint {
    pub fn path(&self) -> &std::path::Path {
        &self.publication.path
    }
    pub fn expected_sha256(&self) -> Result<[u8; 32]> {
        use sha2::Digest;
        Ok(
            sha2::Sha256::digest(codec::encode_endpoint(&self.publication.record)?.as_bytes())
                .into(),
        )
    }
    /// Compare-and-remove the exact publication, then read native absence back.
    /// Native socket/pipe closure and accepted-task joins precede this method.
    pub async fn retire(
        self,
        blocking: &BlockingPool,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<()> {
        blocking
            .run_owned(deadline, move || {
                let expected = self.expected_sha256()?;
                self.publication
                    .lease
                    .files()
                    .remove_owned(&self.publication.path, expected)
                    .map_err(|error| store_error(&error))?;
                self.verify_retired()
            })
            .await
    }
    pub fn verify_retired(self) -> Result<()> {
        match self
            .publication
            .lease
            .files()
            .readback(&self.publication.path)
            .map_err(|e| store_error(&e))?
        {
            Read::Absent { .. } => Ok(()),
            _ => Err(SeError::invalid(
                "endpoint retirement",
                "witnessed native absence after the exact owned removal effect",
            )),
        }
    }
}
fn io_error(subject: &str, error: std::io::Error) -> SeError {
    se_core::scope::unreadable(subject, &error.to_string()).with_cause(error)
}
