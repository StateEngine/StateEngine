use crate::*;
/// Metadata from the same owned staging pass; never caller-path metadata.
pub trait StagedTextValue {
    fn byte_length(&self) -> u64;
    fn sha256(&self) -> [u8; 32];
}
pub use crate::staging::StagedText;
pub enum InputText {
    Inline(String),
    Staged(StagedText),
}
impl InputText {
    /// Apply-side view of queued text: staging::prepare materializes every
    /// staged handle before apply, so only inline bytes are representable at
    /// this seam. A staged handle here means that step was skipped; refuse
    /// it by name instead of reporting a later wave.
    pub(crate) fn as_materialized(&self) -> crate::StoreResult<&str> {
        match self {
            InputText::Inline(text) => Ok(text),
            InputText::Staged(_) => Err(crate::error::invalid(
                "staged text was not materialized before apply",
            )),
        }
    }
}
pub struct NewEvent {
    pub header: EventHeader,
    pub body: EventBody<InputText>,
}
pub struct AtomicBatch {
    pub expected_incarnation: u64,
    pub admission: crate::Admission,
    pub request: Option<crate::RequestIdentity>,
    pub events: Vec<NewEvent>,
    pub import_checkpoint: Option<ImportCheckpoint>,
}
