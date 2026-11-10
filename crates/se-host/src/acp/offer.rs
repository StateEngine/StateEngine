//! Certainty belongs to the writer, including refusal before writer admission.
use se_types::SeError;

#[derive(Debug)]
pub struct OfferFailure {
    pub error: SeError,
    /// Zero means no native bytes were offered; absence means the outcome is uncertain.
    pub completed_bytes: Option<u32>,
}
impl OfferFailure {
    pub(crate) fn uncertain(error: SeError) -> Self {
        Self {
            error,
            completed_bytes: None,
        }
    }
}
impl From<SeError> for OfferFailure {
    fn from(error: SeError) -> Self {
        Self {
            error,
            completed_bytes: Some(0),
        }
    }
}
