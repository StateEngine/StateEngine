use crate::SessionIdentity;
use se_types::{NativePath, ProviderSessionId, Sha256};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessKind {
    ClaudeCode,
    CodexAppServer,
    Secode,
}
/// Created at trusted bind, never from a hook's claimed transcript_path.
#[derive(Clone, Debug)]
pub struct TranscriptPin {
    pub identity: SessionIdentity,
    pub conversation: ProviderSessionId,
    pub path: NativePath,
    pub file_identity: Sha256,
}
