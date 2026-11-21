//! Permanent account-claim creation shares private staging with profile files.
use super::*;

pub(super) fn create(path: &Path) -> Result<()> {
    super::super::private_stage::create_claim(path)
}
