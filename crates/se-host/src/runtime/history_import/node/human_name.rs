//! Deterministic source names never depend on import order or roster suffixes.
use super::*;
pub(in crate::runtime::history_import) fn suffix(recorded: &str, human: &HumanId) -> String {
    let digest = se_types::hex_lower(&Sha256::digest(human.as_str().as_bytes()));
    let stable = human
        .as_str()
        .chars()
        .rev()
        .take(8)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    let suffix = format!(" (historical {stable}-{})", &digest[..8]);
    let prefix = recorded
        .chars()
        .scan(0usize, |used, ch| {
            *used += ch.len_utf8();
            (*used <= 64usize.saturating_sub(suffix.len())).then_some(ch)
        })
        .collect::<String>();
    format!("{prefix}{suffix}")
}
pub(super) fn available<R: Snapshot>(read: &mut R, planned: &str) -> StoreResult<String> {
    let mut after = None;
    for _ in 0..64 {
        let page = read.principals(ReadBudget {
            page: se_types::PageRequest {
                after,
                limit: std::num::NonZeroU32::MIN.saturating_add(99),
                max_bytes: std::num::NonZeroU32::MIN.saturating_add(1024 * 1024 - 1),
            },
            deadline: std::time::Duration::from_secs(5),
        })?;
        for item in page.items() {
            let name = match &item.current.body {
                EventBody::PrincipalRegistered { name, .. }
                | EventBody::PrincipalRenamed { name, .. } => name,
                _ => return Err(invalid("principal roster contains an unexpected record")),
            };
            if name.eq_ignore_ascii_case(planned) {
                return Err(fail(
                    StoreErrorCode::NaturalKeyConflict,
                    format!(
                        "deterministic source human name {planned:?} is already occupied; use explicit --map-human correspondence rather than an order-dependent rename"
                    ),
                ));
            }
        }
        if page.window().complete() {
            return Ok(planned.into());
        }
        after = Some(
            page.next()
                .cloned()
                .ok_or_else(|| invalid("principal roster is incomplete without continuation"))?,
        );
    }
    Err(invalid(
        "principal roster exceeds the bounded historical-name lookup",
    ))
}
