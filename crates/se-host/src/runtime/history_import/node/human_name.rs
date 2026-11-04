//! Display-name collisions never merge recorded human identities.
use super::*;
pub(super) fn available<R: Snapshot>(
    read: &mut R,
    recorded: &str,
    human: &HumanId,
) -> StoreResult<String> {
    let mut names = std::collections::BTreeSet::new();
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
            match &item.current.body {
                EventBody::PrincipalRegistered { name, .. }
                | EventBody::PrincipalRenamed { name, .. } => {
                    names.insert(name.to_ascii_lowercase());
                }
                _ => return Err(invalid("principal roster contains an unexpected record")),
            }
        }
        if page.window().complete() {
            if !names.contains(&recorded.to_ascii_lowercase()) {
                return Ok(recorded.into());
            }
            // Full exact ID determines the suffix; the retained correspondence
            // keeps the unmodified recorded display name and source identity.
            for number in 0..=names.len() {
                let stable = human
                    .as_str()
                    .chars()
                    .rev()
                    .take(8)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>();
                let suffix = if number == 0 {
                    format!(" (historical {stable})")
                } else {
                    format!(" (historical {stable}-{number})")
                };
                let prefix = recorded
                    .chars()
                    .scan(0usize, |used, ch| {
                        *used += ch.len_utf8();
                        (*used <= 64usize.saturating_sub(suffix.len())).then_some(ch)
                    })
                    .collect::<String>();
                let candidate = format!("{prefix}{suffix}");
                if !names.contains(&candidate.to_ascii_lowercase()) {
                    return Ok(candidate);
                }
            }
            return Err(invalid("no available historical human display name"));
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
