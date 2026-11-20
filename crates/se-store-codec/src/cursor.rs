//! Context and mail cursor facts, including the window accounting its public
//! wire form omits.
use super::*;
use se_types::{Cursor, Window, WindowFields};
/// The window's accounting facts, which its public wire form omits.
pub fn window_facts(window: &Window) -> StoreResult<Value> {
    let f = window
        .fields()
        .ok_or_else(|| invalid("a recorded cursor needs its snapshot window bounds"))?;
    Ok(serde_json::json!({
        "source": f.source,
        "from": f.from,
        "to": f.to,
        "start_cursor": f.start_cursor,
        "end_cursor": f.end_cursor,
        "returned": f.returned,
        "limit": f.limit.get(),
        "bytes": f.bytes,
        "max_bytes": f.max_bytes.get(),
        "omitted_before": f.omitted_before,
        "omitted_after": f.omitted_after,
        "unreadable": f.unreadable,
        "stop_reason": f.stop_reason,
    }))
}
fn window_from(v: &Value) -> StoreResult<Window> {
    let nonzero = |k: &str| -> StoreResult<std::num::NonZeroU32> {
        std::num::NonZeroU32::new(crate::field::<u32>(v, k)?)
            .ok_or_else(|| invalid(format!("stored window {k} is zero")))
    };
    Window::new(WindowFields {
        source: crate::field(v, "source")?,
        from: crate::field(v, "from")?,
        to: crate::field(v, "to")?,
        start_cursor: crate::field(v, "start_cursor")?,
        end_cursor: crate::field(v, "end_cursor")?,
        returned: crate::field(v, "returned")?,
        limit: nonzero("limit")?,
        bytes: crate::field(v, "bytes")?,
        max_bytes: nonzero("max_bytes")?,
        omitted_before: crate::field(v, "omitted_before")?,
        omitted_after: crate::field(v, "omitted_after")?,
        unreadable: crate::field(v, "unreadable")?,
        stop_reason: crate::field(v, "stop_reason")?,
    })
    .map_err(invalid)
}
pub fn metadata(record: &CursorRecord) -> StoreResult<Value> {
    Ok(serde_json::json!({
        "id": record.id,
        "agent": record.agent,
        "purpose": record.purpose,
        "value": record.value,
        "window": window_facts(&record.window)?,
        "expected": record.expected,
    }))
}
pub fn decode(v: &Value) -> StoreResult<CursorRecord> {
    Ok(CursorRecord {
        id: crate::field(v, "id")?,
        agent: crate::field(v, "agent")?,
        purpose: crate::field(v, "purpose")?,
        value: crate::field::<Cursor>(v, "value")?,
        window: window_from(
            v.get("window")
                .ok_or_else(|| invalid("stored cursor window missing"))?,
        )?,
        expected: crate::field(v, "expected")?,
    })
}
