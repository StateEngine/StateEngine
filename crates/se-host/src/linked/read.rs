use super::{ToLinked, error_body, host_epoch};
use se_types as core;
use secode_stateengine_api as api;

pub fn read<T, U>(
    value: core::Read<T>,
    context: &core::RenderCx<'_>,
    map: impl FnOnce(T) -> core::Result<U>,
) -> core::Result<api::Read<U>> {
    Ok(match value {
        core::Read::Present { value } => api::Read::Present { value: map(value)? },
        core::Read::Absent { checked } => api::Read::Absent { checked },
        core::Read::Unknown { what } => api::Read::Unknown { what },
        core::Read::Unreadable {
            source,
            reason,
            error,
        } => api::Read::Unreadable {
            source,
            reason,
            error: error
                .as_deref()
                .map(|error| error_body(error, context))
                .transpose()?,
        },
    })
}
pub fn source(value: &core::Source) -> core::Result<api::Source> {
    Ok(match value {
        core::Source::Store { store, project } => api::Source::Store {
            store: store.to_linked(),
            project: project.as_ref().map(ToLinked::to_linked),
        },
        core::Source::Host { epoch } => api::Source::Host {
            epoch: host_epoch(epoch)?,
        },
        core::Source::Configuration { location } => api::Source::Configuration {
            location: location.clone(),
        },
        // Atlas is a separate optional adapter and has no linked API source yet.
        core::Source::Atlas { .. } => {
            return Err(core::SeError::invalid(
                "linked source",
                "a store, host or configuration source",
            ));
        }
    })
}
fn omission(value: &core::Omission) -> api::Omission {
    let reason = |value| match value {
        core::OmissionReason::Limit => api::OmissionReason::Limit,
        core::OmissionReason::Budget => api::OmissionReason::Budget,
        core::OmissionReason::Unreadable => api::OmissionReason::Unreadable,
        core::OmissionReason::SourceIncomplete => api::OmissionReason::SourceIncomplete,
    };
    match value {
        core::Omission::None => api::Omission::None,
        core::Omission::Known { count, reason: why } => api::Omission::Known {
            count: count.get(),
            reason: reason(*why),
        },
        core::Omission::Unknown { reason: why } => api::Omission::Unknown {
            reason: reason(*why),
        },
    }
}
pub fn window(value: &core::Window) -> core::Result<api::Window> {
    let fields = value.fields().ok_or_else(|| {
        core::SeError::invalid(
            "linked window",
            "producer accounting; an aggregate wire window cannot prove its source or bounds",
        )
    })?;
    let stop_reason = match fields.stop_reason {
        core::StopReason::Exhausted => api::StopReason::Exhausted,
        core::StopReason::ItemLimit => api::StopReason::ItemLimit,
        core::StopReason::ByteLimit => api::StopReason::ByteLimit,
        core::StopReason::Unreadable => api::StopReason::Unreadable,
        core::StopReason::Cancelled => api::StopReason::Cancelled,
        core::StopReason::Deadline => api::StopReason::Deadline,
        core::StopReason::Unsupported => api::StopReason::Unsupported,
    };
    Ok(api::Window {
        source: source(&fields.source)?,
        start_cursor: fields.start_cursor.as_ref().map(ToLinked::to_linked),
        end_cursor: fields.end_cursor.as_ref().map(ToLinked::to_linked),
        returned: fields.returned,
        limit: fields.limit.get(),
        bytes: fields.bytes,
        max_bytes: fields.max_bytes.get(),
        omitted_before: omission(&fields.omitted_before),
        omitted_after: omission(&fields.omitted_after),
        unreadable: fields.unreadable,
        stop_reason,
        complete: value.complete(),
    })
}
pub fn page<T, U>(
    value: &core::Page<T>,
    map: impl Fn(&T) -> core::Result<U>,
) -> core::Result<api::Page<U>> {
    Ok(api::Page {
        items: value.items().iter().map(map).collect::<core::Result<_>>()?,
        window: window(value.window())?,
        next: value.next().map(ToLinked::to_linked),
    })
}
