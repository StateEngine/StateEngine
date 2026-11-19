//! Bounded source eligibility shared by cold discovery and renewal.
mod glob;
mod rules;
pub(crate) use rules::Rules;

use crate::atlas_source::NativeAtlasSource;
use crate::atlas_watch_error::{limit, source_error, timely};
use se_atlas::{
    errors::AtlasResult,
    model::{IgnorePolicy, RelativePath},
    source::RegisteredSource,
};
use se_types::code::AtlasText;
use std::time::Instant;
type Source = RegisteredSource<NativeAtlasSource>;
