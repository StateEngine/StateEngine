//! Shared pure codec; no execution or SQLite dependency enters se-types.
pub use se_types::code::{
    CodeCursorPosition as PositionCursor, CursorKey as Key, cursor_digest as digest,
    cursor_invalid as invalid,
};
