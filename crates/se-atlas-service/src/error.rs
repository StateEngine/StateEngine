//! Index failures in the shared error vocabulary. A damaged store, an
//! unreadable source and a bad request stay distinct.
use se_atlas_index::IndexError;
use se_types::{Detail, SeError, details};

pub fn index_error(error: &IndexError) -> SeError {
    match error {
        IndexError::Invalid(what) => SeError::invalid("Atlas request", what),
        IndexError::Corrupt(what) => store_unreadable((*what).into()),
        IndexError::Sqlite(error) => sqlite(error),
        IndexError::Io(error) => {
            SeError::new(Detail::SourceUnreadable(details::SourceUnreadable {
                subject: "the Atlas code index".into(),
                reason: error.to_string(),
                next_step:
                    "Restore access to the project folder and retry; unreadable is not absent."
                        .into(),
            }))
        }
        IndexError::IgnoreRule(rule) => SeError::invalid("Atlas ignore rule", rule),
    }
}

pub fn sqlite(error: &rusqlite::Error) -> SeError {
    store_unreadable(error.to_string())
}

fn store_unreadable(reason: String) -> SeError {
    SeError::new(Detail::AtlasUnreadable(details::AtlasUnreadable {
        path: "atlas.db".into(),
        reason,
    }))
}

pub fn poisoned(what: &str) -> SeError {
    SeError::new(Detail::SourceUnreadable(details::SourceUnreadable {
        subject: format!("the Atlas {what}"),
        reason: "a thread panicked while holding it".into(),
        next_step: "Run se down and se up; the index store is kept.".into(),
    }))
}

pub fn unavailable(reason: &str) -> SeError {
    SeError::new(Detail::FeatureUnavailable(details::FeatureUnavailable {
        subject: "Atlas".into(),
        reason: reason.into(),
        next_step: "Run se down and se up, then retry.".into(),
    }))
}
