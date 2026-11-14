//! Fixture time: debug assertions enable controlled slices; other builds use real time.
//! Keeping the fallback here lets release tests compile without exporting a
//! manual clock from the release Atlas library.
use std::time::Duration;

#[must_use]
pub struct Clock {
    #[cfg(debug_assertions)]
    _paused: se_atlas::clock::Paused,
}

pub fn control() -> Clock {
    Clock {
        #[cfg(debug_assertions)]
        _paused: se_atlas::clock::pause(),
    }
}

#[allow(dead_code, reason = "Only expiry fixtures advance their clock.")]
pub fn advance(duration: Duration) {
    #[cfg(debug_assertions)]
    se_atlas::clock::advance(duration);
    #[cfg(not(debug_assertions))]
    std::thread::sleep(duration);
}
