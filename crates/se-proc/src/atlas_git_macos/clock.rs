//! A cross-process monotonic expiry derived once from the caller's deadline.
use super::invalid;
use std::{
    io,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(super) struct Expiry(u64);

fn ticks() -> io::Result<u64> {
    // SAFETY: initialized native scalar output for the monotonic clock.
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: exact writable timespec and a read-only native clock selector.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seconds = u64::try_from(value.tv_sec).map_err(|_| invalid("negative monotonic seconds"))?;
    let nanos =
        u64::try_from(value.tv_nsec).map_err(|_| invalid("negative monotonic nanoseconds"))?;
    if nanos >= 1_000_000_000 {
        return Err(invalid("invalid monotonic nanoseconds"));
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(nanos))
        .ok_or_else(|| invalid("monotonic clock overflow"))
}
impl Expiry {
    pub(super) fn argument(self) -> String {
        format!("{:016x}", self.0)
    }
    pub(super) fn parse(value: &std::ffi::OsStr) -> io::Result<Self> {
        let value = value
            .to_str()
            .filter(|s| s.len() == 16)
            .ok_or_else(|| invalid("exact private Git expiry required"))?;
        let expiry = Self(
            u64::from_str_radix(value, 16).map_err(|_| invalid("invalid private Git expiry"))?,
        );
        expiry.remaining()?;
        Ok(expiry)
    }
    pub(super) fn from_original(deadline: Instant) -> io::Result<Self> {
        // Sample the native clock first: conversion cannot extend the caller's bound.
        let sampled = ticks()?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|value| *value <= Duration::from_secs(900))
            .ok_or_else(|| invalid("live original Git deadline of at most 900 seconds required"))?;
        let nanos =
            u64::try_from(remaining.as_nanos()).map_err(|_| invalid("Git expiry overflow"))?;
        Ok(Self(
            sampled
                .checked_add(nanos)
                .ok_or_else(|| invalid("Git expiry overflow"))?,
        ))
    }
    pub(super) fn remaining(self) -> io::Result<Duration> {
        let nanos = self
            .0
            .checked_sub(ticks()?)
            .filter(|n| *n > 0)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "original Git deadline elapsed")
            })?;
        if nanos > 900_000_000_000 {
            return Err(invalid("Git expiry is outside the original bounded clock"));
        }
        Ok(Duration::from_nanos(nanos))
    }
    pub(super) fn native_bound(self) -> io::Result<crate::native_ipc::IpcIoBound> {
        Ok(crate::native_ipc::IpcIoBound {
            deadline: Instant::now() + self.remaining()?,
            cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }
}
