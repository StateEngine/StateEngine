//! IDs validate representations, never caller authority.
use crate::Result;
use std::{fmt::Debug, hash::Hash, num::NonZeroU64};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ProjectId([u8; 16]);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AgentId([u8; 16]);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct HumanId([u8; 16]);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SessionId([u8; 16]);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MessageId([u8; 16]);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DecisionId([u8; 16]);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EventId([u8; 16]);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StoreId([u8; 16]);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct LifecycleId([u8; 16]);

/// Future implementations: all nine UUIDv7 newtypes above.
/// No implicit clock/RNG: the caller supplies a 48-bit Unix ms time and entropy.
pub trait UuidV7:
    Sized + Copy + Eq + Ord + Hash + Debug + std::fmt::Display + std::str::FromStr<Err = crate::SeError>
{
    fn parse(text: &str) -> Result<Self>;
    fn from_bytes(bytes: [u8; 16]) -> Result<Self>;
    fn from_parts(unix_millis: u64, random: [u8; 10]) -> Result<Self>;
    fn as_bytes(&self) -> &[u8; 16];
    fn canonical(&self) -> String;
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Cursor(String);
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MachineId(String);
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct BootId(String);
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct HostSessionId(String);
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct HostEventId(String);
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct HostPendingId(String);
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ProviderSessionId(String);
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct IdempotencyKey(String);
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct NoticeId(String);

/// Representation validation only; a cursor is interpreted by its origin store.
pub trait OpaqueValue: Sized + std::fmt::Display + std::str::FromStr<Err = crate::SeError> {
    fn parse(value: &str) -> Result<Self>;
    fn as_str(&self) -> &str;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Sequence(u64);
pub trait SequenceValue: Sized {
    fn new(value: u64) -> Result<Self>;
    fn get(self) -> u64;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Generation(NonZeroU64);
/// SE Code service epoch; distinct from an engine Generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct HostGeneration(NonZeroU64);
pub trait GenerationValue: Sized {
    fn new(value: u64) -> Result<Self>;
    fn get(self) -> u64;
    fn successor(self) -> Result<Self>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct UnixMillis(u64);
pub trait TimestampValue: Sized {
    fn new(value: u64) -> Result<Self>;
    fn get(self) -> u64;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Sha256([u8; 32]);
pub trait DigestValue: Sized {
    fn from_bytes(value: [u8; 32]) -> Self;
    fn parse_hex(value: &str) -> Result<Self>;
    fn as_bytes(&self) -> &[u8; 32];
    fn hex(&self) -> String;
}

/// Wire codecs validate before constructing private fields; no serde Deserialize
/// implementation may bypass these checks. Inputs remain bounded before decode.
pub trait WireCodec<T> {
    fn decode(bytes: &[u8]) -> Result<T>;
    fn encode(value: &T) -> Result<Vec<u8>>;
}
