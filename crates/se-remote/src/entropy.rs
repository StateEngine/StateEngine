//! Bounded native randomness shared by transport retries and saved sessions.
use se_core::scope;
use se_types::Result;
pub fn entropy<const N: usize>() -> Result<[u8; N]> {
    if N > 32 {
        return Err(scope::unreadable(
            "remote entropy",
            "bounded entropy request exceeded",
        ));
    }
    let secret = se_proc::random_secret()
        .map_err(|e| scope::unreadable("remote entropy", &e.to_string()))?;
    secret.expose()[..N]
        .try_into()
        .map_err(|_| scope::unreadable("remote entropy", "entropy length differs"))
}
