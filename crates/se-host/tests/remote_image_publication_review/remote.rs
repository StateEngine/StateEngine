//! Compile the unchanged production constructors with their original visibility.
#[path = "../../src/remote/native_image/staging.rs"]
pub mod staging;
#[path = "../../src/remote/native_image/transactions.rs"]
pub mod transactions;

pub fn publication(upload: &str, target: &str, digest: &str, apple: bool) -> String {
    transactions::publish(upload, target, digest, apple)
}
