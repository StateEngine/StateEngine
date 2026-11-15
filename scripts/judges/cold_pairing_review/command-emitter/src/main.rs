#![allow(dead_code)]
mod remote {
    mod native_image {
        pub mod staging;
        pub mod transactions;
    }
    pub fn commands(upload: &str, path: &str, digest: &str, windows: bool) -> serde_json::Value {
        use native_image::{staging as s, transactions as t};
        #[cfg(feature = "head")]
        let post_promote = s::check(path, windows, false);
        #[cfg(not(feature = "head"))]
        let post_promote = s::verify(path, digest, windows, false);
        serde_json::json!({"prepare":s::prepare(path,windows,false),"post_promote":post_promote,"receive":s::receive(upload,windows),"verify_upload":s::verify(upload,digest,windows,false),
            "verify_path":s::verify(path,digest,windows,false),"publish":s::publish(upload,path,windows),
            "remove":s::remove(upload,windows),"transaction":t::publish(upload,path,digest,false),
            "warm":t::cached(".",path,digest,false)})
    }
}
fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert_eq!(a.len(), 5);
    println!(
        "{}",
        remote::commands(&a[1], &a[2], &a[3], a[4] == "windows")
    );
}
