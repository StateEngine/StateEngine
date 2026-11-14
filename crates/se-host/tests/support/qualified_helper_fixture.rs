use std::{
    env, fs,
    path::Path,
    thread,
    time::{Duration, Instant},
};
const ID: &str = "ORIGINAL";
fn main() {
    let a: Vec<_> = env::args().collect();
    let mode = &a[1];
    let marker = &a[2];
    fs::write(
        marker,
        format!("{}\n{}\n{}\n", ID, a[0], std::process::id()),
    )
    .unwrap();
    if mode == "sleep" {
        thread::sleep(Duration::from_secs(10));
    }
    if mode == "wait" {
        let until = Instant::now() + Duration::from_secs(15);
        while !Path::new(&a[3]).exists() {
            assert!(Instant::now() < until, "fixture wait expired");
            thread::sleep(Duration::from_millis(5));
        }
    }
    println!("secode {}", ID);
}
