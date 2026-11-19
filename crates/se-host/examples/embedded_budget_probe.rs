//! Native linked-host measurement driver.
#[path = "../tests/support/w3_realhost.rs"]
#[allow(dead_code)]
mod fixture;

use std::io::{self, BufRead, Write};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let judge = fixture::Judge::new("budget")?;
    println!("baseline");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim() != "start" {
        return Err("expected start".into());
    }
    let start = Instant::now();
    let opened = judge.open()?;
    eprintln!("open_ms={}", start.elapsed().as_secs_f64() * 1000.0);
    let generation = judge.activate(&opened)?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    println!("ready {elapsed}");
    io::stdout().flush()?;
    line.clear();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim() != "stop" {
        return Err("expected stop".into());
    }
    let receipt = judge.drain_close(&opened.host, generation)?;
    if !receipt.writer_flushed || receipt.unresolved_effects != 0 {
        return Err(format!("incomplete drain: {receipt:?}").into());
    }
    println!("closed");
    Ok(())
}
