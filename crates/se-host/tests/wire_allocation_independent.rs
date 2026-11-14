#![cfg(all(target_os = "linux", target_env = "gnu", feature = "listener"))]

use se_host::{client::wire, *};
use std::{error::Error, io::Write, path::PathBuf, process::Command};

#[path = "support/ipc_fixture.rs"]
mod fixture;
type Check = Result<(), Box<dyn Error>>;
type Event = (char, usize, bool);
type Observation = (usize, Vec<Event>);

struct Failing<'a>(&'a str);
impl serde::Serialize for Failing<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut sequence = serializer.serialize_seq(Some(2))?;
        sequence.serialize_element(self.0)?;
        Err(serde::ser::Error::custom("synthetic serialization failure"))
    }
}

fn marker(bytes: &[u8]) -> std::io::Result<()> {
    std::io::stdout().write_all(bytes)
}

fn child(case: &str) -> Check {
    if matches!(case, "observer_dirty" | "observer_clean") {
        let source = "synthetic-private-body-".repeat(64);
        marker(b"WIRE_TRACE_BEGIN\n")?;
        let mut buffer = Vec::with_capacity(4096);
        buffer.extend_from_slice(source.as_bytes());
        if case == "observer_clean" {
            use zeroize::Zeroize;
            buffer.zeroize();
        }
        std::hint::black_box(&buffer);
        drop(buffer);
        marker(b"WIRE_TRACE_END\n")?;
        println!("SERIALIZED 4096");
        return Ok(());
    }
    let text = if case.contains("escaped") {
        "\"\n\\é".repeat(1024)
    } else {
        "synthetic-private-body-".repeat(128)
    };
    let mut call = fixture::call()?;
    call.authority = Some(PresentedAuthority::Session(fixture::secret(19)?));
    if let IpcRequest::Operation(operation) = &mut call.request {
        operation.arguments = serde_json::json!({"body":text});
    }
    let mut response = fixture::response()?;
    if let IpcResult::Output(output) = &mut response.result {
        output.value = serde_json::json!({"body":text});
    }
    let expected = match case {
        "call" => wire::encode_call(&call)?.as_bytes().to_vec(),
        "response" => wire::encode_response(&response, wire::MAX_FRAME_BYTES)?
            .as_bytes()
            .to_vec(),
        _ => serde_json::to_vec(&text)?,
    };
    let framed = matches!(case, "frame" | "call" | "response");
    let limit = if matches!(case, "over" | "over_frame") {
        expected.len() - 1
    } else {
        wire::MAX_FRAME_BYTES
    };
    marker(b"WIRE_TRACE_BEGIN\n")?;
    let encoded = match case {
        "call" => wire::encode_call(&call),
        "response" => wire::encode_response(&response, limit),
        "frame" => wire::encode_frame(&text, limit),
        "over_frame" => wire::encode_frame(&text, limit),
        "error" => wire::encode_json(&Failing(&text), limit),
        _ => wire::encode_json(&text, limit),
    };
    let correct = if matches!(case, "over" | "over_frame" | "error") {
        encoded.is_err()
    } else if let Ok(encoded) = &encoded {
        if case == "frame" {
            encoded.as_bytes()[4..] == expected
                && encoded.as_bytes()[..4] == u32::try_from(expected.len())?.to_be_bytes()
        } else {
            encoded.as_bytes() == expected
        }
    } else {
        false
    };
    drop(encoded);
    marker(b"WIRE_TRACE_END\n")?;
    assert!(correct, "serialized output/refusal changed for {case}");
    println!(
        "SERIALIZED {}",
        expected.len() + usize::from(case == "frame") * 4
    );
    if framed && case != "frame" {
        assert_eq!(
            wire::frame_length(expected[..4].try_into()?, wire::MAX_FRAME_BYTES)?,
            expected.len() - 4
        );
    }
    Ok(())
}

fn observe(test: &str, case: &str) -> Result<Observation, Box<dyn Error>> {
    let directory = std::env::temp_dir().join(format!(
        "wire-allocation-{}-{test}-{case}",
        std::process::id()
    ));
    std::fs::create_dir(&directory)?;
    let library = directory.join("observer.so");
    let report = directory.join("report.txt");
    let compilation = Command::new("cc")
        .args(["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/wire_allocator.c"))
        .arg("-o")
        .arg(&library)
        .output()?;
    assert!(
        compilation.status.success(),
        "observer compilation: {}",
        String::from_utf8_lossy(&compilation.stderr)
    );
    let output = Command::new(std::env::current_exe()?)
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env("WIRE_ALLOCATOR_CHILD", case)
        .env("WIRE_ALLOCATOR_REPORT", &report)
        .env("LD_PRELOAD", &library)
        .output()?;
    let trace = std::fs::read_to_string(&report)?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(
        output.status.success(),
        "child {case}: {stdout}\n{}\n{trace}",
        String::from_utf8_lossy(&output.stderr)
    );
    let length = stdout
        .lines()
        .find_map(|line| line.strip_prefix("SERIALIZED "))
        .ok_or("missing serialized length")?
        .parse()?;
    let events = trace
        .lines()
        .map(|line| {
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.len() != 3 {
                return Err("malformed allocator report".into());
            }
            Ok((
                parts[0].chars().next().ok_or("empty event")?,
                parts[1].parse()?,
                parts[2] == "1",
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    assert_eq!(events.first().map(|row| row.0), Some('B'));
    assert_eq!(events.last().map(|row| row.0), Some('E'));
    assert!(
        !events.iter().any(|row| row.0 == 'L'),
        "live allocation escaped phase: {trace}"
    );
    println!("{case}: payload={length}, allocator={trace:?}");
    std::fs::remove_file(report)?;
    std::fs::remove_file(library)?;
    std::fs::remove_dir(directory)?;
    Ok((length, events))
}

fn delegated() -> Result<bool, Box<dyn Error>> {
    if let Ok(case) = std::env::var("WIRE_ALLOCATOR_CHILD") {
        child(&case)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[test]
fn wire_capacity_tracks_serialized_payload() -> Check {
    let test = "wire_capacity_tracks_serialized_payload";
    if delegated()? {
        return Ok(());
    }
    for case in ["json", "escaped", "frame", "call", "response"] {
        let (length, events) = observe(test, case)?;
        let allocations: Vec<_> = events.iter().filter(|row| row.0 == 'A').collect();
        assert!(
            !allocations.is_empty(),
            "observer did not see wire allocation"
        );
        assert!(
            allocations.iter().all(|row| row.1 <= length),
            "capacity must follow actual envelope, not its budget: {events:?}"
        );
        assert!(
            !events.iter().any(|row| row.0 == 'R'),
            "secret buffer grew through realloc"
        );
    }
    Ok(())
}

#[test]
fn wire_release_erases_every_allocated_byte() -> Check {
    let test = "wire_release_erases_every_allocated_byte";
    if delegated()? {
        return Ok(());
    }
    let (_, dirty) = observe(test, "observer_dirty")?;
    assert!(
        dirty.iter().any(|row| row.0 == 'F' && !row.2),
        "observer must detect unwiped source and spare capacity"
    );
    let (_, clean) = observe(test, "observer_clean")?;
    assert!(
        clean.iter().any(|row| row.0 == 'F' && row.2),
        "observer must witness whole-capacity wiping"
    );
    for case in [
        "json",
        "escaped",
        "frame",
        "call",
        "response",
        "over",
        "over_frame",
        "error",
    ] {
        let (_, events) = observe(test, case)?;
        assert!(
            events
                .iter()
                .filter(|row| matches!(row.0, 'F' | 'R'))
                .all(|row| row.2),
            "unwiped storage before release: {events:?}"
        );
        assert_eq!(
            events.iter().filter(|row| row.0 == 'A').count(),
            events.iter().filter(|row| row.0 == 'F').count(),
            "unobserved release"
        );
    }
    Ok(())
}

#[test]
fn wire_byte_limits_refuse_without_budget_sized_storage() -> Check {
    let test = "wire_byte_limits_refuse_without_budget_sized_storage";
    if delegated()? {
        return Ok(());
    }
    let text = "é\n\"".repeat(512);
    let expected = serde_json::to_vec(&text)?;
    assert!(wire::encode_json(&text, 0).is_err());
    assert!(wire::encode_json(&text, wire::MAX_FRAME_BYTES + 1).is_err());
    assert_eq!(
        wire::encode_json(&text, expected.len())?.as_bytes(),
        expected
    );
    assert!(wire::encode_json(&text, expected.len() - 1).is_err());
    assert!(wire::encode_frame(&text, expected.len() - 1).is_err());
    let maximum = "x".repeat(wire::MAX_FRAME_BYTES - 2);
    assert_eq!(
        wire::encode_json(&maximum, wire::MAX_FRAME_BYTES)?
            .as_bytes()
            .len(),
        wire::MAX_FRAME_BYTES
    );
    assert_eq!(
        wire::encode_frame(&maximum, wire::MAX_FRAME_BYTES)?
            .as_bytes()
            .len(),
        wire::MAX_FRAME_BYTES + 4
    );
    let excessive = "x".repeat(wire::MAX_FRAME_BYTES - 1);
    assert!(wire::encode_json(&excessive, wire::MAX_FRAME_BYTES).is_err());
    assert!(wire::encode_frame(&excessive, wire::MAX_FRAME_BYTES).is_err());
    let (_, events) = observe(test, "over")?;
    assert!(
        !events.iter().any(|row| row.0 == 'A'),
        "refused oversized JSON allocated a secret buffer: {events:?}"
    );
    Ok(())
}
