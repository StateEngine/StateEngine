use super::*;
fn stat(
    comm: &[u8],
    state: &str,
    parent: &str,
    group: &str,
    session: &str,
    start: &str,
) -> Vec<u8> {
    let mut bytes = b"123 (".to_vec();
    bytes.extend_from_slice(comm);
    bytes.extend_from_slice(format!(") {state} {parent} {group} {session}").as_bytes());
    for _ in 4..19 {
        bytes.extend_from_slice(b" 0");
    }
    bytes.extend_from_slice(format!(" {start} 99\n").as_bytes());
    bytes
}
#[test]
fn arbitrary_comm_bytes_use_the_final_delimiter_and_named_fields() {
    let bytes = stat(b"odd) name\n) \xff", "S", "10", "20", "30", "987654");
    let facts = ProcStat::parse(&bytes).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(facts.state(), Ok(b'S'));
    assert_eq!(facts.parent(), Ok(10));
    assert_eq!(facts.group(), Ok(20));
    assert_eq!(facts.session(), Ok(30));
    assert_eq!(facts.start_ticks(), Ok(987654));
}
#[test]
fn states_remain_raw_facts_for_each_callers_exit_policy() {
    for state in ["R", "S", "T", "t", "Z", "X", "x"] {
        let bytes = stat(b"name", state, "0", "0", "0", "0");
        assert_eq!(
            ProcStat::parse(&bytes).map(|s| s.state()),
            Ok(Ok(state.as_bytes()[0]))
        );
    }
    let bytes = stat(b"name", "ZZ", "1", "2", "3", "4");
    let facts = ProcStat::parse(&bytes).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(facts.state(), Err(StatError::InvalidState));
    // IPC needs only start ticks; it must not acquire the owner's state policy.
    assert_eq!(facts.start_ticks(), Ok(4));
}
#[test]
fn missing_invalid_and_overflowing_fields_refuse_distinctly() {
    assert!(matches!(
        ProcStat::parse(b"not proc stat"),
        Err(StatError::MissingDelimiter)
    ));
    let facts = ProcStat::parse(b"123 (name) S 1").unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(facts.start_ticks(), Err(StatError::TruncatedNumber));
    for bad in ["-1", "oops", "18446744073709551616"] {
        let bytes = stat(b"name", "R", "1", "2", "3", bad);
        assert_eq!(
            ProcStat::parse(&bytes).map(|s| s.start_ticks()),
            Ok(Err(StatError::InvalidNumber))
        );
    }
    let bytes = stat(b"name", "R", "4294967296", "2", "3", "4");
    assert_eq!(
        ProcStat::parse(&bytes).map(|s| s.parent()),
        Ok(Err(StatError::PidOverflow))
    );
}
#[test]
fn boot_uuid_decodes_kernel_hex_without_accepting_truncation_or_extra_digits() {
    let expected = [
        0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255,
    ];
    assert_eq!(
        boot_id(b"00112233-4455-6677-8899-aabbccddeeff\n"),
        Some(expected)
    );
    assert_eq!(
        boot_id(b" 00112233445566778899aabbccddeeff\t"),
        Some(expected)
    );
    for bad in [
        b"00112233-4455-6677-8899-aabbccddee".as_slice(),
        b"00112233445566778899aabbccddeeff0",
        b"00112233445566778899AABBCCDDEEFF",
        b"00112233445566778899aabbccddeefg",
    ] {
        assert_eq!(boot_id(bad), None);
    }
}
