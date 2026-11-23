//! A defining file's own inline tests reach its impact as zero-hop tests,
//! never as a hop from the file back to itself.

mod support;

use se_types::code::AtlasText as _;
use support::*;

#[test]
fn inline_tests_are_zero_hops_from_their_defining_file() -> TestResult {
    let mut live = LiveRoot::start(
        "inline-impact",
        &[
            (
                "src/lib.rs",
                "pub fn inline_covered_helper() -> u32 { 7 }\n\
                 #[cfg(all(test, feature = \"extra\"))]\n\
                 mod tests {\n    #[test]\n    fn helper_is_seven() {\n        \
                 assert_eq!(super::inline_covered_helper(), 7);\n    }\n}\n",
            ),
            ("src/other.rs", "pub fn unrelated_plain_fn() {}\n"),
        ],
    )?;
    wait_current(live.root()?, SETTLE_TIMEOUT)?;
    let impact = present(
        live.root()?
            .impact(&impact_query("src/lib.rs")?, &DenyAllRecords)?
            .data,
    )?;
    let inline: Vec<_> = impact
        .tests
        .iter()
        .filter(|test| test.pointer.path.as_str() == "src/lib.rs")
        .collect();
    assert_eq!(inline.len(), 1, "{:?}", impact.tests);
    assert!(inline[0].hops.is_empty(), "{:?}", inline[0]);
    assert!(inline[0].file_hops.is_empty(), "{:?}", inline[0]);
    assert!(
        impact
            .tests
            .iter()
            .chain(&impact.dependents)
            .all(|d| d.pointer.path.as_str() != "src/other.rs"),
        "{impact:?}"
    );
    live.stop(STOP_TIMEOUT)
}
