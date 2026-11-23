//! Rust inline-test detection reads the whole `#[cfg(..)]` predicate: only a
//! required `test` marks a file as holding inline tests.
use se_atlas_index::extract::{covers::test_flags, flags};

fn inline(text: &str) -> bool {
    test_flags("src/lib.rs", text) & flags::INLINE_TESTS != 0
}

#[test]
fn required_test_marks_inline_tests() {
    for text in [
        "#[cfg(test)]\nmod tests {}\n",
        "#[cfg( test )]\nmod tests {}\n",
        "#[cfg(all(test, feature = \"x\"))]\nmod tests {}\n",
        "#[cfg(all(not(windows), test))]\nmod tests {}\n",
        "#[cfg(all(feature = \"a)\", test))]\nmod tests {}\n",
    ] {
        assert!(inline(text), "missed inline tests in {text:?}");
        assert_eq!(
            test_flags("src/lib.rs", text) & flags::TEST,
            0,
            "a defining file is not a test file: {text:?}"
        );
    }
}

#[test]
fn negated_optional_or_spelled_test_is_not_inline() {
    for text in [
        "#[cfg(not(test))]\nfn real() {}\n",
        "#[cfg(not(any(test, debug_assertions)))]\nfn real() {}\n",
        "#[cfg(any(test, feature = \"x\"))]\nfn shared() {}\n",
        "#[cfg(feature = \"test\")]\nfn featured() {}\n",
        "#[cfg(test = \"x\")]\nfn odd() {}\n",
        "#[cfg(unix) ] fn test() {}\n",
        "#[cfg(unix)]\nfn test() {}\n",
    ] {
        assert!(!inline(text), "invented inline tests in {text:?}");
    }
}

#[test]
fn inline_tests_need_a_rust_file() {
    assert_eq!(
        test_flags("src/lib.py", "#[cfg(test)]\n") & flags::INLINE_TESTS,
        0
    );
}
