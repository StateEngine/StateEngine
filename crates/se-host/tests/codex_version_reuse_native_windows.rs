//! Windows version-qualification checks through the public harness.
//! A native synthetic executable records actual version-probe children.
//! Provider I/O refuses; these checks cover image reuse and invalidation,
//! without provider attachment, accounts or latency measurements.
//! Unix execute-permission and symbolic-link cases are not exercised here.
#![cfg(all(feature = "listener", windows))]
#[path = "support/codex_probe_fixture.rs"]
mod fixture;
use fixture::{Check, Fixture};
use std::fs;

#[test]
fn unchanged_direct_native_image_reuses_only_this_harness_success() -> Check {
    let f = Fixture::new()?;
    let harness = f.harness();
    for _ in 0..2 {
        let version = f.direct(&harness, &f.image)?;
        assert_eq!(version.version, "0.152.0");
        assert_eq!(version.protocol, "app-server/stdio-json-lines");
        assert_eq!(version.executable.to_local()?, f.image);
    }
    assert_eq!(
        f.children()?,
        1,
        "one actual --version child for two warm direct probes"
    );
    f.direct(&f.harness(), &f.image)?;
    assert_eq!(
        f.children()?,
        2,
        "a new harness must independently qualify the same image"
    );
    f.cleanup()
}

#[test]
fn replacing_selected_native_image_at_the_same_path_requalifies() -> Check {
    let f = Fixture::new()?;
    let harness = f.harness();
    f.direct(&harness, &f.image)?;
    let old = f.root.join("retained-old-image");
    fs::rename(&f.image, &old)?;
    fs::copy(&old, &f.image)?;
    f.unsupported(&f.image, false)?;
    assert!(
        f.direct(&harness, &f.image).is_err(),
        "replacement below the version floor must refuse"
    );
    assert_eq!(f.children()?, 2);
    fs::remove_file(&f.image)?;
    fs::copy(&old, &f.image)?;
    f.direct(&harness, &f.image)?;
    assert_eq!(
        f.children()?,
        3,
        "restoring a valid image requires fresh qualification"
    );
    f.cleanup()
}

#[test]
fn in_place_native_edit_with_preserved_length_and_mtime_requalifies() -> Check {
    let f = Fixture::new()?;
    let harness = f.harness();
    f.direct(&harness, &f.image)?;
    let before = fs::metadata(&f.image)?;
    f.unsupported(&f.image, true)?;
    let after = fs::metadata(&f.image)?;
    assert_eq!(before.len(), after.len());
    assert_eq!(before.modified()?, after.modified()?);
    assert!(
        f.direct(&harness, &f.image).is_err(),
        "same-file edits cannot inherit warm success"
    );
    assert_eq!(f.children()?, 2);
    f.cleanup()
}

#[test]
fn failed_probe_never_seeds_success_and_repair_is_observed() -> Check {
    let f = Fixture::new()?;
    let harness = f.harness();
    let flag = f.root.join("probe-fails");
    fs::write(&flag, b"synthetic version failure")?;
    for _ in 0..2 {
        assert!(f.direct(&harness, &f.image).is_err());
    }
    assert_eq!(
        f.children()?,
        2,
        "nonzero version exits must never seed successful reuse"
    );
    fs::remove_file(flag)?;
    f.direct(&harness, &f.image)?;
    f.direct(&harness, &f.image)?;
    assert_eq!(
        f.children()?,
        3,
        "the repaired executable qualifies and can then be reused"
    );
    f.cleanup()
}

#[test]
fn missing_and_replaced_images_cannot_return_retained_success() -> Check {
    let f = Fixture::new()?;
    let harness = f.harness();
    f.direct(&harness, &f.image)?;
    let retained = f.root.join("retained-image");
    fs::rename(&f.image, &retained)?;
    assert!(
        f.direct(&harness, &f.image).is_err(),
        "absence is not a cache hit"
    );
    fs::copy(&retained, &f.image)?;
    f.direct(&harness, &f.image)?;
    assert_eq!(
        f.children()?,
        2,
        "the replaced image must requalify before reuse"
    );
    f.cleanup()
}
