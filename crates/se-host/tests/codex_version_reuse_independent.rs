//! Native version-only public harness judges, not an authenticated provider journey.
#![cfg(all(feature = "listener", unix))]
#[path = "support/codex_probe_fixture.rs"]
mod fixture;
use fixture::{Check, Fixture};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
};

#[test]
fn unchanged_direct_native_image_reuses_only_this_harness_success() -> Check {
    let f = Fixture::new()?;
    let harness = f.harness();
    for _ in 0..2 {
        let version = f.direct(&harness, &f.image)?;
        assert_eq!(version.version, "0.152.0");
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
    assert_ne!(fs::metadata(&old)?.ino(), fs::metadata(&f.image)?.ino());
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
    assert_eq!(before.ino(), after.ino());
    assert_eq!(before.len(), after.len());
    assert_eq!(before.modified()?, after.modified()?);
    assert!(
        f.direct(&harness, &f.image).is_err(),
        "same-inode edits cannot inherit warm success"
    );
    assert_eq!(f.children()?, 2);
    f.cleanup()
}

#[test]
fn changed_selected_path_misses_even_for_a_hard_link_to_the_same_inode() -> Check {
    let f = Fixture::new()?;
    let harness = f.harness();
    let other = f.root.join("other-native-path");
    fs::hard_link(&f.image, &other)?;
    // Create the hard link before qualification: its creation must not itself
    // change the image stamp between the two selected invocation paths.
    f.direct(&harness, &f.image)?;
    assert_eq!(fs::metadata(&other)?.ino(), fs::metadata(&f.image)?.ino());
    f.direct(&harness, &other)?;
    assert_eq!(
        f.children()?,
        2,
        "a selected path change must not hit canonical-image success"
    );
    f.direct(&harness, &other)?;
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
fn missing_and_unexecutable_images_cannot_return_retained_success() -> Check {
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
    fs::set_permissions(&f.image, fs::Permissions::from_mode(0o600))?;
    assert!(
        f.direct(&harness, &f.image).is_err(),
        "unexecutable is not a cache hit"
    );
    fs::set_permissions(&f.image, fs::Permissions::from_mode(0o700))?;
    f.direct(&harness, &f.image)?;
    assert_eq!(f.children()?, 2);
    f.cleanup()
}

#[test]
fn selected_native_alias_stays_fresh_and_preserves_argv_zero_semantics() -> Check {
    let f = Fixture::new()?;
    let harness = f.harness();
    f.direct(&harness, &f.image)?;
    let alias = f.root.join("native-alias");
    symlink(&f.image, &alias)?;
    f.fresh(&harness, &alias)?;
    f.fresh(&harness, &alias)?;
    assert_eq!(
        f.children()?,
        3,
        "selected alias must execute on each discovery qualification"
    );
    f.direct(&harness, &alias)?;
    assert_eq!(
        f.children()?,
        4,
        "the final selected alias must also stay fresh"
    );
    let incompatible_alias = f.root.join("unsupported-alias");
    symlink(&f.image, &incompatible_alias)?;
    assert!(
        f.direct(&harness, &incompatible_alias).is_err(),
        "canonical-image success cannot override argv[0]"
    );
    assert_eq!(f.children()?, 5);
    f.cleanup()
}
