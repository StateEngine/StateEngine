//! Execute the production Windows staging commands; no SSH or detachment is simulated.
#![cfg(all(windows, feature = "remote"))]
#[path = "support/windows_remote_staging.rs"]
mod remote;

use remote::{Check, require, with_fixture};

#[test]
fn os_created_unicode_and_space_profile_runs_staging_through_both_shells() -> Check {
    remote::profile_paths_and_shells()
}

#[test]
fn cold_staging_preserves_binary_bytes_and_verifies_the_published_image() -> Check {
    with_fixture(|f| {
        require(f.prepare()?, "safe runtime directory refused")?;
        let upload = f.upload("binary");
        require(f.receive(&upload, &f.bytes)?, "binary receive refused")?;
        require(f.verify(&upload)?, "complete upload did not verify")?;
        require(f.publish(&upload)?, "first publication refused")?;
        require(f.verify(&f.image())?, "published image did not verify")?;
        require(
            std::fs::read(f.local(&f.image()))? == f.bytes,
            "binary stdin changed during staging",
        )?;
        require(f.prepare()?, "safe cached runtime refused")
    })
}

#[test]
fn corrupt_and_short_uploads_never_verify_or_replace_an_incumbent() -> Check {
    with_fixture(|f| {
        f.install()?;
        for (name, payload) in [
            ("short", f.bytes[..f.bytes.len() / 2].to_vec()),
            ("corrupt", vec![91; f.bytes.len()]),
        ] {
            let upload = f.upload(name);
            require(f.receive(&upload, &payload)?, "owned upload refused")?;
            require(!f.verify(&upload)?, "wrong bytes verified")?;
            require(f.remove(&upload)?, "owned partial upload cleanup refused")?;
        }
        require(f.verify(&f.image())?, "incumbent verification changed")?;
        require(
            std::fs::read(f.local(&f.image()))? == f.bytes,
            "incumbent bytes changed",
        )
    })
}

#[test]
fn publication_and_receive_refuse_an_existing_destination() -> Check {
    with_fixture(|f| {
        f.install()?;
        require(
            !f.receive(&f.image(), b"synthetic replacement")?,
            "create-new receive overwrote an incumbent",
        )?;
        let upload = f.upload("replacement");
        require(
            f.receive(&upload, b"synthetic replacement")?,
            "private replacement upload refused",
        )?;
        require(!f.publish(&upload)?, "publication overwrote an incumbent")?;
        require(f.verify(&f.image())?, "incumbent was not preserved")
    })
}

#[test]
fn competing_publishers_keep_one_complete_image() -> Check {
    with_fixture(|f| {
        require(f.prepare()?, "safe runtime directory refused")?;
        let first = f.upload("first");
        let second = f.upload("second");
        require(f.receive(&first, &f.bytes)?, "first upload refused")?;
        require(f.receive(&second, &f.bytes)?, "second upload refused")?;
        let (a, b) = std::thread::scope(|scope| {
            let a = scope.spawn(|| f.publish(&first));
            let b = scope.spawn(|| f.publish(&second));
            (a.join(), b.join())
        });
        let a = a.map_err(|_| "first publisher panicked")??;
        let b = b.map_err(|_| "second publisher panicked")??;
        require(a != b, "publishers did not observe exactly one winner")?;
        require(f.verify(&f.image())?, "winning image is incomplete")?;
        require(f.remove(&first)?, "first owned upload cleanup refused")?;
        require(f.remove(&second)?, "second owned upload cleanup refused")
    })
}

#[test]
fn foreign_write_access_refuses_both_cache_and_image_verification() -> Check {
    with_fixture(|f| {
        f.install()?;
        f.foreign_write(true)?;
        let directory = f.prepare();
        let image = f.verify(&f.image());
        let restore = f.foreign_write(false);
        restore?;
        require(!directory?, "foreign-writable cache was accepted")?;
        require(!image?, "foreign-writable image was accepted")?;
        require(
            f.verify(&f.image())?,
            "restored private image did not verify",
        )
    })
}

#[test]
fn a_directory_junction_cannot_become_the_runtime_cache() -> Check {
    with_fixture(|f| {
        require(f.prepare()?, "safe runtime directory refused")?;
        let junction = f.junction()?;
        let result = f.prepare_path(&junction);
        let removed = f.remove_junction(&junction);
        removed?;
        require(!result?, "a reparse-point runtime directory was accepted")
    })
}
