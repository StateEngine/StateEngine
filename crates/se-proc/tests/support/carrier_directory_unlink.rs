use super::*;
use crate::windows_policy_fixture::{Check, Home};

/// Protects: J5 — remove original empty directories while preserving occupied or replaced directories.
#[test]
fn readable_carrier_removes_only_original_empty_directories() -> Check {
    let home = Home::new()?;
    let empty = home.0.join("empty");
    let occupied = home.0.join("occupied");
    let replaced = home.0.join("replaced");
    let moved = home.0.join("original");
    let mut pins = Vec::new();
    let mut cases = Vec::new();
    for (path, outcome) in [
        (&empty, "removed"),
        (&occupied, "occupied"),
        (&replaced, "replaced"),
    ] {
        std::fs::create_dir(path)?;
        let original = crate::state_files::windows::effects::uninstall_directory(path)?
            .ok_or("original directory absent")?;
        let inherited = native::duplicate_same(original.as_raw_handle(), true)?;
        cases.push(serde_json::json!({"path":path, "outcome":outcome,
            "handle":inherited.as_raw_handle() as usize as u64}));
        pins.push((original, inherited));
    }
    std::fs::write(occupied.join("foreign.txt"), b"preserved foreign work")?;
    std::fs::rename(&replaced, &moved)?;
    std::fs::create_dir(&replaced)?;
    std::fs::write(replaced.join("foreign.txt"), b"preserved replacement")?;

    // Compile the production helper definitions, then drive their actual native
    // directory effect with the same inherited write-capable pins as the carrier.
    // include_str! preserves checkout line endings. Normalize only CRLF so
    // the exact production definition boundary also matches Windows checkouts.
    let source = include_str!("../../src/uninstall/carrier.ps1").replace("\r\n", "\n");
    let (definitions, _) = source
        .split_once("\n'@\n$held = ")
        .ok_or("production carrier definitions not found")?;
    let mut script = definitions.to_owned();
    script.push_str("\n'@\n$cases = ConvertFrom-Json -InputObject @'\n");
    script.push_str(&serde_json::to_string(&cases)?);
    script.push_str(
        r#"
'@
foreach ($case in $cases) {
    $original = [IntPtr]::new([int64]$case.handle)
    $refused = $false
    try { $code = [SeUninstallObjects]::Unlink($original,$case.path,$true) }
    catch {
        if ($case.outcome -ne 'replaced' -or
            $_.Exception.ToString() -notlike '*identity changed; replacement preserved*') { throw }
        $refused = $true
    }
    if ($case.outcome -eq 'replaced') {
        if (-not $refused) { throw 'Replacement directory was adopted' }
    } elseif ($case.outcome -eq 'occupied') {
        if ($code -ne 145) { throw 'Nonempty directory outcome differs' }
    } else {
        if ($code -ne 0) { throw 'Empty directory removal failed' }
        [SeUninstallObjects]::Absent($case.path)
    }
}
"#,
    );
    let script_path = home.0.join("directory-reader.ps1");
    std::fs::write(
        &script_path,
        [b"\xef\xbb\xbf".as_slice(), script.as_bytes()].concat(),
    )?;
    let diagnostic_path = home.0.join("directory-reader.stderr");
    let diagnostic = File::create(&diagnostic_path)?;
    let (read, _write) = native::pipe()?;
    let input = native::duplicate_same(read.as_raw_handle(), true)?;
    let application = cleanup::system_powershell()?;
    // Bypass isolates this mechanism test from machine policy. The public
    // consumer separately verifies the production carrier's policy refusal.
    let mut line: Vec<u16> = format!(
        "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{}\"",
        script_path.display()
    )
    .encode_utf16()
    .chain(Some(0))
    .collect();
    let inherited: Vec<_> = pins
        .iter()
        .map(|(_, handle)| handle.as_raw_handle())
        .collect();
    let environment = cleanup::environment(&home.0)?;
    // Match the production interpreter launch. The file-custody formatter adds
    // a verbatim prefix that .NET Framework rejects as its application base.
    let application: Vec<u16> = application
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let process = spawn::command(
        &application,
        &mut line,
        &input,
        &inherited,
        CREATE_NO_WINDOW,
        Some(&environment),
        Some(&diagnostic),
    )?;
    // SAFETY: retained exact fixture process and bounded native waits; timeout
    // cancellation uses that handle, never a process-name or reused-PID lookup.
    unsafe {
        if WaitForSingleObject(process.as_raw_handle(), 30000) != WAIT_OBJECT_0 {
            TerminateProcess(process.as_raw_handle(), 97);
            WaitForSingleObject(process.as_raw_handle(), 5000);
            return Err("exact directory reader fixture exceeded its deadline".into());
        }
        let mut code = 0;
        assert_ne!(GetExitCodeProcess(process.as_raw_handle(), &mut code), 0);
        assert_eq!(
            code,
            0,
            "{}",
            String::from_utf8_lossy(&std::fs::read(&diagnostic_path)?)
        );
    }
    // Original pins are still live: the independent delete handle must publish
    // absence without closing them, and must leave both foreign cases intact.
    assert_eq!(
        std::fs::symlink_metadata(&empty)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::NotFound)
    );
    assert!(moved.is_dir());
    assert_eq!(
        std::fs::read(occupied.join("foreign.txt"))?,
        b"preserved foreign work"
    );
    assert_eq!(
        std::fs::read(replaced.join("foreign.txt"))?,
        b"preserved replacement"
    );
    Ok(())
}

/// Protects: J5 — preserve a nonempty retained home despite the live root pin denying delete sharing.
#[test]
fn retained_nonempty_root_does_not_require_delete_sharing() -> Check {
    let home = Home::new()?;
    let files = NativeStateFiles::open(&home.0)?;
    let retained = home.0.join("retained-history.db");
    std::fs::write(&retained, b"retained history")?;
    assert_eq!(
        crate::remove_empty_directory(&home.0)?,
        crate::DirectoryRemoval::NotEmpty
    );
    assert_eq!(std::fs::read(&retained)?, b"retained history");
    // The same reader must still remove an actually empty ordinary directory.
    let empty = home.0.join("empty-child");
    std::fs::create_dir(&empty)?;
    assert_eq!(
        crate::remove_empty_directory(&empty)?,
        crate::DirectoryRemoval::Removed
    );
    assert_eq!(
        std::fs::symlink_metadata(&empty)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::NotFound)
    );
    drop(files);
    Ok(())
}
