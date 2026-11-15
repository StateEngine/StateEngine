//! Fixed, account-owned runtime paths; partial uploads never become executable.
// All substituted paths are generated from hexadecimal hashes and nonces.
pub(in crate::remote) fn receive(path: &str, windows: bool) -> String {
    if windows {
        powershell(&format!(
            "$ErrorActionPreference='Stop'; $f=$null; try {{$p=Join-Path $HOME '{path}'; $f=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None); [Console]::OpenStandardInput().CopyTo($f); $f.Flush($true); $f.Dispose(); $a=[IO.File]::GetAccessControl($p); $a.SetAccessRuleProtection($true,$false); $me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; foreach ($sid in @($me,'S-1-5-18','S-1-5-32-544')) {{ $a.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','None','None','Allow'))) }}; [IO.File]::SetAccessControl($p,$a); exit 0}} catch {{if ($f) {{$f.Dispose()}}; exit 1}}"
        ))
    } else {
        // The mode is set after creation, never inherited: a parent default
        // ACL determines creation permissions from the requested mode
        // instead of the umask, so umask 077 alone leaves a group-writable
        // upload that the later verification refuses. The chmod follows a
        // complete stream only; set -C keeps a partial stream from
        // overwriting an incumbent or from becoming executable.
        format!("umask 077; set -C; cat > {path} && chmod 700 {path}")
    }
}
pub(in crate::remote) fn prepare_windows(directory: &str) -> String {
    // Refusals print one fixed marker line naming the failing check and
    // the path; the caller parses it. Unhandled errors still exit
    // nonzero without a marker, which the caller reports generally.
    // Variables are ${}-delimited: an unbraced $name directly before a
    // colon parses as a drive-qualified reference and fails the whole
    // script. foreign-owner carries the owner SID as a trailing field so
    // both platform producers share one schema.
    // Directories the product creates are hardened to the trusted
    // principals right after creation: inherited ACEs are dropped, never
    // relied on. A directory that already exists is only checked, never
    // repaired.
    let script = r#"$ErrorActionPreference='Stop';
$me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
$trusted=@($me,'S-1-5-18','S-1-5-32-544');
$writes=[Security.AccessControl.FileSystemRights] 'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership';
function Refuse($reason,$p,$extra){ if ($extra) { Write-Output "image-cache-refused:${reason}:${p}:${extra}" } else { Write-Output "image-cache-refused:${reason}:${p}" }; exit 1 }
function Harden($p) {
try {
$a=Get-Acl -LiteralPath $p;
$a.SetAccessRuleProtection($true,$false);
foreach ($sid in @($me,'S-1-5-18','S-1-5-32-544')) { $a.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))) };
Set-Acl -LiteralPath $p -AclObject $a
} catch { Refuse 'harden-failed' $p }
}
function Check($p) {
$i=Get-Item -LiteralPath $p -Force;
if (-not $i.PSIsContainer -or ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)) {Refuse 'unsafe-path' $p $null};
$a=Get-Acl -LiteralPath $p;
$o=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;
if ($o -notin $trusted) {Refuse 'foreign-owner' $p $o};
foreach ($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
if ($r.AccessControlType -eq 'Allow' -and ($r.FileSystemRights -band $writes) -and $r.IdentityReference.Value -notin ($trusted+@('S-1-3-0'))) {Refuse 'foreign-write-access' $p $null}
}
}
Check $HOME;
foreach ($d in @('.stateengine-runtime','@DIR@')) {
$p=Join-Path $HOME $d;
if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p | Out-Null; Harden $p };
Check $p
}; exit 0"#;
    script.replace("@DIR@", directory)
}

pub(in crate::remote) fn prepare(directory: &str, windows: bool, apple: bool) -> String {
    if windows {
        powershell(&prepare_windows(directory))
    } else {
        let stat = if apple { "stat -f" } else { "stat -c" };
        let mode = if apple { "%Lp" } else { "%a" };
        // Creation takes an explicit mode, never the ambient umask: a
        // group-writable umask (002) would otherwise produce a directory
        // this same check then refuses, and the refusal names nothing. A
        // masked -m result is corrected in place before the mode check.
        // Each refusal prints one fixed marker line naming the failing
        // check and the path; the caller parses it.
        format!(
            r#"uid=$(id -u) && for p in . .stateengine-runtime {directory}; do
if ! test -d "$p"; then
mkdir -m 700 "$p" || test -d "$p" || {{ printf 'image-cache-refused:create-failed:%s\n' "$p"; exit 1; }}
cm=$({stat} {mode} "$p") || {{ printf 'image-cache-refused:mode-confirm:%s\n' "$p"; exit 1; }}
if test "$cm" != 700; then chmod 700 "$p" || {{ printf 'image-cache-refused:mode-confirm:%s\n' "$p"; exit 1; }}; fi
fi
if test -L "$p"; then printf 'image-cache-refused:symlink:%s\n' "$p"; exit 1; fi
owner=$({stat} %u "$p") && mode=$({stat} {mode} "$p") || {{ printf 'image-cache-refused:stat-failed:%s\n' "$p"; exit 1; }}
test "$owner" = "$uid" || {{ printf 'image-cache-refused:foreign-owner:%s:%s\n' "$p" "$owner"; exit 1; }}
test "$((0$mode & 022))" -eq 0 || {{ printf 'image-cache-refused:group-or-other-writable:%s:%s\n' "$p" "$mode"; exit 1; }}
done"#
        )
    }
}

/// The identity checks a staged or published image must hold before it is
/// executed: a regular account-owned file without foreign write access. The
/// digest is a separate, heavier proof; see `verify`.
fn unix_identity(path: &str, apple: bool) -> String {
    let stat = if apple { "stat -f" } else { "stat -c" };
    let mode = if apple { "%Lp" } else { "%a" };
    format!(
        r#"test ! -L {path} && test -f {path} && owner=$({stat} %u {path}) && mode=$({stat} {mode} {path}) && uid=$(id -u) && test "$owner" = "$uid" || exit 1
if test "$((0$mode & 022))" -ne 0; then printf 'unsafe-mode:%s\n' "$mode"; exit 1; fi"#
    )
}

fn windows_identity(path: &str) -> String {
    format!(
        r#"$ErrorActionPreference='Stop'; try {{
$p=Join-Path $HOME '{path}'; $i=Get-Item -LiteralPath $p -Force;
if ($i.PSIsContainer -or ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)) {{exit 1}};
$me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
$trusted=@($me,'S-1-5-18','S-1-5-32-544'); $a=Get-Acl -LiteralPath $p;
if ($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {{exit 1}};
$writes=[Security.AccessControl.FileSystemRights] 'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership';
foreach ($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {{
if ($r.AccessControlType -eq 'Allow' -and ($r.FileSystemRights -band $writes) -and $r.IdentityReference.Value -notin ($trusted+@('S-1-3-0'))) {{exit 1}}
}};
"#
    )
}

/// The identity checks only, no digest proof: a promotion that is a
/// byte-preserving rename of an upload whose bytes were just hash-verified
/// re-proves identity, because only the destination account itself can
/// write inside its own 0700 runtime directory.
pub(in crate::remote) fn check(path: &str, windows: bool, apple: bool) -> String {
    if windows {
        powershell(&format!(
            r#"{identity}exit 0
}} catch {{exit 1}}"#,
            identity = windows_identity(path)
        ))
    } else {
        unix_identity(path, apple)
    }
}

/// The identity checks plus the digest proof, for paths whose bytes have not
/// already been hash-verified in this same pairing.
pub(in crate::remote) fn verify(path: &str, digest: &str, windows: bool, apple: bool) -> String {
    if windows {
        powershell(&format!(
            r#"{identity}if ((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -ne '{digest}') {{exit 1}}; exit 0
}} catch {{exit 1}}"#,
            identity = windows_identity(path)
        ))
    } else {
        let hash = if apple { "shasum -a 256" } else { "sha256sum" };
        let identity = unix_identity(path, apple);
        format!(
            r#"{identity}
hash=$({hash} {path}) && test "${{hash%% *}}" = {digest}"#
        )
    }
}
pub(in crate::remote) fn publish(upload: &str, path: &str, windows: bool) -> String {
    if windows {
        powershell(&format!(
            r#"$ErrorActionPreference='Stop'; try {{
$s=Join-Path $HOME '{upload}'; $d=Join-Path $HOME '{path}';
[IO.File]::Move($s,$d); exit 0
}} catch {{exit 1}}"#
        ))
    } else {
        // link(2) refuses an incumbent atomically. Source and destination are
        // in the same directory; no existing image or provider is overwritten.
        format!("chmod 700 {upload} && ln {upload} {path}")
    }
}
pub(in crate::remote) fn remove(upload: &str, windows: bool) -> String {
    if windows {
        powershell(&format!(
            "$ErrorActionPreference='Stop'; try {{$p=Join-Path $HOME '{upload}'; if (Test-Path -LiteralPath $p -ErrorAction Stop) {{Remove-Item -LiteralPath $p -Force -ErrorAction Stop}}; exit 0}} catch {{exit 1}}"
        ))
    } else {
        format!("rm -f {upload}")
    }
}
pub(in crate::remote) fn powershell(script: &str) -> String {
    use base64::Engine as _;
    // Both command-interpreter and PowerShell SSH shells must pass the script
    // unchanged. Quoted -Command text expands variables in the outer shell.
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    format!(
        "powershell.exe -NoProfile -NonInteractive -EncodedCommand {}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "test setup and assertions retain the failing fs operation"
)]
mod tests {
    use super::*;

    fn decode_windows(encoded: &str) -> String {
        use base64::Engine as _;
        let b64 = encoded.split(' ').next_back().expect("encoded command");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("b64");
        // -EncodedCommand is UTF-16LE, not UTF-8.
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&units).expect("utf16")
    }

    #[test]
    fn check_is_the_identity_half_of_verify() {
        let unix_check = check(".stateengine-runtime/abc", false, false);
        assert!(unix_check.contains("test ! -L .stateengine-runtime/abc"));
        assert!(unix_check.contains("owner=$(stat -c %u .stateengine-runtime/abc)"));
        assert!(unix_check.contains("0$mode & 022"));
        assert!(unix_check.contains("unsafe-mode:"));
        assert!(!unix_check.contains("sha256sum"), "check must not hash");
        assert!(!unix_check.contains("shasum"), "check must not hash");
        let apple_check = check(".stateengine-runtime/abc", false, true);
        assert!(apple_check.contains("stat -f"));
        assert!(!apple_check.contains("sha256sum"));
        let verify = verify(".stateengine-runtime/abc", "deadbeef", false, false);
        assert!(verify.starts_with(&unix_check));
        assert!(verify.contains("hash=$(sha256sum .stateengine-runtime/abc)"));
        assert!(verify.contains(r#"test "${hash%% *}" = deadbeef"#));
    }

    #[test]
    fn windows_check_drops_only_the_file_hash() {
        let windows_check = decode_windows(&check("abc", true, false));
        let windows_verify = decode_windows(&verify("abc", "deadbeef", true, false));
        assert!(windows_check.contains("Get-Acl -LiteralPath $p"));
        assert!(!windows_check.contains("Get-FileHash"));
        assert!(windows_verify.contains("Get-FileHash -LiteralPath $p -Algorithm SHA256"));
        assert!(windows_verify.contains("-ne 'deadbeef'"));
        // The identity half is byte-identical between the two commands.
        let tail = "exit 0\n} catch {exit 1}";
        assert!(windows_check.ends_with(tail));
        let identity = windows_check[..windows_check.len() - tail.len()].to_owned();
        assert!(windows_verify.starts_with(&identity));
    }
}
