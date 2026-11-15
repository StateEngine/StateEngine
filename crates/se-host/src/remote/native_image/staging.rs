//! Fixed, account-owned runtime paths; partial uploads never become executable.
// All substituted paths are generated from hexadecimal hashes and nonces.
pub(in crate::remote) fn prepare_windows(directory: &str) -> String {
    // Refusals print one fixed marker line naming the failing check and
    // the path; the caller parses it. Unhandled errors still exit
    // nonzero without a marker, which the caller reports generally.
    let script = r#"$ErrorActionPreference='Stop';
$me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
$trusted=@($me,'S-1-5-18','S-1-5-32-544');
$writes=[Security.AccessControl.FileSystemRights] 'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership';
function Refuse($reason,$p){ Write-Output "image-cache-refused:$reason:$p"; exit 1 }
function Check($p) {
$i=Get-Item -LiteralPath $p -Force;
if (-not $i.PSIsContainer -or ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)) {Refuse 'unsafe-path' $p};
$a=Get-Acl -LiteralPath $p;
$o=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;
if ($o -notin $trusted) {Refuse 'foreign-owner' $p};
foreach ($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
if ($r.AccessControlType -eq 'Allow' -and ($r.FileSystemRights -band $writes) -and $r.IdentityReference.Value -notin ($trusted+@('S-1-3-0'))) {Refuse 'foreign-write-access' $p}
}
}
Check $HOME;
foreach ($d in @('.stateengine-runtime','@DIR@')) {
$p=Join-Path $HOME $d;
if (-not (Test-Path -LiteralPath $p)) {New-Item -ItemType Directory -Path $p | Out-Null};
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
if test "$((0$cm))" -ne 700; then chmod 700 "$p" || {{ printf 'image-cache-refused:mode-confirm:%s\n' "$p"; exit 1; }}; fi
fi
if test -L "$p"; then printf 'image-cache-refused:symlink:%s\n' "$p"; exit 1; fi
owner=$({stat} %u "$p") && mode=$({stat} {mode} "$p") || {{ printf 'image-cache-refused:stat-failed:%s\n' "$p"; exit 1; }}
test "$owner" = "$uid" || {{ printf 'image-cache-refused:foreign-owner:%s:%s\n' "$p" "$owner"; exit 1; }}
test "$((0$mode & 022))" -eq 0 || {{ printf 'image-cache-refused:group-or-other-writable:%s:%s\n' "$p" "$mode"; exit 1; }}
done"#
        )
    }
}

pub(in crate::remote) fn verify(path: &str, digest: &str, windows: bool, apple: bool) -> String {
    if windows {
        powershell(&format!(
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
if ((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -ne '{digest}') {{exit 1}}; exit 0
}} catch {{exit 1}}"#
        ))
    } else {
        let hash = if apple { "shasum -a 256" } else { "sha256sum" };
        let stat = if apple { "stat -f" } else { "stat -c" };
        let mode = if apple { "%Lp" } else { "%a" };
        format!(
            r#"test ! -L {path} && test -f {path} && owner=$({stat} %u {path}) && mode=$({stat} {mode} {path}) && uid=$(id -u) && test "$owner" = "$uid" || exit 1
if test "$((0$mode & 022))" -ne 0; then printf 'unsafe-mode:%s\n' "$mode"; exit 1; fi
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
