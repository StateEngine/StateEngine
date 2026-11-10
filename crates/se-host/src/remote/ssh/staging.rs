//! Fixed, account-owned runtime paths; partial uploads never become executable.
// All substituted paths are generated from hexadecimal hashes and nonces.
pub(super) fn prepare(directory: &str, windows: bool, apple: bool) -> String {
    if windows {
        let script = r#"$ErrorActionPreference='Stop'; try {
$me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
$trusted=@($me,'S-1-5-18','S-1-5-32-544');
$writes=[Security.AccessControl.FileSystemRights] 'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership';
function Check($p) {
$i=Get-Item -LiteralPath $p -Force;
if (-not $i.PSIsContainer -or ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'unsafe runtime directory'};
$a=Get-Acl -LiteralPath $p;
$o=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;
if ($o -notin $trusted) {throw 'foreign runtime directory owner'};
foreach ($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
if ($r.AccessControlType -eq 'Allow' -and ($r.FileSystemRights -band $writes) -and $r.IdentityReference.Value -notin ($trusted+@('S-1-3-0'))) {throw 'runtime directory permits foreign writes'}
}}
Check $HOME;
foreach ($d in @('.stateengine-runtime','@DIR@')) {
$p=Join-Path $HOME $d;
if (-not (Test-Path -LiteralPath $p)) {New-Item -ItemType Directory -Path $p | Out-Null};
Check $p
}; exit 0
} catch {exit 1}"#;
        powershell(&script.replace("@DIR@", directory))
    } else {
        let stat = if apple { "stat -f" } else { "stat -c" };
        let mode = if apple { "%Lp" } else { "%a" };
        format!(
            r#"uid=$(id -u) && for p in . .stateengine-runtime {directory}; do
if ! test -d "$p"; then (umask 077 && mkdir "$p") || test -d "$p" || exit 1; fi
if test -L "$p"; then exit 1; fi
owner=$({stat} %u "$p") && mode=$({stat} {mode} "$p") || exit 1
test "$owner" = "$uid" && test "$((0$mode & 022))" -eq 0 || exit 1
done"#
        )
    }
}

pub(super) fn verify(path: &str, digest: &str, windows: bool, apple: bool) -> String {
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
            r#"test ! -L {path} && test -f {path} && owner=$({stat} %u {path}) && mode=$({stat} {mode} {path}) && uid=$(id -u) && test "$owner" = "$uid" && test "$((0$mode & 022))" -eq 0 && hash=$({hash} {path}) && test "${{hash%% *}}" = {digest}"#
        )
    }
}
pub(super) fn publish(upload: &str, path: &str, windows: bool) -> String {
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
pub(super) fn remove(upload: &str, windows: bool) -> String {
    if windows {
        powershell(&format!(
            "$ErrorActionPreference='Stop'; try {{$p=Join-Path $HOME '{upload}'; if (Test-Path -LiteralPath $p -ErrorAction Stop) {{Remove-Item -LiteralPath $p -Force -ErrorAction Stop}}; exit 0}} catch {{exit 1}}"
        ))
    } else {
        format!("rm -f {upload}")
    }
}
pub(super) fn powershell(script: &str) -> String {
    use base64::Engine as _;
    // Both command-interpreter and PowerShell SSH shells must pass the script
    // unchanged. Quoted -Command text expands variables in the outer shell.
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    format!(
        "powershell.exe -NoProfile -NonInteractive -EncodedCommand {}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}
