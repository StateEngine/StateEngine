# Standalone Windows installation. All uninstall effects belong to `se uninstall`.
param([switch]$Recover)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$utf8 = New-Object Text.UTF8Encoding($false)
$claimed = $false
$created = New-Object 'System.Collections.Generic.List[string]'
$record = $null
$registry = $null
$pending = $null
$pendingStream = $null
$pendingDigest = $null
$resumePending = $false

function Assert-PlainPath([string]$Path, [switch]$AllowCloudSource) {
    $part = [IO.Path]::GetFullPath($Path)
    while ($part) {
        if ([IO.File]::Exists($part) -or [IO.Directory]::Exists($part)) {
            if (([IO.File]::GetAttributes($part) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Initialize-NativeTypes
                if (-not $AllowCloudSource -or -not [StateEngineInstall.Native]::IsCloud($part)) {
                    throw "linked path is preserved: $part"
                }
            }
        }
        $part = [IO.Path]::GetDirectoryName($part)
    }
}
function Get-PlainFiles([string]$Root) {
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($Root)
    while ($pending.Count -gt 0) {
        $dir = $pending.Pop()
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($dir)) {
            $attr = [IO.File]::GetAttributes($path)
            if (($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Assert-PlainPath $path -AllowCloudSource }
            if (($attr -band [IO.FileAttributes]::Directory) -ne 0) { $pending.Push($path) }
            else { $path }
        }
    }
}
function Get-Digest([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Get-TextDigest([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Set-NativeOwner([string]$Path, [Security.Principal.SecurityIdentifier]$Owner) {
    Assert-PlainPath $Path
    $security = Get-Acl -LiteralPath $Path
    if ($security.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $Owner.Value) {
        $security.SetOwner($Owner)
        Set-Acl -LiteralPath $Path -AclObject $security
    }
    $readback = Get-Acl -LiteralPath $Path
    if ($readback.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $Owner.Value) {
        throw "installed native-owner readback failed: $Path"
    }
}
function New-OwnedDirectory([string]$Path, [Security.Principal.SecurityIdentifier]$Owner) {
    if (-not [IO.Directory]::Exists($Path)) {
        $parent = [IO.Path]::GetDirectoryName($Path)
        if ($parent) { New-OwnedDirectory $parent $Owner }
        Initialize-NativeTypes
        if ([StateEngineInstall.Native]::MakeDirectory($Path, $Owner.Value)) {
            $created.Add($Path)
            Set-NativeOwner $Path $Owner
        }
        Assert-PlainPath $Path
    }
}
function Assert-ProtectedDataHome([string]$Path, [Security.Principal.SecurityIdentifier]$Owner) {
    Assert-PlainPath $Path
    $security = Get-Acl -LiteralPath $Path
    if (-not $security.AreAccessRulesProtected -or
        $security.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $Owner.Value) {
        throw "data home requires a protected current-user DACL; existing permissions were preserved: $Path"
    }
    $principals = @($Owner.Value, 'S-1-5-18')
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($rule in $security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.IsInherited -or $rule.IdentityReference.Value -notin $principals -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne $inheritance -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw "data home requires inheritable full control only for its user and SYSTEM; existing permissions were preserved: $Path"
        }
        [void]$seen.Add($rule.IdentityReference.Value)
    }
    if ($seen.Count -ne 2) { throw "data home requires user and SYSTEM protection: $Path" }
}
function Read-Pending([IO.FileStream]$Stream) {
    if ($Stream.Length -gt 1048576) { throw 'partial installation journal exceeds one MiB' }
    $Stream.Position = 0
    $bytes = New-Object byte[] ([int]$Stream.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $count = $Stream.Read($bytes, $offset, $bytes.Length - $offset)
        if ($count -eq 0) { throw 'partial installation journal read was incomplete' }
        $offset += $count
    }
    $utf8.GetString($bytes)
}
function Flush-Copy([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
    try { $stream.Flush($true) } finally { $stream.Dispose() }
}
function Initialize-NativeTypes {
    if (-not ('StateEngineInstall.Native' -as [type])) {
        Add-Type @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace StateEngineInstall {
    public static class Native {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool MoveFileEx(string source, string destination, uint flags);
        public static void PublishRecord(string source, string destination) {
            // WRITE_THROUGH, without REPLACE_EXISTING or COPY_ALLOWED.
            if (!MoveFileEx(source, destination, 8)) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct AttributeTag { public uint Attributes; public uint Tag; }
        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes {
            public int Length;
            public IntPtr Descriptor;
            public int InheritHandle;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string name, uint access, uint sharing,
            IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind,
            out AttributeTag info, uint size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateDirectory(string name, ref SecurityAttributes security);
        public static bool MakeDirectory(string path, string owner) {
            var security = new System.Security.AccessControl.DirectorySecurity();
            security.SetSecurityDescriptorSddlForm(
                "O:" + owner + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + owner + ")");
            var descriptor = GCHandle.Alloc(security.GetSecurityDescriptorBinaryForm(), GCHandleType.Pinned);
            try {
                var attributes = new SecurityAttributes {
                    Length = Marshal.SizeOf(typeof(SecurityAttributes)),
                    Descriptor = descriptor.AddrOfPinnedObject(), InheritHandle = 0
                };
                if (CreateDirectory(path, ref attributes)) return true;
                int error = Marshal.GetLastWin32Error();
                if (error == 183 && Directory.Exists(path)) return false;
                throw new Win32Exception(error);
            } finally { descriptor.Free(); }
        }
        // Cloud placeholders are not name-surrogate links. Only source reads admit them.
        // https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-tags
        public static bool IsCloud(string path) {
            using (SafeFileHandle handle = CreateFile(path, 0x80, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero)) {
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                AttributeTag info;
                if (!GetFileInformationByHandleEx(handle, 9, out info, 8))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return (info.Tag & 0xffff0fffu) == 0x9000001au;
            }
        }
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr SendMessageTimeout(IntPtr window, uint message, UIntPtr parameter,
            string text, uint flags, uint timeout, out UIntPtr result);
    }
}
'@
    }
}
function Notify-Environment {
    Initialize-NativeTypes
    $result = [UIntPtr]::Zero
    [void][StateEngineInstall.Native]::SendMessageTimeout([IntPtr]0xffff, 0x1a,
        [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
}
try {
    if ($args.Count -ne 0) { throw 'usage: .\install.ps1 [-Recover]' }
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitOperatingSystem) { throw 'this archive requires Windows x86_64' }
    if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'X64') { throw 'this archive requires native Windows x86_64' }
    $bundle = [IO.Path]::GetFullPath($PSScriptRoot)
    Assert-PlainPath $bundle -AllowCloudSource
    $archiveFiles = @(Get-PlainFiles $bundle)
    $listed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $bundle 'SHA256SUMS'))) {
        if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9_./+-]+)$') { throw 'invalid archive checksum line' }
        $expected = $Matches[1]
        $relative = $Matches[2]
        if ($relative.StartsWith('/') -or ($relative.Split('/') -contains '..') -or -not $listed.Add($relative)) {
            throw "unsafe or duplicate inventory entry: $relative"
        }
        if ((Get-Digest (Join-Path $bundle $relative)) -ne $expected) { throw "archive checksum mismatch: $relative" }
    }
    if ($archiveFiles.Count -ne ($listed.Count + 1)) { throw 'archive has unlisted files' }
    $manifest = Get-Content -LiteralPath (Join-Path $bundle 'manifest.json') -Raw | ConvertFrom-Json
    if ($manifest.schema -ne 'se.release/v1' -or $manifest.variant -ne 'standalone' -or
        $manifest.trust -ne 'unsigned' -or $manifest.target -ne 'x86_64-pc-windows-msvc') { throw 'unsupported archive variant or target' }
    if (-not $env:LOCALAPPDATA -or -not [IO.Path]::IsPathRooted($env:LOCALAPPDATA)) { throw 'LOCALAPPDATA must name an absolute user directory' }
    $root = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'StateEngine'))
    $bin = Join-Path $root 'bin'
    $binary = Join-Path $bin 'se.exe'
    $assets = Join-Path $root 'installation'
    if ($env:SE_HOME -and -not [IO.Path]::IsPathRooted($env:SE_HOME)) { throw 'SE_HOME must be absolute' }
    $data = if ($env:SE_HOME) { [IO.Path]::GetFullPath($env:SE_HOME) } else { $root }
    $record = Join-Path $data 'standalone-install.json'
    $pending = Join-Path $data 'standalone-install.pending.json'
    Assert-PlainPath $pending
    if ($Recover) {
        if (-not [IO.File]::Exists($pending)) { throw "partial installation journal is absent: $pending" }
    } elseif (Test-Path -LiteralPath $pending) { throw "partial installation at $pending; rerun this archive's install.ps1 -Recover" }
    foreach ($path in @($root, $bin, $assets, $record)) { Assert-PlainPath $path }
    foreach ($path in @($binary, $assets, $record)) {
        if (-not $Recover -and (Test-Path -LiteralPath $path)) { throw "existing installation path is preserved; run se uninstall before reinstalling: $path" }
    }
    $collision = Get-Command se -ErrorAction SilentlyContinue
    if ($collision -and -not $Recover) { throw "another se command is already on PATH: $($collision.Source)" }
    $registry = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $false)
    $hadPath = $null -ne $registry -and $registry.GetValueNames() -contains 'Path'
    $currentHadPath = $hadPath
    $before = if ($hadPath) { $registry.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } else { $null }
    $kind = if ($hadPath) { $registry.GetValueKind('Path') } else { [Microsoft.Win32.RegistryValueKind]::ExpandString }
    if ($hadPath -and $kind -notin @([Microsoft.Win32.RegistryValueKind]::String, [Microsoft.Win32.RegistryValueKind]::ExpandString)) { throw 'the user PATH has an unsupported registry type' }
    $alreadyPresent = @(([string]$before).Split(';') | Where-Object { $_.TrimEnd('\') -ieq $bin.TrimEnd('\') }).Count -gt 0
    $currentAlreadyPresent = $alreadyPresent
    $after = if ($alreadyPresent) { [string]$before } elseif ([string]::IsNullOrEmpty($before)) { $bin } else { [string]$before + ';' + $bin }
    $files = @(@{path = $binary; sha256 = Get-Digest (Join-Path $bundle 'se.exe')})
    $copies = @(@{from = (Join-Path $bundle 'se.exe'); to = $binary})
    foreach ($path in $archiveFiles) {
        $relative = $path.Substring($bundle.Length + 1).Replace('\', '/')
        if ($relative -in @('manifest.json', 'build.json', 'NOTICE.txt', 'notices.tar', 'uninstall.ps1') -or $relative.StartsWith('notices/')) {
            $destination = Join-Path $assets $relative
            $copies += @{from = $path; to = $destination}
            $files += @{path = $destination; sha256 = Get-Digest $path}
        }
    }
    $ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $owner = $ownerSid.Value
    if ([IO.Directory]::Exists($data)) { Assert-ProtectedDataHome $data $ownerSid }
    $priorDigest = if ($hadPath) { Get-TextDigest ([string]$before) } else { $null }
    $edits = @()
    if (-not $alreadyPresent) {
        $edits += @{target = 'HKCU\Environment\Path'; before_sha256 = $priorDigest; block = $bin}
    }
    # All checks above are read-only. Record only directories this install creates.
    New-OwnedDirectory $bin $ownerSid
    New-OwnedDirectory $data $ownerSid
    Assert-ProtectedDataHome $data $ownerSid
    foreach ($copy in $copies) { New-OwnedDirectory ([IO.Path]::GetDirectoryName($copy.to)) $ownerSid }
    $owned = [ordered]@{schema = 'stateengine-install/v1'; owner = $owner;
        files = $files; created_directories = $created.ToArray(); path_edits = @($edits)}
    # The pending journal is the exclusive per-home claim. It advertises only
    # intended paths; no completed installation record exists during copying.
    if ($Recover) {
        if ((Get-Acl -LiteralPath $pending).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner) { throw 'partial journal has a different native owner' }
        & (Join-Path $bundle 'se.exe') __install-files-check $pending
        if ($LASTEXITCODE -ne 0) { throw 'partial journal native file custody refused' }
        $pendingStream = [IO.File]::Open($pending, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $claimed = $true
        $rawPending = Read-Pending $pendingStream
        $partial = $null
        try { $partial = $rawPending | ConvertFrom-Json } catch { $partial = $null }
        if ($null -eq $partial -and (@($copies | Where-Object { Test-Path -LiteralPath $_.to }).Count -ne 0 -or (Test-Path -LiteralPath $record))) { throw 'incomplete journal with published paths; preserve the partial installation' }
        if ($null -ne $partial) {
            if ($partial.schema -ne 'stateengine-install-pending/v1' -or $partial.owner -ne $owner -or
                $partial.archive_sha256 -ne (Get-Digest (Join-Path $bundle 'manifest.json'))) { throw 'recovery requires the original native owner and archive' }
            if (@($partial.planned_files).Count -ne $files.Count) { throw 'partial installation file inventory differs' }
            foreach ($file in $files) {
                $found = @($partial.planned_files | Where-Object { $_.path -ceq $file.path -and $_.sha256 -ceq $file.sha256 })
                if ($found.Count -ne 1) { throw 'partial installation does not name the exact original files' }
            }
            $edits = @($partial.path_edits)
            if ($edits.Count -gt 1 -or ($edits.Count -eq 1 -and ($edits[0].target -cne 'HKCU\Environment\Path' -or $edits[0].block -cne $bin -or
                ($null -ne $edits[0].before_sha256 -and $edits[0].before_sha256 -cnotmatch '^[0-9a-f]{64}$')))) { throw 'partial PATH edit differs from the original bin entry' }
            if ($partial.had_path -isnot [bool] -or $partial.path_kind -notin @('String', 'ExpandString')) { throw 'partial PATH type is invalid' }
            $hadPath = $partial.had_path
            $kind = [Enum]::Parse([Microsoft.Win32.RegistryValueKind], [string]$partial.path_kind)
            $alreadyPresent = $edits.Count -eq 0
            if ($alreadyPresent -and -not $currentAlreadyPresent) { throw 'original PATH entry changed; partial state preserved' }
            if (-not $alreadyPresent) {
                $prior = $edits[0].before_sha256
                $unchanged = if ($null -eq $prior) { -not $currentHadPath } else { $currentHadPath -and (Get-TextDigest ([string]$before)) -ceq $prior }
                if (-not $unchanged) {
                    $suffix = ';' + $bin
                    $prefix = if ([string]$before -ceq $bin) { '' } elseif (([string]$before).EndsWith($suffix, [StringComparison]::Ordinal)) { ([string]$before).Substring(0, ([string]$before).Length - $suffix.Length) } else { throw 'user PATH changed; partial state preserved' }
                    $matchesPrior = if ($null -eq $prior) { $prefix -ceq '' } else { (Get-TextDigest $prefix) -ceq $prior }
                    if (-not $matchesPrior) { throw 'user PATH prefix changed; partial state preserved' }
                    $alreadyPresent = $true
                }
            }
            if (@($partial.created_directories).Count -gt 128) { throw 'partial directory inventory exceeds its bound' }
            foreach ($directory in @($partial.created_directories)) {
                Assert-PlainPath $directory
                if (-not [IO.Path]::IsPathRooted([string]$directory) -or [IO.Path]::GetFullPath([string]$directory) -cne [string]$directory -or
                    [string]$directory -ieq [IO.Path]::GetPathRoot([string]$directory)) { throw 'partial directory is not a normalized non-root path' }
                $prefix = ([IO.Path]::GetFullPath([string]$directory)).TrimEnd('\') + '\'
                if (@($files | Where-Object { $_.path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0 -and
                    -not (($data.TrimEnd('\') + '\').StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase))) { throw 'partial directory is outside the exact installation roots' }
                if (-not $created.Contains([string]$directory)) { $created.Add([string]$directory) }
            }
            $owned = [ordered]@{schema = 'stateengine-install/v1'; owner = $owner;
                files = $files; created_directories = $created.ToArray(); path_edits = @($edits)}
            $resumePending = $true
        }
    } else {
        $pendingStream = [IO.File]::Open($pending, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    }
    $claimed = $true
    $pendingPlan = [ordered]@{schema = 'stateengine-install-pending/v1'; owner = $owner;
        archive_sha256 = Get-Digest (Join-Path $bundle 'manifest.json'); planned_files = $files;
        created_directories = $created.ToArray(); path_edits = @($edits); had_path = $hadPath; path_kind = $kind.ToString()}
    if (-not $resumePending) {
        $pendingBytes = $utf8.GetBytes(($pendingPlan | ConvertTo-Json -Depth 12) + "`n")
        $pendingStream.Position = 0
        $pendingStream.SetLength(0)
        $pendingStream.Write($pendingBytes, 0, $pendingBytes.Length)
        $pendingStream.Flush($true)
        $rawPending = $utf8.GetString($pendingBytes)
    }
    $pendingDigest = Get-TextDigest $rawPending
    if ((Read-Pending $pendingStream) -cne $rawPending) { throw 'partial journal durable readback failed' }
    foreach ($copy in $copies) {
        Assert-PlainPath $copy.to
        if ($Recover -and [IO.File]::Exists($copy.to)) {
            if ((Get-Digest $copy.to) -cne (Get-Digest $copy.from) -or
                (Get-Acl -LiteralPath $copy.to).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner) { throw "partial destination changed; preserved: $($copy.to)" }
        } else {
            [IO.File]::Copy($copy.from, $copy.to, $false)
            Set-NativeOwner $copy.to $ownerSid
        }
        Flush-Copy $copy.to
        if ((Get-Digest $copy.to) -ne (Get-Digest $copy.from)) { throw "installed file readback failed: $($copy.to)" }
    }
    if ($null -ne $registry) { $registry.Dispose() }
    $registry = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    $now = $registry.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($now -cne $before) { throw 'the user PATH changed during installation' }
    if (-not $alreadyPresent) {
        $after = if ([string]::IsNullOrEmpty($before)) { $bin } else { [string]$before + ';' + $bin }
        $registry.SetValue('Path', $after, $kind)
        if ($registry.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -cne $after) { throw 'user PATH readback failed' }
        Notify-Environment
    }
    $fileCheck = @('__install-files-check') + @($files | ForEach-Object { $_.path })
    & (Join-Path $bundle 'se.exe') @fileCheck
    if ($LASTEXITCODE -ne 0) { throw 'installed native file custody readback failed' }
    # Publish the complete record only after every copy was flushed/read back
    # and the exact PATH effect was observed.
    $recordText = ($owned | ConvertTo-Json -Depth 12) + "`n"
    if ($Recover -and [IO.File]::Exists($record)) {
        Assert-PlainPath $record
        if ([IO.File]::ReadAllText($record) -cne $recordText -or
            (Get-Acl -LiteralPath $record).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner) { throw 'completed record differs from the partial journal' }
        Flush-Copy $record
    } else {
        $temporary = Join-Path $data '.standalone-install.publish'
        Assert-PlainPath $temporary
        $mode = [IO.FileMode]::CreateNew
        if ($Recover -and [IO.File]::Exists($temporary)) {
            & (Join-Path $bundle 'se.exe') __install-files-check $temporary
            if ($LASTEXITCODE -ne 0) { throw 'record staging native file custody refused' }
            if ((Get-Acl -LiteralPath $temporary).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner) { throw 'record staging has a different owner' }
            $mode = [IO.FileMode]::Open
        }
        $stream = [IO.File]::Open($temporary, $mode, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.SetLength(0); $bytes = $utf8.GetBytes($recordText); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
        Initialize-NativeTypes
        [StateEngineInstall.Native]::PublishRecord($temporary, $record)
    }
    if ([IO.File]::ReadAllText($record) -cne $recordText) { throw 'ownership record readback failed' }
    & (Join-Path $bundle 'se.exe') __install-files-check $record
    if ($LASTEXITCODE -ne 0) { throw 'ownership record native custody readback failed' }
    $pendingStream.Dispose(); $pendingStream = $null
    Assert-PlainPath $pending
    if ((Get-Digest $pending) -cne $pendingDigest) { throw 'partial journal changed before completion' }
    [IO.File]::Delete($pending)
    Write-Output "Installed se at $binary"
    Write-Output 'Open a fresh login terminal and run se --version.'
} catch {
    [Console]::Error.WriteLine("Install refused: $($_.Exception.Message)")
    if ($claimed) {
        [Console]::Error.WriteLine("Partial installation preserved at $pending; resume with this archive's install.ps1 -Recover")
    } else {
        for ($i = $created.Count - 1; $i -ge 0; $i--) {
            try { [IO.Directory]::Delete($created[$i], $false) } catch { }
        }
    }
    exit 1
} finally {
    if ($null -ne $pendingStream) { $pendingStream.Dispose() }
    if ($null -ne $registry) { $registry.Dispose() }
}
