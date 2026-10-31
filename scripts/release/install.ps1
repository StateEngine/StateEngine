# Standalone Windows installation. All uninstall effects belong to `se uninstall`.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$utf8 = New-Object Text.UTF8Encoding($false)
$claimed = $false
$pathWritten = $false
$written = New-Object 'System.Collections.Generic.List[string]'
$created = New-Object 'System.Collections.Generic.List[string]'
$record = $null
$registry = $null

function Assert-PlainPath([string]$Path) {
    $part = [IO.Path]::GetFullPath($Path)
    while ($part) {
        if ([IO.File]::Exists($part) -or [IO.Directory]::Exists($part)) {
            if (([IO.File]::GetAttributes($part) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "linked path is preserved: $part"
            }
        }
        if (Test-Path -LiteralPath (Join-Path $part '.git')) { throw "installation must be outside a repository: $part" }
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
            if (($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "archive contains a link: $path" }
            if (($attr -band [IO.FileAttributes]::Directory) -ne 0) { $pending.Push($path) }
            else { $path }
        }
    }
}
function Get-Digest([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function New-OwnedDirectory([string]$Path) {
    if (-not [IO.Directory]::Exists($Path)) {
        $parent = [IO.Path]::GetDirectoryName($Path)
        if ($parent) { New-OwnedDirectory $parent }
        [void][IO.Directory]::CreateDirectory($Path)
        $created.Add($Path)
    }
}
function Notify-Environment {
    if (-not ('StateEngineInstall.EnvironmentNotice' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
namespace StateEngineInstall {
    public static class EnvironmentNotice {
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr SendMessageTimeout(IntPtr window, uint message, UIntPtr parameter,
            string text, uint flags, uint timeout, out UIntPtr result);
    }
}
'@
    }
    $result = [UIntPtr]::Zero
    [void][StateEngineInstall.EnvironmentNotice]::SendMessageTimeout([IntPtr]0xffff, 0x1a,
        [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
}
try {
    if ($args.Count -ne 0) { throw 'usage: .\install.ps1' }
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitOperatingSystem) { throw 'this archive requires Windows x86_64' }
    if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'X64') { throw 'this archive requires native Windows x86_64' }
    $bundle = [IO.Path]::GetFullPath($PSScriptRoot)
    Assert-PlainPath $bundle
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
    $record = Join-Path $bin 'install.json'
    foreach ($path in @($root, $bin, $assets, $record)) { Assert-PlainPath $path }
    foreach ($path in @($binary, $assets, $record)) {
        if (Test-Path -LiteralPath $path) { throw "existing installation path is preserved; run se uninstall before reinstalling: $path" }
    }
    $collision = Get-Command se -ErrorAction SilentlyContinue
    if ($collision) { throw "another se command is already on PATH: $($collision.Source)" }
    $registry = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    $hadPath = $registry.GetValueNames() -contains 'Path'
    $before = if ($hadPath) { $registry.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } else { $null }
    $kind = if ($hadPath) { $registry.GetValueKind('Path') } else { [Microsoft.Win32.RegistryValueKind]::ExpandString }
    if ($hadPath -and $kind -notin @([Microsoft.Win32.RegistryValueKind]::String, [Microsoft.Win32.RegistryValueKind]::ExpandString)) { throw 'the user PATH has an unsupported registry type' }
    $alreadyPresent = @(([string]$before).Split(';') | Where-Object { $_.TrimEnd('\') -ieq $bin.TrimEnd('\') }).Count -gt 0
    $after = if ($alreadyPresent) { [string]$before } elseif ([string]::IsNullOrEmpty($before)) { $bin } else { [string]$before + ';' + $bin }
    $files = @(@{path = 'bin/se.exe'; sha256 = Get-Digest (Join-Path $bundle 'se.exe')})
    $copies = @(@{from = (Join-Path $bundle 'se.exe'); to = $binary})
    foreach ($path in $archiveFiles) {
        $relative = $path.Substring($bundle.Length + 1).Replace('\', '/')
        if ($relative -in @('manifest.json', 'build.json', 'NOTICE.txt', 'uninstall.ps1') -or $relative.StartsWith('notices/')) {
            $destination = Join-Path $assets $relative
            $copies += @{from = $path; to = $destination}
            $files += @{path = ('installation/' + $relative); sha256 = Get-Digest $path}
        }
    }
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $edits = if ($alreadyPresent) { @() } else { @(@{target = 'HKCU\Environment\Path'; before = $before; after = $after}) }
    $owned = [ordered]@{schema = 'stateengine-install/v1'; install_root = $root; owner = $owner;
        files = $files; path_edits = @($edits)}
    New-OwnedDirectory $bin
    # Claim the record with create-new before copying files or changing PATH.
    $stream = [IO.File]::Open($record, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $claimed = $true
    $stream.Dispose()
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $sid = New-Object Security.Principal.SecurityIdentifier($owner)
    $acl.SetOwner($sid)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')))
    Set-Acl -LiteralPath $record -AclObject $acl
    $readAcl = Get-Acl -LiteralPath $record
    if (-not $readAcl.AreAccessRulesProtected -or $readAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner) {
        throw 'ownership-record ACL readback failed'
    }
    $stream = [IO.File]::Open($record, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = $utf8.GetBytes(($owned | ConvertTo-Json -Depth 12) + "`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    foreach ($copy in $copies) {
        Assert-PlainPath $copy.to
        New-OwnedDirectory ([IO.Path]::GetDirectoryName($copy.to))
        [IO.File]::Copy($copy.from, $copy.to, $false)
        $written.Add($copy.to)
        if ((Get-Digest $copy.to) -ne (Get-Digest $copy.from)) { throw "installed file readback failed: $($copy.to)" }
    }
    $now = $registry.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($now -cne $before) { throw 'the user PATH changed during installation' }
    if (-not $alreadyPresent) {
        $registry.SetValue('Path', $after, $kind)
        $pathWritten = $true
        if ($registry.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -cne $after) { throw 'user PATH readback failed' }
        Notify-Environment
    }
    if ([IO.File]::ReadAllText($record) -cne (($owned | ConvertTo-Json -Depth 12) + "`n")) { throw 'ownership record readback failed' }
    Write-Output "Installed se at $binary"
    Write-Output 'Open a fresh login terminal and run se --version.'
} catch {
    [Console]::Error.WriteLine("Install refused: $($_.Exception.Message)")
    $rollbackComplete = $true
    if ($pathWritten) {
        try {
            if ($registry.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -cne $after) { throw 'user PATH was edited' }
            if ($hadPath) { $registry.SetValue('Path', $before, $kind) } else { $registry.DeleteValue('Path', $false) }
            Notify-Environment
        } catch { $rollbackComplete = $false; [Console]::Error.WriteLine("PATH rollback incomplete: $($_.Exception.Message)") }
    }
    foreach ($path in $written) {
        try {
            Assert-PlainPath $path
            $relative = $path.Substring($root.Length + 1).Replace('\', '/')
            $entry = $files | Where-Object { $_.path -ceq $relative }
            if ((Get-Digest $path) -ne $entry.sha256) { throw 'installed file was edited' }
            [IO.File]::Delete($path)
        } catch { $rollbackComplete = $false; [Console]::Error.WriteLine("Rollback preserves ${path}: $($_.Exception.Message)") }
    }
    if ($claimed -and $rollbackComplete) {
        try {
            $contents = [IO.File]::ReadAllText($record)
            if ($contents -ne '' -and $contents -cne (($owned | ConvertTo-Json -Depth 12) + "`n")) { throw 'ownership record was edited' }
            [IO.File]::Delete($record)
        } catch { $rollbackComplete = $false; [Console]::Error.WriteLine("Ownership-record rollback incomplete: $($_.Exception.Message)") }
    }
    for ($i = $created.Count - 1; $i -ge 0; $i--) {
        try { [IO.Directory]::Delete($created[$i], $false) } catch { }
    }
    if (-not $rollbackComplete) { [Console]::Error.WriteLine("Ownership record retained for se uninstall: $record") }
    exit 1
} finally {
    if ($null -ne $registry) { $registry.Dispose() }
}
