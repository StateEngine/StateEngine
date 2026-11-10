# One-shot installer for Windows x86_64.
#
#     irm <base>/bootstrap.ps1 | iex
#
# The one-liner fetches the release index, downloads the signed package for
# this platform, verifies its published checksum and its signature, and hands
# off to the SE Code installer (secode.exe update --from). It keeps no state
# of its own, so running it twice is safe: the second run re-verifies and
# updates the installation. It needs only PowerShell 5.1 or newer. No
# compiler and no Node are required.
#
# The one-liner installs signed releases only: the index must name
# trust "signed:<scheme>", each package entry must carry a signature URL,
# and the public verification key is a release-time setting stamped into
# this script. An unsigned release is refused, not bypassed.
#
# Honest Windows note: until the release is code-signed, SmartScreen still
# warns about the unsigned secode.exe itself ("Windows protected your PC").
# That warning is about the dropped executable, not about the package bytes
# this one-liner verifies; a signing decision is open.
$ErrorActionPreference = 'Stop'
function Fail([string]$Message) { Write-Error "Install refused: $Message" -ErrorAction Stop }

# Release-time settings: the release job stamps these two lines when it
# publishes. Nothing is published until then.
$SE_RELEASE_BASE_DEFAULT = ''
$SE_RELEASE_PUBLIC_KEY_B64_DEFAULT = ''   # base64 DER/SPKI RSA public key
$base = if ($env:SE_RELEASE_BASE) { $env:SE_RELEASE_BASE } else { $SE_RELEASE_BASE_DEFAULT }
if ([string]::IsNullOrWhiteSpace($base)) {
    Fail 'no release base URL is set; the release host stamps this script when it publishes, or set $env:SE_RELEASE_BASE for a local release server'
}
$base = $base.TrimEnd('/')
if ($base -notmatch '^https?://') { Fail "the release base URL must start with http:// or https://: $base" }
$pubKeyB64 = if ($env:SE_RELEASE_PUBLIC_KEY_B64) { $env:SE_RELEASE_PUBLIC_KEY_B64 } else { $SE_RELEASE_PUBLIC_KEY_B64_DEFAULT }
if ($env:OS -ne 'Windows_NT') { Fail 'this one-liner is for Windows only; on Linux or macOS use the shell one-liner instead' }
$target = 'x86_64-pc-windows-msvc'

# Minimal DER reader: enough to walk a SubjectPublicKeyInfo for
# rsaEncryption and pull out the modulus and exponent.
function Get-DerElement {
    param([byte[]]$Bytes, [int]$Offset)
    $tag = $Bytes[$Offset]
    $first = [int]$Bytes[$Offset + 1]
    $off = $Offset + 2
    if ($first -band 0x80) {
        $count = $first -band 0x7F
        if ($count -eq 0 -or $count -gt 8) { throw 'unsupported key length encoding' }
        $len = 0
        for ($i = 0; $i -lt $count; $i++) {
            $len = (($len -band 0xFFFFFF) -shl 8) -bor [int]$Bytes[$off + $i]
        }
        $off += $count
    } else {
        $len = $first
    }
    [pscustomobject]@{ Tag = $tag; Content = $off; Length = $len; End = $off + $len }
}

function Get-RsaUnsignedInteger {
    param([byte[]]$Bytes, $Element)
    $start = $Element.Content
    if ([int]$Bytes[$start] -band 0x80) { throw 'negative RSA integer' }
    if ($Element.Length -gt 1 -and $Bytes[$start] -eq 0) {
        if (([int]$Bytes[$start + 1] -band 0x80) -eq 0) { throw 'non-minimal RSA integer' }
        # DER adds a sign byte; RSAParameters expects only the unsigned magnitude.
        $start++
    }
    return ,([byte[]]@($Bytes[$start .. ($Element.End - 1)]))
}

function Get-RsaPublicKey {
    param([byte[]]$Spki)
    $outer = Get-DerElement $Spki 0
    if ($outer.Tag -ne 0x30) { throw 'not a DER document' }
    $alg = Get-DerElement $Spki $outer.Content
    if ($alg.Tag -ne 0x30) { throw 'not an RSA document' }
    $oid = Get-DerElement $Spki $alg.Content
    if ($oid.Tag -ne 0x06 -or $oid.Length -ne 9) { throw 'not an RSA key' }
    $rsaOid = [byte[]](0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01)
    for ($i = 0; $i -lt 9; $i++) {
        if ([int]$Spki[$oid.Content + $i] -ne [int]$rsaOid[$i]) { throw 'not an RSA key' }
    }
    $bits = Get-DerElement $Spki $alg.End
    if ($bits.Tag -ne 0x03) { throw 'not an RSA document' }
    if ([int]$Spki[$bits.Content] -ne 0) { throw 'not an RSA document' }
    $inner = Get-DerElement $Spki ($bits.Content + 1)
    if ($inner.Tag -ne 0x30) { throw 'not an RSA document' }
    $modulus = Get-DerElement $Spki $inner.Content
    if ($modulus.Tag -ne 0x02 -or $modulus.Length -lt 1) { throw 'not an RSA document' }
    $exponent = Get-DerElement $Spki $modulus.End
    if ($exponent.Tag -ne 0x02 -or $exponent.Length -lt 1) { throw 'not an RSA document' }
    if ($exponent.End -ne $inner.End) { throw 'trailing bytes in the RSA key' }
    $parameters = New-Object System.Security.Cryptography.RSAParameters
    $parameters.Modulus = Get-RsaUnsignedInteger $Spki $modulus
    $parameters.Exponent = Get-RsaUnsignedInteger $Spki $exponent
    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.ImportParameters($parameters)
    return $rsa
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ('se-one-line-' + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Write-Host "Fetching the release index from $base"
    try {
        Invoke-WebRequest -Uri "$base/releases/index.json" -OutFile (Join-Path $work 'index.json') -UseBasicParsing | Out-Null
    } catch {
        Fail "cannot reach $base/releases/index.json; check the URL and your network connection, then rerun the one-liner"
    }
    try {
        $index = Get-Content (Join-Path $work 'index.json') -Raw | ConvertFrom-Json
    } catch {
        Fail 'the release index is not a readable JSON document; do not install from it, and tell the maintainer the base URL'
    }
    if ($index.schema -ne 'secode.release-index.v1') {
        Fail 'the release index is not a readable secode.release-index.v1 document; do not install from it, and tell the maintainer the base URL'
    }
    if ([string]::IsNullOrWhiteSpace([string]$index.version)) {
        Fail 'the release index names no version; do not install from it'
    }
    if (-not $index.PSObject.Properties['packages']) {
        Fail 'the release index names no packages; do not install from it'
    }
    if ($index.packages.PSObject.Properties.Name -notcontains $target) {
        Fail "the release index has no package for this platform ($target); supported targets are in the index"
    }
    $entry = $index.packages.$target
    if ([string]::IsNullOrWhiteSpace([string]$entry.url)) { Fail "the release index entry for $target has no package URL" }
    if ($entry.sha256 -notmatch '^[0-9a-f]{64}$') { Fail "the release index entry for $target has no published checksum; do not install unverified bytes" }
    if ([string]::IsNullOrWhiteSpace([string]$entry.signature)) { Fail "the release index entry for $target names no signature; the one-liner only installs signed releases" }
    $trust = [string]$index.trust
    if (-not $trust.StartsWith('signed:')) {
        Fail 'this release is not signed; the one-liner only installs signed releases, so check back when the signed release is published'
    }
    $scheme = $trust.Substring('signed:'.Length)
    if ($scheme -ne 'rsa-sha256') { Fail "signature scheme $scheme is not supported by this installer build; do not install until the installer names it" }
    if ([string]::IsNullOrWhiteSpace($pubKeyB64)) {
        Fail 'no public verification key is set for this release; the one-liner only installs signed releases, so check back when the signed release is published'
    }
    if ($entry.url -match '^https?://') { $archiveUrl = $entry.url }
    elseif ($entry.url.StartsWith('/')) { $archiveUrl = "$base$($entry.url)" }
    else { Fail "the release index entry for $target has a bad package URL: $($entry.url)" }
    if (-not $archiveUrl.EndsWith('.zip')) { Fail "the release package URL for $target must end in .zip: $($entry.url)" }
    if ($entry.signature -match '^https?://') { $sigUrl = $entry.signature }
    elseif ($entry.signature.StartsWith('/')) { $sigUrl = "$base$($entry.signature)" }
    else { Fail "the release index entry for $target has a bad signature URL: $($entry.signature)" }

    Write-Host "Downloading $([System.IO.Path]::GetFileName($archiveUrl)) (release $($index.version))..."
    try {
        Invoke-WebRequest -Uri $archiveUrl -OutFile (Join-Path $work 'package.zip') -UseBasicParsing | Out-Null
    } catch {
        Fail "the download from $archiveUrl failed; check your network connection and rerun the one-liner"
    }
    $actual = (Get-FileHash -Path (Join-Path $work 'package.zip') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $entry.sha256) {
        Fail 'the downloaded package does not match its published checksum; do not bypass this check, rerun the one-liner, and if it repeats tell the maintainer which version you installed'
    }

    Write-Host "Verifying the signature ($scheme)..."
    try {
        Invoke-WebRequest -Uri $sigUrl -OutFile (Join-Path $work 'package.sig') -UseBasicParsing | Out-Null
    } catch {
        Fail "the signature from $sigUrl could not be downloaded; do not install unsigned-by-omission, rerun the one-liner"
    }
    $keyBytes = $null
    try { $keyBytes = [Convert]::FromBase64String($pubKeyB64) } catch { Fail 'the release public key is not readable base64; do not install from it' }
    $rsa = $null
    try { $rsa = Get-RsaPublicKey $keyBytes } catch { Fail 'the release public key is not a readable RSA key; do not install from it' }
    $archiveBytes = [System.IO.File]::ReadAllBytes((Join-Path $work 'package.zip'))
    $sigBytes = [System.IO.File]::ReadAllBytes((Join-Path $work 'package.sig'))
    $signatureOk = $false
    try {
        $digest = [System.Security.Cryptography.SHA256]::Create().ComputeHash($archiveBytes)
        $signatureOk = [bool]$rsa.VerifyHash($digest, 'SHA256', $sigBytes)
    } catch { $signatureOk = $false }
    if (-not $signatureOk) {
        Fail 'the package signature does not verify against the release key; do not install it, and tell the maintainer which version you tried'
    }

    Write-Host 'Extracting and checking the package...'
    try {
        Expand-Archive -Path (Join-Path $work 'package.zip') -DestinationPath $work -Force
    } catch {
        Fail 'the package is not a readable zip archive; the release is corrupt, do not install it, and tell the maintainer which version you tried'
    }
    $topDirs = Get-ChildItem -Path $work -Directory
    if ($topDirs.Count -ne 1) { Fail 'the package must hold exactly one top-level folder; this one does not, so do not install it' }
    $pkgRoot = $topDirs[0].FullName
    $secode = Join-Path $pkgRoot 'secode.exe'
    if (-not (Test-Path -LiteralPath $secode)) { Fail 'the package is missing its installer command (secode.exe); do not install it' }
    # The release package bundles the engine as one of two payload manifests:
    # stateengine/native-payload.json (schema stateengine.native-payload/v1)
    # from the current bundler, or the legacy
    # stateengine/stateengine-payload.json (schema stateengine.se-payload.v1)
    # from older packages. When both are present the native manifest is the
    # package's; a present manifest whose schema is wrong is a refusal, never
    # a fallback to the other file.
    $bundlesSe = $false
    $nativePayload = Join-Path $pkgRoot 'stateengine/native-payload.json'
    $legacyPayload = Join-Path $pkgRoot 'stateengine/stateengine-payload.json'
    if (Test-Path -LiteralPath $nativePayload) {
        try {
            $payloadJson = Get-Content $nativePayload -Raw | ConvertFrom-Json
        } catch {
            Fail 'the package carries a native StateEngine payload that is not a readable JSON manifest; do not install it'
        }
        if ($payloadJson.schema -ne 'stateengine.native-payload/v1') {
            Fail 'the package carries a native StateEngine payload that is not a readable stateengine.native-payload/v1 manifest; do not install it'
        }
        $bundlesSe = $true
    }
    elseif (Test-Path -LiteralPath $legacyPayload) {
        try {
            $payloadJson = Get-Content $legacyPayload -Raw | ConvertFrom-Json
        } catch {
            Fail 'the package carries a StateEngine payload that is not a readable JSON manifest; do not install it'
        }
        if ($payloadJson.schema -ne 'stateengine.se-payload.v1') {
            Fail 'the package carries a StateEngine payload that is not a readable stateengine.se-payload.v1 manifest; do not install it'
        }
        $bundlesSe = $true
    }

    Write-Host "Installing release $($index.version) as your normal user..."
    & $secode update --from $pkgRoot
    $rc = $LASTEXITCODE
    if ($rc -ne 0) {
        Fail "the installer stopped (exit $rc); read the message it printed above, do what it says, and rerun the one-liner"
    }
    if ($bundlesSe) {
        Write-Host 'Installed. Open a new terminal and run: se --version'
    } else {
        Write-Host 'Installed SE Code without the StateEngine engine; se is not available in this package. Open a new terminal and run: secode --version'
    }
} finally {
    Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
}
