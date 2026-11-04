param([Parameter(Mandatory=$true)][string]$Se, [Parameter(Mandatory=$true)][string]$OutputRoot)
# Run locally on Windows with a binary built from this candidate. All homes are new.
$ErrorActionPreference = 'Stop'
$script:Binary = (Resolve-Path -LiteralPath $Se).Path
if (Test-Path -LiteralPath $OutputRoot) { throw 'OutputRoot must not exist' }
[void][System.IO.Directory]::CreateDirectory($OutputRoot)
$OutputRoot = (Resolve-Path -LiteralPath $OutputRoot).Path
$script:Calls = 0
$homes = [System.Collections.Generic.List[string]]::new()
function Invoke-Se([string]$StateHome, [string[]]$Words) {
    $script:Calls++
    $prefix = Join-Path $OutputRoot ('call-{0:d3}' -f $script:Calls)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $stdout = & $script:Binary --home $StateHome --json @Words 2> ($prefix + '.stderr')
    $code = $LASTEXITCODE
    $ErrorActionPreference = $previous
    $text = $stdout -join "`n"
    [System.IO.File]::WriteAllText($prefix + '.stdout', $text)
    [System.IO.File]::WriteAllText($prefix + '.exit', [string]$code)
    return [pscustomobject]@{ Code=$code; Value=($text | ConvertFrom-Json) }
}
function Require($Condition, [string]$Reason) { if (-not $Condition) { throw $Reason } }
function Block([string]$Text, [string]$Name) {
    $start = "BEGIN SE $Name`n"; $end = "`nEND SE $Name"
    $parts = $Text.Split(@($start), [System.StringSplitOptions]::None)
    Require ($parts.Length -eq 2) 'Missing or duplicate start marker'
    $parts = $parts[1].Split(@($end), [System.StringSplitOptions]::None)
    Require ($parts.Length -eq 2) 'Missing or duplicate end marker'
    return $parts[0]
}
function Read-Host([string]$Prompt) { return $script:RetainedCopy }
function se {
    & $script:Binary @args
    if ($LASTEXITCODE -ne 0) { throw "Printed se command failed: $LASTEXITCODE" }
}
$passed = 0
try {
    $parent = Join-Path $OutputRoot ("O" + [char]0x2019 + "Brien's [home]")
    $state = Join-Path $parent 'state'
    $homes.Add($state)
    $repo = Join-Path $OutputRoot 'repository'
    [void][System.IO.Directory]::CreateDirectory($repo)
    [System.IO.File]::WriteAllText((Join-Path $repo 'user-work.txt'), 'User work survives recovery.')
    $init = Invoke-Se -StateHome $state -Words @('init','--repo',$repo,'--name','Recovery witness')
    Require ($init.Code -eq 0) 'Initial setup failed'
    $owner = $init.Value.owner.human_id
    Require ((Invoke-Se -StateHome $state -Words @('down')).Code -eq 0) 'Initial down failed'
    $script:RetainedCopy = Join-Path $parent 'closed copy [retained]'
    [void][System.IO.Directory]::CreateDirectory($script:RetainedCopy)
    $db = Join-Path $state 'state.db'
    $savedDb = Join-Path $script:RetainedCopy 'state.db'
    [System.IO.File]::Move($db, $savedDb)
    $sourceHash = (Get-FileHash -LiteralPath $savedDb -Algorithm SHA256).Hash
    # Old sidecars are arbitrary retained bytes, never applied to the restored DB.
    foreach ($leaf in @('state.db-wal','state.db-shm')) {
        [System.IO.File]::WriteAllText((Join-Path $state $leaf), "Retain old $leaf bytes")
    }
    $missing = Invoke-Se -StateHome $state -Words @('status')
    Require ($missing.Code -ne 0 -and $missing.Value.code -eq 'state-conflict') 'Missing state was not identified'
    $restore = Block $missing.Value.remedy.text 'RESTORE COMMANDS'
    [System.IO.File]::WriteAllText((Join-Path $OutputRoot 'printed-restore.ps1'), $restore)
    & ([scriptblock]::Create($restore)) *> (Join-Path $OutputRoot 'restore.log')
    Require ((Invoke-Se -StateHome $state -Words @('status')).Value.setup.state -eq 'configured') 'Printed restore did not recover setup'
    Require ((Get-FileHash -LiteralPath $savedDb -Algorithm SHA256).Hash -eq $sourceHash) 'Retained copy changed'
    $preserved = @(Get-ChildItem -LiteralPath $state -Directory | Where-Object Name -Like 'recovery-sidecars-*')
    Require ($preserved.Count -eq 1) 'Missing sidecar preservation directory'
    foreach ($leaf in @('state.db-wal','state.db-shm')) {
        Require ([System.IO.File]::ReadAllText((Join-Path $preserved[0].FullName $leaf)) -eq "Retain old $leaf bytes") 'Old sidecar bytes changed'
    }
    $acl = Get-Acl -LiteralPath $preserved[0].FullName
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Require $acl.AreAccessRulesProtected 'Preservation directory inherits permissions'
    Require ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -eq $sid) 'Wrong preservation owner'
    foreach ($rule in $acl.Access) {
        Require ($rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $sid) 'Foreign preservation ACL'
    }
    $sameOwner = Invoke-Se -StateHome $state -Words @('init','--repo',$repo)
    Require ($sameOwner.Code -eq 0 -and $sameOwner.Value.owner.human_id -eq $owner) 'Restore replaced the owner'
    $passed++; Write-Output 'ok 1 - printed restore, unusual path, retained sidecars and private ACL'
    Require ((Invoke-Se -StateHome $state -Words @('down')).Code -eq 0) 'Down before guard failed'
    $beforeGuard = (Get-FileHash -LiteralPath $db -Algorithm SHA256).Hash
    $refused = $false
    try { & ([scriptblock]::Create($restore)) *> (Join-Path $OutputRoot 'guard.log') } catch { $refused = $true }
    Require $refused 'Printed restore overwrote an existing database'
    Require ((Get-FileHash -LiteralPath $db -Algorithm SHA256).Hash -eq $beforeGuard) 'Existing database bytes changed'
    $passed++; Write-Output 'ok 2 - existing database refuses unchanged'
    $fresh = Block $missing.Value.remedy.text 'FRESH COMMAND'
    [System.IO.File]::WriteAllText((Join-Path $OutputRoot 'printed-fresh.ps1'), $fresh)
    Push-Location -LiteralPath $repo
    try { & ([scriptblock]::Create($fresh)) *> (Join-Path $OutputRoot 'fresh.log') } finally { Pop-Location }
    $freshHomes = @(Get-ChildItem -LiteralPath $parent -Directory | Where-Object Name -Like 'state-fresh-*')
    Require ($freshHomes.Count -eq 1) 'Printed fresh-home path was not created'
    $homes.Add($freshHomes[0].FullName)
    $freshInit = Invoke-Se -StateHome $freshHomes[0].FullName -Words @('init','--repo',$repo)
    Require ($freshInit.Code -eq 0 -and $freshInit.Value.owner.human_id -ne $owner) 'Fresh setup reused a lost identity'
    $passed++; Write-Output 'ok 3 - printed separate fresh home creates new identities'
    $firstHome = Join-Path $parent 'never initialized'
    $homes.Add($firstHome)
    Push-Location -LiteralPath $repo
    try {
        $required = Invoke-Se -StateHome $firstHome -Words @('resume')
        Require ($required.Code -ne 0 -and $required.Value.code -eq 'setup-required') 'First-time setup remedy missing'
        $hint = $required.Value.remedy.text
        Require ($hint.StartsWith('Run se ')) 'First-time command missing'
        [System.IO.File]::WriteAllText((Join-Path $OutputRoot 'printed-setup.ps1'), $hint.Substring(4))
        & ([scriptblock]::Create($hint.Substring(4))) *> (Join-Path $OutputRoot 'setup.log')
        Require ((Invoke-Se -StateHome $firstHome -Words @('status')).Value.setup.state -eq 'configured') 'Printed first-time command failed'
    } finally { Pop-Location }
    $passed++; Write-Output 'ok 4 - first-time setup command preserves curly quote home'
    $stage = '.se-stage-' + ('0' * 32)
    foreach ($leaf in @($stage,($stage + '-journal'))) { [System.IO.File]::WriteAllText((Join-Path $state $leaf), "Preserve $leaf") }
    $retry = Invoke-Se -StateHome $state -Words @('--key','windows-recovery-fixed-key','init','--repo',$repo)
    Require ($retry.Code -eq 0 -and $retry.Value.owner.human_id -eq $owner) 'Staging retry failed'
    $quarantine = @(Get-ChildItem -LiteralPath $state -Directory | Where-Object Name -Like 'init-quarantine-*')
    Require ($quarantine.Count -eq 1) 'Quarantine missing'
    foreach ($leaf in @($stage,($stage + '-journal'))) {
        Require (-not (Test-Path -LiteralPath (Join-Path $state $leaf))) 'Original staging path remains'
        Require ([System.IO.File]::ReadAllText((Join-Path $quarantine[0].FullName $leaf)) -eq "Preserve $leaf") 'Quarantine bytes changed'
    }
    Require ([System.IO.File]::ReadAllText((Join-Path $repo 'user-work.txt')) -eq 'User work survives recovery.') 'User work changed'
    $passed++; Write-Output 'ok 5 - staging quarantined and owner preserved'
} finally {
    foreach ($stateHome in $homes) {
        $down = Invoke-Se -StateHome $stateHome -Words @('down')
        Require ($down.Code -eq 0 -and $down.Value.complete) 'Public down incomplete'
        Require (-not (Test-Path -LiteralPath (Join-Path $stateHome 'endpoint.json'))) 'Endpoint remains'
    }
    [System.IO.File]::WriteAllText((Join-Path $OutputRoot 'result.json'), (@{passed=$passed; expected=5; homes=$homes; public_down=$true} | ConvertTo-Json -Depth 5))
}
Require ($passed -eq 5) 'Not all consumers ran'
Write-Output '1..5'
