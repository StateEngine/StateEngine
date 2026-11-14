$ErrorActionPreference='Stop'
$root='@ROOT@'; $name='@NAME@'; $sid=$null; $child=$null; $profilePath=$null
try {
    $password=ConvertTo-SecureString ('SyntheticOnly!'+[Guid]::NewGuid().ToString('N')+'a7') -AsPlainText -Force
    $user=New-LocalUser -Name $name -Password $password -AccountNeverExpires -PasswordNeverExpires
    $sid=$user.SID.Value
    $acl=Get-Acl -LiteralPath $root
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($trust in @($sid,'S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) {
        $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($trust),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $root -AclObject $acl
    $credential=[Management.Automation.PSCredential]::new(($env:COMPUTERNAME+'\'+$name),$password)
    $worker=Join-Path $root 'worker.ps1'
    $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$worker+'" -Root "'+$root+'"'
    $child=Start-Process -FilePath (Get-Command powershell.exe).Source -ArgumentList $arguments -Credential $credential -LoadUserProfile -RedirectStandardOutput (Join-Path $root 'worker.stdout') -RedirectStandardError (Join-Path $root 'worker.stderr') -PassThru
    $retainedHandle=$child.Handle
    if ($retainedHandle -eq [IntPtr]::Zero) {throw 'owned profile worker handle absent'}
    if (-not $child.WaitForExit(75000)) {
        $observed=Get-CimInstance Win32_Process -Filter ('ProcessId='+$child.Id)
        if (-not $observed.CommandLine.Contains($worker)) {throw 'owned profile worker identity unreadable'}
        $child.Kill(); $child.WaitForExit(); throw 'owned profile worker exceeded bound'
    }
    $child.Refresh()
    $resultExists=Test-Path -LiteralPath (Join-Path $root 'result.json')
    if ($null -eq $child.ExitCode -or $child.ExitCode -ne 0 -or -not $resultExists) {throw ('native profile staging did not pass; exit='+$child.ExitCode+'; result_exists='+$resultExists+'; '+[IO.File]::ReadAllText((Join-Path $root 'worker.stderr')))}
} finally {
    if ($child) {$child.Dispose()}
    if ($sid) {
        $taskProfileRecord=Get-CimInstance Win32_UserProfile -Filter ("SID='"+$sid+"'")
        if ($taskProfileRecord) {
            $profilePath=$taskProfileRecord.LocalPath
            if ($taskProfileRecord.Special -or $taskProfileRecord.Loaded -or -not $profilePath.Contains($name)) {throw 'owned profile cleanup identity/closure unproved'}
            $taskProfileRecord | Remove-CimInstance
        }
        Remove-LocalUser -SID $sid
        $accountAbsent=$null -eq (Get-LocalUser -SID $sid -ErrorAction SilentlyContinue)
        $profileAbsent=$null -eq (Get-CimInstance Win32_UserProfile -Filter ("SID='"+$sid+"'"))
        if ($profilePath -and (Test-Path -LiteralPath $profilePath)) {$profileAbsent=$false}
        [IO.File]::WriteAllText((Join-Path $root 'cleanup.json'),(@{account_absent=$accountAbsent;profile_absent=$profileAbsent}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
        if (-not $accountAbsent -or -not $profileAbsent) {throw 'owned account/profile remains'}
    }
}
