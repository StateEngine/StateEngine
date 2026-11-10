param([string]$Se, [string]$HomePath, [string]$Out, [switch]$NoEligibleBroker)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class StrictJobFixture {
  [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
  [StructLayout(LayoutKind.Sequential)] struct Privileges { public uint Count; public Luid Id; public uint Attributes; }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern IntPtr CreateJobObjectW(IntPtr security, string name);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool member);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool LookupPrivilegeValueW(string system, string name, out Luid id);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref Privileges value, uint length, IntPtr previous, IntPtr returned);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr buffer, uint size, out uint returned);
  [DllImport("advapi32.dll")] static extern bool IsTokenRestricted(IntPtr token);
  static void Require(bool ok, string operation) {
    if (!ok) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), operation);
  }
  public static bool InJob(IntPtr process, IntPtr job) {
    bool member; Require(IsProcessInJob(process, job, out member), "query owned job membership"); return member;
  }
  static bool HasPrivilege(IntPtr token, Luid id) {
    IntPtr buffer=Marshal.AllocHGlobal(65536);
    try {
      uint returned; Require(GetTokenInformation(token, 3, buffer, 65536, out returned), "read owned token privileges");
      int count=Marshal.ReadInt32(buffer);
      if (returned < 4 || count < 0 || 4L + count*12L > returned || returned > 65536) throw new Exception("invalid bounded token privilege list");
      for (int i=0; i<count; i++) {
        if ((uint)Marshal.ReadInt32(buffer,4+i*12)==id.Low && Marshal.ReadInt32(buffer,8+i*12)==id.High) return true;
      }
      return false;
    } finally { Marshal.FreeHGlobal(buffer); }
  }
  public static bool CallerRestricted() {
    IntPtr token; Require(OpenProcessToken(GetCurrentProcess(),0x8,out token),"query dedicated fixture token");
    try { return IsTokenRestricted(token); } finally { CloseHandle(token); }
  }
  public static string RemoveNonFilePrivilege() {
    IntPtr token; Require(OpenProcessToken(GetCurrentProcess(),0x28,out token),"open dedicated fixture token");
    try {
      // Keep traverse checking unchanged: removing SeChangeNotifyPrivilege can
      // make the protected home unreadable before broker selection is reached.
      Luid traverse; Require(LookupPrivilegeValueW(null,"SeChangeNotifyPrivilege",out traverse),"resolve traverse privilege");
      if (!HasPrivilege(token,traverse)) throw new Exception("fixture caller must retain its traverse privilege");
      foreach (string name in new string[] {"SeShutdownPrivilege", "SeTimeZonePrivilege", "SeIncreaseWorkingSetPrivilege", "SeUndockPrivilege"}) {
        Luid id; Require(LookupPrivilegeValueW(null,name,out id),"resolve non-filesystem fixture privilege");
        if (!HasPrivilege(token,id)) continue;
        Privileges value=new Privileges {Count=1,Id=id,Attributes=4}; // SE_PRIVILEGE_REMOVED
        Require(AdjustTokenPrivileges(token,false,ref value,0,IntPtr.Zero,IntPtr.Zero),"remove only dedicated fixture caller privilege");
        Require(Marshal.GetLastWin32Error()==0,"privilege removal fully assigned");
        if (HasPrivilege(token,id) || !HasPrivilege(token,traverse) || IsTokenRestricted(token)) throw new Exception("fixture must remove only the selected privilege, retain traversal, and keep IsTokenRestricted FALSE");
        return name;
      }
      throw new Exception("fixture has no removable non-filesystem privilege; refusing to remove SeChangeNotifyPrivilege");
    } finally { CloseHandle(token); }
  }
  public static IntPtr Enter() {
    // No BREAKAWAY_OK/SILENT_BREAKAWAY_OK. Only this dedicated shell and children enter.
    IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
    Require(job!=IntPtr.Zero,"create private strict job");
    if (!AssignProcessToJobObject(job, GetCurrentProcess())) {
      int code=Marshal.GetLastWin32Error(); CloseHandle(job); throw new System.ComponentModel.Win32Exception(code);
    }
    return job;
  }
  public static bool CallerInJob(IntPtr job) { return InJob(GetCurrentProcess(),job); }
}
'@
# Adjust only this dedicated fixture shell; the cargo driver and all other processes keep their tokens.
$removedPrivilege = $null
if ($NoEligibleBroker) { $removedPrivilege = [StrictJobFixture]::RemoveNonFilePrivilege() }
# Prove the changed caller can still read the actual initialized home before
# either public CLI mode attempts broker selection.
$homeProbe = [IO.File]::Open((Join-Path $HomePath 'state.db'),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
$homeProbe.Dispose()
function Invoke-OwnedCli([string]$Verb) {
  $info = New-Object System.Diagnostics.ProcessStartInfo
  $info.FileName = $Se
  $info.Arguments = '--home "' + $HomePath.TrimEnd('\') + '" --json ' + $Verb
  $info.UseShellExecute = $false
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardError = $true
  $process = [Diagnostics.Process]::Start($info)
  try {
    $output = $process.StandardOutput.ReadToEndAsync()
    $errors = $process.StandardError.ReadToEndAsync()
    if (!$process.WaitForExit(15000)) {
      $process.Kill(); $process.WaitForExit()
      throw "owned $Verb client exceeded its bound"
    }
    return @{exit=$process.ExitCode; stdout=$output.Result; stderr=$errors.Result}
  } finally { $process.Dispose() }
}
$job = [StrictJobFixture]::Enter()
try {
  $witness = @{caller_in_job_before=[StrictJobFixture]::CallerInJob($job); privilege_removed=($null -ne $removedPrivilege); removed_privilege=$removedPrivilege; home_readable_after_restriction=$true; restricting_sids=[StrictJobFixture]::CallerRestricted(); foreground_cases=@()}
  foreach ($mode in @('json','plain')) {
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Se
    $info.Arguments = '--home "' + $HomePath.TrimEnd('\') + '" ' + $(if ($mode -eq 'json') {'--json '}) + 'up'
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $child = [System.Diagnostics.Process]::Start($info)
    $stdout = $child.StandardOutput.ReadToEndAsync()
    $stderr = $child.StandardError.ReadToEndAsync()
    if ($NoEligibleBroker) {
      # A working foreground fallback stays alive until this independent client
      # witnesses the same root and requests public shutdown.
      $until = [DateTime]::UtcNow.AddSeconds(30)
      $ready = $false
      while (!$child.HasExited -and [DateTime]::UtcNow -lt $until) {
        if (Test-Path (Join-Path $HomePath 'endpoint.json')) {
          $status = Invoke-OwnedCli 'status'
          if ($status.exit -eq 0) {
            $view = $status.stdout | ConvertFrom-Json
            if ($view.runtime.state -eq 'running') {
              if ([int]$view.runtime.process.pid -ne $child.Id) { throw 'foreground fallback detached a different owner' }
              $member = [StrictJobFixture]::InJob($child.Handle,[IntPtr]::Zero)
              if (!$member) { throw 'no-broker arm did not exercise an in-job foreground host' }
              $stopped = Invoke-OwnedCli 'down'
              if ($stopped.exit -ne 0) { throw "public foreground down failed: $($stopped.stderr)" }
              $witness.foreground_cases += @{mode=$mode; pid=$child.Id; creation_filetime=$child.StartTime.ToFileTimeUtc().ToString(); in_job=$member; down_exit=$stopped.exit}
              $ready = $true
              break
            }
          }
        }
        Start-Sleep -Milliseconds 30
      }
      if (!$ready -and !$child.HasExited) {
        # Preserve the refusal below, but request normal owned-home cleanup first.
        if (Test-Path (Join-Path $HomePath 'endpoint.json')) { $null = Invoke-OwnedCli 'down' }
      }
    }
    if (!$child.WaitForExit(30000)) {
      # This exact Process object pins the CLI child created here; no name/pattern signaling.
      $child.Kill(); $child.WaitForExit()
      throw 'exact strict-job CLI child exceeded its original bound'
    }
    [IO.File]::WriteAllText((Join-Path $Out "$mode.stdout"), $stdout.Result)
    [IO.File]::WriteAllText((Join-Path $Out "$mode.stderr"), $stderr.Result)
    [IO.File]::WriteAllText((Join-Path $Out "$mode.exit"), [string]$child.ExitCode)
    if (!$NoEligibleBroker -and $mode -eq 'json' -and $child.ExitCode -eq 0) {
      $started = $stdout.Result | ConvertFrom-Json
      $runtime = [Diagnostics.Process]::GetProcessById([int]$started.process.pid)
      try {
        $witness.runtime_pid = $runtime.Id
        $witness.runtime_creation_filetime = $runtime.StartTime.ToFileTimeUtc().ToString()
        $witness.runtime_outside_all_jobs = ![StrictJobFixture]::InJob($runtime.Handle,[IntPtr]::Zero)
      } finally { $runtime.Dispose() }
    }
    $child.Dispose()
  }
  $witness.caller_in_job_after = [StrictJobFixture]::CallerInJob($job)
  [IO.File]::WriteAllText((Join-Path $Out 'job.json'),($witness | ConvertTo-Json -Compress))
} finally { [void][StrictJobFixture]::CloseHandle($job) }
