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
  public static bool RemoveOwnPrivilege() {
    IntPtr token; Require(OpenProcessToken(GetCurrentProcess(),0x28,out token),"open dedicated fixture token");
    try {
      Luid id; Require(LookupPrivilegeValueW(null,"SeChangeNotifyPrivilege",out id),"resolve fixture privilege");
      if (!HasPrivilege(token,id)) throw new Exception("fixture caller did not initially hold SeChangeNotifyPrivilege");
      Privileges value=new Privileges {Count=1,Id=id,Attributes=4}; // SE_PRIVILEGE_REMOVED
      Require(AdjustTokenPrivileges(token,false,ref value,0,IntPtr.Zero,IntPtr.Zero),"remove only dedicated fixture caller privilege");
      Require(Marshal.GetLastWin32Error()==0,"privilege removal fully assigned");
      if (HasPrivilege(token,id) || IsTokenRestricted(token)) throw new Exception("fixture must remove the privilege while IsTokenRestricted stays FALSE");
      return true;
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
$removed = $false
if ($NoEligibleBroker) { $removed = [StrictJobFixture]::RemoveOwnPrivilege() }
$job = [StrictJobFixture]::Enter()
try {
  $witness = @{caller_in_job_before=[StrictJobFixture]::CallerInJob($job); privilege_removed=$removed; restricting_sids=[StrictJobFixture]::CallerRestricted()}
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
