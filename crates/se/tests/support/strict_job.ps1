param([string]$Se, [string]$HomePath, [string]$Out)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class StrictJobFixture {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern IntPtr CreateJobObjectW(IntPtr security, string name);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
  public static IntPtr Enter() {
    // A new job has no BREAKAWAY_OK or SILENT_BREAKAWAY_OK flags. Only this
    // newly created fixture shell and its children are assigned to it.
    IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
    if (job == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
    if (!AssignProcessToJobObject(job, GetCurrentProcess())) {
      int code=Marshal.GetLastWin32Error(); CloseHandle(job);
      throw new System.ComponentModel.Win32Exception(code);
    }
    return job;
  }
}
'@
$job = [StrictJobFixture]::Enter()
try {
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
      # The exact Process object was created above; no name/pattern signaling.
      $child.Kill(); $child.WaitForExit()
      throw 'exact strict-job CLI child exceeded its original bound'
    }
    [IO.File]::WriteAllText((Join-Path $Out "$mode.stdout"), $stdout.Result)
    [IO.File]::WriteAllText((Join-Path $Out "$mode.stderr"), $stderr.Result)
    [IO.File]::WriteAllText((Join-Path $Out "$mode.exit"), [string]$child.ExitCode)
    $child.Dispose()
  }
} finally { [void][StrictJobFixture]::CloseHandle($job) }
