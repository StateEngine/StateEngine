$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
public static class ScopeControl {
    public delegate bool Handler(uint code);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetConsoleCtrlHandler(Handler handler, bool add);
    private static Handler callback;
    public static bool Start(string path) {
        callback = code => { File.WriteAllText(path, code.ToString()); return false; };
        return SetConsoleCtrlHandler(callback, true);
    }
}
'@
$interrupt = Join-Path $PWD 'powershell.interrupt'
if (-not [ScopeControl]::Start($interrupt)) { throw 'Ctrl handler registration failed' }
[IO.File]::WriteAllText((Join-Path $PWD 'powershell.ready'),'ready')
$deadline = [DateTime]::UtcNow.AddSeconds(80)
while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Path -LiteralPath 'normal-exit')) {
    Start-Sleep -Milliseconds 50
}
