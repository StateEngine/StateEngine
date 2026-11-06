# Fixed readable source. Targets arrive only as inherited native objects; no
# user pathname, program text or deletion plan is accepted from command arguments.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
public static class SeUninstallObjects {
 [StructLayout(LayoutKind.Sequential)] struct Info {
  public uint Attributes,CreationLow,CreationHigh,AccessLow,AccessHigh,WriteLow,WriteHigh;
  public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
 }
 [StructLayout(LayoutKind.Sequential)] struct Id {
  public ulong Volume;
  [MarshalAs(UnmanagedType.ByValArray,SizeConst=16)] public byte[] Value;
 }
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetFileType(IntPtr file);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr file,out Info info);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(IntPtr file,int kind,out Id id,uint size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr ReOpenFile(IntPtr file,uint access,uint share,uint flags);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(IntPtr file,int kind,ref uint flags,uint size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr file);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool FlushFileBuffers(IntPtr file);
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr process,uint milliseconds);
 [DllImport("kernel32.dll")] public static extern ulong GetTickCount64();
 static void Error() { throw new Win32Exception(Marshal.GetLastWin32Error()); }
 public static string Identity(IntPtr file,bool directory) {
  Info info=new Info(); Id id=new Id();
  if(GetFileType(file)!=1 || !GetFileInformationByHandle(file,out info)) Error();
  if((info.Attributes&1024)!=0 || ((info.Attributes&16)!=0)!=directory || (!directory && info.Links!=1))
   throw new IOException("Carrier object must retain its original regular no-reparse type and single file link");
  if(!GetFileInformationByHandleEx(file,18,out id,(uint)Marshal.SizeOf(typeof(Id)))) Error();
  return id.Volume.ToString("x16")+":"+BitConverter.ToString(id.Value).Replace("-","").ToLowerInvariant();
 }
 public static string Digest(IntPtr file) {
  using(var handle=new SafeFileHandle(file,false))
  using(var stream=new FileStream(handle,FileAccess.Read,65536,false))
  using(var sha=SHA256.Create()) {
   if(stream.Length>536870912) throw new IOException("Carrier object exceeds hash bound");
   stream.Position=0;
   return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","").ToLowerInvariant();
  }
 }
 public static int Unlink(IntPtr original,string path,bool directory) {
  // ReOpenFile refuses these directory handles under an ordinary user token.
  // A fresh no-reparse open must match the retained original before any effect.
  // Its independent close also publishes POSIX absence while read pins remain.
  var file=directory ? CreateFileW(path,0x10080,7,IntPtr.Zero,3,0x2200000,IntPtr.Zero)
                     : ReOpenFile(original,0x10080,7,0x2200000);
  if(file==new IntPtr(-1))
   throw new Win32Exception(Marshal.GetLastWin32Error(),"Open exact uninstall object: "+path);
  try { uint flags=3;
   if(Identity(file,directory)!=Identity(original,directory))
    throw new IOException("Uninstall object identity changed; replacement preserved: "+path);
   if(!SetFileInformationByHandle(file,21,ref flags,4)) {
    int error=Marshal.GetLastWin32Error();
    if(error==145) return error;
    throw new Win32Exception(error,"Unlink exact uninstall object: "+path);
   }
   return 0;
  } finally { CloseHandle(file); }
 }
 public static void Flush(IntPtr file) { if(!FlushFileBuffers(file)) Error(); }
 public static void Absent(string path) {
  var file=CreateFileW(path,0x80,7,IntPtr.Zero,3,0x2200000,IntPtr.Zero);
  if(file==new IntPtr(-1)) {
   int error=Marshal.GetLastWin32Error();
   if(error==2 || error==3) return;
   throw new Win32Exception(error);
  }
  CloseHandle(file); throw new IOException("Removed name remains or was replaced; replacement preserved: "+path);
 }
 public static void SameName(string path,string expected) {
  var file=CreateFileW(path,0x80,7,IntPtr.Zero,3,0x2200000,IntPtr.Zero);
  if(file==new IntPtr(-1)) Error();
  try { if(Identity(file,true)!=expected) throw new IOException("Directory name changed; replacement preserved"); }
  finally { CloseHandle(file); }
 }
}
'@
$held = [Collections.Generic.List[IDisposable]]::new()
$completion = $null
$report = $null
$failure = $null
try {
    $inputReader = [IO.StreamReader]::new([Console]::OpenStandardInput(),[Text.Encoding]::UTF8)
    $line = $inputReader.ReadLine()
    if ($null -eq $line -or $line.Length -gt 2097152) { throw 'Inherited carrier frame is absent or exceeds its bound' }
    $frame = $line | ConvertFrom-Json
    if ($frame.nonce -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid private carrier nonce' }
    function Remaining {
        $left = [decimal]$frame.deadline - [decimal][SeUninstallObjects]::GetTickCount64()
        if ($left -le 0 -or $left -gt 90000) { throw 'Private carrier deadline expired or invalid' }
        return [uint32]$left
    }
    $null = Remaining
    $parent = [IntPtr]::new([int64]$frame.parent)
    if ([SeUninstallObjects]::WaitForSingleObject($parent,0) -ne 258) { throw 'Exact native parent is no longer live' }
    # Holding this inherited file object keeps the account-wide deny-write
    # installation claim after the parent's byte-range lock is released.
    $claim = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr]::new([int64]$frame.claim),$true)
    $held.Add($claim)
    $entries = @($frame.entries)
    if ($entries.Count -lt 4 -or $entries.Count -gt 132) { throw 'Carrier object inventory is outside its finite bound' }
    foreach ($entry in $entries) {
        $handle = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr]::new([int64]$entry.handle),$true)
        $held.Add($handle)
        $directory = $entry.kind -in @('directory','flush')
        if ($entry.kind -notin @('image','record','directory','flush') -or
            [SeUninstallObjects]::Identity($handle.DangerousGetHandle(),$directory) -cne $entry.identity) { throw 'Inherited carrier object identity differs' }
        if (-not $directory -and [SeUninstallObjects]::Digest($handle.DangerousGetHandle()) -cne $entry.sha256) { throw 'Inherited carrier object bytes differ' }
    }
    $images = @($entries | Where-Object { $_.kind -eq 'image' })
    $records = @($entries | Where-Object { $_.kind -eq 'record' })
    if ($images.Count -ne 1 -or $records.Count -ne 1) { throw 'One original image and installation record required' }
    $readyHandle = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr]::new([int64]$frame.ready),$true)
    $ready = [IO.FileStream]::new($readyHandle,[IO.FileAccess]::Write)
    try {
        $ack = New-Object byte[] 33; $ack[0] = 82
        for ($index=0;$index -lt 32;$index++) { $ack[$index+1]=[Convert]::ToByte($frame.nonce.Substring($index*2,2),16) }
        $ready.Write($ack,0,33); $ready.Flush()
    } finally { $ready.Dispose() }
    $authHandle = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr]::new([int64]$frame.authorize),$true)
    $auth = [IO.FileStream]::new($authHandle,[IO.FileAccess]::Read)
    $held.Add($auth)
    $authorizationBytes = New-Object byte[] 33
    $offset = 0
    while ($offset -lt 33) {
        $task = $auth.ReadAsync($authorizationBytes,$offset,33-$offset)
        if (-not $task.Wait([int](Remaining))) { throw 'Parent authorization deadline expired; installation image retained' }
        if ($task.Result -eq 0) { throw 'Parent exited without authorization; installation image retained' }
        $offset += $task.Result
    }
    $nonce = [BitConverter]::ToString($authorizationBytes,1,32).Replace('-','').ToLowerInvariant()
    if ($authorizationBytes[0] -ne 71 -or $nonce -cne $frame.nonce) { throw 'Private parent authorization frame differs' }
    $reportHandle = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr]::new([int64]$frame.report),$true)
    $reportStream = [IO.FileStream]::new($reportHandle,[IO.FileAccess]::Read)
    $held.Add($reportStream)
    if ($reportStream.Length -gt 2097152) { throw 'Private completion report exceeds its bound' }
    $reportReader = [IO.StreamReader]::new($reportStream,[Text.Encoding]::UTF8)
    $held.Add($reportReader)
    $line = $reportReader.ReadLine()
    if ($null -eq $line -or $line.Length -gt 2097152) { throw 'Private completion report is absent or exceeds its bound' }
    $authorization = $line | ConvertFrom-Json
    if ($authorization.nonce -cne $frame.nonce) { throw 'Parent authorization nonce differs' }
    $report = $authorization.report
    if ($null -ne $report.PSObject.Properties['completion']) { $completion = $report.completion }
    if ([SeUninstallObjects]::WaitForSingleObject($parent,(Remaining)) -ne 0) { throw 'Exact authorized parent did not exit before the deadline' }
    foreach ($entry in @($images[0],$records[0])) {
        $handle = [IntPtr]::new([int64]$entry.handle)
        if ([SeUninstallObjects]::Identity($handle,$false) -cne $entry.identity -or
            [SeUninstallObjects]::Digest($handle) -cne $entry.sha256) { throw 'Authorized object changed before removal' }
        $null = [SeUninstallObjects]::Unlink($handle,$entry.path,$false)
        [SeUninstallObjects]::Absent($entry.path)
    }
    foreach ($entry in @($entries | Where-Object { $_.kind -eq 'flush' })) {
        [SeUninstallObjects]::Flush([IntPtr]::new([int64]$entry.handle))
    }
    foreach ($entry in @($entries | Where-Object { $_.kind -eq 'directory' } | Sort-Object { $_.path.Length } -Descending)) {
        $handle = [IntPtr]::new([int64]$entry.handle)
        if ([SeUninstallObjects]::Identity($handle,$true) -cne $entry.identity) { throw 'Directory object changed' }
        [SeUninstallObjects]::SameName($entry.path,$entry.identity)
        $code = [SeUninstallObjects]::Unlink($handle,$entry.path,$true)
        if ($code -eq 145) { [SeUninstallObjects]::SameName($entry.path,$entry.identity) }
        else { [SeUninstallObjects]::Absent($entry.path) }
    }
} catch {
    $failure = $_.Exception.Message
    [Console]::Error.WriteLine($failure)
}
finally {
    if ($null -ne $completion) {
        try {
            # Output only: neither the pipe name nor its token select any object.
            $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', $completion.pipe,[IO.Pipes.PipeDirection]::Out,[IO.Pipes.PipeOptions]::None,[Security.Principal.TokenImpersonationLevel]::Identification)
            try {
                $pipe.Connect(5000)
                $reply = @{ schema='se.uninstall-completion/v2'; token=$completion.token;
                    complete=($null -eq $failure); error=$failure; image=$images[0].path;
                    record=$records[0].path; helper=$null; directory=$null; achieved=$report.achieved }
                $bytes = [Text.Encoding]::UTF8.GetBytes(($reply | ConvertTo-Json -Depth 64 -Compress)+"`n")
                $pipe.Write($bytes,0,$bytes.Length); $pipe.Flush()
            } finally { $pipe.Dispose() }
        } catch { $failure = 'Completion delivery failed: '+$_.Exception.Message }
    }
    foreach ($item in $held) { $item.Dispose() }
}
if ($null -ne $failure) { exit 78 }
exit 0
