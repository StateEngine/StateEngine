param([uint32]$ObservedProcessId)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class OutsideBirth {
 [StructLayout(LayoutKind.Sequential)] struct Time {public uint low,high;}
 [DllImport("kernel32.dll",SetLastError=true)] static extern SafeProcessHandle OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(SafeProcessHandle process,out Time created,out Time exited,out Time kernel,out Time user);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder image,ref uint length);
 public static string[] Read(uint pid) {
  using(var process=OpenProcess(0x1000|0x100000,false,pid)) {
   if(process.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());
   Time created,exited,kernel,user;
   if(!GetProcessTimes(process,out created,out exited,out kernel,out user))throw new Win32Exception(Marshal.GetLastWin32Error());
   var image=new StringBuilder(32768);uint length=32768;
   if(!QueryFullProcessImageName(process,0,image,ref length))throw new Win32Exception(Marshal.GetLastWin32Error());
   return new[]{(((ulong)created.high<<32)|created.low).ToString(),image.ToString()};
  }
 }
}
'@
$native=[OutsideBirth]::Read($ObservedProcessId)
@{creation_filetime=$native[0];image=$native[1]} | ConvertTo-Json -Compress
