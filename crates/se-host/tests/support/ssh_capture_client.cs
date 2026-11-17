using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
public static class CaptureClient {
 [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr GetStdHandle(int kind);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr value);
 public static int Main(string[] args) {
  string mode=args[args.Length-1];
  using(Process self=Process.GetCurrentProcess()) {
   File.AppendAllText(Environment.GetEnvironmentVariable("SE_SSH_CAPTURE_REVIEW_PIDS"),self.Id+"|"+self.StartTime.ToUniversalTime().ToFileTimeUtc()+"|"+self.MainModule.FileName+Environment.NewLine);
  }
  Console.Out.Write(mode=="overflow" ? new string('x',65537) : "hello");Console.Out.Flush();Console.Error.Write("note");Console.Error.Flush();
  if(mode=="complete") return 0;
  if(mode=="closed") {
   if(!CloseHandle(GetStdHandle(-11))||!CloseHandle(GetStdHandle(-12))) return 73;
  } else if(mode=="overflow") {
   if(!CloseHandle(GetStdHandle(-12))) return 75;
  } else if(mode!="open") return 74;
  Thread.Sleep(30000);return 0;
 }
}
