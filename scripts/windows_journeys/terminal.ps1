param([Parameter(Mandatory=$true)][string]$ArgvBase64)
$ErrorActionPreference = 'Stop'
# Independent test terminal only. Inherits the caller's ancestry, token and job.
# https://learn.microsoft.com/windows/console/creating-a-pseudoconsole-session
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
public static class JourneyTerminal {
    [StructLayout(LayoutKind.Sequential)] struct Coord { public short X, Y; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Startup {
        public int cb; public string reserved, desktop, title;
        public int x,y,xSize,ySize,xChars,yChars,fill,flags;
        public short show, reservedBytes; public IntPtr reservedPtr, stdin, stdout, stderr;
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupEx { public Startup startup; public IntPtr attributes; }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr process, thread; public uint pid, tid; }
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CreatePipe(out IntPtr read, out IntPtr write, IntPtr sa, uint size);
    [DllImport("kernel32.dll")] static extern int CreatePseudoConsole(Coord size, IntPtr input, IntPtr output, uint flags, out IntPtr console);
    [DllImport("kernel32.dll")] static extern void ClosePseudoConsole(IntPtr console);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcessW(string app, StringBuilder args, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string cwd, ref StartupEx startup, out ProcessInfo process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadFile(IntPtr file, byte[] buffer, uint size, out uint read, IntPtr overlapped);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    static void Check(bool ok) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static void Close(ref IntPtr handle) { if (handle != IntPtr.Zero) { CloseHandle(handle); handle = IntPtr.Zero; } }
    static string Quote(string value) {
        var result = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value) {
            if (c == '\\') { slashes++; continue; }
            result.Append('\\', c == '"' ? slashes*2+1 : slashes); result.Append(c); slashes = 0;
        }
        return result.Append('\\', slashes*2).Append('"').ToString();
    }
    public static int Run(string[] argv) {
        IntPtr inputRead=IntPtr.Zero, inputWrite=IntPtr.Zero, outputRead=IntPtr.Zero, outputWrite=IntPtr.Zero, console=IntPtr.Zero, attributes=IntPtr.Zero;
        var process = new ProcessInfo(); bool initialized = false; Task pump = null;
        try {
            Check(CreatePipe(out inputRead, out inputWrite, IntPtr.Zero, 0));
            Check(CreatePipe(out outputRead, out outputWrite, IntPtr.Zero, 0));
            int hr = CreatePseudoConsole(new Coord { X=32767, Y=40 }, inputRead, outputWrite, 0, out console);
            if (hr < 0) Marshal.ThrowExceptionForHR(hr);
            // Drain on a separate thread throughout creation, execution and close.
            IntPtr readHandle = outputRead;
            pump = Task.Run(() => {
                var output = Console.OpenStandardOutput(); byte[] bytes = new byte[8192]; uint count;
                while (true) {
                    if (!ReadFile(readHandle, bytes, (uint)bytes.Length, out count, IntPtr.Zero)) {
                        int error = Marshal.GetLastWin32Error();
                        if (error == 109) break; throw new Win32Exception(error);
                    }
                    if (count == 0) break; output.Write(bytes, 0, (int)count); output.Flush();
                }
            });
            IntPtr size = IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            if (size == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            attributes = Marshal.AllocHGlobal(size); Check(InitializeProcThreadAttributeList(attributes, 1, 0, ref size)); initialized = true;
            Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20016), console, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero));
            var startup = new StartupEx { attributes=attributes }; startup.startup.cb = Marshal.SizeOf(typeof(StartupEx));
            // ConPTY replaces NULL standard handles with its console handles. Without
            // STARTF_USESTDHANDLES, Windows can copy the runner's redirected pipes
            // even with handle inheritance disabled, leaving the child off-terminal.
            // https://github.com/microsoft/terminal/discussions/15814
            startup.startup.flags = 0x100; // STARTF_USESTDHANDLES; stdin/out/err stay NULL.
            var command = new StringBuilder(); foreach (string arg in argv) { if (command.Length > 0) command.Append(' '); command.Append(Quote(arg)); }
            // A null application name lets Windows resolve a bare executable on
            // the inherited PATH from the quoted command line (e.g. powershell.exe).
            Check(CreateProcessW(null, command, IntPtr.Zero, IntPtr.Zero, false, 0x80000, IntPtr.Zero, null, ref startup, out process));
            Close(ref inputRead); Close(ref outputWrite);
            if (WaitForSingleObject(process.process, 180000) != 0) throw new Exception("ConPTY child deadline/wait failure");
            uint code; Check(GetExitCodeProcess(process.process, out code)); return checked((int)code);
        } finally {
            if (console != IntPtr.Zero) ClosePseudoConsole(console);
            Close(ref inputRead); Close(ref inputWrite); Close(ref outputWrite);
            Exception drainError = null;
            try { if (pump != null && !pump.Wait(5000)) drainError = new Exception("ConPTY output join deadline"); }
            catch (Exception error) { drainError = error; }
            Close(ref outputRead); Close(ref process.thread); Close(ref process.process);
            if (initialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (drainError != null) throw drainError;
        }
    }
}
'@
$decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ArgvBase64)) | ConvertFrom-Json
exit [JourneyTerminal]::Run([string[]]$decoded)
