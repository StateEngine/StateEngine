using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Win32;

static class Program
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
    private static long Now() => Micros(Stopwatch.GetTimestamp());
    private static long Micros(long ticks) => (long)((decimal)ticks * 1_000_000 / Stopwatch.Frequency);
    private static string Name(string? path) => string.IsNullOrEmpty(path) ? "" : Path.GetFileName(path);
    private static string FileClass(string? path)
    {
        string name = Name(path).ToLowerInvariant();
        return name switch
        {
            "" => "unresolved",
            "product.exe" => "product-image",
            "config.toml" => "config",
            "state.db" or "state.db-wal" or "state.db-shm" => "store",
            "endpoint.json" or "ipc-image-cache.json" => "runtime-metadata",
            "calibration.bin" => "calibration",
            _ when name.EndsWith(".dll") => "dll",
            _ => "other",
        };
    }

    private sealed record Window(string Kind, int Pid, int Clients, long Spawn, long Entry, long Connect, long Exit)
    {
        public List<long> Starts { get; } = new();
        public List<long> Stops { get; } = new();
        public List<int> Threads { get; } = new();
        public List<(long Start, long End)> Cpu { get; } = new();
        public List<Image> Images { get; } = new();
        public List<FileRead> Reads { get; } = new();
        public List<RegistryOp> Registry { get; } = new();
        public List<Fault> Faults { get; } = new();
    }
    private sealed record Image(long At, string Name, long Bytes);
    private sealed record FileRead(long Start, long? End, string Class, long Bytes, int? Status);
    private sealed record RegistryOp(long At, string Operation, double? Milliseconds);
    private sealed record Fault(long At, string Class, double? Milliseconds);

    private static Process Start(string program, params string[] args)
    {
        var info = new ProcessStartInfo(program) { UseShellExecute = false, CreateNoWindow = true };
        foreach (string arg in args) info.ArgumentList.Add(arg);
        return Process.Start(info) ?? throw new InvalidOperationException("A fixture child did not start.");
    }

    private static double? Nonnegative(double elapsed) => double.IsFinite(elapsed) && elapsed >= 0 ? elapsed : null;

    private static List<Window> LoadWindows(string output, string kind)
    {
        var windows = new List<Window>();
        foreach (int clients in new[] { 1, 8 })
        {
            using var cohort = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(output, $"cohort-{clients}.json")));
            var root = cohort.RootElement;
            if (!root.GetProperty("complete").GetBoolean() || root.GetProperty("observed_peak").GetInt32() != clients)
                throw new InvalidDataException("The observed write cohort is incomplete.");
            foreach (var row in root.GetProperty("samples").EnumerateArray())
            {
                if (!row.GetProperty("verified").GetBoolean()) throw new InvalidDataException("A write was not read back.");
                var points = row.GetProperty("phases").GetProperty("cli_us");
                windows.Add(new Window(kind, row.GetProperty("pid").GetInt32(), clients,
                    row.GetProperty("spawned_us").GetInt64(), points[0].GetInt64(), points[8].GetInt64(),
                    row.GetProperty("exited_us").GetInt64()));
            }
        }
        return windows;
    }

    private static void Parse(string trace, List<Window> windows, string output)
    {
        var groups = windows.GroupBy(w => w.Pid).ToDictionary(g => g.Key, g => g.ToArray());
        Window? Find(int pid, long time) => groups.TryGetValue(pid, out var group)
            ? group.SingleOrDefault(w => w.Spawn <= time && time <= w.Exit)
            : null;
        var reads = new Dictionary<string,(Window Window, int Index)>();
        var running = new Dictionary<(int Pid, int Tid), long>();
        using var source = new ETWTraceEventSource(trace);
        source.Kernel.ProcessStart += e =>
        {
            long at = Micros(e.TimeStampQPC);
            Find(e.ProcessID, at)?.Starts.Add(at);
        };
        source.Kernel.ProcessStop += e =>
        {
            long at = Micros(e.TimeStampQPC);
            Find(e.ProcessID, at)?.Stops.Add(at);
        };
        source.Kernel.ThreadStart += e =>
        {
            long at = Micros(e.TimeStampQPC);
            if (Find(e.ProcessID, at) is { } w && at <= w.Exit) w.Threads.Add(e.ThreadID);
        };
        source.Kernel.ThreadCSwitch += e =>
        {
            long at = Micros(e.TimeStampQPC);
            if (running.Remove((e.OldProcessID, e.OldThreadID), out long from))
                Find(e.OldProcessID, from)?.Cpu.Add((from, at));
            if (Find(e.NewProcessID, at) is { } w && at <= w.Exit)
                running[(e.NewProcessID, e.NewThreadID)] = at;
        };
        source.Kernel.ImageLoad += e =>
        {
            long at = Micros(e.TimeStampQPC);
            if (Find(e.ProcessID, at) is { } w && at <= w.Exit)
                w.Images.Add(new Image(at, Name(e.FileName), Convert.ToInt64(e.ImageSize)));
        };
        source.Kernel.FileIORead += e =>
        {
            long at = Micros(e.TimeStampQPC);
            if (Find(e.ProcessID, at) is not { } w || at > w.Connect) return;
            string? size = e.PayloadNames.FirstOrDefault(name => name.Equals("IoSize", StringComparison.OrdinalIgnoreCase));
            if (size is null) throw new InvalidDataException("Native read event has no byte count.");
            int index = w.Reads.Count;
            w.Reads.Add(new FileRead(at, null, FileClass(e.FileName), Convert.ToInt64(e.PayloadByName(size)), null));
            if (!reads.TryAdd(e.IrpPtr.ToString("x"), (w, index)))
                throw new InvalidDataException("A targeted read reused an unfinished IRP.");
        };
        source.Kernel.FileIOOperationEnd += e =>
        {
            if (reads.Remove(e.IrpPtr.ToString("x"), out var item))
            {
                var row = item.Window.Reads[item.Index];
                item.Window.Reads[item.Index] = row with { End = Micros(e.TimeStampQPC), Status = e.NtStatus };
            }
        };
        void Registry(RegistryTraceData e, string operation)
        {
            long at = Micros(e.TimeStampQPC);
            if (Find(e.ProcessID, at) is { } w && at <= w.Connect)
                w.Registry.Add(new RegistryOp(at, operation, Nonnegative(e.ElapsedTimeMSec)));
        }
        source.Kernel.RegistryOpen += e => Registry(e, "open");
        source.Kernel.RegistryQuery += e => Registry(e, "query");
        source.Kernel.RegistryQueryValue += e => Registry(e, "query-value");
        source.Kernel.RegistryEnumerateKey += e => Registry(e, "enumerate");
        source.Kernel.RegistryEnumerateValueKey += e => Registry(e, "enumerate-values");
        source.Kernel.MemoryHardFault += e =>
        {
            long at = Micros(e.TimeStampQPC);
            if (Find(e.ProcessID, at) is { } w && at <= w.Connect)
                w.Faults.Add(new Fault(at, FileClass(e.FileName), Nonnegative(e.ElapsedTimeMSec)));
        };
        source.Process();
        var persist = windows.Select(w => new
        {
            w.Kind, w.Pid, w.Clients, w.Spawn, w.Entry, w.Connect, w.Exit, w.Starts, w.Stops, w.Threads,
            Cpu = w.Cpu.Select(span => new { span.Start, span.End }), w.Images, w.Reads, w.Registry, w.Faults
        });
        File.WriteAllText(Path.Combine(output, "etw.json"),
            JsonSerializer.Serialize(new { source.EventsLost, Windows = persist }, Json) + "\n");
        var calibration = windows.Single(w => w.Clients == 0);
        if (source.EventsLost != 0 || calibration.Starts.Count != 1 || calibration.Images.Count == 0
            || calibration.Registry.Count == 0 || calibration.Cpu.Count == 0
            || !calibration.Reads.Any(r => r.Class == "calibration" && r.Bytes == 65536 && r.Status == 0))
            throw new InvalidDataException("Native trace calibration or loss check failed.");
        if (windows.Any(w => w.Starts.Count != 1 || w.Images.Count == 0 || w.Cpu.Count == 0
            || w.Connect < w.Entry || (w.Clients != 0 && w.Entry < w.Starts[0])))
            throw new InvalidDataException("A measured CLI lacks an exact process start, image load, or CPU interval.");
    }

    public static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "calibrate")
        {
            using var file = new FileStream(args[1], FileMode.Open, FileAccess.Read, FileShare.Read, 1);
            file.ReadExactly(new byte[65536]);
            using var registry = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return registry?.GetValue("ProductName") is string ? 0 : 2;
        }
        if (args.Length != 7) throw new ArgumentException("Expected node, driver, image, minimal driver, minimal image, output and trace temporary directory.");
        var (node, driver, image, minimalDriver, minimalImage, output, temporary) = (args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
        var productOutput = Path.Combine(output, "product");
        var minimalOutput = Path.Combine(output, "minimal");
        Directory.CreateDirectory(output);
        Directory.CreateDirectory(temporary);
        if (TraceEventSession.IsElevated() != true) throw new InvalidOperationException("Kernel ETW requires elevation on this runner.");
        var trace = Path.Combine(temporary, "startup.etl");
        var calibrationFile = Path.Combine(temporary, "calibration.bin");
        File.WriteAllBytes(calibrationFile, new byte[65536]);
        try
        {
            Window calibration;
            using (var session = new TraceEventSession("StartupMeasure-" + Guid.NewGuid().ToString("N"), trace))
            {
                session.BufferSizeMB = 256;
                session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.Thread
                    | KernelTraceEventParser.Keywords.ContextSwitch | KernelTraceEventParser.Keywords.ImageLoad
                    | KernelTraceEventParser.Keywords.FileIO | KernelTraceEventParser.Keywords.FileIOInit
                    | KernelTraceEventParser.Keywords.Registry | KernelTraceEventParser.Keywords.MemoryHardFaults);
                long begin = Now();
                using var known = Start("dotnet", Assembly.GetExecutingAssembly().Location, "calibrate", calibrationFile);
                if (!known.WaitForExit(10_000) || known.ExitCode != 0) throw new InvalidOperationException("Calibration child failed.");
                long end = Now();
                calibration = new Window("calibration", known.Id, 0, begin, end, end, end);
                using var driverProcess = Start(node, driver, image, productOutput, "200", "trace");
                if (!driverProcess.WaitForExit(480_000) || driverProcess.ExitCode != 0) throw new InvalidOperationException("Write driver failed.");
                using var minimalProcess = Start(node, minimalDriver, minimalImage, minimalOutput, "200");
                if (!minimalProcess.WaitForExit(480_000) || minimalProcess.ExitCode != 0) throw new InvalidOperationException("Minimal driver failed.");
            }
            var windows = LoadWindows(productOutput, "product");
            windows.AddRange(LoadWindows(minimalOutput, "minimal"));
            windows.Add(calibration);
            Parse(trace, windows, output);
        }
        finally
        {
            File.Delete(trace);
        }
        return 0;
    }
}
