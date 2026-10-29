using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace LaneFlow;

/// <summary>Process entry for the binding panel.</summary>
public sealed class ProcessEntry
{
    public int Id { get; init; }
    public string Name { get; init; } = string.Empty;
    public string MainWindowTitle { get; init; } = string.Empty;

    public string Display => string.IsNullOrEmpty(MainWindowTitle)
        ? $"{Name} (PID {Id})"
        : $"{Name} (PID {Id}) — {MainWindowTitle}";
}

/// <summary>
/// Process enumeration and duplicate-image-name detection (binding panel).
/// Application-level enumeration only; does not touch sing-box / TUN mechanics.
/// </summary>
public static class ProcessCatalog
{
    /// <summary>Enumerates local processes (sorted by image name).</summary>
    public static IReadOnlyList<ProcessEntry> Enumerate()
    {
        var list = new List<ProcessEntry>();
        Process[] all;
        try { all = Process.GetProcesses(); }
        catch { return list; }

        foreach (var p in all)
        {
            string name;
            try { name = p.ProcessName; }
            catch { name = "?"; }

            string title;
            try { title = p.MainWindowTitle ?? string.Empty; }
            catch { title = string.Empty; }

            list.Add(new ProcessEntry { Id = p.Id, Name = name, MainWindowTitle = title });
            p.Dispose();
        }

        list.Sort((a, b) => string.Compare(a.Name, b.Name, System.StringComparison.OrdinalIgnoreCase));
        return list;
    }

    /// <summary>
    /// Detects multiple live processes with the same image name. Returns a warning when
    /// count &gt; 1: the user should close the others before binding.
    /// </summary>
    public static (int Count, string? Warning) DetectDuplicateByName(string processName)
    {
        if (string.IsNullOrWhiteSpace(processName))
            return (0, null);

        Process[] matches;
        try { matches = Process.GetProcessesByName(processName.Trim()); }
        catch { return (0, null); }

        var count = matches.Length;
        foreach (var m in matches) m.Dispose();

        if (count > 1)
            return (count, $"Detected {count} processes with the same name; close the others before binding");

        return (count, null);
    }
}

/// <summary>
/// sing-box child-process lifecycle management (TUN takeover / routing / DNS takeover /
/// start-stop / restore / liveness monitoring). The whole app runs with
/// requireAdministrator, so creating the TUN adapter and changing interface DNS is allowed.
/// Known failure modes guarded here:
///   - Start/stop idempotency: Start stops a running instance first; no orphan kernels or
///     dual instances fighting over interface_name=LaneFlow.
///   - Liveness monitoring: Exited event + KernelExited callback; sudden kernel death
///     immediately flips the UI to fail-closed red.
///   - Pipes must be drained: stdout/stderr read asynchronously so a full pipe cannot
///     deadlock the kernel.
///   - Startup order invariant (v3 final form): start kernel (TUN /30
///     on-link ready) → add fakeip pool route 100.64.0.0/10 → LaneFlow (metric 1) → only
///     then DNS takeover (all interfaces → 172.19.0.2, the peer address). Reversed order
///     opens a window where DNS already points at the TUN that does not exist yet, and the
///     base fake-IP answers queries (fail-open direction); without the pool route, fakeip
///     connections fall to the default route via the base (V1 fake-green / actually red).
///   - TUN readiness gate (live-machine verified): ready = /30 on-link route present
///     (polled; timeout see <see cref="ReadyTimeoutMs"/>); <see cref="Dns"/> is not touched
///     before ready. Taking over after only 400ms was one root cause observed live
///     V1/V2 RED.
///   - Zombie-adapter retry (live-machine verified): wintun driver state — TerminateProcess
///     on a sing-box that owns an adapter (hard kill / sandbox cleanup / Task Manager)
///     leaves a zombie adapter (invisible to netsh, lingering ≥30s); the next CreateAdapter
///     hangs ~10s then FATALs at 15s, while one failed create self-heals the driver state.
///     Therefore a pre-ready process exit = this attempt failed and is retried once
///     (<see cref="MaxStartAttempts"/>); still failing → fail-closed with log tail, never
///     take over DNS in a half-ready state.
///   - Orphan kernel sweep (live-machine hardening): a live orphan sing-box holds the LaneFlow adapter →
///     new instance CreateAdapter FATALs at t0 ("file already exists"). On app startup we
///     sweep by path==core/sing-box.exe (only our own kernel; user's other sing-box
///     instances are untouched).
///   - Sudden death → restore DNS immediately: kernel gone while DNS still points at the
///     TUN address → queries fall to the default route and get answered by the base —
///     also a fail-open direction. The fakeip pool route dies with the TUN interface
///     (verified: netsh route table has no 100.64.0.0 after kernel stop).
/// </summary>
public static class SingBoxRunner
{
    /// <summary>DNS takeover component (v2). Windows implementation by default; SelfTest injects a fake here to verify the protocol. internal: test seam, not writable by arbitrary in-process code.</summary>
    internal static IDnsOverride Dns { get; set; } = new WindowsDnsOverride();

    private static Process? _proc;
    private static readonly object Gate = new();
    private static readonly System.Text.StringBuilder LogTail = new(4096);
    private const int LogTailCap = 8192;

    /// <summary>Kernel exited event (sudden death / killed / instant exit). UI subscribes and flips to fail-closed red.</summary>
    public static event Action? KernelExited;

    /// <summary>sing-box.exe location: core/sing-box.exe next to the app executable.</summary>
    public static string SingBoxExe =>
        SingBoxExeOverride ?? Path.Combine(AppContext.BaseDirectory, "core", "sing-box.exe");

    /// <summary>sing-box.exe path override (SelfTest injection; always null in production). internal: test seam.</summary>
    internal static string? SingBoxExeOverride { get; set; }

    // ---- Test injection seams (SelfTest fakes verify the startup protocol; production uses real implementations) ----

    /// <summary>Kernel launcher override (SelfTest fake launcher). internal: test seam.</summary>
    internal static Func<ProcessStartInfo, Process?>? LauncherOverride { get; set; }

    /// <summary>TUN readiness probe override (SelfTest fake readiness). internal: test seam.</summary>
    internal static Func<bool>? ReadyProbeOverride { get; set; }

    /// <summary>Orphan kernel finder override (SelfTest fake finder, returns PID list). internal: test seam.</summary>
    internal static Func<IReadOnlyList<int>>? OrphanFinderOverride { get; set; }

    /// <summary>Orphan kernel killer override (SelfTest fake killer for bookkeeping). internal: test seam.</summary>
    internal static Action<int>? OrphanKillerOverride { get; set; }

    /// <summary>fakeip pool route override (SelfTest fake routing; always null in production → real netsh). internal: test seam.</summary>
    internal static Func<(bool Ok, string Message)>? AddFakeIpRouteOverride { get; set; }

    /// <summary>TUN readiness wait cap (default 20s; tunable in SelfTest). internal: test seam.</summary>
    internal static int ReadyTimeoutMs { get; set; } = 20_000;

    /// <summary>Readiness poll interval (default 250ms; tunable in SelfTest). internal: test seam.</summary>
    internal static int ReadyPollMs { get; set; } = 250;

    /// <summary>Max start attempts: zombie-adapter self-heal retry (live-machine: after one failed create, the next can succeed).</summary>
    public const int MaxStartAttempts = 2;

    public static bool IsRunning
    {
        get { lock (Gate) { return _proc is { HasExited: false }; } }
    }

    /// <summary>Recent bounded kernel log tail (capped against unbounded growth) for the status panel / diagnostics.</summary>
    public static string LastLogTail
    {
        get { lock (Gate) { return LogTail.ToString(); } }
    }

    private static void AppendLog(string? line)
    {
        if (string.IsNullOrEmpty(line)) return;
        lock (Gate)
        {
            LogTail.Append(line).Append('\n');
            if (LogTail.Length > LogTailCap)
                LogTail.Remove(0, LogTail.Length - LogTailCap);
        }
    }

    private static void OnExited(object? sender, EventArgs e)
    {
        lock (Gate) { _proc = null; }
        // Sudden death → restore DNS immediately: kernel gone while DNS still points at the
        // TUN address means queries fall to the default route and get answered by the base
        // (fail-open direction verified); restore synchronously in the kernel-exit path.
        try { Dns.Restore(); }
        catch
        {
            // Never swallow the fact: the trace file remains, next startup RecoverIfStale covers it.
        }
        KernelExited?.Invoke();
    }

    /// <summary>
    /// Starts sing-box: renders config to %APPDATA%\LaneFlow\singbox\config.json and spawns
    /// the child process. <paramref name="appExeName"/> is the bound app's image name
    /// (e.g. chrome.exe).
    ///
    /// v3 readiness gate (final form): TUN /30 on-link ready → add fakeip
    /// pool route 100.64.0.0/10 → LaneFlow → DNS takeover (all interfaces → 172.19.0.2).
    /// Any step failing stops the kernel and fails closed — never release in a half-ready state.
    /// </summary>
    public static (bool Ok, string Message) Start(OutboundConfig ob, string appExeName, string? appExePath = null)
    {
        if (!File.Exists(SingBoxExe))
            return (false, "core/sing-box.exe not found (bundled kernel missing)");

        // Idempotency: stop the previous instance first; no orphan kernels / dual instances
        // fighting over interface_name=LaneFlow.
        if (IsRunning) Stop();

        // Zombie-adapter wait (E-run [9] FATAL scenario): after a hard kernel kill, wintun
        // adapter dissipation has driver-level latency (sometimes <1s, sometimes ≥30s);
        // while the leftover exists, CreateAdapter hangs ~10s then FATALs. Wait for it to
        // disappear before attempting, avoiding the "hang + FATAL + retry" detour;
        // production path only (SelfTest has LauncherOverride and never touches real PNP).
        // Never force-delete on timeout (PNP deletion is risky); the attempt-loop
        // zombie self-heal retry below covers it.
        if (LauncherOverride is null) WaitZombieAdapterGone();

        try
        {
            Directory.CreateDirectory(Settings.SingBoxConfigDir);
            var json = ConfigRenderer.Render(ob, appExeName, appExePath);
            File.WriteAllText(Settings.SingBoxConfigPath, json);
            // Render fingerprint (input-sensitivity hardening): records the settings input
            // of this render. UI compares on startup — if settings changed without re-binding,
            // the on-disk config is stale and the UI must say so explicitly (never silently).
            File.WriteAllText(Settings.RenderFingerprintPath, Settings.Fingerprint(ob, appExeName));
        }
        catch (Exception ex)
        {
            return (false, "Failed to write the runtime config: " + ex.Message);
        }

        var psi = new ProcessStartInfo(SingBoxExe, $"run -c \"{Settings.SingBoxConfigPath}\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(SingBoxExe) ?? AppContext.BaseDirectory
        };

        for (var attempt = 1; attempt <= MaxStartAttempts; attempt++)
        {
            Process? proc;
            try
            {
                proc = LauncherOverride is null ? Process.Start(psi) : LauncherOverride(psi);
            }
            catch (Exception ex)
            {
                return (false, "Failed to start sing-box: " + ex.Message);
            }
            if (proc is null)
                return (false, "Failed to start sing-box (process was not created)");

            // Liveness monitoring + mandatory pipe draining: sudden death notifies the UI;
            // async reads prevent a full pipe from deadlocking the kernel.
            // Each line gets an [aN] tag: under retries, old attempts' FATALs mix into the
            // tail with the live kernel log — unattributable without tags (E/G-run proof).
            var attemptTag = $"[a{attempt}] ";
            try
            {
                proc.EnableRaisingEvents = true;
                proc.Exited += OnExited;
                proc.OutputDataReceived += (_, e2) => AppendLog(attemptTag + e2.Data);
                proc.ErrorDataReceived += (_, e2) => AppendLog(attemptTag + e2.Data);
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();
            }
            catch
            {
                // Fake / handle-less processes cannot take event subscriptions; harmless for
                // the decision path (SelfTest seam).
            }

            ChildJob.Assign(proc);
            lock (Gate) { _proc = proc; }

            // TUN readiness gate: kernel is ready only when the /30 on-link route appears
            // (the hard prerequisite for DNS queries entering the TUN to be hijacked);
            // a process exit during polling = this attempt failed (instant exit / zombie
            // adapter FATAL).
            var (ready, died) = AwaitTunReady(proc);
            if (ready)
            {
                // fakeip pool route (v3): split routes were emptied by
                // route_exclude_address=["0.0.0.0/0"]; fakeip connections reach the LaneFlow
                // TUN through this precise route (/10 is longer than any default route).
                // Fail-closed: without it, no DNS takeover — a bound app's fakeip connection
                // would fall to the default route via the base (exit IP looks fine but no
                // proxy involved; V1 fake-green / actually red).
                var (routeOk, routeMsg) = AddFakeIpRouteOverride is not null
                    ? AddFakeIpRouteOverride()
                    : AddFakeIpRoute();
                if (!routeOk)
                {
                    Stop();
                    return (false, "Failed to add the fakeip pool route; kernel stopped, forwarding NOT enabled (fail-closed): " + routeMsg);
                }

                // Liveness re-check: route/takeover are multi-second PowerShell operations;
                // the kernel may die meanwhile (E-run [9]: the "ok but kernel already dead"
                // window lets traffic fall to the base).
                if (!IsProcAlive(proc))
                {
                    Stop();
                    return (false, "Kernel exited after readiness but before takeover (fail-closed); forwarding NOT enabled: " + LastLogTail.Trim());
                }

                // DNS takeover (v3): /30 on-link + fakeip pool route are both in place, so
                // queries and fakeip connections are guaranteed to enter the TUN. Target =
                // 172.19.0.2 (peer address; the TUN's own address gets RST by the kernel).
                // Fail-closed: takeover failure stops the kernel — never release in the
                // "DNS points at TUN while TUN is down" window.
                var (dnsOk, dnsMsg) = Dns.Takeover(ConfigRenderer.DnsTakeoverAddress);
                if (!dnsOk)
                {
                    Stop();
                    return (false, "DNS takeover failed; kernel stopped, forwarding NOT enabled (fail-closed): " + dnsMsg);
                }
                if (!IsProcAlive(proc))
                {
                    Stop();
                    return (false, "Kernel exited immediately after DNS takeover (fail-closed); DNS restored: " + LastLogTail.Trim());
                }
                var retryNote = attempt > 1 ? $" (attempt {attempt}: zombie adapter self-heal retry)" : string.Empty;
                return (true, "Started (TUN ready + fakeip pool route + DNS takeover active)" + retryNote);
            }

            // Not ready: kill this attempt's kernel; retry or fail based on the log tail.
            // DNS not yet taken over, so nothing to restore.
            var tail = LastLogTail.Trim();
            var tailNote = tail.Length > 0 ? "; log tail: " + tail : string.Empty;
            var cause = died ? "kernel exited before readiness" : $"TUN did not become ready within {ReadyTimeoutMs}ms";
            KillProc(proc);
            lock (Gate) { if (ReferenceEquals(_proc, proc)) _proc = null; }

            if (attempt >= MaxStartAttempts)
                return (false, $"sing-box {cause} (retried {MaxStartAttempts} time(s)); blocked, forwarding NOT enabled (fail-closed)" + tailNote);
            // Zombie-adapter scenario: one failed CreateAdapter self-heals the driver state;
            // a single retry can succeed (proven live).
        }

        return (false, "sing-box failed to become ready; blocked (fail-closed)");
    }

    /// <summary>
    /// fakeip pool route (v3, manually managed): netsh adds 100.64.0.0/10 → LaneFlow
    /// (metric 1). Idempotent: existing route counts as success (retry/restart paths).
    /// Read-back verified after adding; missing = failure (fail-closed). No explicit cleanup
    /// needed — the route is bound to the TUN interface and dies with it when the kernel
    /// exits (proven live).
    /// </summary>
    public static (bool Ok, string Message) AddFakeIpRoute()
    {
        var pool = ConfigRenderer.FakeIpRange; // "100.64.0.0/10"
        var script =
            $"netsh interface ipv4 add route {pool} \"LaneFlow\" 0.0.0.0 metric=1 2>&1 | Out-Null; " +
            "$r=@(Get-NetRoute -InterfaceAlias 'LaneFlow' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -eq '" + pool + "' }); " +
            "if ($r.Count -gt 0) { 'OK' } else { 'MISSING' }";
        var (exit, stdout, stderr) = RunNetsh(script);
        if (exit != 0)
            return (false, $"Failed to add the fakeip pool route: {Trim(stderr, stdout)}");
        if (!stdout.Contains("OK", StringComparison.Ordinal))
            return (false, "fakeip pool route read-back verification failed (absent after add; fail-closed)");
        return (true, $"fakeip pool route ready: {pool} → LaneFlow");
    }

    /// <summary>netsh/PowerShell hybrid runner (route management; same spec as DnsOverride.RunPs).</summary>
    private static (int Exit, string Out, string Err) RunNetsh(string script, int timeoutMs = 15000)
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + script + "\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            if (p is null) return (-1, string.Empty, "failed to start powershell");
            // Concurrent pipe drain (see DnsOverride.RunPs): sequential synchronous ReadToEnd
            // deadlocks when stderr fills while stdout is read, and the timeout never fires.
            var outTask = p.StandardOutput.ReadToEndAsync();
            var errTask = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(); } catch { /* best effort on timeout */ }
                try { Task.WaitAll(new Task[] { outTask, errTask }, 3000); } catch { /* aggregate noise on kill */ }
                return (-2, outTask.Status == TaskStatus.RanToCompletion ? outTask.Result : string.Empty,
                        "powershell execution timed out");
            }
            return (p.ExitCode, outTask.GetAwaiter().GetResult(), errTask.GetAwaiter().GetResult());
        }
        catch (Exception ex)
        {
            return (-3, string.Empty, ex.Message);
        }
    }

    private static string Trim(string err, string out0)
    {
        var t = string.IsNullOrEmpty(err) ? out0 : err;
        t = t.Trim();
        return t.Length > 200 ? t.Substring(0, 200) + "…" : t;
    }

    /// <summary>
    /// TUN readiness polling: /30 on-link route appears (DNS takeover prerequisite), or the
    /// process exits, or timeout. Returns (ready, died). Process exit takes precedence over
    /// readiness — a dead kernel never triggers takeover even if the route was seen.
    /// </summary>
    private static (bool Ready, bool Died) AwaitTunReady(Process proc)
    {
        var probe = ReadyProbeOverride ?? (Func<bool>)RouteReady;
        var deadline = Environment.TickCount64 + ReadyTimeoutMs;
        while (true)
        {
            bool exited;
            try { exited = proc.HasExited; }
            catch { exited = true; }
            if (exited) return (false, true);
            if (probe()) return (true, false);
            if (Environment.TickCount64 >= deadline) return (false, false);
            Thread.Sleep(ReadyPollMs);
        }
    }

    /// <summary>
    /// Production readiness probe: LaneFlow adapter OperationalStatus=Up (live adapter) plus
    /// the /30 on-link prefix present in the netsh route table. **The adapter gate is the
    /// E-run [9] fix**: a stale /30 route of a ghost/zombie adapter can linger in netsh text
    /// after a hard kill; text-only matching let Start report "instant fake readiness"
    /// (the real kernel was still stuck in CreateAdapter) → kernel died right after DNS
    /// takeover → traffic fell to the base. OperationalStatus uses pure .NET IP Helper
    /// queries (zero process overhead, affordable at 250ms polling); ghost adapters do not
    /// report Up.
    /// </summary>
    private static bool RouteReady()
    {
        if (!LaneFlowAdapterUp()) return false;
        try
        {
            var psi = new ProcessStartInfo("netsh", "interface ipv4 show route")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p is null) return false;
            var outp = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
            return outp.Contains(TunOnLinkPrefix, StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Whether the LaneFlow adapter is Up (live). Absent / ghost / disabled → false.</summary>
    private static bool LaneFlowAdapterUp()
    {
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (string.Equals(nic.Name, "LaneFlow", StringComparison.OrdinalIgnoreCase))
                    return nic.OperationalStatus == OperationalStatus.Up;
            }
        }
        catch
        {
            // Enumeration failure: treat as not ready (fail-closed direction).
        }
        return false;
    }

    /// <summary>
    /// Zombie-adapter wait: after a hard kernel kill, wintun adapter dissipation has
    /// driver-level latency. Adapter visible at PNP level with no live sing-box process =
    /// zombie → poll for disappearance (≤35s) before attempting, avoiding the
    /// "CreateAdapter hangs 10s → FATAL → retry" detour (E-run [9] proof). No forced delete
    /// on timeout (PNP deletion is risky); the attempt-loop self-heal retry covers it.
    /// A ghost adapter invisible at PNP level cannot be waited out here — the attempt loop
    /// covers that too.
    /// </summary>
    private static void WaitZombieAdapterGone()
    {
        // Fast path: no LaneFlow adapter at PNP level → return immediately (single query).
        if (!LaneFlowAdapterPresentPnp()) return;
        for (var waited = 0; waited < 35_000; waited += 1000)
        {
            var procs = 0;
            try { procs = Process.GetProcessesByName("sing-box").Length; } catch { procs = 1; }
            if (!LaneFlowAdapterPresentPnp() || procs > 0) return;
            Thread.Sleep(1000);
        }
        // Still present after 35s: hand over to the attempt loop (zombie self-heal retry).
    }

    /// <summary>Whether a LaneFlow adapter is visible at PNP level (ghost/disabled included; independent of OperationalStatus).</summary>
    private static bool LaneFlowAdapterPresentPnp()
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -Command \"(Get-NetAdapter -Name LaneFlow -ErrorAction SilentlyContinue) -ne \\$null\"")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p is null) return false;
            var outp = p.StandardOutput.ReadToEnd();
            p.WaitForExit(10_000);
            return outp.Contains("True", StringComparison.Ordinal);
        }
        catch
        {
            return false; // Query failure → treat as absent (the wait is an optimization, not a correctness dependency)
        }
    }

    /// <summary>Process liveness re-check (closes the sudden-death window after readiness/takeover).</summary>
    private static bool IsProcAlive(Process proc)
    {
        try { return !proc.HasExited; }
        catch { return false; }
    }

    /// <summary>/30 on-link prefix (derived from TunAddress "172.19.0.1/30" → network part "172.19.0.").</summary>
    private static string TunOnLinkPrefix
    {
        get
        {
            var addr = ConfigRenderer.TunAddress.Split('/')[0];
            var octets = addr.Split('.');
            return octets.Length == 4
                ? string.Join('.', octets[0], octets[1], octets[2]) + "."
                : addr;
        }
    }

    /// <summary>Disposes a failed attempt's kernel: unsubscribe, kill, wait for exit, dispose.</summary>
    private static void KillProc(Process proc)
    {
        try
        {
            proc.Exited -= OnExited;
            if (!proc.HasExited)
            {
                proc.Kill();
                proc.WaitForExit(3000);
            }
        }
        catch
        {
            // Already exited / cannot kill — best effort; the log tail and the readiness gate
            // decide the truth.
        }
        try { proc.Dispose(); }
        catch { /* disposal failure does not affect the main flow */ }
    }

    /// <summary>
    /// Orphan kernel sweep (startup hardening): a live sing-box left behind by a hard
    /// app kill (sandbox cleanup / Task Manager / crash) still owns the
    /// interface_name=LaneFlow adapter → a new instance's CreateAdapter FATALs at t0
    /// (real-machine proof). Only kernels with path==core/sing-box.exe are killed; the
    /// user's other sing-box instances are untouched. Returns the kill count.
    /// </summary>
    public static int SweepOrphanKernels()
    {
        IReadOnlyList<int> pids;
        if (OrphanFinderOverride is not null)
        {
            pids = OrphanFinderOverride();
        }
        else
        {
            var found = new List<int>();
            Process[] all;
            try { all = Process.GetProcessesByName("sing-box"); }
            catch { return 0; }
            foreach (var p in all)
            {
                try
                {
                    if (string.Equals(p.MainModule?.FileName, SingBoxExe, StringComparison.OrdinalIgnoreCase))
                        found.Add(p.Id);
                }
                catch
                {
                    // Access denied / already exited: skip (better to miss than to kill wrong).
                }
                finally { p.Dispose(); }
            }
            pids = found;
        }

        var killer = OrphanKillerOverride;
        var killed = 0;
        foreach (var pid in pids)
        {
            try
            {
                if (killer is not null) killer(pid);
                else Process.GetProcessById(pid).Kill();
                killed++;
            }
            catch
            {
                // Already exited: counts as cleaned.
            }
        }
        return killed;
    }

    /// <summary>
    /// Stops the sing-box child process and restores DNS. sing-box cleans up its TUN adapter
    /// on exit; the manually added fakeip pool route (100.64.0.0/10 → LaneFlow) is bound to
    /// that interface and dies with it (proven live: no 100.64.0.0 in netsh route table after
    /// kernel stop — no explicit delete needed). DNS restore MUST happen after killing the
    /// kernel (withdraw TUN first, then change DNS back, avoiding queries entering a
    /// vanished TUN in the window). Restore failure does not throw: the trace file remains,
    /// next startup RecoverIfStale covers it, and the UI status panel turns red.
    /// </summary>
    public static void Stop()
    {
        Process? proc;
        lock (Gate)
        {
            proc = _proc;
            _proc = null;
        }
        if (proc is not null)
        {
            try
            {
                proc.Exited -= OnExited;
                if (!proc.HasExited)
                {
                    proc.Kill();
                    proc.WaitForExit(3000);
                }
            }
            catch
            {
                // Ignore stop-time exceptions; keep the main flow alive.
            }
            try { proc.Dispose(); } catch { }
        }

        // Restore DNS after killing the kernel (sequence: withdraw TUN first, then DNS).
        // Idempotent: no-op when not taken over.
        try { Dns.Restore(); }
        catch
        {
            // As above: trace retained, next startup re-checks and restores.
        }
    }
}
