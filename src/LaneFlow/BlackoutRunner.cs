using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace LaneFlow;

/// <summary>
/// Setup-gate blackout: a second sing-box instance with a TUN default route and final=block.
/// Every connection is rejected while the user is still filling the form. The process owns the
/// TUN, so a crash releases the network as soon as the process dies (the child job is the
/// backstop for a hard kill of this app).
/// </summary>
internal static class BlackoutRunner
{
    private static readonly object Gate = new();
    private static readonly StringBuilder Log = new();
    private static Process? _proc;

    public static bool IsRunning
    {
        get
        {
            lock (Gate)
                return _proc is { HasExited: false };
        }
    }

    public static (bool Ok, string Message) Start()
    {
        if (!File.Exists(SingBoxRunner.SingBoxExe))
            return (false, "core/sing-box.exe not found (bundled kernel missing)");

        Stop();

        var configPath = Path.Combine(Settings.SingBoxConfigDir, "gate.json");
        try
        {
            Directory.CreateDirectory(Settings.SingBoxConfigDir);
            File.WriteAllText(configPath, ConfigRenderer.RenderBlackhole());
        }
        catch (Exception ex)
        {
            return (false, "failed to write the gate config: " + ex.Message);
        }

        var psi = new ProcessStartInfo(SingBoxRunner.SingBoxExe, $"run -c \"{configPath}\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(SingBoxRunner.SingBoxExe) ?? AppContext.BaseDirectory
        };

        try
        {
            lock (Log)
                Log.Clear();

            var proc = Process.Start(psi);
            if (proc is null)
                return (false, "kernel process was not created");

            proc.OutputDataReceived += (_, e) => Append(e.Data);
            proc.ErrorDataReceived += (_, e) => Append(e.Data);
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();
            ChildJob.Assign(proc);

            lock (Gate)
                _proc = proc;

            // TUN creation window: the adapter must be up before traffic can be considered
            // paused. A process exit here means the config was rejected (fail visible).
            Thread.Sleep(3000);

            if (proc.HasExited)
            {
                var tail = LogTail();
                lock (Gate)
                    _proc = null;
                return (false, "kernel exited during setup: " + tail);
            }

            return (true, "network paused");
        }
        catch (Exception ex)
        {
            return (false, "failed to start the gate kernel: " + ex.Message);
        }
    }

    public static void Stop()
    {
        Process? proc;
        lock (Gate)
        {
            proc = _proc;
            _proc = null;
        }
        if (proc is null)
            return;
        try
        {
            if (!proc.HasExited)
            {
                proc.Kill();
                proc.WaitForExit(3000);
            }
        }
        catch
        {
            // Stop is best effort; the child job still kills the kernel if this process dies.
        }
        finally
        {
            try { proc.Dispose(); } catch { }
        }
    }

    private static void Append(string? line)
    {
        if (line is null)
            return;
        lock (Log)
            Log.AppendLine(line);
    }

    private static string LogTail()
    {
        lock (Log)
        {
            var text = Log.ToString().Trim();
            return text.Length <= 600 ? text : text[^600..];
        }
    }
}
