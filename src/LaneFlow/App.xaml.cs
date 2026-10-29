using System;
using System.Threading;
using System.Windows;
using System.Windows.Threading;

namespace LaneFlow;

public partial class App : Application
{
    private Mutex? _instanceMutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        var doc = Settings.Load();
        L10n.Apply(doc.UiLanguage);

        if (!ClaimSingleInstance())
        {
            MessageBox.Show(
                L10n.T("GateAlreadyRunning"),
                "LaneFlow Free",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            Shutdown();
            return;
        }

        ChildJob.Install();
        AppDomain.CurrentDomain.ProcessExit += (_, _) => ShutDownBackground();
        RegisterCrashHandlers();
        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        ShutDownBackground();
        try { _instanceMutex?.ReleaseMutex(); } catch { }
        _instanceMutex?.Dispose();
        base.OnExit(e);
    }

    private bool ClaimSingleInstance()
    {
        _instanceMutex = new Mutex(true, @"Global\LaneFlowFree.SingleInstance", out var created);
        return created;
    }

    private static void ShutDownBackground()
    {
        try { BlackoutRunner.Stop(); } catch { }
        try { SingBoxRunner.Stop(); } catch { }
    }

    // Global crash net: an unhandled exception while the DNS takeover is active would otherwise
    // leave the machine pointing at the (now gone) TUN address until the next launch. Best-effort
    // restore first, then let the process die (never swallow the exception).
    private void RegisterCrashHandlers()
    {
        DispatcherUnhandledException += (_, e) =>
        {
            CrashRecover();
            e.Handled = false;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, _) => CrashRecover();
    }

    internal static string CrashRecover(string? statePath = null)
    {
        ShutDownBackground();
        try
        {
            var (found, message) = new WindowsDnsOverride(statePath).RecoverIfStale();
            return found ? message : "no active takeover trace; nothing to restore";
        }
        catch (Exception ex)
        {
            return $"crash recovery failed: {ex.Message}";
        }
    }
}
