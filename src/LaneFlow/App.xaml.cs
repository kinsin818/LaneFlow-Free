using System;
using System.Windows;
using System.Windows.Threading;

namespace LaneFlow;

public partial class App : Application
{
    // Apply the persisted UI language before any window is constructed, so the first paint is
    // already in the chosen language (UI defaults to English, switchable;
    // culture bound to CurrentUICulture).
    protected override void OnStartup(StartupEventArgs e)
    {
        RegisterCrashHandlers();
        var doc = Settings.Load();
        L10n.Apply(doc.UiLanguage);
        base.OnStartup(e);
    }

    // Global crash net (packaging review): an unhandled exception while the DNS takeover is
    // active would otherwise leave the machine pointing at the (now gone) TUN address until the
    // next launch. The handlers perform a best-effort synchronous restore first, then let the
    // process die — fail-closed: the exception is never swallowed or marked handled.
    private void RegisterCrashHandlers()
    {
        DispatcherUnhandledException += (_, e) =>
        {
            CrashRecover();
            e.Handled = false;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, _) => CrashRecover();
    }

    /// <summary>
    /// Best-effort synchronous DNS restore on a fatal crash path (idempotent). Reads the
    /// persisted takeover trace from disk, so it also covers a crash of the whole process.
    /// Never throws; returns the recovery message (or the failure reason) for logging.
    /// The optional state path exists for the self-test (injection-sealed); production uses
    /// the default trace location.
    /// </summary>
    internal static string CrashRecover(string? statePath = null)
    {
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
