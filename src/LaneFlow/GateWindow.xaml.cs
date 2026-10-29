using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;

namespace LaneFlow;

/// <summary>
/// Full-screen setup gate. The network is paused (kernel blackhole) while the user enters the
/// exit and the target program; the lane is then verified by real probes for a continuous
/// five-minute window before the session is released. No configuration is persisted.
/// </summary>
public partial class GateWindow : Window
{
    private const int SessionMinutes = 30;
    private const int StableSeconds = 300;
    private const int ProbeIntervalSeconds = 10;
    private const int MaxConsecutiveFailures = 3;

    private readonly DispatcherTimer _clock = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly DispatcherTimer _probeTimer = new() { Interval = TimeSpan.FromSeconds(ProbeIntervalSeconds) };
    private readonly DispatcherTimer _escTimer = new() { Interval = TimeSpan.FromSeconds(3) };

    private DateTime _sessionEnd;
    private OutboundConfig? _cfg;
    private string _ip = string.Empty;
    private string _path = string.Empty;
    private int _stableRemaining = StableSeconds;
    private int _failures;
    private bool _laneStarted;
    private bool _blackoutActive;
    private bool _probing;
    private bool _allowClose;
    private bool _exiting;
    private bool _zh = true;

    public GateWindow()
    {
        InitializeComponent();
        L10n.Apply("zh");
        ApplyStrings();
        DisablePaste(TxtIp);
        DisablePaste(TxtPort);
        DisablePaste(TxtUser);
        DisablePaste(TxtPath);
        DisablePaste(PwdPass);

        _sessionEnd = DateTime.Now.AddMinutes(SessionMinutes);
        _clock.Tick += (_, _) => OnClockTick();
        _probeTimer.Tick += async (_, _) => await ProbeTickAsync();
        _escTimer.Tick += (_, _) => { _escTimer.Stop(); ExitAndRestore(null); };
        _clock.Start();
        UpdateSessionLabel();
        ShowPanel(IntroPanel);
    }

    private void ApplyStrings()
    {
        TxtIntroTitle.Text = L10n.T("GateIntroTitle");
        TxtIntroBody.Text = L10n.T("GateIntroBody");
        TxtSafety.Text = L10n.T("GateSafety");
        BtnStart.Content = L10n.T("GateStart");
        TxtFormTitle.Text = L10n.T("GateFormTitle");
        LblIp.Text = L10n.T("GateIp");
        LblPort.Text = L10n.T("GatePort");
        LblUser.Text = L10n.T("GateUser");
        LblPass.Text = L10n.T("GatePass");
        LblPath.Text = L10n.T("GatePath");
        TxtPathHint.Text = L10n.T("GatePathHint");
        TxtNoPaste.Text = L10n.T("GateNoPaste");
        BtnBegin.Content = L10n.T("GateBegin");
        BtnBack.Content = L10n.T("GateBack");
        TxtStabilityTitle.Text = L10n.T("GateStabilityTitle");
        TxtProbe.Text = L10n.T("GateStable");
        TxtCountdown.Text = "05:00";
        TxtRunTitle.Text = L10n.T("GateRunningTitle");
        BtnExit.Content = L10n.T("GateExit");
        BtnUpgrade.Content = L10n.T("GateUpgrade");
        BtnEmergency.Content = L10n.T("GateExit");
        TxtEscHint.Text = L10n.T("GateEscHint");
        BtnLang.Content = _zh ? L10n.T("GateLangToEn") : L10n.T("GateLangToZh");
    }

    private void BtnLang_Click(object sender, RoutedEventArgs e)
    {
        _zh = !_zh;
        L10n.Apply(_zh ? "zh" : "en");
        ApplyStrings();
    }

    private static void DisablePaste(Control box)
    {
        box.AllowDrop = false;
        box.ContextMenu = null;
        DataObject.AddPastingHandler(box, (_, e) => e.CancelCommand());
        box.PreviewKeyDown += (_, e) =>
        {
            if ((Keyboard.Modifiers & ModifierKeys.Control) != 0 && e.Key == Key.V)
                e.Handled = true;
            if ((Keyboard.Modifiers & ModifierKeys.Shift) != 0 && e.Key == Key.Insert)
                e.Handled = true;
        };
    }

    private void ShowPanel(UIElement panel)
    {
        foreach (var p in new UIElement[] { IntroPanel, FormPanel, StabilityPanel, RunningPanel })
            p.Visibility = ReferenceEquals(p, panel) ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void BtnStart_Click(object sender, RoutedEventArgs e)
    {
        BtnStart.IsEnabled = false;
        TxtIntroBody.Text = L10n.T("GateVerifying");
        var (ok, msg) = await Task.Run(() => BlackoutRunner.Start());
        if (!ok)
        {
            TxtIntroBody.Text = L10n.F("GateBlackoutFailed", msg);
            BtnStart.IsEnabled = true;
            return;
        }
        _blackoutActive = true;
        BtnEmergency.Visibility = Visibility.Visible;
        TxtEscHint.Visibility = Visibility.Visible;
        ShowPanel(FormPanel);
        TxtIp.Focus();
    }

    private void BtnBack_Click(object sender, RoutedEventArgs e)
    {
        if (_blackoutActive)
        {
            BlackoutRunner.Stop();
            _blackoutActive = false;
        }
        TxtIntroBody.Text = L10n.T("GateIntroBody");
        BtnStart.IsEnabled = true;
        TxtStatus.Text = string.Empty;
        ShowPanel(IntroPanel);
    }

    private async void BtnBegin_Click(object sender, RoutedEventArgs e)
    {
        if (!ValidateInputs(out var error))
        {
            TxtStatus.Text = error;
            return;
        }

        BtnBegin.IsEnabled = false;
        TxtStatus.Text = L10n.T("GateVerifying");
        try
        {
            if (!_blackoutActive)
            {
                var (blackoutOk, blackoutMsg) = await Task.Run(() => BlackoutRunner.Start());
                if (!blackoutOk)
                {
                    TxtStatus.Text = L10n.F("GateBlackoutFailed", blackoutMsg);
                    return;
                }
                _blackoutActive = true;
                BtnEmergency.Visibility = Visibility.Visible;
                TxtEscHint.Visibility = Visibility.Visible;
            }

            await Task.Run(() => BlackoutRunner.Stop());
            _blackoutActive = false;

            var cfg = new OutboundConfig
            {
                Type = ProxyType.Socks5,
                Host = _ip,
                Port = int.Parse(TxtPort.Text.Trim()),
                Username = string.IsNullOrWhiteSpace(TxtUser.Text) ? null : TxtUser.Text.Trim(),
                Password = string.IsNullOrEmpty(PwdPass.Password) ? null : PwdPass.Password
            };
            var (ok, msg) = await Task.Run(() => SingBoxRunner.Start(cfg, Path.GetFileName(_path), _path));
            if (!ok)
            {
                TxtStatus.Text = L10n.F("GateStartFailed", msg);
                return;
            }

            _cfg = cfg;
            _laneStarted = true;
            _stableRemaining = StableSeconds;
            _failures = 0;
            BarStable.Value = StableSeconds;
            TxtCountdown.Text = "05:00";
            TxtProbe.Text = L10n.T("GateStable");
            ShowPanel(StabilityPanel);
            _probeTimer.Start();
        }
        finally
        {
            BtnBegin.IsEnabled = true;
        }
    }

    private bool ValidateInputs(out string error)
    {
        error = string.Empty;
        _ip = TxtIp.Text.Trim();
        _path = TxtPath.Text.Trim();

        if (!IPAddress.TryParse(_ip, out var address) || address.AddressFamily != AddressFamily.InterNetwork)
        {
            error = L10n.T("GateInvalidIp");
            return false;
        }
        if (!int.TryParse(TxtPort.Text.Trim(), out var port) || port < 1 || port > 65535)
        {
            error = L10n.T("GateInvalidPort");
            return false;
        }
        if (!File.Exists(_path) || !_path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            error = L10n.T("GateInvalidPath");
            return false;
        }
        return true;
    }

    private async Task ProbeTickAsync()
    {
        if (_probing || !_laneStarted || _cfg is null)
            return;
        _probing = true;
        try
        {
            var (ok, detail) = await ProbeAsync(_cfg);
            if (!ok)
            {
                RegisterFailure(detail);
                return;
            }
            if (!string.Equals(detail, _ip, StringComparison.Ordinal))
            {
                RegisterFailure(L10n.F("GateMismatch", _ip, detail));
                return;
            }

            _failures = 0;
            _stableRemaining = Math.Max(0, _stableRemaining - ProbeIntervalSeconds);
            BarStable.Value = _stableRemaining;
            TxtCountdown.Text = Fmt(TimeSpan.FromSeconds(_stableRemaining));
            TxtProbe.Text = L10n.T("GateStable") + "  " + detail;

            if (_stableRemaining <= 0)
                EnterRunning();
        }
        finally
        {
            _probing = false;
        }
    }

    private void RegisterFailure(string reason)
    {
        _failures++;
        _stableRemaining = StableSeconds;
        BarStable.Value = StableSeconds;
        TxtCountdown.Text = "05:00";
        TxtProbe.Text = L10n.F("GateProbeFailed", reason) + "  " + L10n.T("GateUnstable");
        if (_failures >= MaxConsecutiveFailures)
            AbortStability();
    }

    private void AbortStability()
    {
        _probeTimer.Stop();
        try { SingBoxRunner.Stop(); } catch { }
        _laneStarted = false;
        TxtStatus.Text = L10n.T("GateAbort");
        ShowPanel(FormPanel);
    }

    private void EnterRunning()
    {
        _probeTimer.Stop();
        TxtRunProgram.Text = _path;
        TxtRunExit.Text = _ip;
        ShowPanel(RunningPanel);
    }

    private void OnClockTick()
    {
        var left = _sessionEnd - DateTime.Now;
        if (left <= TimeSpan.Zero)
        {
            ExitAndRestore(L10n.T("GateSessionEnded"));
            return;
        }
        UpdateSessionLabel();
        if (_laneStarted)
        {
            TxtCountdown.Text = Fmt(TimeSpan.FromSeconds(_stableRemaining));
            BarStable.Value = _stableRemaining;
        }
    }

    private void UpdateSessionLabel()
    {
        var left = _sessionEnd - DateTime.Now;
        if (left < TimeSpan.Zero)
            left = TimeSpan.Zero;
        var text = L10n.T("GateRemaining") + " " + Fmt(left);
        TxtSession.Text = text;
        TxtRunRemaining.Text = text;
    }

    private static string Fmt(TimeSpan t)
    {
        if (t < TimeSpan.Zero)
            t = TimeSpan.Zero;
        return $"{(int)t.TotalMinutes:00}:{t.Seconds:00}";
    }

    private static async Task<(bool Ok, string Detail)> ProbeAsync(OutboundConfig cfg)
    {
        try
        {
            var proxy = new WebProxy($"socks5://{cfg.Host}:{cfg.Port}");
            if (!string.IsNullOrEmpty(cfg.Username))
                proxy.Credentials = new NetworkCredential(cfg.Username, cfg.Password ?? string.Empty);

            using var handler = new SocketsHttpHandler
            {
                Proxy = proxy,
                UseProxy = true,
                ConnectTimeout = TimeSpan.FromSeconds(5),
                PooledConnectionIdleTimeout = TimeSpan.FromSeconds(5)
            };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
            using var response = await http.GetAsync("https://api.ipify.org");
            if (!response.IsSuccessStatusCode)
                return (false, "HTTP " + response.StatusCode);
            var body = (await response.Content.ReadAsStringAsync()).Trim();
            return (true, body);
        }
        catch (Exception ex)
        {
            return (false, ex.GetType().Name);
        }
    }

    private void BtnExit_Click(object sender, RoutedEventArgs e) => ExitAndRestore(null);

    private void BtnEmergency_Click(object sender, RoutedEventArgs e) => ExitAndRestore(null);

    private void BtnUpgrade_Click(object sender, RoutedEventArgs e)
    {
        if (_exiting)
            return;
        _exiting = true;
        _allowClose = true;
        _clock.Stop();
        _probeTimer.Stop();
        _escTimer.Stop();
        try { if (_laneStarted) SingBoxRunner.Stop(); } catch { }
        _laneStarted = false;
        try { BlackoutRunner.Stop(); } catch { }
        _blackoutActive = false;
        try
        {
            Process.Start(new ProcessStartInfo(ProLink.PurchaseUrl) { UseShellExecute = true });
        }
        catch
        {
            // best effort: opening the storefront must never block exit
        }
        Close();
        Application.Current.Shutdown();
    }

    private void ExitAndRestore(string? message)
    {
        if (_exiting)
            return;
        _exiting = true;
        _allowClose = true;
        _clock.Stop();
        _probeTimer.Stop();
        _escTimer.Stop();
        try { if (_laneStarted) SingBoxRunner.Stop(); } catch { }
        _laneStarted = false;
        try { BlackoutRunner.Stop(); } catch { }
        _blackoutActive = false;
        if (!string.IsNullOrEmpty(message))
            MessageBox.Show(message, "LaneFlow Free", MessageBoxButton.OK, MessageBoxImage.Information);
        Close();
        Application.Current.Shutdown();
    }

    private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (!_allowClose)
            e.Cancel = true;
    }

    private void OnKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Escape || _escTimer.IsEnabled)
            return;
        _escTimer.Start();
    }

    private void OnKeyUp(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
            _escTimer.Stop();
    }
}
