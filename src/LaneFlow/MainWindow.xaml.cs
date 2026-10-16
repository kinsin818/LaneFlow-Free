using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace LaneFlow;

public partial class MainWindow : Window
{
    // Single constant: the footer "Get Pro" link (from Config.ProLink.PurchaseUrl).
    private AppBinding _binding = new();
    private readonly DispatcherTimer _livenessTimer;
    private bool _lastRunning;
    private bool _suppressLangEvents;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;

        // Language selector items are self-named constants set once from the
        // neutral resources, before any selection — per i18n convention they never translate with
        // the active culture (and post-selection content edits hit a WPF selection-box refresh
        // quirk, so they must never be re-applied).
        foreach (var item in CmbLang.Items)
        {
            if (item is ComboBoxItem cbi)
                cbi.Content = L10n.TInvariant((cbi.Tag as string) == "zh" ? "LangItemZh" : "LangItemEn");
        }

        // Liveness double-guard: kernel-death event flips to red immediately + a 2s
        // polling backstop catches missed events.
        SingBoxRunner.KernelExited += OnKernelExited;
        _livenessTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _livenessTimer.Tick += LivenessTimer_Tick;
        _livenessTimer.Start();
    }

    // Kernel sudden death → hop back to the UI thread, refresh status, fail-closed red.
    private void OnKernelExited()
    {
        Dispatcher.BeginInvoke(new Action(() =>
        {
            _lastRunning = false;
            RefreshStatus();
        }));
    }

    // Backstop probe: compare the running state every 2s; refresh only on change (covers
    // missed Exited events).
    private void LivenessTimer_Tick(object? sender, EventArgs e)
    {
        var running = SingBoxRunner.IsRunning;
        if (running != _lastRunning)
        {
            _lastRunning = running;
            RefreshStatus();
        }
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        var doc = Settings.Load(out var corrupted, out var loadDetail);
        _binding = doc.Binding;
        WriteUiFromConfig(doc.Outbound);
        // Suppress the SelectionChanged handler while restoring the persisted language choice
        // (otherwise startup would trigger a redundant save round-trip).
        _suppressLangEvents = true;
        SelectComboTag(CmbLang, doc.UiLanguage, languageMode: true);
        _suppressLangEvents = false;
        ApplyLanguage();
        RefreshProcessList();

        // Orphan kernel sweep (startup hardening): a live sing-box left by a previous
        // hard kill (sandbox cleanup / Task Manager / crash) still owns the LaneFlow adapter
        // → the new instance's CreateAdapter FATALs at t0 (real-machine proof). Only sweeps
        // path==core/sing-box.exe (our own kernel); zombie adapters invisible to netsh are
        // covered by the Start readiness gate + retry.
        var swept = SingBoxRunner.SweepOrphanKernels();
        var sweepMsg = swept > 0 ? L10n.F("SweepMsg", swept) : null;

        // v2 crash-recovery chain: DNS takeover traces left by a previous hard kill are
        // restored at startup (never silently). RecoverIfStale reads the Windows trace file
        // (%APPDATA%\LaneFlow\dns-override.json) — WindowsDnsOverride-specific semantics (not
        // on the IDnsOverride interface, so fake injections need not implement it).
        if (SingBoxRunner.Dns is WindowsDnsOverride winDns)
        {
            var (found, recoverMsg) = winDns.RecoverIfStale();
            if (found)
            {
                TxtStatusMsg.Text = recoverMsg;
                TxtStatusMsg.Foreground = recoverMsg.Contains("Failed", StringComparison.Ordinal) ? Brushes.Red : Brushes.Orange;
            }
            else if (sweepMsg is not null)
            {
                TxtStatusMsg.Text = sweepMsg;
                TxtStatusMsg.Foreground = Brushes.Orange;
            }
        }
        else if (sweepMsg is not null)
        {
            TxtStatusMsg.Text = sweepMsg;
            TxtStatusMsg.Foreground = Brushes.Orange;
        }

        RefreshStatus();

        // Render fingerprint check (input-sensitivity hardening): binding enabled while the
        // on-disk config is a stale render (settings changed without re-binding) → explicit
        // orange notice, never silent (fool-proofing rule 2: config changes take effect).
        // Not overridden by a higher-priority message (recovery/sweep).
        if (_binding.Enabled && !string.IsNullOrEmpty(_binding.AppIdentifier)
            && string.IsNullOrEmpty(TxtStatusMsg.Text))
        {
            var fpNow = Settings.Fingerprint(doc.Outbound, _binding.AppIdentifier);
            var fpDisk = File.Exists(Settings.RenderFingerprintPath)
                ? File.ReadAllText(Settings.RenderFingerprintPath).Trim()
                : null;
            if (fpDisk != fpNow)
            {
                TxtStatusMsg.Text = L10n.T("StaleConfigMsg");
                TxtStatusMsg.Foreground = Brushes.Orange;
            }
        }

        if (corrupted)
        {
            // Corrupted config is never silently reset: explicit red notice that defaults were
            // restored.
            TxtStatusMsg.Text = loadDetail ?? L10n.T("CorruptFallback");
            TxtStatusMsg.Foreground = Brushes.Red;
        }
    }

    /// <summary>
    /// Applies all user-visible strings from the i18n resource set (i18n requirement: no
    /// hardcoded display text in XAML/code; this method is the single re-apply point for the
    /// language switch).
    /// </summary>
    private void ApplyLanguage()
    {
        GrpOutbound.Header = L10n.T("OutboundGroup");
        GrpBind.Header = L10n.T("BindGroup");
        GrpStatus.Header = L10n.T("StatusGroup");
        LblType.Content = L10n.T("TypeLabel");
        LblHost.Content = L10n.T("HostLabel");
        LblPort.Content = L10n.T("PortLabel");
        LblUser.Content = L10n.T("UserLabel");
        LblPass.Content = L10n.T("PassLabel");
        TxtHost.ToolTip = L10n.T("HostTooltip");
        BtnParseHost.Content = L10n.T("ParseHostBtn");
        BtnTestProxy.Content = L10n.T("TestProxyBtn");
        BtnSave.Content = L10n.T("SaveBtn");
        TxtProxyState.Text = string.IsNullOrEmpty(TxtProxyState.Text) || _proxyStateIsDefault
            ? L10n.T("ProxyStateDefault") : TxtProxyState.Text;
        BtnRefresh.Content = L10n.T("RefreshBtn");
        CmbProcess.ToolTip = L10n.T("ProcessTooltip");
        BtnBind.Content = L10n.T("BindBtn");
        BtnUnbind.Content = L10n.T("UnbindBtn");
        if (_bindStateIsDefault) TxtBindState.Text = L10n.T("BindStateDefault");
        TxtFreeNote.Text = L10n.T("FreeEditionNote");
        TxtUdpNote.Text = L10n.T("UdpNote");
        LnkUpgrade.Inlines.Clear();
        LnkUpgrade.Inlines.Add(L10n.T("GetProLink"));
        // Language selector items are self-named constants set once in the constructor
        // (TInvariant); they are intentionally NOT re-applied here — post-selection content
        // edits hit a WPF selection-box refresh quirk.
        RefreshStatus();
    }

    // Whether TxtProxyState / TxtBindState currently hold a "default/neutral" text (safe to
    // re-localize) vs. an operation result (keep as-is across language switches).
    private bool _proxyStateIsDefault = true;
    private bool _bindStateIsDefault = true;

    // Language switch: persist ui_language, apply the culture, re-apply all texts. The refresh
    // below re-derives status lines in the new language. No kernel interaction — UI text only.
    private void CmbLang_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressLangEvents) return;
        if (CmbLang.SelectedItem is not ComboBoxItem item || item.Tag is not string lang) return;
        L10n.Apply(lang);
        ApplyLanguage();
        try
        {
            var doc = Settings.Load();
            doc.UiLanguage = L10n.Normalize(lang);
            Settings.Save(doc, out _);
        }
        catch
        {
            // Language persistence failure never blocks the switch itself.
        }
    }

    // On close: stop sing-box, withdraw the TUN, restore the direct path.
    private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        SingBoxRunner.Stop();
    }

    // ---------- Outbound config: UI <-> model ----------

    private OutboundConfig ReadUiOutbound()
    {
        var typeTag = (CmbType.SelectedItem as ComboBoxItem)?.Tag as string;
        return new OutboundConfig
        {
            Type = typeTag == "Http" ? ProxyType.Http : ProxyType.Socks5,
            // IPv4 only: the free edition's TUN pipeline handles IPv4; the IPv4/IPv6 selector
            // was removed as a decorative control (packaging review). The persisted
            // settings.json "ip_version" field is kept for deserialization compatibility but is
            // no longer written or consumed by the UI (orphan field, documented).
            IpVersion = IpProtocol.IPv4,
            Host = TxtHost.Text.Trim(),
            Port = int.TryParse(TxtPort.Text.Trim(), out var p) ? p : 0,
            // Credentials stored as plaintext in settings.json per spec (see README capability
            // boundary statement).
            Username = string.IsNullOrWhiteSpace(TxtUser.Text) ? null : TxtUser.Text.Trim(),
            Password = string.IsNullOrEmpty(TxtPass.Password) ? null : TxtPass.Password
        };
    }

    private void WriteUiFromConfig(OutboundConfig cfg)
    {
        SelectComboTag(CmbType, cfg.Type == ProxyType.Http ? "Http" : "Socks5");
        TxtHost.Text = cfg.Host;
        TxtPort.Text = cfg.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        TxtUser.Text = cfg.Username ?? string.Empty;
        TxtPass.Password = cfg.Password ?? string.Empty;
    }

    private static void SelectComboTag(ComboBox box, string tag, bool languageMode = false)
    {
        // Two explicit matching modes (see ComboTagMatcher): strict Ordinal for the
        // type/protocol dropdowns, normalization for the language selector only. Collapsing
        // both into one normalized matcher was a real regression — the type/protocol tags all
        // normalized to the same value and the first item always won.
        var tags = new List<string?>();
        foreach (var item in box.Items)
            tags.Add((item as ComboBoxItem)?.Tag as string);
        var idx = ComboTagMatcher.SelectIndex(tags, tag, languageMode);
        if (idx >= 0) box.SelectedIndex = idx;
    }

    // ---------- Host input parsing (supports 192.0.2.1:1080 and socks5://user:pass@host:port) ----------

    private void BtnParseHost_Click(object sender, RoutedEventArgs e)
    {
        if (OutboundConfig.TryParseHostInput(TxtHost.Text, out var r, out var err))
        {
            if (r is not null)
            {
                TxtHost.Text = r.Host;
                TxtPort.Text = r.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
                if (r.Username is not null) TxtUser.Text = r.Username;
                if (r.Password is not null) TxtPass.Password = r.Password;
            }
            TxtStatusMsg.Text = L10n.T("ParsedOk");
        }
        else
        {
            TxtStatusMsg.Text = L10n.F("ParseFailed", err);
        }
    }

    // ---------- Proxy test (one HTTP GET through the proxy echoing the exit IP; negative case:
    // wrong credentials must go red) ----------

    private async void BtnTestProxy_Click(object sender, RoutedEventArgs e)
    {
        var cfg = ReadUiOutbound();
        if (string.IsNullOrEmpty(cfg.Host) || !cfg.IsPortValid)
        {
            TxtProxyState.Text = L10n.T("InvalidHostPort");
            TxtProxyState.Foreground = Brushes.Red;
            _proxyStateIsDefault = false;
            return;
        }

        TxtProxyState.Text = L10n.T("Testing");
        TxtProxyState.Foreground = Brushes.Black;
        var (ok, detail) = await ProbeAsync(cfg);
        if (ok)
        {
            TxtProxyState.Text = L10n.T("ProxyReachable");
            TxtProxyState.Foreground = Brushes.Green;
            TxtStatusMsg.Text = string.IsNullOrEmpty(detail) ? L10n.T("ProxyOkMsg") : L10n.F("ExitIpFmt", detail);
        }
        else
        {
            TxtProxyState.Text = L10n.T("ProxyUnreachable");
            TxtProxyState.Foreground = Brushes.Red;
            TxtStatusMsg.Text = L10n.F("ProxyUnreachMsg", detail);
        }
        _proxyStateIsDefault = false;
        RefreshStatus();
    }

    private static async Task<(bool Ok, string Detail)> ProbeAsync(OutboundConfig cfg)
    {
        try
        {
            var scheme = cfg.Type == ProxyType.Http ? "http" : "socks5";
            var proxy = new WebProxy($"{scheme}://{cfg.Host}:{cfg.Port}");
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
            using var resp = await http.GetAsync("https://api.ipify.org");
            if (resp.IsSuccessStatusCode)
            {
                var body = (await resp.Content.ReadAsStringAsync()).Trim();
                return (true, body);
            }
            return (false, "HTTP " + resp.StatusCode);
        }
        catch (Exception ex)
        {
            // Wrong credentials / unreachable proxy / handshake failure → uniformly "unreachable" (red).
            return (false, ex.GetType().Name);
        }
    }

    // ---------- Save config (with credential-pair validation) ----------

    private async void BtnSave_Click(object sender, RoutedEventArgs e)
    {
        var cfg = ReadUiOutbound();
        var doc = new SettingsDocument { Outbound = cfg, Binding = _binding, UiLanguage = L10n.Normalize((CmbLang.SelectedItem as ComboBoxItem)?.Tag as string ?? "en") };

        if (!Settings.Save(doc, out var err))
        {
            TxtStatusMsg.Text = L10n.F("SaveFailed", err);
            return;
        }

        // Config changes take effect: when forwarding is active, kill → rewrite → restart the
        // kernel (fail-closed disclosure rule).
        if (_binding.Enabled && !string.IsNullOrEmpty(_binding.AppIdentifier)
            && cfg.IsPortValid && !string.IsNullOrEmpty(cfg.Host))
        {
            var appExe = ToExeName(_binding.AppIdentifier);
            TxtStatusMsg.Text = L10n.T("SavedRestarting");
            var (ok, msg) = await Task.Run(() => SingBoxRunner.Start(cfg, appExe));
            _lastRunning = ok;
            TxtStatusMsg.Text = ok
                ? L10n.F("SavedRestarted", Settings.SettingsPath)
                : L10n.F("SavedRestartFailed", msg);
            RefreshStatus();
            return;
        }

        TxtStatusMsg.Text = L10n.F("SavedOk", Settings.SettingsPath);
        RefreshStatus();
    }

    // ---------- Process binding panel ----------

    private void BtnRefresh_Click(object sender, RoutedEventArgs e) => RefreshProcessList();

    private void RefreshProcessList()
    {
        var procs = ProcessCatalog.Enumerate();
        CmbProcess.ItemsSource = procs;
        if (procs.Count > 0) CmbProcess.SelectedIndex = 0;
        TxtDupWarn.Visibility = Visibility.Collapsed;
    }

    private async void BtnBind_Click(object sender, RoutedEventArgs e)
    {
        if (CmbProcess.SelectedValue is not string name || string.IsNullOrEmpty(name))
        {
            TxtBindState.Text = L10n.T("SelectProcessFirst");
            _bindStateIsDefault = false;
            return;
        }

        // Reset the previous binding's red/green coloring to prevent color bleed across ops.
        TxtBindState.Foreground = Brushes.Black;

        var (_, warning) = ProcessCatalog.DetectDuplicateByName(name);
        if (warning is not null)
        {
            TxtDupWarn.Text = warning;
            TxtDupWarn.Visibility = Visibility.Visible;
            TxtBindState.Text = L10n.T("MultiInstanceState");
            _bindStateIsDefault = false;
            RefreshStatus();
            return;
        }
        TxtDupWarn.Visibility = Visibility.Collapsed;

        // Bind = persist the outbound config + set binding (enabled) + start sing-box split
        // tunneling.
        var cfg = ReadUiOutbound();
        var doc = new SettingsDocument
        {
            Outbound = cfg,
            Binding = new AppBinding { AppIdentifier = name, Enabled = true },
            UiLanguage = L10n.Normalize((CmbLang.SelectedItem as ComboBoxItem)?.Tag as string ?? "en")
        };
        if (!Settings.Save(doc, out var err))
        {
            TxtStatusMsg.Text = L10n.F("SaveFailedNoEnable", err);
            return;
        }
        _binding = doc.Binding;

        var appExe = ToExeName(name);
        // Start does synchronous DNS resolution + file IO; run on a background thread to keep
        // the UI responsive.
        TxtStatusMsg.Text = L10n.T("StartingKernel");
        var (ok, msg) = await Task.Run(() => SingBoxRunner.Start(cfg, appExe));
        _lastRunning = ok;
        if (!ok)
        {
            TxtBindState.Text = L10n.T("EnableFailed");
            _bindStateIsDefault = false;
            TxtStatusMsg.Text = msg;
            RefreshStatus();
            return;
        }

        TxtBindState.Text = L10n.F("BoundFmt", appExe);
        _bindStateIsDefault = false;
        TxtStatusMsg.Text = msg;
        RefreshStatus();

        // Exit verification (productized, "test connection" style: verify the
        // proxy exit automatically once binding takes effect; failure goes red — never claim
        // "split tunneling available" without proof. Truth boundary: this is a proxy-side
        // check (probe → proxy → exit echo; route_exclude_address keeps the proxy host out of
        // the TUN, so this path shares the network path of lane→proxy). The full
        // "bound process → TUN → lane → proxy → echo" loop is a real-machine item
        // (documented real-machine checks V2/D1/D2) and is NOT claimed covered at code level.
        TxtBindState.Text = L10n.F("BoundVerifyingFmt", appExe);
        var (probeOk, probeDetail) = await ProbeAsync(cfg);
        if (probeOk)
        {
            TxtBindState.Text = L10n.F("BoundExitFmt", appExe, probeDetail);
            TxtBindState.Foreground = Brushes.Green;
            TxtStatusMsg.Text = L10n.F("ExitVerifyPassFmt", msg, probeDetail);
        }
        else
        {
            TxtBindState.Text = L10n.F("BoundVerifyFailedFmt", appExe);
            TxtBindState.Foreground = Brushes.Red;
            // Bound traffic is forced to lane by the route rules with no direct fallback:
            // proxy unreachable = outbound failure, not a leak.
            TxtStatusMsg.Text = L10n.F("ExitVerifyFailFmt", msg, probeDetail);
        }
        RefreshStatus();
    }

    // Normalizes a binding identifier into an xxx.exe image name (for process_name route
    // matching).
    private static string ToExeName(string name)
    {
        var exe = System.IO.Path.GetFileName(name);
        if (string.IsNullOrEmpty(exe)) exe = name;
        if (!exe.EndsWith(".exe", System.StringComparison.OrdinalIgnoreCase))
            exe += ".exe";
        return exe;
    }

    private void BtnUnbind_Click(object sender, RoutedEventArgs e)
    {
        TxtBindState.Foreground = Brushes.Black;
        SingBoxRunner.Stop();
        _binding = new AppBinding { AppIdentifier = _binding.AppIdentifier, Enabled = false };
        var doc = new SettingsDocument
        {
            Outbound = ReadUiOutbound(),
            Binding = _binding,
            UiLanguage = L10n.Normalize((CmbLang.SelectedItem as ComboBoxItem)?.Tag as string ?? "en")
        };
        if (!Settings.Save(doc, out var err))
        {
            TxtStatusMsg.Text = L10n.F("SaveFailed", err);
            return;
        }
        TxtBindState.Text = string.IsNullOrEmpty(_binding.AppIdentifier)
            ? L10n.T("BindStateDefault")
            : L10n.F("DisabledFmt", System.IO.Path.GetFileName(_binding.AppIdentifier));
        _bindStateIsDefault = string.IsNullOrEmpty(_binding.AppIdentifier);
        TxtStatusMsg.Text = L10n.T("StoppedMsg");
        RefreshStatus();
    }

    // ---------- Status panel (fail-closed + UDP/QUIC wording) ----------

    private void RefreshStatus()
    {
        var cfg = ReadUiOutbound();
        TxtStatusOutbound.Text = L10n.F("StatusOutboundFmt", $"{cfg.Type} / {cfg.Host}:{cfg.Port}");
        TxtStatusBind.Text = L10n.F("StatusBindFmt", _binding.Enabled && !string.IsNullOrEmpty(_binding.AppIdentifier)
            ? L10n.F("BindEnabledFmt", System.IO.Path.GetFileName(_binding.AppIdentifier))
            : L10n.T("BindNotEnabled"));

        // v2 DNS takeover state cross-read against kernel liveness — takeover + kernel running
        // = green; trace present but kernel exited = sudden-death restore failure
        // (fail-closed direction, red; never claim "takeover active").
        if (SingBoxRunner.Dns.IsActive)
        {
            if (SingBoxRunner.IsRunning)
            {
                TxtStatusDns.Text = L10n.F("StatusDnsFmt", L10n.T("DnsTakeoverActive"));
                TxtStatusDns.Foreground = Brushes.Green;
            }
            else
            {
                TxtStatusDns.Text = L10n.F("StatusDnsFmt", L10n.T("DnsTakeoverStale"));
                TxtStatusDns.Foreground = Brushes.Red;
            }
        }
        else
        {
            TxtStatusDns.Text = L10n.F("StatusDnsFmt", L10n.T("DnsOriginal"));
            TxtStatusDns.Foreground = Brushes.Black;
        }

        if (_binding.Enabled && !string.IsNullOrEmpty(_binding.AppIdentifier))
        {
            if (!SingBoxRunner.IsRunning)
            {
                // fail-closed: forwarding claims enabled but the kernel is not running →
                // forwarding NOT enabled, never claim "splitting active". Note (fail-closed rule):
                // kernel not running ≠ traffic blocked — traffic follows the system default
                // path (possibly direct, exposing the real exit); the wording must not promise
                // "blocked".
                TxtStatusConn.Text = L10n.F("StatusConnFmt", L10n.T("ConnKernelDown"));
                TxtStatusConn.Foreground = Brushes.Red;
            }
            else
            {
                TxtStatusConn.Text = L10n.F("StatusConnFmt", L10n.T("ConnRunning"));
                TxtStatusConn.Foreground = Brushes.Green;
            }
        }
        else
        {
            TxtStatusConn.Text = L10n.F("StatusConnFmt", L10n.T("ConnNotEnabled"));
            TxtStatusConn.Foreground = Brushes.Black;
        }
    }

    // ---------- Footer link ----------

    private void LnkUpgrade_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo(ProLink.PurchaseUrl) { UseShellExecute = true });
        }
        catch
        {
            // Link-open failure does not affect the main flow.
        }
    }
}
