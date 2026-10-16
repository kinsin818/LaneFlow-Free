using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace LaneFlow;

/// <summary>
/// DNS takeover trace (persisted to %APPDATA%\LaneFlow\dns-override.json).
/// Presence with Active=true while LaneFlow has exited = leftover from a previous hard kill
/// that never got restored; the next startup restores it via
/// <see cref="WindowsDnsOverride.RecoverIfStale"/> (crash-recovery chain).
/// v3 (proven live): take over **all** interfaces (changing only the base interface
/// misses WLAN etc.; queries then go to the LAN router's DNS, get real IPs, and bypass
/// LaneFlow); target = the TUN /30 peer address 172.19.0.2 (the TUN's own address 172.19.0.1
/// is delivered locally by the kernel stack and RST — queries never enter the TUN).
/// v3.1 (live-machine re-run proof): the interface primary key is **InterfaceIndex**
/// (numeric) rather than InterfaceAlias — non-ASCII alias flow through the C#→PowerShell
/// command line gets corrupted into U+FFFD (PS 5.1 redirected output uses the GBK code page
/// while C# decodes as UTF-8 by default → Set-DnsClientServerAddress cannot find the
/// interface; measured). The alias remains as an informational field in the trace; legacy
/// traces (alias only) still restore by alias (encoding now UTF-8 on both ends).
/// </summary>
public sealed class DnsState
{
    /// <summary>v3 multi-interface trace (each entry = interface index + original DNS list).</summary>
    [JsonPropertyName("entries")]
    public InterfaceDnsEntry[] Entries { get; set; } = Array.Empty<InterfaceDnsEntry>();

    /// <summary>Legacy single-interface trace field (v2 and earlier; converted into <see cref="Entries"/> on read, never written back).</summary>
    [JsonPropertyName("interface_alias")]
    public string? LegacyInterfaceAlias { get; set; }

    /// <summary>Legacy single-interface original values (v2 and earlier).</summary>
    [JsonPropertyName("original_servers")]
    public string[]? LegacyOriginalServers { get; set; }

    [JsonPropertyName("active")]
    public bool Active { get; set; }

    /// <summary>
    /// Converts the legacy single-interface trace (v2 and earlier) into <see cref="Entries"/>
    /// so the cross-version crash-recovery chain never breaks. Idempotent: no-op when entries
    /// already exist or the legacy fields are absent.
    /// </summary>
    public void NormalizeLegacy()
    {
        if (Entries.Length > 0) return;
        if (string.IsNullOrEmpty(LegacyInterfaceAlias)) return;
        if (LegacyOriginalServers is not { Length: > 0 }) return;
        Entries = new[]
        {
            new InterfaceDnsEntry
            {
                InterfaceAlias = LegacyInterfaceAlias,
                OriginalServers = LegacyOriginalServers
            }
        };
    }
}

/// <summary>Per-interface DNS takeover trace (index primary key + alias info field + original server list).</summary>
public sealed class InterfaceDnsEntry
{
    /// <summary>Interface index (primary key for Set/restore; 0 = legacy trace without index, falls back to alias).</summary>
    [JsonPropertyName("interface_index")]
    public int InterfaceIndex { get; set; }

    /// <summary>Interface alias (informational; legacy traces carry only this field).</summary>
    [JsonPropertyName("interface_alias")]
    public string InterfaceAlias { get; set; } = string.Empty;

    [JsonPropertyName("original_servers")]
    public string[] OriginalServers { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Whether the interface was DHCP-configured at takeover time (fix for the DHCP-solidification
    /// defect; approved 2026-10-16). Restoring a
    /// DHCP-configured interface MUST use ResetServerAddresses to hand it back to DHCP —
    /// writing back the static list would solidify the DHCP dynamic values as static (after a
    /// router/network change the DNS would not follow; real-machine proof: WLAN/Ethernet got
    /// solidified to the router LAN address). Legacy traces lack this field → deserializes as
    /// false → static write-back (old behavior).
    /// </summary>
    [JsonPropertyName("was_dhcp")]
    public bool WasDhcp { get; set; }
}

/// <summary>
/// DNS takeover abstraction (core component of the v3 plan). Temporarily points the DNS of
/// **all** interfaces to the LaneFlow TUN /30 peer address (172.19.0.2) so that every
/// process's resolution queries enter the TUN via the /30 on-link route and are hijacked by
/// sing-box hijack-dns — bypassing the base's fake-IP preemption of the DNS entry point at
/// the root. Design discipline (known-failure-mode checklist):
///   - Reversible: record each interface's original values before takeover and persist them;
///     delete the trace after a successful restore; keep the trace for retry on failure.
///   - Fail-closed: after Set, read back and verify; any interface failing → roll back the
///     whole takeover (restore already-changed interfaces) and report failure.
///   - No silent fallback: probing zero DNS-bearing interfaces = nothing to take over →
///     explicit failure, never guessing interfaces.
///   - Testable behavior: fake implementations injected through this interface verify the
///     state-machine semantics (SelfTest, see FakeDnsOverride).
/// </summary>
public interface IDnsOverride
{
    /// <summary>Whether the system is currently in the takeover state.</summary>
    bool IsActive { get; }

    /// <summary>
    /// Takes over the system DNS to <paramref name="dnsServer"/> (the LaneFlow TUN /30 peer
    /// address, 172.19.0.2). Repeated calls restore first, then take over (idempotent
    /// re-establishment). On failure, no state is changed.
    /// </summary>
    (bool Ok, string Message) Takeover(string dnsServer);

    /// <summary>
    /// Restores the system DNS to the pre-takeover originals. Idempotent: no-op success when
    /// not taken over. On restore failure the trace is kept (file not deleted) and false is
    /// returned for the caller to surface in red.
    /// </summary>
    (bool Ok, string Message) Restore();
}

/// <summary>
/// Windows implementation: via PowerShell Set-DnsClientServerAddress /
/// Get-DnsClientServerAddress (measured path, 2026-10-15: after setting the base
/// interface → 172.19.0.2, nslookup's Server line flips to 172.19.0.2 immediately and queries
/// enter the TUN and get hijacked by sing-box; Windows does not filter non-interface
/// addresses). v3 proof highlights:
///   - Target address = 172.19.0.2 (/30 peer, non-local): taking over to the TUN's own
///     address 172.19.0.1 gets the query delivered locally by the kernel stack and RST
///     (proven live: "the remote host forcibly closed an existing connection").
///   - Takeover scope = all interfaces with IPv4 DNS (excluding LaneFlow itself): changing
///     only the base interface misses WLAN/Ethernet DNS (proven live: queries went to the
///     LAN router's DNS, got real IPs, and bypassed LaneFlow).
///   - Target interface selection = probe-driven (never hardcode the base interface name):
///     wholesale takeover of all interfaces in the current DNS inventory.
///   - Interface primary key = InterfaceIndex (numeric): Chinese aliases crossing the
///     C#→PS command line get corrupted into U+FFFD (live-machine re-run proof); the
///     numeric key eliminates that class of problems at the root; legacy alias-only traces
///     fall back to alias-based restore.
/// </summary>
public sealed class WindowsDnsOverride : IDnsOverride
{
    private readonly object _gate = new();
    private DnsState? _state;
    private readonly string _statePath;

    public WindowsDnsOverride(string? statePath = null)
    {
        _statePath = statePath ?? Settings.DnsOverridePath;
        LoadStateFromDisk();
    }

    public bool IsActive
    {
        get { lock (_gate) { return _state is { Active: true }; } }
    }

    public (bool Ok, string Message) Takeover(string dnsServer)
    {
        if (string.IsNullOrWhiteSpace(dnsServer))
            return (false, "DNS takeover target address is empty");

        lock (_gate)
        {
            // Idempotent re-establishment: restore first if already taken over; stacking
            // takeovers is forbidden (overwritten originals = irreversible). The lock is
            // reentrant: Restore() under the Takeover lock does not deadlock.
            if (_state is { Active: true })
            {
                var (rOk, rMsg) = Restore();
                if (!rOk)
                    return (false, "Failed to restore the previous takeover state; refusing to stack takeovers: " + rMsg);
            }

            // 1) Enumerate all interfaces with IPv4 DNS (excluding LaneFlow itself).
            //    v3: changing only the single interface "holding the system DNS" misses the
            //    others (proven live: WLAN DNS bypassed LaneFlow).
            if (!TryProbeInterfaces(out var interfaces, out var probeErr))
                return (false, "Failed to probe the interface DNS inventory: " + probeErr);
            if (interfaces.Length == 0)
                return (false, "No interfaces with IPv4 DNS found; nothing to take over");

            // 1.5) Leftover self-heal (F-run [1] proof): an interface whose current DNS equals
            //      the takeover target with no active trace = a leftover takeover state from a
            //      previous run (the trace was deleted by a "successful restore" but the value
            //      is a polluted-chain artifact, or only some interfaces were restored).
            //      Never silently guess the original values — this address is LaneFlow-TUN-
            //      specific, so ResetServerAddresses (back to DHCP/auto defaults) is the
            //      owner's correct repair; the post-reset dynamic values are recorded as this
            //      takeover's originals in the trace.
            var repaired = new List<string>();
            foreach (var (idx, alias, servers, _) in interfaces)
            {
                if (!servers.Contains(dnsServer, StringComparer.Ordinal)) continue;
                var (rExit, rOut, rErr) = RunPs(
                    $"Set-DnsClientServerAddress -InterfaceIndex {idx} -ResetServerAddresses -ErrorAction Stop | Out-Null; " +
                    $"(Get-DnsClientServerAddress -InterfaceIndex {idx} -AddressFamily IPv4).ServerAddresses -join ','");
                if (rExit != 0)
                    return (false, $"Detected a leftover takeover state ({Describe(idx, alias)} = {dnsServer}) and the automatic reset failed: {Trim(rErr, rOut)} (fail-closed)");
                repaired.Add(Describe(idx, alias));
            }
            if (repaired.Count > 0)
            {
                // The reset changed the probe snapshot; re-enumerate to get the true originals.
                if (!TryProbeInterfaces(out interfaces, out probeErr))
                    return (false, "Failed to re-probe after resetting leftovers: " + probeErr);
                if (interfaces.Length == 0)
                    return (false, "No interfaces with IPv4 DNS after resetting leftovers; nothing to take over");
            }

            // 2) Set each interface + read-back verification; any failure rolls back the whole
            //    takeover (restoring already-changed interfaces) and reports failure
            //    (fail-closed). Fault-injection hook (acceptance testing, off by default):
            //    LANEFLOW_FAULT_DNS_READBACK=1 simulates "Set succeeded but read-back
            //    mismatch", driving the real Set/Rollback chain through fail-closed
            //    (behavior-first assertion rule).
            var faultReadback = Environment.GetEnvironmentVariable("LANEFLOW_FAULT_DNS_READBACK") == "1";
            var changed = new List<InterfaceDnsEntry>();
            foreach (var (idx, alias, servers, dhcp) in interfaces)
            {
                var setScript = SetScript(idx, alias, dnsServer);
                if (setScript is null)
                {
                    Rollback(changed);
                    return (false, $"Refused to set interface DNS: unsafe interface identity ({Describe(idx, alias)}) (rolled back {changed.Count} changed interface(s))");
                }
                var (exit, stdout, stderr) = RunPs(setScript);
                if (exit != 0)
                {
                    Rollback(changed);
                    return (false, $"Failed to set interface DNS ({Describe(idx, alias)}): {Trim(stderr, stdout)} (rolled back {changed.Count} changed interface(s))");
                }
                // Set succeeded = this interface's DNS was already modified: record it into
                // `changed` BEFORE verifying the read-back. A read-back mismatch must go
                // through Rollback(changed) to cover this interface too — omitting the record
                // would leak a changed interface in takeover state while the product claims
                // "not taken over" (proven by live fault injection).
                changed.Add(new InterfaceDnsEntry { InterfaceIndex = idx, InterfaceAlias = alias, OriginalServers = servers, WasDhcp = dhcp });
                var readback = stdout.Trim();
                if (faultReadback)
                {
                    faultReadback = false;
                    readback = "<fault-injected: readback mismatch>";
                }
                // Read-back verification = **exact membership** in the parsed address array
                // (exact-match hardening): a substring Contains can be fooled by partial
                // inclusion (expected x.x.x.1, actually got x.x.x.10 would also pass).
                if (!ParseIpList(readback).Contains(dnsServer, StringComparer.Ordinal))
                {
                    Rollback(changed);
                    return (false, $"DNS takeover read-back verification failed ({Describe(idx, alias)}): expected {dnsServer}, got {readback} (fail-closed, rolled back)");
                }
            }

            // 3) Persist the trace (recovery basis for hard-kill leftovers).
            _state = new DnsState
            {
                Entries = changed.ToArray(),
                Active = true
            };
            if (!TrySaveState())
            {
                Rollback(changed);
                _state = null;
                return (false, "DNS taken over but persisting the trace failed; rolled back");
            }
            var summary = string.Join("; ", changed.Select(e => $"{Describe(e.InterfaceIndex, e.InterfaceAlias)} {string.Join(",", e.OriginalServers)} → {dnsServer}"));
            var repairNote = repaired.Count > 0 ? $"; auto-reset {repaired.Count} leftover takeover interface(s) ({string.Join(",", repaired)})" : string.Empty;
            return (true, $"DNS takeover applied to {changed.Count} interface(s): {summary}{repairNote}");
        }
    }

    /// <summary>
    /// Rolls back already-changed interfaces (mid-takeover failure path). Restore semantics
    /// identical to Restore (same as fool-proofing rule 3): DHCP-configured interfaces (or
    /// empty originals) go through ResetServerAddresses back to DHCP; only static-type
    /// interfaces get their original values written back. Single-point failures are ignored
    /// (best effort; no trace on disk, so nothing resurfacing at next startup).
    /// </summary>
    private void Rollback(List<InterfaceDnsEntry> changed)
    {
        foreach (var e in changed)
        {
            try
            {
                var script = BuildRestoreScript(e);
                if (script is null)
                {
                    // Static-empty safety rule: static-type with no original values = cannot be safely restored;
                    // the rollback path performs no write either (without a persisted trace
                    // this interface is not in any trace anyway; defensive skip here).
                    continue;
                }
                RunPs(script);
            }
            catch
            {
                // Rollback is best effort; no trace on disk, so nothing resurfacing at next startup.
            }
        }
    }

    /// <summary>
    /// Builds the restore script for a trace entry (shared by Restore/Rollback; single source
    /// of truth for semantics). Three branches (static-empty safety fix: the old two-branch logic
    /// executed Reset for a Dhcp=Disabled static interface, wiping it to "no DNS" with no
    /// DHCP self-healing — TAP/VPN-style interfaces lose resolution entirely until
    /// reconnected):
    ///   ① was_dhcp → ResetServerAddresses (hand back to DHCP);
    ///   ② static-type with original values → write the original list back;
    ///   ③ static-type with empty originals → return null = cannot be safely restored; the
    ///      caller MUST count it as a failure and ask for manual verification (never Reset,
    ///      never silently skip — DHCP-handback semantics and static-empty safety together).
    /// Both executable modes share the read-back format (comma-joined IP list).
    /// </summary>
    private static string? BuildRestoreScript(InterfaceDnsEntry e)
    {
        // Trace-file values are spliced into an elevated PowerShell command line, and the trace
        // file lives in %APPDATA% (user-writable). Values are whitelisted here — anything that
        // cannot be proven safe fails closed as "cannot be safely restored" (never executed).
        // Note: InterfaceIndex > 0 is the primary (and current) key; the alias branch exists
        // only for legacy traces.
        var target = e.InterfaceIndex > 0
            ? $"-InterfaceIndex {e.InterfaceIndex}"
            : IsSafeInterfaceAlias(e.InterfaceAlias) ? $"-InterfaceAlias '{Esc(e.InterfaceAlias)}'"
            : null;
        if (target is null)
            return null; // unsafe/absent identity: refuse to build any command for this entry

        if (e.WasDhcp)
        {
            return $"Set-DnsClientServerAddress {target} -ResetServerAddresses -ErrorAction Stop | Out-Null; " +
                   $"(Get-DnsClientServerAddress {target} -AddressFamily IPv4).ServerAddresses -join ','";
        }
        if (e.OriginalServers.Length == 0)
        {
            return null; // Static-type with no originals: no DHCP to fall back to, no originals to write back — any automatic write is harmful.
        }
        // Every original server must be a strict IP literal (canonical round-trip: the parsed
        // address must re-serialize to the exact same string). A tampered trace entry (e.g.
        // containing quotes or command text) is rejected, never executed.
        foreach (var s in e.OriginalServers)
        {
            if (!IsValidIpLiteral(s)) return null;
        }
        var list = string.Join("','", Array.ConvertAll(e.OriginalServers, Esc));
        return $"Set-DnsClientServerAddress {target} -ServerAddresses ('{list}') -ErrorAction Stop | Out-Null; " +
               $"(Get-DnsClientServerAddress {target} -AddressFamily IPv4).ServerAddresses -join ','";
    }

    /// <summary>
    /// Command-injection characters for PowerShell -Command context (packaging review
    /// hardening): quotes, sub-expression and variable operators, statement separators,
    /// redirections, and line breaks. Legitimate Windows adapter aliases (including localized
    /// names) never contain these; a trace-file value that does must never reach a command line.
    /// </summary>
    private static readonly char[] ForbiddenAliasChars =
        { '"', '\'', '`', '$', ';', '|', '&', '<', '>', '\r', '\n', '\t', '{', '}' };

    private static bool IsSafeInterfaceAlias(string? alias)
        => !string.IsNullOrWhiteSpace(alias) && alias.Length <= 64 && alias.IndexOfAny(ForbiddenAliasChars) < 0;

    /// <summary>Strict IP literal: parses as IPv4/IPv6 and round-trips to the exact same string.</summary>
    private static bool IsValidIpLiteral(string? s)
    {
        if (string.IsNullOrWhiteSpace(s) || s.Length > 45) return false;
        if (!System.Net.IPAddress.TryParse(s, out var addr)) return false;
        return addr.ToString() == s;
    }

    public (bool Ok, string Message) Restore()
    {
        lock (_gate) { return RestoreLocked(); }

        (bool, string) RestoreLocked()
        {
            if (_state is not { Active: true })
                return (true, "No active takeover; nothing to restore");

            var entries = _state.Entries;
            if (entries.Length == 0)
            {
                // No entries (abnormal state): clear the trace; no interfaces to restore.
                TryDeleteState();
                _state = null;
                return (true, "Takeover trace contained no interface records; trace cleared");
            }

            // Restore one by one + read-back verification; the trace is deleted only when all
            // succeed. Partial failures (including Reset interfaces and unrestorable static
            // interfaces) keep the trace for the next retry — never a silent skip.
            var failures = new List<string>();
            foreach (var e in entries)
            {
                var original = e.OriginalServers;
                var script = BuildRestoreScript(e);
                if (script is null)
                {
                    // Static-empty safety rule: static-type interface with no original values — no
                    // DHCP to fall back to, no originals to write back, and any automatic
                    // write is harmful (Reset would wipe a TAP/VPN-style interface to no DNS
                    // with no self-healing). Count it as a failure for manual verification,
                    // keep the trace, never be silent.
                    failures.Add($"{Describe(e.InterfaceIndex, e.InterfaceAlias)}: cannot be restored automatically (static-type interface with no recorded original values; no safe automatic action) — please verify this interface's DNS manually (e.g. reconnect the corresponding VPN/dial-up)");
                    continue;
                }
                var resetMode = e.WasDhcp;
                var (exit, stdout, stderr) = RunPs(script);
                if (exit != 0)
                {
                    failures.Add($"{Describe(e.InterfaceIndex, e.InterfaceAlias)}: {Trim(stderr, stdout)}");
                    continue;
                }
                // Read-back verification = exact array semantics (exact-match hardening;
                // substring Contains is not acceptable):
                //   static-type: every original value must appear **exactly** in the read-back array;
                //   reset-type: the takeover target address must NOT appear in the read-back
                //   (an empty array = DHCP not renewed yet, still counts as restored).
                var parsed = ParseIpList(stdout.Trim());
                var verified = resetMode
                    ? !parsed.Contains(ConfigRenderer.DnsTakeoverAddress, StringComparer.Ordinal)
                    : original.All(o => parsed.Contains(o, StringComparer.Ordinal));
                if (!verified)
                {
                    failures.Add(resetMode
                        ? $"{Describe(e.InterfaceIndex, e.InterfaceAlias)}: restore verification failed (read-back still contains the takeover target {ConfigRenderer.DnsTakeoverAddress})"
                        : $"{Describe(e.InterfaceIndex, e.InterfaceAlias)}: read-back mismatch (expected {string.Join(",", original)}, got {stdout.Trim()})");
                }
            }

            if (failures.Count > 0)
                return (false, $"Failed to restore {failures.Count}/{entries.Length} interface(s): {string.Join(" | ", failures)} (trace retained for retry)");

            // Delete the trace only after a fully successful restore.
            TryDeleteState();
            _state = null;
            return (true, $"DNS restored on {entries.Length} interface(s)");
        }
    }

    /// <summary>Read-back text (comma-joined IP list) → exact address array (empties trimmed away).</summary>
    public static string[] ParseIpList(string readback) =>
        readback.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(s => s.Length > 0).ToArray();

    /// <summary>
    /// Startup self-check: takeover traces left by a previous hard kill (Active=true while the
    /// process is gone). Called by the UI on startup; leftovers are restored and reported.
    /// </summary>
    public (bool Found, string Message) RecoverIfStale()
    {
        DnsState? snap;
        bool hasTrace;
        lock (_gate)
        {
            hasTrace = _state is { Active: true };
            snap = hasTrace ? _state : null;
        }

        // Ghost interface sweep (hardening sweep): run once regardless of takeover
        // traces — orphan keys may come from earlier sessions whose trace file was deleted or
        // whose interface vanished mid-run (real-machine proof: {a6820235-…}).
        // The sweep only touches keys whose "GUID has vanished + NameServer exactly equals
        // this product's takeover target"; safety boundary in the method doc.
        var ghost = SweepGhostInterfaces();

        if (!hasTrace)
        {
            // No takeover trace: ghost-key removals must be reported explicitly (never
            // silent); no hits / scan failure stays quiet (hygiene sweep, not a security
            // property; must not block startup; details in SweepGhostInterfaces).
            return ghost.Removed > 0
                ? (true, "No unrestored takeover traces; " + ghost.Detail)
                : (false, string.Empty);
        }

        var (ok, msg) = Restore();
        var summary = snap!.Entries.Length > 0
            ? string.Join("; ", snap.Entries.Select(e => Describe(e.InterfaceIndex, e.InterfaceAlias) + " → " + string.Join(",", e.OriginalServers)))
            : (snap.LegacyInterfaceAlias ?? "?") + " → " + string.Join(",", snap.LegacyOriginalServers ?? Array.Empty<string>());
        var result = ok
            ? $"Detected an unrestored DNS takeover trace from the previous run; auto-restored ({summary})"
            : "Detected an unrestored DNS takeover trace from the previous run; AUTO-RESTORE FAILED: " + msg;
        if (ghost.Removed > 0)
            result += "; " + ghost.Detail;
        return (true, result);
    }

    /// <summary>
    /// SelfTest injection point: replaces the ghost-sweep path's PS executor (null = real
    /// execution). Only affects SweepGhostInterfaces, not the takeover/restore main chain.
    /// internal + InternalsVisibleTo(LaneFlow.SelfTest) — injection hooks are not exposed to
    /// arbitrary in-process code (production tamperability closed).
    /// </summary>
    internal static Func<string, (int Exit, string Out, string Err)>? GhostPsRunnerOverride;

    /// <summary>
    /// Ghost interface sweep (hardening sweep; approved 2026-10-16):
    /// under Tcpip\Parameters\Interfaces, registry keys whose interface has vanished (GUID not
    /// in the live adapter set) but whose NameServer still equals this product's takeover
    /// target. The existing restore path works by InterfaceIndex and cannot clean such keys
    /// once the interface is gone (real-machine proof). Safety boundary (anti-deletion):
    ///   1. Only delete keys whose NameServer **exactly equals** DnsTakeoverAddress — that is
    ///      this product's own fingerprint; any other product's/user's static DNS is untouched;
    ///   2. Only delete keys whose GUID is no longer in the live adapter set (live interfaces
    ///      restore via the existing Restore chain);
    ///   3. Read-back verify after deletion; unverified keys are honestly counted as failures,
    ///      never claiming clean silently.
    /// Decision logic lives in C# (SelfTest-testable); the PS side only does read-only
    /// enumeration and controlled value deletion. Requires admin (guaranteed by the app's
    /// requireAdministrator manifest).
    /// </summary>
    public (int Removed, string Detail) SweepGhostInterfaces()
    {
        // Read-only enumeration: all Tcpip interface keys { guid, ns, live }.
        var enumerate =
            "$live=@(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object { $_.InterfaceGuid }); " +
            "$base='Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces'; " +
            "$keys=@(Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object { " +
            "$ns=[string](Get-ItemProperty -Path $_.PSPath -Name NameServer -ErrorAction SilentlyContinue).NameServer; " +
            "[pscustomobject]@{ guid=$_.PSChildName; ns=$ns; live=($live -contains $_.PSChildName) } }); " +
            "[pscustomobject]@{ keys=$keys } | ConvertTo-Json -Compress -Depth 3";
        var (exit, stdout, stderr) = RunGhostPs(enumerate);
        if (exit != 0)
            return (0, "Ghost interface scan failed: " + Trim(stderr, stdout));

        List<string> ghosts;
        try
        {
            using var doc = JsonDocument.Parse(stdout);
            ghosts = new List<string>();
            foreach (var k in doc.RootElement.GetProperty("keys").EnumerateArray())
            {
                var guid = k.GetProperty("guid").GetString() ?? string.Empty;
                var ns = k.GetProperty("ns").GetString() ?? string.Empty;
                var live = k.GetProperty("live").GetBoolean();
                if (!live && guid.Length > 0 && string.Equals(ns, ConfigRenderer.DnsTakeoverAddress, StringComparison.Ordinal))
                    ghosts.Add(guid);
            }
        }
        catch (Exception ex)
        {
            // Never silently fall back on parse failure (fool-proofing rule 9): return the
            // failure honestly; the caller decides whether to surface it.
            return (0, "Failed to parse ghost interface scan output: " + ex.Message);
        }
        if (ghosts.Count == 0)
            return (0, string.Empty);

        // Controlled deletion: per key Remove-ItemProperty + read-back verification (after
        // deletion NameServer must be empty).
        var arr = string.Join(",", ghosts.Select(g => "'" + Esc(g) + "'"));
        var remove =
            "$base='Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces'; " +
            "$done=@(); foreach($g in @(" + arr + ")) { " +
            "$p=Join-Path $base $g; " +
            "try { Remove-ItemProperty -Path $p -Name NameServer -ErrorAction Stop; " +
            "$ns=[string](Get-ItemProperty -Path $p -Name NameServer -ErrorAction SilentlyContinue).NameServer; " +
            "if([string]::IsNullOrEmpty($ns)){ $done+=$g } } catch {} }; " +
            "[pscustomobject]@{ removed=$done } | ConvertTo-Json -Compress";
        var (rExit, rOut, rErr) = RunGhostPs(remove);
        if (rExit != 0)
            return (0, "Failed to delete ghost interface leftover keys: " + Trim(rErr, rOut));
        try
        {
            using var rdoc = JsonDocument.Parse(rOut);
            var removedList = new List<string>();
            foreach (var g in rdoc.RootElement.GetProperty("removed").EnumerateArray())
                removedList.Add(g.GetString() ?? string.Empty);
            var shown = string.Join(", ", removedList.Select(g => g.Length > 13 ? g[..13] + "…" : g));
            var detail = $"Ghost interface sweep cleared {removedList.Count}/{ghosts.Count} leftover DNS key(s) ({shown})";
            if (removedList.Count < ghosts.Count)
                detail += "; remaining keys not verified deleted; will rescan on next startup";
            return (removedList.Count, detail);
        }
        catch (Exception ex)
        {
            return (0, "Failed to parse ghost interface deletion result: " + ex.Message);
        }
    }

    private static (int Exit, string Out, string Err) RunGhostPs(string script) =>
        GhostPsRunnerOverride is not null ? GhostPsRunnerOverride(script) : RunPs(script);

    // ---------- internals ----------

    private void LoadStateFromDisk()
    {
        try
        {
            if (!File.Exists(_statePath)) return;
            var st = JsonSerializer.Deserialize<DnsState>(File.ReadAllText(_statePath));
            if (st is not { Active: true })
                return;
            // Legacy single-interface trace (v2 and earlier) converted into entries so the
            // cross-version crash-recovery chain never breaks.
            st.NormalizeLegacy();
            if (st.Entries.Length > 0)
                _state = st;
        }
        catch
        {
            // Corrupted trace file: treat as no trace (never claim safety silently; the UI
            // layer re-runs the takeover flow whenever forwarding is enabled anyway).
        }
    }

    private bool TrySaveState()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
            File.WriteAllText(_statePath, JsonSerializer.Serialize(_state, new JsonSerializerOptions { WriteIndented = true }));
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void TryDeleteState()
    {
        try { if (File.Exists(_statePath)) File.Delete(_statePath); }
        catch { /* deletion failure does not negate a successful restore; next startup re-checks */ }
    }

    /// <summary>
    /// Probe-driven enumeration: enumerates all interfaces with IPv4 DNS (excluding LaneFlow
    /// itself) and records each interface's IPv4 DHCP state (restore semantics: DHCP-type
    /// hands back to DHCP, static-type writes originals back — anti-solidification).
    /// Output JSON: { "interfaces": [ {"idx":12,"alias":"...","servers":[...],"dhcp":0|1} ] }.
    /// Since v3 there is no need to reverse-infer "the interface holding the system DNS" via
    /// nslookup — wholesale takeover (proven live: changing only the base interface misses
    /// WLAN/Ethernet DNS; queries went to the LAN router's DNS and bypassed LaneFlow).
    /// </summary>
    private static bool TryProbeInterfaces(out (int Idx, string Alias, string[] Servers, bool Dhcp)[] interfaces, out string error)
    {
        interfaces = Array.Empty<(int, string, string[], bool)>();
        error = string.Empty;
        var script =
            "$ifs=@(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 -and $_.InterfaceAlias -ne 'LaneFlow' } | ForEach-Object { $d=(Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp; [pscustomobject]@{ idx=[int]$_.InterfaceIndex; alias=[string]$_.InterfaceAlias; servers=@($_.ServerAddresses); dhcp=[int]($d -eq 'Enabled') } }); " +
            "[pscustomobject]@{ interfaces=$ifs } | ConvertTo-Json -Compress -Depth 4";
        var (exit, stdout, stderr) = RunPs(script);
        if (exit != 0)
        {
            error = Trim(stderr, stdout);
            return false;
        }
        try
        {
            using var doc = JsonDocument.Parse(stdout);
            var root = doc.RootElement;
            var list = new List<(int, string, string[], bool)>();
            if (root.TryGetProperty("interfaces", out var ifs) && ifs.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in ifs.EnumerateArray())
                {
                    var idx = el.TryGetProperty("idx", out var i) ? i.GetInt32() : 0;
                    var alias = el.TryGetProperty("alias", out var a) ? a.GetString() ?? string.Empty : string.Empty;
                    var dhcp = el.TryGetProperty("dhcp", out var dd) && dd.ValueKind == JsonValueKind.Number && dd.GetInt32() == 1;
                    var servers = Array.Empty<string>();
                    if (el.TryGetProperty("servers", out var sv))
                    {
                        var tmp = new List<string>();
                        // PS 5.1 ConvertTo-Json may collapse a single-element array into a
                        // scalar: accept both shapes.
                        if (sv.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var s in sv.EnumerateArray())
                            {
                                var v = s.GetString();
                                if (!string.IsNullOrEmpty(v)) tmp.Add(v);
                            }
                        }
                        else if (sv.ValueKind == JsonValueKind.String)
                        {
                            var v = sv.GetString();
                            if (!string.IsNullOrEmpty(v)) tmp.Add(v);
                        }
                        servers = tmp.ToArray();
                    }
                    if (servers.Length > 0)
                        list.Add((idx, alias, servers, dhcp));
                }
            }
            interfaces = list.ToArray();
            return true;
        }
        catch (Exception ex)
        {
            error = "Failed to parse probe output: " + ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Builds the Set-DnsClientServerAddress script: index when available (numeric, immune to
    /// encoding corruption), otherwise falls back to the alias (legacy traces). A read-back
    /// (Get + join) is appended for caller verification. Returns null when the identity cannot
    /// be proven safe (alias containing command-injection characters) — callers must treat that
    /// as a failed Set and roll back (fail-closed, never execute).
    /// </summary>
    private static string? SetScript(int idx, string alias, string servers, bool multi = false)
    {
        var target = idx > 0 ? $"-InterfaceIndex {idx}" : IsSafeInterfaceAlias(alias) ? $"-InterfaceAlias '{Esc(alias)}'" : null;
        if (target is null) return null;
        var serverArg = multi ? $"('{servers}')" : $"'{servers}'";
        return $"Set-DnsClientServerAddress {target} -ServerAddresses {serverArg} -ErrorAction Stop | Out-Null; " +
               $"(Get-DnsClientServerAddress {target} -AddressFamily IPv4).ServerAddresses -join ','";
    }

    private static string Describe(int idx, string alias)
        => idx > 0 ? $"if#{idx}({alias})" : alias;

    /// <summary>
    /// PowerShell runner (DNS management).
    /// v3.1 encoding fix (live-machine re-run proof): PS 5.1 redirected stdout/stderr
    /// defaults to the system OEM code page (Chinese UI = GBK) while C# decodes UTF-8 by
    /// default → non-ASCII content corrupts into U+FFFD and feeding it back into a command
    /// line breaks Set ("parameter not found"). Fixed on both ends:
    ///   script prefix [Console]::OutputEncoding=UTF8 (PS write side);
    ///   StandardOutputEncoding/StandardErrorEncoding=UTF8 (C# read side).
    /// </summary>
    private static (int Exit, string Out, string Err) RunPs(string script, int timeoutMs = 15000)
    {
        // SelfTest injection point (same pattern as GhostPsRunnerOverride): replaces the PS
        // executor to verify the C# decision semantics of the takeover/restore chain
        // (null = real execution).
        if (PsRunnerOverride is not null)
            return PsRunnerOverride(script);
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + PsUtf8Prefix + script + "\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            using var p = Process.Start(psi);
            if (p is null) return (-1, string.Empty, "failed to start powershell");
            // Both pipes must be drained concurrently: sequential synchronous ReadToEnd calls
            // deadlock when stderr fills its buffer while stdout is still being read (and the
            // timeout only runs after both reads return — i.e. never). Async reads pump both
            // buffers; the timeout then actually fires.
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

    /// <summary>PS write-side UTF-8 prefix (idempotent and harmless; failure does not affect the main script).</summary>
    private const string PsUtf8Prefix = "try{[Console]::OutputEncoding=[Text.Encoding]::UTF8}catch{}; ";

    /// <summary>
    /// SelfTest injection point: replaces the takeover/restore main chain's PS executor
    /// (null = real execution). internal + InternalsVisibleTo(LaneFlow.SelfTest) — injection
    /// hooks are not exposed to arbitrary in-process code (production
    /// tamperability closed).
    /// </summary>
    internal static Func<string, (int Exit, string Out, string Err)>? PsRunnerOverride;

    private static string Esc(string s) => s.Replace("'", "''");

    private static string Trim(string err, string out0)
    {
        var t = string.IsNullOrEmpty(err) ? out0 : err;
        t = t.Trim();
        return t.Length > 200 ? t.Substring(0, 200) + "…" : t;
    }
}

/// <summary>
/// In-memory fake for SelfTest: verifies takeover/restore state-machine semantics (recording
/// originals, idempotency, read-back-failure handling) without touching the real system.
/// Behavior assertions take precedence over wording.
/// </summary>
public sealed class FakeDnsOverride : IDnsOverride
{
    public bool IsActive { get; private set; }
    public string? Server { get; private set; }
    public string[]? Original { get; private set; }
    public int TakeoverCalls { get; private set; }
    public int RestoreCalls { get; private set; }

    /// <summary>Simulates a Set failure (fail-closed path test).</summary>
    public bool FailNextSet { get; set; }

    /// <summary>Simulates a read-back mismatch (verifies fail-closed: changed-but-unverified must be rejected).</summary>
    public bool FailNextReadback { get; set; }

    /// <summary>Simulates a restore failure (verifies: when restoring a previous takeover state fails, stacking is refused to protect the originals).</summary>
    public bool FailNextRestore { get; set; }

    public (bool Ok, string Message) Takeover(string dnsServer)
    {
        TakeoverCalls++;
        if (IsActive)
        {
            var (rOk, rMsg) = Restore();
            if (!rOk) return (false, "Failed to restore the previous takeover state; refusing to stack takeovers: " + rMsg);
        }
        if (FailNextSet) { FailNextSet = false; return (false, "simulated Set failure"); }
        if (FailNextReadback)
        {
            FailNextReadback = false;
            // Simulates the real semantics (real-machine fault injection proof): Set took
            // effect (this interface was changed) while the read-back mismatches — a correct
            // implementation must roll this interface back internally before reporting
            // failure; skipping the rollback leaks the DNS in takeover state. Originals use a
            // documentation-reserved range (TEST-NET-2) placeholder, representing no real
            // environment.
            Original = new[] { "198.51.100.53" };
            Server = dnsServer;
            IsActive = true;
            Restore();
            return (false, "simulated read-back verification failure (fail-closed, changed interfaces rolled back)");
        }
        Original = new[] { "198.51.100.53" };
        Server = dnsServer;
        IsActive = true;
        return (true, "fake takeover " + dnsServer);
    }

    public (bool Ok, string Message) Restore()
    {
        RestoreCalls++;
        if (!IsActive) return (true, "No active takeover; nothing to restore");
        if (FailNextRestore) { FailNextRestore = false; return (false, "simulated restore failure"); }
        IsActive = false;
        Server = null;
        Original = null;
        return (true, "fake restored");
    }
}
