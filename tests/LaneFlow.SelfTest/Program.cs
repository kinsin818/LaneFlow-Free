using System.Diagnostics;
using System.Text.Json;
using LaneFlow;

// Invariant behavior assertions (design invariant: "invariants into CI"). Any failed assertion
// → non-zero exit code, CI goes red.
// Coverage: account-pair consistency / port 1-65535 / socks5h rejection /
//           config rendering DNS rules / fakeip skeleton + global hijack +
//           process-agnostic DNS rules + disjoint pools (final form) /
//           DNS takeover state machine (record originals / idempotent / fail-closed / no overlay) /
//           loop-prevention resolution / startup protocol (TUN-ready gate / zombie adapter
//           retry / orphan sweep, live-machine verified) / ghost interface sweep /
//           restore semantics (DHCP/static-empty branches) / config fingerprint (input sensitivity).
int failures = 0;

void Check(string name, bool cond)
{
    Console.WriteLine((cond ? "PASS " : "FAIL ") + name);
    if (!cond) failures++;
}

// ---- Account-pair consistency invariant: username/password keys exist ⇔ both non-empty ----
Check("account both-null consistent", Settings.AccountKeysConsistent(new OutboundConfig()));
Check("account both-filled consistent", Settings.AccountKeysConsistent(new OutboundConfig { Username = "u", Password = "p" }));
Check("account user-only inconsistent", !Settings.AccountKeysConsistent(new OutboundConfig { Username = "u" }));
Check("account pass-only inconsistent", !Settings.AccountKeysConsistent(new OutboundConfig { Password = "p" }));
Check("account pair half rejected", !Settings.ValidateAccountPair(new OutboundConfig { Username = "u" }, out var e1) && !string.IsNullOrEmpty(e1));

// ---- Port 1-65535: 0 is no longer valid ----
Check("port 0 invalid", !new OutboundConfig { Port = 0 }.IsPortValid);
Check("port 1 valid", new OutboundConfig { Port = 1 }.IsPortValid);
Check("port 65535 valid", new OutboundConfig { Port = 65535 }.IsPortValid);
Check("port 65536 invalid", !new OutboundConfig { Port = 65536 }.IsPortValid);

// ---- Host input parsing: socks5h rejected + host:port + socks5 URL field split ----
Check("socks5h rejected", !OutboundConfig.TryParseHostInput("socks5h://1.2.3.4:1080", out _, out var e2) && !string.IsNullOrEmpty(e2));
Check("host:port parse ok",
    OutboundConfig.TryParseHostInput("1.2.3.4:1080", out var r1, out _) && r1!.Host == "1.2.3.4" && r1.Port == 1080);
Check("socks5 url split",
    OutboundConfig.TryParseHostInput("socks5://user:pass@host.example:1080", out var r2, out _)
    && r2!.Username == "user" && r2!.Password == "pass" && r2.Host == "host.example" && r2.Port == 1080);

// ---- Rendering skeleton (fixed skeleton) ----
var ob = new OutboundConfig { Type = ProxyType.Socks5, Host = "1.2.3.4", Port = 1080 };

// Unbound state: must match the historical rendering exactly (zero regression) — single local
// DNS; 53→direct as first rule; no fakeip/hijack/resolver declaration.
var jsonUnbound = ConfigRenderer.Render(ob, null);
using var docU = JsonDocument.Parse(jsonUnbound);
var rulesU = docU.RootElement.GetProperty("route").GetProperty("rules");
var firstU = rulesU[0];
Check("unbound: dns-direct rule is first",
    firstU.GetProperty("action").GetString() == "route"
    && firstU.GetProperty("outbound").GetString() == "direct"
    && firstU.GetProperty("port").ValueKind == JsonValueKind.Number
    && firstU.GetProperty("port").GetInt32() == 53);
Check("unbound: no fakeip/hijack/resolver (legacy zero-regression)",
    !jsonUnbound.Contains("fakeip", StringComparison.OrdinalIgnoreCase)
    && !jsonUnbound.Contains("hijack", StringComparison.OrdinalIgnoreCase)
    && !jsonUnbound.Contains("default_domain_resolver", StringComparison.Ordinal));
var serversU = docU.RootElement.GetProperty("dns").GetProperty("servers");
Check("unbound: single local dns server",
    serversU.GetArrayLength() == 1 && serversU[0].GetProperty("type").GetString() == "local");

// Log level diagnostic switch: default error (zero regression); LANEFLOW_LOG_LEVEL
// explicit override; invalid values fall back to error. Background: sing-box "found process path"
// attribution lines are INFO level and never emitted at error level — a prior run once diffed "no
// attribution line" at error level against "attribution line" at trace level (invalid diff).
Check("log: default level is error (zero regression)",
    docU.RootElement.GetProperty("log").GetProperty("level").GetString() == "error");
Environment.SetEnvironmentVariable("LANEFLOW_LOG_LEVEL", "debug");
var jsonDbg = ConfigRenderer.Render(ob, null);
Check("log: LANEFLOW_LOG_LEVEL=debug override works",
    JsonDocument.Parse(jsonDbg).RootElement.GetProperty("log").GetProperty("level").GetString() == "debug");
Environment.SetEnvironmentVariable("LANEFLOW_LOG_LEVEL", "bogus");
var jsonBadLevel = ConfigRenderer.Render(ob, null);
Check("log: invalid LANEFLOW_LOG_LEVEL falls back to error",
    JsonDocument.Parse(jsonBadLevel).RootElement.GetProperty("log").GetProperty("level").GetString() == "error");
Environment.SetEnvironmentVariable("LANEFLOW_LOG_LEVEL", null);

// Bound state: v3 full fakeip split + global DNS takeover (all interfaces) + split routes
// emptied + manual pool route.
var json = ConfigRenderer.Render(ob, "chrome.exe");
using var doc = JsonDocument.Parse(json);
var root = doc.RootElement;

var rules = root.GetProperty("route").GetProperty("rules");
// v3: the DNS entry point is taken over globally by WindowsDnsOverride (**all** interfaces'
// DNS → 172.19.0.2 → into TUN; overriding only the base adapter misses WLAN DNS (proven
// live on a real machine), so route rule[0] = unconditional hijack-dns(53).
Check("bound: rule[0] hijack-dns unconditional port 53",
    rules[0].GetProperty("action").GetString() == "hijack-dns"
    && !rules[0].TryGetProperty("process_name", out _)
    && rules[0].GetProperty("port").GetInt32() == 53);
// Legacy form abolished: bound state must NOT contain a 53→direct rule (otherwise bound-process
// DNS is sent direct and fakeip never engages).
Check("bound: no dns-direct rule (legacy form abolished)",
    !rules.EnumerateArray().Any(r =>
        r.GetProperty("action").GetString() == "route"
        && r.GetProperty("outbound").GetString() == "direct"
        && r.TryGetProperty("port", out var p53) && p53.ValueKind == JsonValueKind.Number && p53.GetInt32() == 53));
Check("bound: exactly 3 route rules (hijack/reject-udp/lane)",
    rules.GetArrayLength() == 3);
int IdxOfRejectUdp = -1, IdxOfLane = -1, IdxOfHijack = -1;
for (int i = 0; i < rules.GetArrayLength(); i++)
{
    var act = rules[i].GetProperty("action").GetString();
    if (act == "reject" && rules[i].GetProperty("network").GetString() == "udp") IdxOfRejectUdp = i;
    if (act == "route" && rules[i].GetProperty("outbound").GetString() == "lane") IdxOfLane = i;
    if (act == "hijack-dns") IdxOfHijack = i;
}
Check("bound: hijack-dns precedes reject-udp (sequence invariant)",
    IdxOfHijack >= 0 && IdxOfRejectUdp >= 0 && IdxOfHijack < IdxOfRejectUdp);
Check("bound: reject-udp precedes lane route (sequence invariant)",
    IdxOfRejectUdp >= 0 && IdxOfLane >= 0 && IdxOfRejectUdp < IdxOfLane);

// DNS skeleton (v3): fakeip + real-dns (DoH 223.5.5.5 via base, guarding against base-side
// fake-IP / UDP53 pollution, not depending on lane);
// **all** A/HTTPS queries → fakeip (not per-process: dnscache attribution is svchost, verified
// live that per-process dns.rules are dead rules);
// remaining queries (non-A/HTTPS) fall to final=real-dns; bootstrap-dns form abolished.
var servers = root.GetProperty("dns").GetProperty("servers");
Check("bound: exactly 2 dns servers (fakeip + real-dns)",
    servers.GetArrayLength() == 2);
var fakeip = servers.EnumerateArray().First(s => s.GetProperty("tag").GetString() == "fakeip-dns");
Check("bound: fakeip server present with disjoint range",
    fakeip.GetProperty("type").GetString() == "fakeip"
    && fakeip.GetProperty("inet4_range").GetString() == ConfigRenderer.FakeIpRange);
Check("bound: fakeip range disjoint from base fakeip range (198.18.0.0/15)",
    !CidrOverlap(ConfigRenderer.FakeIpRange, ConfigRenderer.BaseFakeIpRange));
var realDns = servers.EnumerateArray().First(s => s.GetProperty("tag").GetString() == "real-dns");
// Verified live: explicit detour to the "empty" direct outbound → sing-box 1.14.3
// runtime FATAL (detour.go:69-75 IsEmpty(); static check does not catch it). The new DoH server
// default dialer is equivalent to empty direct, hence no detour.
// Verified live: DoH upstream is Ali 223.5.5.5 (reachable and stable via the base).
Check("bound: real-dns is DoH 223.5.5.5 with NO detour (live: explicit detour to empty direct = runtime FATAL)",
    realDns.GetProperty("type").GetString() == "https"
    && realDns.GetProperty("server").GetString() == "223.5.5.5"
    && !realDns.TryGetProperty("detour", out _));
Check("bound: no bootstrap-dns (legacy form abolished)",
    !json.Contains("bootstrap-dns", StringComparison.Ordinal));
var dnsRules = root.GetProperty("dns").GetProperty("rules");
// v3 verified correction: dns.rules are NOT per-process (Windows DNS queries are sent on behalf
// of apps by dnscache(svchost), process attribution can never be the bound app — verified
// live, curl.exe appears zero times), so all A/HTTPS → fakeip; splitting relies solely
// on connection-level process_name (route rules).
Check("bound: dns rule is process-agnostic A/HTTPS → fakeip (live: svchost attribution makes per-process DNS rules dead)",
    dnsRules.GetArrayLength() == 1
    && !dnsRules[0].TryGetProperty("process_name", out _)
    && dnsRules[0].GetProperty("query_type").EnumerateArray().Select(q => q.GetString()).SequenceEqual(new[] { "A", "HTTPS" })
    && dnsRules[0].GetProperty("server").GetString() == "fakeip-dns");
Check("bound: dns final is real-dns",
    root.GetProperty("dns").GetProperty("final").GetString() == "real-dns");
Check("bound: route default_domain_resolver is real-dns (1.12+ migration, else FATAL)",
    root.GetProperty("route").GetProperty("default_domain_resolver").GetString() == "real-dns");

var lane = root.GetProperty("outbounds").EnumerateArray().First(o => o.GetProperty("tag").GetString() == "lane");
Check("render server_port is int",
    lane.GetProperty("server_port").ValueKind == JsonValueKind.Number && lane.GetProperty("server_port").GetInt32() == 1080);
Check("render socks version 5", lane.GetProperty("version").GetString() == "5");
Check("bound: lane domain_resolver is real-dns (v3; proxy-host bootstrap via direct DoH)",
    lane.GetProperty("domain_resolver").GetString() == "real-dns");
// v3: lane does not bind an interface and does not exclude the proxy host (verified live:/n// the proxy server is reachable only via the base; direct dialing over the physical
// interface is transparently intercepted).
Check("bound: lane has NO bind_interface / NO inet4_bind_address (live: proxy reachable only via base)",
    !lane.TryGetProperty("bind_interface", out _)
    && !lane.TryGetProperty("inet4_bind_address", out _));

Check("render no stack", !json.Contains("stack", StringComparison.Ordinal));
Check("render interface LaneFlow",
    root.GetProperty("inbounds")[0].GetProperty("interface_name").GetString() == "LaneFlow");
Check("render address /30 in-chain (v3 DNS entry-point prerequisite)",
    root.GetProperty("inbounds")[0].GetProperty("address")[0].GetString() == "172.19.0.1/30");
// v3: auto_route=true (RegisterMyInterface, isLocalSource dependency) + route_exclude 0.0.0.0/0
// (split routes emptied).
// Verified live: auto_route=false made TCP connection process-attribution lookup skipped
// and process_name rules dead; split routes (0.0.0.0/4…128.0.0.0/1) were the root cause of
// the direct-dial self-loop (698 sing-box.exe attribution re-entries).
Check("bound: auto_route=true (RegisterMyInterface; isLocalSource gate for process attribution)",
    root.GetProperty("inbounds")[0].GetProperty("auto_route").GetBoolean() == true);
Check("bound: strict_route=false (WFP block-dns/ipv6 would hijack base-stack DNS)",
    root.GetProperty("inbounds")[0].GetProperty("strict_route").GetBoolean() == false);
Check("bound: route_exclude_address=[0.0.0.0/0] (split routes emptied; pool route added by app)",
    root.GetProperty("inbounds")[0].GetProperty("route_exclude_address")[0].GetString() == "0.0.0.0/0");
Check("bound: no per-host exclude /32 in tun (live: exclusion replaced by full split removal)",
    !json.Contains("1.2.3.4/32", StringComparison.Ordinal));
Check("bound: dns takeover address is /30 peer 172.19.0.2 (live: tun self addr gets kernel RST)",
    ConfigRenderer.DnsTakeoverAddress == "172.19.0.2");

// ---- Loop-prevention resolution: literal → resolved=true; empty host → resolved=false, no silence ----
// Note: the v3 rendering path no longer calls this (with split routes fully emptied the proxy
// host is reachable via the base); method retained for diagnostics/reuse.
Check("resolve literal ok", ConfigRenderer.ResolveExcludeAddress("1.2.3.4", out var ok1) == "1.2.3.4/32" && ok1);
Check("resolve empty not resolved", ConfigRenderer.ResolveExcludeAddress(string.Empty, out var ok2) is null && !ok2);

// ---- DNS takeover state machine (v3; via IDnsOverride fake injection, real system untouched) ----
// Semantic invariants: record originals / idempotent recompose / Set failure stays inactive /
//                     readback mismatch stays inactive / prior failed restore refuses overlay
//                     takeover / restore idempotent. Behavior assertions over message text (locked wording).
// v3 production target address = 172.19.0.2 (/30 peer; 172.19.0.1 is the TUN's own address and
// gets kernel RST, verified live).
var dnsFake = new FakeDnsOverride();
Check("dns: initial not active", !dnsFake.IsActive);
var (dk1, _) = dnsFake.Takeover("172.19.0.2");
Check("dns: takeover activates and records original",
    dk1 && dnsFake.IsActive && dnsFake.Server == "172.19.0.2"
    && dnsFake.Original is { Length: 1 } && dnsFake.Original[0] == "198.51.100.53");
var (dk2, _) = dnsFake.Takeover("172.19.0.2");
Check("dns: re-takeover restores then re-takes (idempotent recompose, no overlay)",
    dk2 && dnsFake.IsActive && dnsFake.Server == "172.19.0.2"
    && dnsFake.RestoreCalls == 1 && dnsFake.Original is { Length: 1 });

var dnsSetFail = new FakeDnsOverride { FailNextSet = true };
var (dk3, _) = dnsSetFail.Takeover("172.19.0.2");
Check("dns: set failure → stays inactive (fail-closed)", !dk3 && !dnsSetFail.IsActive);

var dnsRbFail = new FakeDnsOverride { FailNextReadback = true };
var (dk4, _) = dnsRbFail.Takeover("172.19.0.2");
// Contract (live-machine fault injection verified): when readback mismatch reports failure,
// interfaces already Set must be rolled back internally —
// IsActive=false (no leaked takeover state); in fake semantics Set has happened, so RestoreCalls
// must be >= 1.
Check("dns: readback mismatch → fail-closed AND rollback applied (no leaked takeover state)",
    !dk4 && !dnsRbFail.IsActive && dnsRbFail.RestoreCalls >= 1);

var dnsOverlay = new FakeDnsOverride();
dnsOverlay.Takeover("172.19.0.2");
dnsOverlay.FailNextRestore = true;
var (dk5, dk5Msg) = dnsOverlay.Takeover("172.19.0.2");
Check("dns: overlay takeover rejected when prior restore fails (original preserved)",
    !dk5 && dnsOverlay.IsActive && dnsOverlay.Server == "172.19.0.2"
    && dk5Msg.Contains("refusing to stack takeovers", StringComparison.Ordinal));

var (dk6, _) = dnsOverlay.Restore();
var (dk7, _) = dnsOverlay.Restore();
Check("dns: restore clears active state", dk6 && !dnsOverlay.IsActive);
Check("dns: restore idempotent no-op when inactive", dk7 && dnsOverlay.RestoreCalls == 3);

// ---- Startup protocol (live-machine verified): TUN-ready gate + zombie adapter retry + orphan sweep ----
// Semantic invariants: zero takeover before ready; exactly one takeover after ready;
//                     pre-ready exit → one retry → still failing = fail-closed;
//                     orphan sweep executes only the injected own PIDs. Behavior assertions
//                     over message text (locked wording).
// Real Start is driven through the injection seams: fake launcher starts harmless real
// processes (cmd exit=exits instantly / ping=stays alive),
// fake ready probe controls readiness timing, fake DNS records takeover calls. Real
// sing-box/system DNS untouched.
var savedDns = SingBoxRunner.Dns;
var savedExe = SingBoxRunner.SingBoxExeOverride;
var savedTimeout = SingBoxRunner.ReadyTimeoutMs;
var savedPoll = SingBoxRunner.ReadyPollMs;
var savedRoute = SingBoxRunner.AddFakeIpRouteOverride;
SingBoxRunner.SingBoxExeOverride = typeof(object).Assembly.Location; // any existing file; launcher is fake, never really executed
SingBoxRunner.ReadyTimeoutMs = 800;
SingBoxRunner.ReadyPollMs = 50;
SingBoxRunner.AddFakeIpRouteOverride = () => (true, "fake pool route"); // CI has no LaneFlow TUN; real netsh would fail
var startOb = new OutboundConfig { Type = ProxyType.Socks5, Host = "1.2.3.4", Port = 1080 };
var startDns = new FakeDnsOverride();
SingBoxRunner.Dns = startDns;
var launched = new List<Process>();
try
{
    // Scenario 1: never ready (probe always false + process alive) → timeout failure, zero DNS
    // takeover (takeover forbidden before the ready gate).
    SingBoxRunner.ReadyProbeOverride = () => false;
    SingBoxRunner.LauncherOverride = psi =>
    {
        Process? p = Process.Start(new ProcessStartInfo("cmd", "/c ping -n 20 127.0.0.1")
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true });
        if (p is not null) launched.Add(p);
        return p;
    };
    var (s1, m1) = SingBoxRunner.Start(startOb, "curl.exe");
    Check("start: never-ready → fail-closed, DNS NOT taken over", !s1 && startDns.TakeoverCalls == 0 && !startDns.IsActive);
    Check("start: never-ready → kernel not left running", !SingBoxRunner.IsRunning);

    // Scenario 2: ready → success (probe always true) → success with exactly one takeover
    // (ordering iron rule behaviorized).
    startDns = new FakeDnsOverride();
    SingBoxRunner.Dns = startDns;
    SingBoxRunner.ReadyProbeOverride = () => true;
    var (s2, m2) = SingBoxRunner.Start(startOb, "curl.exe");
    Check("start: ready → success with exactly one takeover", s2 && startDns.TakeoverCalls == 1 && startDns.IsActive);
    Check("start: takeover only after ready (message reflects gate)", m2.Contains("TUN ready", StringComparison.Ordinal));
    SingBoxRunner.Stop();

    // Scenario 3: zombie adapter retry — first attempt exits instantly (FATAL form), second
    // attempt becomes ready → automatic retry succeeds.
    startDns = new FakeDnsOverride();
    SingBoxRunner.Dns = startDns;
    var launchN = 0;
    // Probe gated by attempt: first attempt never ready (let it die instantly), second attempt
    // ready — deterministic reproduction of the retry path.
    SingBoxRunner.ReadyProbeOverride = () => launchN >= 2;
    SingBoxRunner.LauncherOverride = psi =>
    {
        launchN++;
        Process? p = launchN == 1
            ? Process.Start(new ProcessStartInfo("cmd", "/c exit")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })
            : Process.Start(new ProcessStartInfo("cmd", "/c ping -n 20 127.0.0.1")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true });
        if (p is not null) launched.Add(p);
        return p;
    };
    var (s3, m3) = SingBoxRunner.Start(startOb, "curl.exe");
    Check("start: pre-ready death → retry once → success", s3 && launchN == 2 && startDns.TakeoverCalls == 1);
    Check("start: retry surfaced in message (truthful, not silent)", m3.Contains("attempt 2", StringComparison.Ordinal));
    SingBoxRunner.Stop();

    // Scenario 4: both attempts exit instantly (zombie not self-healed) → still failing after
    // retry, fail-closed with zero takeover.
    startDns = new FakeDnsOverride();
    SingBoxRunner.Dns = startDns;
    launchN = 0;
    SingBoxRunner.ReadyProbeOverride = () => false;
    SingBoxRunner.LauncherOverride = psi =>
    {
        launchN++;
        Process? p = Process.Start(new ProcessStartInfo("cmd", "/c exit")
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true });
        if (p is not null) launched.Add(p);
        return p;
    };
    var (s4, m4) = SingBoxRunner.Start(startOb, "curl.exe");
    Check("start: double pre-ready death → fail-closed after retry", !s4 && launchN == 2 && startDns.TakeoverCalls == 0);
    Check("start: fail-closed message carries kernel log tail (log tail kept for triage)", m4.Contains("blocked", StringComparison.Ordinal));
    Check("start: fail-closed leaves no running kernel", !SingBoxRunner.IsRunning);

    // Scenario 5: orphan sweep contract — executes only the injected own PIDs (fake finder/killer
    // record keeping).
    var killedPids = new List<int>();
    SingBoxRunner.OrphanFinderOverride = () => new List<int> { 111, 222 };
    SingBoxRunner.OrphanKillerOverride = pid => killedPids.Add(pid);
    var sweptN = SingBoxRunner.SweepOrphanKernels();
    Check("sweep: kills exactly injected own-kernel pids",
        sweptN == 2 && killedPids.Count == 2 && killedPids.Contains(111) && killedPids.Contains(222));
    // The real finder must execute zero kills and throw zero exceptions in an environment
    // without sing-box (CI) (path matching logic must not blow up).
    // Remove the fake finder first, otherwise it keeps returning injected PIDs (the object under
    // test would silently become the fake).
    SingBoxRunner.OrphanFinderOverride = null;
    Check("sweep: real finder no-op when no orphans (CI safe)", SingBoxRunner.SweepOrphanKernels() == 0);
    // Scenario 6: fakeip pool route add failure → kernel stopped, fail-closed, zero DNS takeover
    // (the V1 false-green/true-red defense line).
    startDns = new FakeDnsOverride();
    SingBoxRunner.Dns = startDns;
    SingBoxRunner.AddFakeIpRouteOverride = () => (false, "simulated netsh add failure");
    SingBoxRunner.ReadyProbeOverride = () => true;
    SingBoxRunner.LauncherOverride = psi =>
    {
        Process? p = Process.Start(new ProcessStartInfo("cmd", "/c ping -n 20 127.0.0.1")
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true });
        if (p is not null) launched.Add(p);
        return p;
    };
    var (s5, m5) = SingBoxRunner.Start(startOb, "curl.exe");
    Check("start: pool route fail → fail-closed, DNS NOT taken over",
        !s5 && startDns.TakeoverCalls == 0 && !startDns.IsActive && !SingBoxRunner.IsRunning);
    Check("start: pool route fail message carries cause", m5.Contains("fakeip pool route", StringComparison.Ordinal));
    SingBoxRunner.AddFakeIpRouteOverride = () => (true, "fake pool route");
}
finally
{
    foreach (var p in launched)
    {
        try { if (!p.HasExited) p.Kill(); } catch { /* best effort */ }
    }
    SingBoxRunner.Stop();
    SingBoxRunner.Dns = savedDns;
    SingBoxRunner.SingBoxExeOverride = savedExe;
    SingBoxRunner.LauncherOverride = null;
    SingBoxRunner.ReadyProbeOverride = null;
    SingBoxRunner.OrphanFinderOverride = null;
    SingBoxRunner.OrphanKillerOverride = null;
    SingBoxRunner.AddFakeIpRouteOverride = savedRoute;
    SingBoxRunner.ReadyTimeoutMs = savedTimeout;
    SingBoxRunner.ReadyPollMs = savedPoll;
}

// Trace-file contract (field names stable on disk; RecoverIfStale depends on them).
// v3 multi-interface trace: entries[] (interface_alias/original_servers) + active.
var stTrace = new DnsState
{
    Entries = new[]
    {
        new InterfaceDnsEntry { InterfaceIndex = 44, InterfaceAlias = "BaseTunAdapter", OriginalServers = new[] { "198.51.100.53" } },
        new InterfaceDnsEntry { InterfaceIndex = 12, InterfaceAlias = "WLAN", OriginalServers = new[] { "192.0.2.1" } }
    },
    Active = true
};
var stJson = JsonSerializer.Serialize(stTrace);
Check("dns: trace json contract (entries/interface_index/interface_alias/original_servers/active)",
    stJson.Contains("entries", StringComparison.Ordinal)
    && stJson.Contains("interface_index", StringComparison.Ordinal)
    && stJson.Contains("interface_alias", StringComparison.Ordinal)
    && stJson.Contains("original_servers", StringComparison.Ordinal)
    && stJson.Contains("\"active\":true", StringComparison.Ordinal));
// Legacy single-interface trace (v2 and earlier) deserializes and converts into entries; the
// cross-version crash-recovery chain stays intact.
var legacyJson = "{\"interface_alias\":\"BaseTunAdapter\",\"original_servers\":[\"198.51.100.53\"],\"active\":true}";
var stLegacy = JsonSerializer.Deserialize<DnsState>(legacyJson);
stLegacy!.NormalizeLegacy();
Check("dns: legacy trace converts into entries (cross-version recovery)",
    stLegacy is { Active: true }
    && stLegacy.Entries.Length == 1
    && stLegacy.Entries[0].InterfaceAlias == "BaseTunAdapter"
    && stLegacy.Entries[0].OriginalServers[0] == "198.51.100.53");

// ---- Ghost interface sweep (hardening sweep; via GhostPsRunnerOverride injection) ----
// Invariants: only keys with "GUID vanished AND NameServer exactly equal to the takeover target"
// are removed; live interfaces / other DNS untouched;
// deletions counted truthfully by read-back; scan failures reported honestly (foolproofing 9:
// resolution failures are never silently swallowed).
{
    var ghostGuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"; // vanished interface (carrying takeover-target residue)
    var liveGuid = "11111111-2222-3333-4444-555555555555";  // existing interface (carrying takeover target = live interface being taken over)
    var otherNs = "198.51.100.53";                          // vanished interface but DNS is not this product's fingerprint
    bool removeIssued = false, touchedGhost = false, touchedLive = false, touchedOther = false;
    WindowsDnsOverride.GhostPsRunnerOverride = script =>
    {
        if (script.Contains("Get-ChildItem"))
        {
            var json = "{\"keys\":[" +
                $"{{\"guid\":\"{ghostGuid}\",\"ns\":\"{ConfigRenderer.DnsTakeoverAddress}\",\"live\":false}}," +
                $"{{\"guid\":\"{liveGuid}\",\"ns\":\"{ConfigRenderer.DnsTakeoverAddress}\",\"live\":true}}," +
                $"{{\"guid\":\"66666666-7777-8888-9999-000000000000\",\"ns\":\"{otherNs}\",\"live\":false}}]}}";
            return (0, json, string.Empty);
        }
        if (script.Contains("Remove-ItemProperty"))
        {
            removeIssued = true;
            touchedGhost = script.Contains(ghostGuid, StringComparison.Ordinal);
            touchedLive = script.Contains(liveGuid, StringComparison.Ordinal);
            touchedOther = script.Contains("66666666", StringComparison.Ordinal);
            return (0, $"{{\"removed\":[\"{ghostGuid}\"]}}", string.Empty);
        }
        return (1, string.Empty, "unexpected script");
    };
    var ghostWin = new WindowsDnsOverride(Path.Combine(Path.GetTempPath(), "laneflow-selftest-ghost-nofile.json"));
    var (gRemoved, gDetail) = ghostWin.SweepGhostInterfaces();
    Check("ghost: only dead-guid + takeover-target keys removed (live/other-ns untouched)",
        removeIssued && touchedGhost && !touchedLive && !touchedOther
        && gRemoved == 1 && gDetail.Contains("1/1", StringComparison.Ordinal));

    WindowsDnsOverride.GhostPsRunnerOverride = _ => (-1, string.Empty, "ps boom");
    var (fRemoved, fDetail) = ghostWin.SweepGhostInterfaces();
    Check("ghost: scan failure reported honestly (no silent clean claim)",
        fRemoved == 0 && fDetail.Contains("Ghost interface scan failed", StringComparison.Ordinal));
    WindowsDnsOverride.GhostPsRunnerOverride = null;
}

// ---- Restore semantics triple (restore-semantics hardening; via PsRunnerOverride injection) ----
// Invariants: ① takeover readback = exact item containment (172.19.0.21 cannot cheat)
//             ② DHCP interface / empty originals restore via Reset
//             ③ static interface readback exact per-item (192.0.2.10 cannot cheat)
//             ④ empty originals no longer silently skipped, counted into the result
//             ⑤ trace contains was_dhcp.
{
    var statePath = Path.Combine(Path.GetTempPath(), "laneflow-selftest-restore-state.json");
    var win = new WindowsDnsOverride(statePath);
    bool resetUsed = false;
    WindowsDnsOverride.PsRunnerOverride = script =>
    {
        // Branch-order note: the Reset script also contains the "Set-DnsClientServerAddress"
        // text, so it must be tested first.
        if (script.Contains("-ResetServerAddresses"))
        {
            resetUsed = true;
            return (0, string.Empty, string.Empty); // After Reset DHCP has not renewed → empty readback = restoration success
        }
        if (script.Contains("interfaces=$ifs"))
            return (0, "{\"interfaces\":[" +
                "{\"idx\":21,\"alias\":\"WLAN\",\"servers\":[\"192.0.2.1\"],\"dhcp\":1}," +
                "{\"idx\":44,\"alias\":\"TUNX\",\"servers\":[\"198.51.100.53\"],\"dhcp\":0}]}", string.Empty);
        if (script.Contains("Set-DnsClientServerAddress"))
        {
            if (script.Contains("-ServerAddresses '172.19.0.2'"))
                return (0, "172.19.0.2", string.Empty);
            if (script.Contains("-ServerAddresses ('198.51.100.53')"))
                return (0, "198.51.100.53", string.Empty);
            return (1, string.Empty, "unexpected set");
        }
        return (1, string.Empty, "unexpected script");
    };

    var (tOk, _) = win.Takeover(ConfigRenderer.DnsTakeoverAddress);
    // The trace file is serialized with WriteIndented (space after colon); assertions compare
    // with spaces stripped.
    var traceJson = File.Exists(statePath) ? File.ReadAllText(statePath).Replace(" ", "") : "<none>";
    Check("restore-sem: takeover ok and trace records was_dhcp per interface",
        tOk && traceJson.Contains("\"was_dhcp\":true", StringComparison.Ordinal)
        && traceJson.Contains("\"was_dhcp\":false", StringComparison.Ordinal));

    resetUsed = false;
    var (rOk, rMsg) = win.Restore();
    Check("restore-sem: dhcp interface restored via ResetServerAddresses (not static write-back)",
        rOk && resetUsed && !File.Exists(statePath));

    // Negative sample (restore side): original 192.0.2.1, readback 192.0.2.10 → must fail and
    // the trace retained.
    WindowsDnsOverride.PsRunnerOverride = script =>
    {
        if (script.Contains("-ResetServerAddresses"))
        {
            resetUsed = true;
            return (0, string.Empty, string.Empty);
        }
        if (script.Contains("interfaces=$ifs"))
            return (0, "{\"interfaces\":[{\"idx\":21,\"alias\":\"WLAN\",\"servers\":[\"192.0.2.1\"],\"dhcp\":0}]}", string.Empty);
        if (script.Contains("-ServerAddresses '172.19.0.2'"))
            return (0, "172.19.0.2", string.Empty);
        return (0, "192.0.2.10", string.Empty); // static restore readback: partial-containment trap value
    };
    var (t2Ok, _) = win.Takeover(ConfigRenderer.DnsTakeoverAddress);
    var (r2Ok, r2Msg) = win.Restore();
    Check("restore-sem: readback substring trap rejected (192.0.2.10 != 192.0.2.1), trace retained",
        t2Ok && !r2Ok && File.Exists(statePath) && r2Msg.Contains("192.0.2.10", StringComparison.Ordinal));

    // Empty-originals branches (static-empty safety semantics):
    //   was_dhcp=true → Reset hands back to DHCP (handback path);
    //   was_dhcp=false (static type) → never write any command, report "cannot be restored
    //   automatically" and count into failures (Reset would wipe TAP/VPN-type static
    //   interfaces to no DNS with no self-healing). Restore uses in-memory _state: fresh
    //   instance per scenario.
    void WriteEmptyOriginalState(bool wasDhcp) =>
        File.WriteAllText(statePath,
            "{\"entries\":[{\"interface_index\":21,\"interface_alias\":\"WLAN\",\"original_servers\":[],\"was_dhcp\":" + (wasDhcp ? "true" : "false") + "}],\"active\":true}");

    WriteEmptyOriginalState(wasDhcp: true);
    resetUsed = false;
    var anyWrite = false;
    WindowsDnsOverride.PsRunnerOverride = script =>
    {
        if (script.Contains("-ResetServerAddresses")) { resetUsed = true; return (0, string.Empty, string.Empty); }
        if (script.Contains("-ServerAddresses")) { anyWrite = true; return (0, string.Empty, string.Empty); }
        return (1, string.Empty, "unexpected");
    };
    var winE1 = new WindowsDnsOverride(statePath);
    var (r3Ok, _) = winE1.Restore();
    var dhcpEmptyResets = resetUsed && r3Ok && !File.Exists(statePath) && !anyWrite;

    WriteEmptyOriginalState(wasDhcp: false);
    resetUsed = false;
    anyWrite = false;
    WindowsDnsOverride.PsRunnerOverride = script =>
    {
        // Static-empty contract: static-type empty originals must not trigger any Set/Reset — the runner
        // rejects everything and leaves a mark.
        if (script.Contains("-ResetServerAddresses")) { resetUsed = true; return (0, string.Empty, string.Empty); }
        if (script.Contains("-ServerAddresses")) { anyWrite = true; return (0, string.Empty, string.Empty); }
        return (1, string.Empty, "unexpected");
    };
    var winE2 = new WindowsDnsOverride(statePath);
    var (r4Ok, r4Msg) = winE2.Restore();
    Check("restore-sem: empty-original dhcp resets, static-empty never written and reported (safety rule)",
        dhcpEmptyResets && !r4Ok && r4Msg.Contains("cannot be restored automatically", StringComparison.Ordinal)
        && !resetUsed && !anyWrite && File.Exists(statePath));

    // Takeover-side negative sample: after Set, readback 172.19.0.21 (substring hit but not
    // an exact item) → fail-closed + rollback.
    WindowsDnsOverride.PsRunnerOverride = script =>
    {
        if (script.Contains("interfaces=$ifs"))
            return (0, "{\"interfaces\":[{\"idx\":21,\"alias\":\"WLAN\",\"servers\":[\"192.0.2.1\"],\"dhcp\":1}]}", string.Empty);
        return script.Contains("-ServerAddresses '172.19.0.2'") ? (0, "172.19.0.21", string.Empty) : (0, string.Empty, string.Empty);
    };
    var t3State = Path.Combine(Path.GetTempPath(), "laneflow-selftest-takeover-trap.json");
    var win3 = new WindowsDnsOverride(t3State);
    var (t3Ok, t3Msg) = win3.Takeover(ConfigRenderer.DnsTakeoverAddress);
    Check("takeover-sem: readback substring trap rejected (172.19.0.21 != 172.19.0.2), rollback applied",
        !t3Ok && t3Msg.Contains("read-back verification failed", StringComparison.Ordinal) && !File.Exists(t3State));

    // Trace-file injection hardening (packaging review): the trace file lives in %APPDATA%
    // (user-writable) and its values feed elevated PowerShell command lines. A tampered alias
    // (command-injection characters) or a tampered original server (not a strict IP literal)
    // must be rejected without executing anything — fail closed as "cannot be restored".
    void WriteTamperedState(string alias, string[] servers) =>
        File.WriteAllText(statePath,
            "{\"entries\":[{\"interface_index\":0,\"interface_alias\":\"" + alias + "\",\"original_servers\":[" +
            string.Join(",", Array.ConvertAll(servers, s => "\"" + s + "\"")) + "],\"was_dhcp\":false}],\"active\":true}");

    WindowsDnsOverride.PsRunnerOverride = script =>
    {
        if (script.Contains("-ServerAddresses") || script.Contains("-InterfaceAlias") || script.Contains("-InterfaceIndex"))
        { anyWrite = true; return (0, string.Empty, string.Empty); }
        return (1, string.Empty, "unexpected");
    };

    WriteTamperedState("WLAN\\\"; whoami", Array.Empty<string>());
    anyWrite = false;
    var winInj1 = new WindowsDnsOverride(statePath);
    var (inj1Ok, _) = winInj1.Restore();
    Check("injection-sem: tampered alias with command-injection chars is rejected, nothing executed",
        !inj1Ok && !anyWrite && File.Exists(statePath));

    WriteTamperedState("WLAN", new[] { "1.2.3.4'; whoami" });
    anyWrite = false;
    var winInj2 = new WindowsDnsOverride(statePath);
    var (inj2Ok, _) = winInj2.Restore();
    Check("injection-sem: tampered original server (non-IP literal) is rejected, nothing executed",
        !inj2Ok && !anyWrite && File.Exists(statePath));

    WriteTamperedState("WLAN", new[] { "1.2.3.04" }); // parses as an IP but does not round-trip canonically
    anyWrite = false;
    var winInj3 = new WindowsDnsOverride(statePath);
    var (inj3Ok, _) = winInj3.Restore();
    Check("injection-sem: non-canonical IP literal (1.2.3.04) is rejected, nothing executed",
        !inj3Ok && !anyWrite && File.Exists(statePath));

    // Crash recovery net (global exception handlers in App): without a takeover trace the
    // recovery must be an explicit no-op; with a stale active trace (hard kill during
    // takeover) it must drive the restore path and clear the trace. Injection-sealed: every
    // PS script is served by the fake runner, the real system is untouched.
    bool restoreRan = false;
    WindowsDnsOverride.PsRunnerOverride = script =>
    {
        if (script.Contains("-ResetServerAddresses")) { restoreRan = true; return (0, string.Empty, string.Empty); }
        if (script.Contains("interfaces=$ifs"))
            return (0, "{\"interfaces\":[{\"idx\":21,\"alias\":\"WLAN\",\"servers\":[\"192.0.2.1\"],\"dhcp\":1}]}", string.Empty);
        if (script.Contains("-ServerAddresses '172.19.0.2'")) return (0, "172.19.0.2", string.Empty);
        return (1, string.Empty, "unexpected");
    };
    var crashPath = Path.Combine(Path.GetTempPath(), "laneflow-selftest-crash-state.json");
    try { File.Delete(crashPath); } catch { }
    Check("crash-recover: no-trace no-op is explicit (never silent, never throws)",
        App.CrashRecover(crashPath) == "no active takeover trace; nothing to restore");
    restoreRan = false;
    var winCrash = new WindowsDnsOverride(crashPath);
    var (tCrashOk, _) = winCrash.Takeover(ConfigRenderer.DnsTakeoverAddress);
    var crashMsg = App.CrashRecover(crashPath);
    Check("crash-recover: stale active trace drives the restore path and clears the trace",
        tCrashOk && restoreRan && crashMsg.Length > 0 && !File.Exists(crashPath));

    // Settings persistence: atomic write (packaging review). A crash mid-write must never
    // leave a truncated settings.json (which would silently revert the user's configuration
    // to defaults on next startup). Invariants here: save succeeds, output is readable JSON
    // carrying the saved value, and no .tmp residue remains. The user's real settings file is
    // snapshotted and restored around the check.
    {
        var path = Settings.SettingsPath;
        string? original = File.Exists(path) ? File.ReadAllText(path) : null;
        try
        {
            var settingsDoc = new SettingsDocument();
            settingsDoc.Outbound.Host = "203.0.113.77";
            settingsDoc.Outbound.Port = 1080;
            var savedOk = Settings.Save(settingsDoc, out var saveErr);
            var settingsJson = savedOk ? File.ReadAllText(path) : "<not written>";
            var tmpResidue = Directory.GetFiles(Settings.AppDataDir, "*.tmp").Length;
            Check("settings: atomic save persists readable JSON with no temp residue",
                savedOk && saveErr.Length == 0
                && settingsJson.Contains("203.0.113.77", StringComparison.Ordinal)
                && tmpResidue == 0);
        }
        finally
        {
            if (original is null) { try { File.Delete(path); } catch { /* nothing to clean */ } }
            else { try { File.WriteAllText(path, original); } catch { /* keep original best-effort */ } }
        }
    }

    WindowsDnsOverride.PsRunnerOverride = null;

    Check("parse: ParseIpList trims and drops empties (exact semantics)",
        WindowsDnsOverride.ParseIpList(" 192.0.2.1 , ,172.19.0.2 ").Length == 2
        && WindowsDnsOverride.ParseIpList("").Length == 0);

// ---- Combo tag matcher modes (regression guard, packaging review 2026-10-16) ----
// Strict mode (type/protocol dropdowns) must use exact Ordinal matching; if anyone collapses
// the two modes back into one normalized matcher, "Http" would normalize to the same value as
// "Socks5" and the first item would always win. Language mode must restore a persisted
// "zh-CN" onto the item tagged "zh" (and only language tags go through normalization).
{
    var typeTags = new[] { "Socks5", "Http" };      // CmbType items
    var ipTags = new[] { "IPv4", "IPv6" };          // protocol dropdown tags
    var langTags = new[] { "en", "zh" };            // CmbLang items
    Check("combotag: strict mode never collides type tags (Http selects index 1, not 0)",
        ComboTagMatcher.SelectIndex(typeTags, "Http", languageMode: false) == 1
        && ComboTagMatcher.SelectIndex(typeTags, "Socks5", languageMode: false) == 0);
    Check("combotag: strict mode never collides protocol tags (IPv6 selects index 1)",
        ComboTagMatcher.SelectIndex(ipTags, "IPv6", languageMode: false) == 1
        && ComboTagMatcher.SelectIndex(ipTags, "IPv4", languageMode: false) == 0);
    Check("combotag: strict mode rejects unknown tags",
        ComboTagMatcher.SelectIndex(typeTags, "en", languageMode: false) == -1
        && ComboTagMatcher.SelectIndex(typeTags, "zh-CN", languageMode: false) == -1);
    Check("combotag: language mode restores persisted zh-CN onto tag zh",
        ComboTagMatcher.SelectIndex(langTags, "zh-CN", languageMode: true) == 1
        && ComboTagMatcher.SelectIndex(langTags, "zh", languageMode: true) == 1
        && ComboTagMatcher.SelectIndex(langTags, "en", languageMode: true) == 0
        && ComboTagMatcher.SelectIndex(langTags, null, languageMode: true) == 0);
    Check("combotag: language mode WOULD collide type tags (all normalize equal) — documents why type/protocol dropdowns must stay strict",
        ComboTagMatcher.SelectIndex(typeTags, "Http", languageMode: true) == 0
        && ComboTagMatcher.SelectIndex(typeTags, "Socks5", languageMode: true) == 0);
}

// ---- Config fingerprint (input-sensitivity hardening): determinism + input sensitivity ----
{
    var fpA = Settings.Fingerprint(new OutboundConfig { Host = "203.0.113.9", Port = 1080 }, "app.exe");
    Check("fingerprint: deterministic, input-sensitive across fields, 16-hex",
        fpA == Settings.Fingerprint(new OutboundConfig { Host = "203.0.113.9", Port = 1080 }, "app.exe")
        && fpA != Settings.Fingerprint(new OutboundConfig { Host = "203.0.113.10", Port = 1080 }, "app.exe")
        && fpA != Settings.Fingerprint(new OutboundConfig { Host = "203.0.113.9", Port = 1081 }, "app.exe")
        && fpA != Settings.Fingerprint(new OutboundConfig { Host = "203.0.113.9", Port = 1080 }, "other.exe")
        && fpA != Settings.Fingerprint(new OutboundConfig { Host = "203.0.113.9", Port = 1080, Username = "u", Password = "p" }, "app.exe")
        && fpA.Length == 16);
}

// ---- Exit-IP HIT criterion (verify-tool criterion-tightening order, 2026-10-16) ----
// LaneFlow.ExitHitMatcher is the single testable invariant behind the verify-tool's V1/V2
// verdicts. Rules (explicit): first non-empty token, optional curl "|HTTP:...|time:..." suffix
// stripped, exact Ordinal equality; everything else is MISS — substring traps, base-injected
// pages, JSON/HTML shapes (reported as shape mismatch, never a hit), decorated tokens, garbage.
// Prefer MISS over a false HIT.
{
    const string ip = "203.0.113.10";
    Check("exithit: bare IP line is a hit",
        ExitHitMatcher.IsExactHit("203.0.113.10", ip));
    Check("exithit: surrounding whitespace trimmed, first token wins",
        ExitHitMatcher.IsExactHit("  \n 203.0.113.10 \n ", ip));
    Check("exithit: curl wrapper suffix |HTTP:200|time:... stripped before compare",
        ExitHitMatcher.IsExactHit("203.0.113.10|HTTP:200|time:0.123", ip));
    Check("exithit: substring trap 203.0.113.110 is NOT a hit",
        !ExitHitMatcher.IsExactHit("203.0.113.110", ip));
    Check("exithit: prefixed token x203.0.113.10 is NOT a hit",
        !ExitHitMatcher.IsExactHit("x203.0.113.10", ip));
    Check("exithit: suffixed token 203.0.113.10. is NOT a hit (bare IP token only)",
        !ExitHitMatcher.IsExactHit("203.0.113.10.", ip));
    Check("exithit: decorated token ip=203.0.113.10 is NOT a hit",
        !ExitHitMatcher.IsExactHit("ip=203.0.113.10", ip));
    Check("exithit: base-injected HTML page containing the IP is NOT a hit (shape mismatch)",
        !ExitHitMatcher.IsExactHit("<html><body>gateway check 203.0.113.10 blocked</body></html>", ip));
    Check("exithit: JSON shape is NOT a hit (shape mismatch; rotate to a bare-IP echo domain)",
        !ExitHitMatcher.IsExactHit("{\"ip\":\"203.0.113.10\",\"country\":\"US\"}", ip));
    Check("exithit: IP on a later line (first token non-IP) is NOT a hit",
        !ExitHitMatcher.IsExactHit("error\n203.0.113.10", ip));
    Check("exithit: empty and garbage responses are NOT a hits",
        !ExitHitMatcher.IsExactHit("", ip) && !ExitHitMatcher.IsExactHit("CURL-ERR: timeout", ip));
    Check("exithit: wrong bare IP is NOT a hit",
        !ExitHitMatcher.IsExactHit("192.0.2.254", ip));
}

    WindowsDnsOverride.PsRunnerOverride = null;
    if (File.Exists(statePath)) File.Delete(statePath);
}

Console.WriteLine(failures == 0 ? "ALL PASS" : $"{failures} FAILED");
return failures == 0 ? 0 : 1;

// CIDR overlap check (fakeip pool vs base pool: collision → runtime "missing fakeip record" hard error).
static bool CidrOverlap(string a, string b)
{
    var (s1, e1) = ParseCidr(a);
    var (s2, e2) = ParseCidr(b);
    return s1 <= e2 && s2 <= e1;
    static (uint start, uint end) ParseCidr(string cidr)
    {
        var parts = cidr.Split('/');
        var octets = parts[0].Split('.');
        uint addr = 0;
        foreach (var o in octets) addr = (addr << 8) | uint.Parse(o);
        int bits = int.Parse(parts[1]);
        uint mask = bits == 0 ? 0 : uint.MaxValue << (32 - bits);
        uint net = addr & mask;
        return (net, net | ~mask);
    }
}
