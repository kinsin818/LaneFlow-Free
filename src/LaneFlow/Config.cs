using System.Text.Json;
using System.Text.Json.Serialization;

namespace LaneFlow;

/// <summary>Proxy type. Note: socks5h (remote resolution) is explicitly banned and absent from this enum.</summary>
public enum ProxyType
{
    Socks5,
    Http
}

/// <summary>IP protocol stack.</summary>
public enum IpProtocol
{
    IPv4,
    IPv6
}

/// <summary>
/// Host input parse result (produced by <see cref="OutboundConfig.TryParseHostInput"/>).
/// </summary>
public sealed record HostParseResult(
    string Host,
    int Port,
    string? Username,
    string? Password);

/// <summary>
/// Outbound configuration — maps the UI's "six controls, five field groups":
///   controls: type dropdown / IP protocol dropdown / host / port / username / password (6 controls)
///   field groups: type / IP protocol / host / port / credential pair (5 groups)
/// </summary>
public sealed class OutboundConfig
{
    /// <summary>Proxy type, default Socks5 (socks5h banned, hence absent from the enum).</summary>
    [JsonPropertyName("type")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public ProxyType Type { get; set; } = ProxyType.Socks5;

    /// <summary>IP protocol, default IPv4.</summary>
    [JsonPropertyName("ip_version")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public IpProtocol IpVersion { get; set; } = IpProtocol.IPv4;

    /// <summary>Host (may be auto-split into port/credentials by <see cref="TryParseHostInput"/>).</summary>
    [JsonPropertyName("host")]
    public string Host { get; set; } = string.Empty;

    /// <summary>Port 1-65535.</summary>
    [JsonPropertyName("port")]
    public int Port { get; set; }

    /// <summary>Username (paired with password; both may be empty; key omitted when null).</summary>
    [JsonPropertyName("username")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Username { get; set; }

    /// <summary>Password (paired with username; key omitted when null).</summary>
    [JsonPropertyName("password")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Password { get; set; }

    public const int PortMin = 1;
    public const int PortMax = 65535;

    [JsonIgnore]
    public bool IsPortValid => Port >= PortMin && Port <= PortMax;

    /// <summary>
    /// Parses host input. Two accepted forms:
    ///   1) plain host:port       — e.g. 192.0.2.1:1080
    ///   2) scheme URL            — e.g. socks5://user:pass@host:port (http:// also supported)
    /// On success, host/port/username/password are written into <paramref name="result"/>.
    /// Does not mutate the current instance; the caller decides whether to apply it to the UI.
    /// </summary>
    public static bool TryParseHostInput(string raw, out HostParseResult? result, out string error)
    {
        result = null;
        error = string.Empty;

        var input = (raw ?? string.Empty).Trim();
        if (string.IsNullOrEmpty(input))
        {
            error = "Host must not be empty";
            return false;
        }

        var remainder = input;
        var schemeIdx = input.IndexOf("://", System.StringComparison.Ordinal);
        if (schemeIdx >= 0)
        {
            var scheme = input.Substring(0, schemeIdx).ToLowerInvariant();
            remainder = input.Substring(schemeIdx + 3);
            // Only socks5 / http / https allowed; socks5h is intercepted here (remote DNS banned).
            if (scheme is not ("socks5" or "http" or "https"))
            {
                error = $"Unsupported scheme: {scheme} (only socks5 / http allowed; socks5h disabled)";
                return false;
            }
            if (scheme == "socks5h")
            {
                error = "socks5h is disabled (remote DNS resolution banned)";
                return false;
            }
        }

        // userinfo@host:port
        string userInfo = string.Empty;
        var atIdx = remainder.IndexOf('@');
        if (atIdx >= 0)
        {
            userInfo = remainder.Substring(0, atIdx);
            remainder = remainder.Substring(atIdx + 1);
        }

        // Port = after the last colon
        var colonIdx = remainder.LastIndexOf(':');
        if (colonIdx < 0)
        {
            error = "Missing port (expected format host:port)";
            return false;
        }
        var hostPart = remainder.Substring(0, colonIdx);
        var portPart = remainder.Substring(colonIdx + 1);

        if (string.IsNullOrEmpty(hostPart))
        {
            error = "Host name is empty";
            return false;
        }
        if (!int.TryParse(portPart, out var port) || port < PortMin || port > PortMax)
        {
            error = $"Invalid port: {portPart} (must be {PortMin}-{PortMax})";
            return false;
        }

        // Credentials: user:pass
        string? user = null;
        string? pass = null;
        if (!string.IsNullOrEmpty(userInfo))
        {
            var upColon = userInfo.IndexOf(':');
            if (upColon >= 0)
            {
                user = userInfo.Substring(0, upColon);
                pass = userInfo.Substring(upColon + 1);
            }
            else
            {
                user = userInfo;
            }
        }

        result = new HostParseResult(hostPart, port, user, pass);
        return true;
    }
}

/// <summary>
/// Single constant: the footer "Get Pro" link (centralized config, avoids scattered hardcodes).
/// No affiliate / tracking parameters; not used in business logic. Note: the GPL redaction
/// allowlist permits "Gumroad" only in the README files and this file.
/// </summary>
public static class ProLink
{
    public const string PurchaseUrl = "https://5787773983017.gumroad.com";
}

/// <summary>
/// Renders the saved outbound config plus the bound app into a sing-box runtime config.
/// Strictly follows the fixed config skeleton (no "stack" key; server_port emitted as int;
/// new DNS format; interface_name=LaneFlow; address=172.19.0.1/30).
/// UDP/QUIC are non-committed traffic: UDP of the bound app is rejected outright; only TCP
/// goes through lane (fail-closed fallback).
///
/// DNS/routing architecture (v3 = final form verified on a live machine, 2026-10-15,
/// five checks all green: V1 bound traffic echoes proxy exit / V2 unbound traffic via base /
/// fakeip split / zero self-loop / zero errors. verified against a live run):
///   ① DNS entry: <see cref="WindowsDnsOverride"/> temporarily points the DNS of **all**
///      interfaces to <see cref="DnsTakeoverAddress"/> (172.19.0.2 = the /30 peer address,
///      **not** the TUN's own address 172.19.0.1 — the own address is delivered locally by
///      the kernel stack and RST, proven live; queries enter the TUN via the /30 on-link
///      route and are hijacked wholesale by this config's first route rule hijack-dns).
///   ② fakeip split: dns.rules return pool addresses (100.64.0.0/10, disjoint from the
///      base's 198.18.0.0/15) for **all** A/HTTPS queries. **Not per-process** — on Windows
///      DNS queries are sent on behalf of apps by dnscache (svchost), so process attribution
///      can never be the bound app (proven live: zero occurrences of curl.exe); the
///      split happens at connection level (route rules with process_name, attribution
///      verified working).
///   ③ fakeip pool route: sing-tun's split routes are emptied by
///      route_exclude_address=["0.0.0.0/0"] (BuildAutoRouteRanges subtraction, proven live
///      split count=0); the app layer manually adds 100.64.0.0/10 → LaneFlow (metric 1)
///      once the kernel is ready — only fakeip connections enter the LaneFlow TUN; all other
///      traffic (including sing-box's own direct dials) goes via the base, eliminating split
///      route self-loops at the root (proven live: 698 sing-box.exe attribution re-entries).
///   ④ auto_route stays true: sing-tun Start() only calls RegisterMyInterface when
///      AutoRoute is set — sing-box's isLocalSource check (route/process_cache.go) depends
///      on the interface registry, otherwise TCP connection process-attribution lookups are
///      silently skipped (proven live: with auto_route=false, fakeip connections
///      had no "found process path" and process_name rules were dead).
///   ⑤ Splitting: a connection hitting a fakeip → reverse lookup restores the domain
///      (route.go:564-577) → route rules split per-connection by process_name: bound
///      process → lane (socks5; domain sent to proxy as-is with ATYP=3, equivalent to
///      socks5h); unbound process → final=direct (sing-box dials via the base, identical
///      behavior to LaneFlow being off).
///   ⑥ real-dns = DoH **223.5.5.5** (AliDNS, a public resolver address): reachable and stable via
///      the base (proven live; 1.1.1.1 is a non-local address whose via-base behavior
///      was unverified; measured live: this public DoH works both direct and via base).
///   ⑦ lane has no bind and no proxy-host exclusion: the proxy server (endpoint configured
///      by the user in settings) is **only reachable via the base** (proven live: WLAN direct
///      to the proxy is transparently intercepted with HTTP/1.1 404; bound interface = naked
///      direct exposure on the physical interface; no bind = rides the base's split routes (measured
///      live: a 1.58s handshake with correct exit echo).
///   ⑧ Unbound state = the original single local server (byte-identical to the historical
///      render, zero regression; kernel not started when unbound).
/// </summary>
public static class ConfigRenderer
{
    /// <summary>fakeip pool range. Must stay disjoint from the known base fake-IP range 198.18.0.0/15 (live-machine fact).</summary>
    public const string FakeIpRange = "100.64.0.0/10";

    /// <summary>Known base fake-IP range (live-machine fact); used for the disjointness assertion.</summary>
    public const string BaseFakeIpRange = "198.18.0.0/15";

    /// <summary>LaneFlow TUN's own address (.1 within the /30). Note: the DNS takeover target is the peer address, see <see cref="DnsTakeoverAddress"/>.</summary>
    public const string TunAddress = "172.19.0.1";

    /// <summary>
    /// DNS takeover target = the TUN /30 peer address (172.19.0.2).
    /// Proven live: taking over to the TUN's own address 172.19.0.1 gets the query delivered
    /// locally by the kernel stack and RST ("the remote host forcibly closed the existing
    /// connection") — queries never enter the TUN; the peer address (non-local) enters wintun
    /// via the /30 on-link route and sing-box hijacks normally (proven live).
    /// </summary>
    public const string DnsTakeoverAddress = "172.19.0.2";

    /// <summary>LaneFlow TUN subnet (/30 on-link route, longer prefix than the default route, guaranteeing queries enter the TUN).</summary>
    public const string TunCidr = "172.19.0.1/30";

    /// <summary>
    /// DoH upstream (AliDNS 223.5.5.5, IP form avoids bootstrap domain dependency).
    /// Proven live: reachable and stable via the base; 1.1.1.1 (foreign) via-base
    /// behavior unverified, hence not adopted.
    /// </summary>
    private const string DohServer = "223.5.5.5";

    /// <summary>
    /// Resolves a host name into a route-exclusion address.
    /// Note (v3): the render path no longer calls this — after
    /// route_exclude_address=["0.0.0.0/0"] empties the split routes, the proxy host is
    /// reachable via the base (proven live: physical-NIC direct to the proxy is transparently
    /// intercepted; only via-base works), so per-host exclusion is unnecessary. Kept for
    /// diagnostics / future plans; SelfTest still covers its parse semantics.
    /// </summary>
    public static string? ResolveExcludeAddress(string host) =>
        ResolveExcludeAddress(host, out _);

    /// <summary>
    /// Resolves an anti-loop exclusion address; <paramref name="resolved"/> reports whether an
    /// address was obtained. On failure this never silently falls back: the caller must
    /// explicitly surface the weakened anti-loop protection (design baseline: bans
    /// silent degradation into an unsafe state).
    /// </summary>
    public static string? ResolveExcludeAddress(string host, out bool resolved)
    {
        resolved = false;
        if (string.IsNullOrWhiteSpace(host))
            return null;
        // Already an IP literal
        if (System.Net.IPAddress.TryParse(host, out var lit))
        {
            resolved = true;
            return lit.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                ? $"{lit}/128"
                : $"{lit}/32";
        }
        // Host name → resolve the first address
        try
        {
            var entries = System.Net.Dns.GetHostAddresses(host);
            if (entries.Length > 0)
            {
                resolved = true;
                var first = entries[0];
                return first.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                    ? $"{first}/128"
                    : $"{first}/32";
            }
        }
        catch
        {
            // Resolution failure: resolved stays false; the caller must surface it explicitly,
            // never silently degrade into an unsafe state.
        }
        return null;
    }

    /// <summary>
    /// Renders the sing-box config JSON.
    /// When <paramref name="appExeName"/> is empty (unbound), the output is final=direct only
    /// (everything direct).
    /// </summary>
    public static string Render(OutboundConfig ob, string? appExeName)
    {
        var bound = !string.IsNullOrWhiteSpace(appExeName);
        var config = new System.Text.Json.Nodes.JsonObject();
        // Log level: default "error" (historical behavior, zero regression). Diagnostic
        // switch: environment variable LANEFLOW_LOG_LEVEL (debug/info/warn/error; unset or
        // invalid values fall back to error). Attribution diagnostics
        // need debug-level logs — sing-box's "found process path" attribution line is INFO
        // level and never printed under "error"; "no attribution line in kernel log" must
        // never be treated as proof of attribution failure (a prior run made this invalid-diff mistake).
        var logLevel = System.Environment.GetEnvironmentVariable("LANEFLOW_LOG_LEVEL");
        if (logLevel is not ("debug" or "info" or "warn" or "error"))
            logLevel = "error";
        config["log"] = new System.Text.Json.Nodes.JsonObject { ["level"] = logLevel };

        // DNS: bound state = v3 fakeip wholesale split + DoH; unbound state = single local
        // (historical behavior, zero regression).
        var dns = new System.Text.Json.Nodes.JsonObject();
        if (bound)
        {
            dns["servers"] = new System.Text.Json.Nodes.JsonArray(
                new System.Text.Json.Nodes.JsonObject
                {
                    ["type"] = "fakeip", ["tag"] = "fakeip-dns", ["inet4_range"] = FakeIpRange
                },
                // DoH upstream dials by default (**no detour**, live-machine fix):
                // sing-box 1.14.3 forbids an explicit detour to an "empty" direct outbound —
                // detour.go:69-75 IsEmpty() treats an all-default DialerOptions as empty →
                // runtime FATAL "detour to an empty direct outbound makes no sense" (check
                // does not catch it; only runtime). The new-format DoH server's default dialer
                // already equals an empty direct (https.md:36), so drop it. The effect of
                // keeping queries off the base's fake-IP / UDP53 interference is unchanged:
                // queries go through the system stack to 223.5.5.5:443 where the TLS layer
                // prevents base spoofing; v3: does not depend on lane — DNS still works when
                // the proxy is down.
                new System.Text.Json.Nodes.JsonObject
                {
                    ["type"] = "https", ["tag"] = "real-dns", ["server"] = DohServer
                });
            // All A/HTTPS queries → fakeip (live-machine fix: **not per-process**).
            // On Windows every app's DNS queries are sent on behalf by dnscache (svchost.exe);
            // a per-process dns.rules never matches the bound app (dead rule — capture logs
            // prove zero curl.exe occurrences); the fakeip-vs-real split happens at connection
            // level (route process_name rules, attribution verified working).
            dns["rules"] = new System.Text.Json.Nodes.JsonArray(
                new System.Text.Json.Nodes.JsonObject
                {
                    ["query_type"] = new System.Text.Json.Nodes.JsonArray("A", "HTTPS"),
                    ["server"] = "fakeip-dns"
                });
            dns["final"] = "real-dns";
        }
        else
        {
            dns["servers"] = new System.Text.Json.Nodes.JsonArray(
                new System.Text.Json.Nodes.JsonObject { ["type"] = "local", ["tag"] = "local" });
        }
        config["dns"] = dns;

        var outbounds = new System.Text.Json.Nodes.JsonArray();
        outbounds.Add(new System.Text.Json.Nodes.JsonObject { ["type"] = "direct", ["tag"] = "direct" });
        var lane = new System.Text.Json.Nodes.JsonObject
        {
            ["type"] = ob.Type == ProxyType.Http ? "http" : "socks",
            ["tag"] = "lane",
            ["server"] = ob.Host,
            ["server_port"] = ob.Port
        };
        if (ob.Type == ProxyType.Socks5)
            lane["version"] = "5";
        // When the proxy server is a domain name, bootstrap resolution uses real-dns (direct
        // DoH, not through the proxy) to avoid a resolve-through-lane self-loop.
        if (bound)
            lane["domain_resolver"] = "real-dns";
        if (!string.IsNullOrEmpty(ob.Username))
        {
            lane["username"] = ob.Username;
            lane["password"] = ob.Password ?? string.Empty;
        }
        outbounds.Add(lane);
        config["outbounds"] = outbounds;

        var rules = new System.Text.Json.Nodes.JsonArray();
        if (bound)
        {
            // v3: the DNS entry point is globally taken over by WindowsDnsOverride (**all**
            // interfaces' DNS → 172.19.0.2 → queries enter the TUN; changing only the base
            // NIC misses WLAN etc., proven live: queries went to the LAN router's DNS and
            // got real IPs bypassing LaneFlow), hence unconditional wholesale hijack of 53.
            // Must precede reject-udp, otherwise the bound app's DNS is refused.
            rules.Add(new System.Text.Json.Nodes.JsonObject
            {
                ["action"] = "hijack-dns",
                ["port"] = 53
            });
            rules.Add(new System.Text.Json.Nodes.JsonObject
            {
                ["action"] = "reject",
                ["network"] = "udp",
                ["process_name"] = new System.Text.Json.Nodes.JsonArray(appExeName!)
            });
            rules.Add(new System.Text.Json.Nodes.JsonObject
            {
                ["action"] = "route",
                ["outbound"] = "lane",
                ["process_name"] = new System.Text.Json.Nodes.JsonArray(appExeName!)
            });
        }
        else
        {
            // Unbound state: 53→direct keeps historical semantics (kernel never runs in
            // this state — render compatibility only).
            rules.Add(new System.Text.Json.Nodes.JsonObject
            {
                ["action"] = "route",
                ["outbound"] = "direct",
                ["port"] = 53
            });
        }
        var route = new System.Text.Json.Nodes.JsonObject
        {
            ["rules"] = rules,
            ["final"] = "direct"
        };
        // Both the fakeip reverse lookup and direct-outbound domain targets require a
        // declared resolver (1.12+ migration; missing = FATAL). real-dns does not go through
        // lane, so it can safely double as lane's domain bootstrap resolver (no self-loop when
        // the proxy host is a domain).
        if (bound)
            route["default_domain_resolver"] = "real-dns";
        config["route"] = route;

        var inbound = new System.Text.Json.Nodes.JsonObject
        {
            ["type"] = "tun",
            ["tag"] = "tun-in",
            ["interface_name"] = "LaneFlow",
            ["address"] = new System.Text.Json.Nodes.JsonArray(TunCidr),
            // Necessity of auto_route=true (proven live): sing-tun Start() only calls
            // RegisterMyInterface when AutoRoute is set — sing-box's isLocalSource check
            // (route/process_cache.go) depends on the interface registry; otherwise TCP
            // connection process-attribution lookups are silently skipped and process_name
            // routing rules die.
            ["auto_route"] = true,
            ["strict_route"] = false,
            // route_exclude_address=["0.0.0.0/0"] (proven live): BuildAutoRouteRanges's
            // subtraction empties the split route set (split count=0) — global split routes
            // were the root cause of direct-dial self-loops (698 sing-box.exe attribution
            // re-entries). fakeip connections reach the LaneFlow TUN via the manually added
            // 100.64.0.0/10 → LaneFlow precise route; the proxy server is reachable via the
            // base (no bind, no exclusion).
            ["route_exclude_address"] = new System.Text.Json.Nodes.JsonArray("0.0.0.0/0")
        };
        config["inbounds"] = new System.Text.Json.Nodes.JsonArray(inbound);

        return config.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }
}
