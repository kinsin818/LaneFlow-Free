using System;
using System.Linq;

namespace LaneFlow;

/// <summary>
/// Strict exit-IP HIT criterion (tightened 2026-10-16; re-locked as a
/// testable invariant by the verify-tool criterion-tightening pass, 2026-10-16).
///
/// Form rules (explicit, no ambiguity — prefer MISS over a false HIT):
///   1. The response body's first non-empty token (split on whitespace) is taken; a trailing
///      curl wrapper suffix "|HTTP:200|time:0.123" is stripped before comparing.
///   2. HIT requires the resulting token to be EXACTLY equal (Ordinal) to the exit IP.
///   3. Everything else is MISS, explicitly including:
///        - substring traps: "203.0.113.110" contains "203.0.113.10" but is NOT a hit;
///        - base-injected pages: an HTML/error page that merely contains the IP anywhere is
///          NOT a hit (the IP is never extracted from surrounding markup);
///        - JSON form: {"ip":"203.0.113.10",...} is NOT a hit — it is reported as
///          "shape mismatch" (a JSON/HTML response means the echo service did not answer with
///          a bare IP line; the remedy is to rotate to a bare-IP echo domain, never to loosen
///          this rule);
///        - decorated tokens: "ip=203.0.113.10", "[203.0.113.10]", "203.0.113.10." are
///          NOT a hit (only a bare IP token counts);
///        - garbage / empty responses.
///   4. Historical verdicts gathered under the old Contains criterion are not retroactively re-judged.
///      is not retroactively re-judged.
/// </summary>
public static class ExitHitMatcher
{
    /// <summary>
    /// True only when the response's first non-empty token (after stripping the optional curl
    /// "|HTTP:...|time:..." wrapper) equals <paramref name="ip"/> exactly (Ordinal).
    /// </summary>
    public static bool IsExactHit(string resp, string ip)
    {
        if (string.IsNullOrWhiteSpace(resp) || string.IsNullOrWhiteSpace(ip)) return false;
        var first = resp.Trim()
            .Split(new[] { ' ', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault();
        // The curl-wrapped output format is "IP|HTTP:200|time:..." — the pipe suffix must be
        // stripped before comparing.
        if (first != null) first = first.Split('|')[0];
        return string.Equals(first, ip, StringComparison.Ordinal);
    }
}
