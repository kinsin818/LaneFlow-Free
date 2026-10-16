using System;
using System.Collections.Generic;

namespace LaneFlow;

/// <summary>
/// Tag-to-index matching for ComboBox selection restore, split into two explicit modes.
/// Regression guard (found in packaging review, 2026-10-16): a single normalized matcher was
/// accidentally reused for the type/protocol dropdowns — every tag normalized to the same value,
/// so the first item always won and a saved HTTP/IPv6 selection was silently rewritten back to
/// Socks5/IPv4 on the next save. Modes:
///   - Strict (type/protocol dropdowns): exact Ordinal equality; tags like "Socks5"/"Http" or
///     "IPv4"/"IPv6" must never collide.
///   - Language (language selector only): both sides go through L10n.Normalize, so a persisted
///     "zh-CN" restores the item tagged "zh"; null/unknown values fall back to "en".
/// </summary>
public static class ComboTagMatcher
{
    /// <summary>Returns the first matching index, or -1 when nothing matches. A null tag is legal (language mode falls back to "en").</summary>
    public static int SelectIndex(IReadOnlyList<string?> tags, string? tag, bool languageMode)
    {
        for (var i = 0; i < tags.Count; i++)
        {
            var hit = languageMode
                ? L10n.Normalize(tags[i]) == L10n.Normalize(tag)
                : string.Equals(tags[i], tag, StringComparison.Ordinal);
            if (hit) return i;
        }
        return -1;
    }
}
