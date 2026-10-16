using System.Globalization;
using System.Reflection;
using System.Resources;
using System.Threading;

namespace LaneFlow;

/// <summary>
/// Minimal i18n accessor (Englishization change, 2026-10-16): all UI display strings
/// come from the resx resource set; the Chinese translations live only in
/// Properties/Resources.zh.resx (the sole sanctioned CJK location in code-bearing files).
/// Non-UI messages (kernel/service layer) are English literals by design.
/// Culture selection is persisted as settings.json "ui_language" ("en" default) and applied to
/// Thread.CurrentThread.CurrentUICulture, per the design requirement to bind CurrentUICulture.
/// </summary>
public static class L10n
{
    private static readonly ResourceManager Rs =
        new("LaneFlow.Properties.Resources", typeof(L10n).Assembly);

    /// <summary>Active UI culture (en default). Never null after Apply.</summary>
    public static CultureInfo Culture { get; private set; } = new("en");

    /// <summary>Applies a language code ("en" / "zh") to the current UI culture.</summary>
    public static void Apply(string lang)
    {
        Culture = new CultureInfo(Normalize(lang));
        Thread.CurrentThread.CurrentUICulture = Culture;
    }

    /// <summary>Looks up a localized string; a missing key returns the key itself (never throws).</summary>
    public static string T(string key) => Rs.GetString(key, Culture) ?? key;

    /// <summary>
    /// Culture-invariant lookup (neutral resx only). Used for self-named constants like the
    /// language selector items, which by i18n convention never translate.
    /// </summary>
    public static string TInvariant(string key) => Rs.GetString(key, CultureInfo.InvariantCulture) ?? key;

    /// <summary>Formatted lookup (string.Format over the localized template).</summary>
    public static string F(string key, params object[] args) => string.Format(Culture, T(key), args);

    /// <summary>Normalizes a language code to a supported culture name ("en" / "zh-CN"); null/unknown falls back to "en".</summary>
    public static string Normalize(string? lang) =>
        lang is "zh" or "zh-CN" or "zh-Hans" ? "zh-CN" : "en";
}
