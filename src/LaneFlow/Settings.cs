using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LaneFlow;

/// <summary>Binding target: { app_identifier, enabled }. No auth_mode enum.</summary>
public sealed class AppBinding
{
    [JsonPropertyName("app_identifier")]
    public string AppIdentifier { get; set; } = string.Empty;

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }
}

/// <summary>Root document of settings.json.</summary>
public sealed class SettingsDocument
{
    /// <summary>Outbound proxy configuration.</summary>
    [JsonPropertyName("outbound")] public OutboundConfig Outbound { get; set; } = new();

    /// <summary>Per-app binding state.</summary>
    [JsonPropertyName("binding")] public AppBinding Binding { get; set; } = new();

    /// <summary>
    /// UI language ("en" default; "zh" = Chinese). Persisted so the choice survives restarts;
    /// drives Thread.CurrentThread.CurrentUICulture at startup (see L10n).
    /// </summary>
    [JsonPropertyName("ui_language")] public string UiLanguage { get; set; } = "en";
}

/// <summary>
/// settings.json read/write + validation.
/// Key constraints:
///   - File location: %APPDATA%\LaneFlow\settings.json (exclusive to LaneFlow).
///   - Credential pair validation: a half-filled pair is rejected (nothing written).
///   - Empty means no key: Username/Password null → omitted at serialization (see JsonIgnore).
///   - Binding { app_identifier, enabled }, no auth_mode enum.
/// </summary>
public static class Settings
{
    public const string FileName = "settings.json";

    /// <summary>User config directory: %APPDATA%\LaneFlow</summary>
    public static string AppDataDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "LaneFlow");

    /// <summary>Full path of settings.json.</summary>
    public static string SettingsPath => Path.Combine(AppDataDir, FileName);

    /// <summary>sing-box runtime config directory: %APPDATA%\LaneFlow\singbox</summary>
    public static string SingBoxConfigDir => Path.Combine(AppDataDir, "singbox");

    /// <summary>Full path of the sing-box runtime config.</summary>
    public static string SingBoxConfigPath => Path.Combine(SingBoxConfigDir, "config.json");

    /// <summary>DNS takeover trace file (recovery basis for hard-kill leftovers, v2).</summary>
    public static string DnsOverridePath => Path.Combine(AppDataDir, "dns-override.json");

    /// <summary>Render fingerprint file (written alongside the rendered config; compared by the UI on startup for the "config changed but not applied" notice).</summary>
    public static string RenderFingerprintPath => Path.Combine(SingBoxConfigDir, "config.fingerprint");

    /// <summary>
    /// Render input fingerprint (input-sensitivity hardening; approved
    /// 2026-10-16): SHA256 first-16-hex over the outbound's full fields + bound app name.
    /// Written to disk together with the rendered config and compared by the UI on startup —
    /// when settings changed without re-binding, the on-disk config is a stale render and the
    /// UI must say so explicitly (never silently; fool-proofing rule 2 "config changes take
    /// effect" applied to the render path).
    /// The fingerprint includes the password: the file lives in the local AppData (same
    /// exposure domain as the plaintext settings.json; no new exposure surface).
    /// </summary>
    public static string Fingerprint(OutboundConfig ob, string boundApp)
    {
        var raw = $"{ob.Type}|{ob.IpVersion}|{ob.Host}|{ob.Port}|{ob.Username}|{ob.Password}|{boundApp}";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(bytes)[..16];
    }

    /// <summary>Credential pair validation: one filled and the other empty → false with an error.</summary>
    public static bool ValidateAccountPair(OutboundConfig cfg, out string error)
    {
        error = string.Empty;
        var hasUser = !string.IsNullOrEmpty(cfg.Username);
        var hasPass = !string.IsNullOrEmpty(cfg.Password);
        if (hasUser != hasPass)
        {
            error = "Username and password must be filled as a pair: filling one requires the other";
            return false;
        }
        return true;
    }

    /// <summary>
    /// Credential-key consistency invariant (CI-checkable): username/password keys present
    /// ⇔ both keys non-empty. Serialization's JsonIgnore(WhenWritingNull) guarantees
    /// "empty → no key"; together with this check, a "single key only" half-state can never
    /// be written.
    /// </summary>
    public static bool AccountKeysConsistent(OutboundConfig cfg) =>
        string.IsNullOrEmpty(cfg.Username) == string.IsNullOrEmpty(cfg.Password);

    public static SettingsDocument Load() => Load(out _, out _);

    /// <summary>
    /// Reads settings.json; a corrupted file is never silently reset — the caller is told
    /// explicitly via out parameters.
    /// </summary>
    public static SettingsDocument Load(out bool corrupted, out string? detail)
    {
        corrupted = false;
        detail = null;
        var path = SettingsPath;
        if (!File.Exists(path))
            return new SettingsDocument();
        try
        {
            var json = File.ReadAllText(path);
            var doc = JsonSerializer.Deserialize<SettingsDocument>(json);
            if (doc is null)
            {
                corrupted = true;
                detail = $"Config is empty or unparsable ({path}); reverted to defaults.";
                return new SettingsDocument();
            }
            return doc;
        }
        catch (Exception ex)
        {
            // Corrupted config: fall back to defaults without throwing, but report explicitly (never silent).
            corrupted = true;
            detail = $"Config corrupted, reverted to defaults ({path}): {ex.Message}";
            return new SettingsDocument();
        }
    }

    /// <summary>Pre-save validation: credential pair + port range. Returns false with a non-empty error.</summary>
    public static bool Save(SettingsDocument doc, out string error)
    {
        error = string.Empty;
        if (!ValidateAccountPair(doc.Outbound, out error))
            return false;
        if (!AccountKeysConsistent(doc.Outbound))
        {
            error = "Inconsistent username/password key state (consistency invariant violated)";
            return false;
        }
        if (!doc.Outbound.IsPortValid)
        {
            error = $"Port out of range (must be {OutboundConfig.PortMin}-{OutboundConfig.PortMax}); got {doc.Outbound.Port}";
            return false;
        }

        Directory.CreateDirectory(AppDataDir);
        var options = new JsonSerializerOptions { WriteIndented = true };
        var json = JsonSerializer.Serialize(doc, options);

        // Atomic persist (packaging review): write to a temp file next to the target, then
        // File.Replace/Move. A crash mid-write can never leave a truncated settings.json that
        // would silently revert the user's configuration to defaults on next startup. On any
        // failure the previous file stays intact (fail-closed) and the error is reported.
        var tmp = SettingsPath + ".tmp";
        try
        {
            File.WriteAllText(tmp, json);
            if (File.Exists(SettingsPath))
                File.Replace(tmp, SettingsPath, null);
            else
                File.Move(tmp, SettingsPath);
            return true;
        }
        catch (Exception ex)
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { /* best-effort cleanup */ }
            error = $"Failed to persist settings ({SettingsPath}): {ex.Message}";
            return false;
        }
    }
}
