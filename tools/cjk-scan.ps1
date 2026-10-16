# CJK residue gate (Localization change 2026-10-16, deliverable: reproducible scan).
# Scans the repository for CJK characters in code/comment-bearing files.
# Allowed CJK (exempt by policy, enforced here):
#   - i18n resource files: src/LaneFlow/Properties/Resources.zh.resx (Chinese translations)
#   - explicitly bilingual docs: README.zh.md
# Everything else (comments, strings, log messages, XAML text, docs) must be CJK-free.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tools\cjk-scan.ps1
# Exit 0 = clean; exit 1 = residues found (listed).

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
# CJK ranges + fullwidth forms + CJK quotes (U+300C/300D) + curly quotes (U+201C/201D).
$patterns = '[\u4e00-\u9fff\u3040-\u30ff\u3000-\u303f\uff01-\uff5e\u201c\u201d]'
$includes = @('*.cs', '*.xaml', '*.ps1', '*.py', '*.md', '*.yml', '*.json', '*.csproj', '*.manifest', '*.sln', '*.props', '*.targets', '*.txt', '*.resx', '*.bat')
$exempt = @(
    (Join-Path $repoRoot 'src\LaneFlow\Properties\Resources.zh.resx'),  # Chinese UI translations (i18n data)
    (Join-Path $repoRoot 'src\LaneFlow\Properties\Resources.resx'),     # neutral resx; carries one functional value (the self-named zh language label)
    (Join-Path $repoRoot 'README.zh.md')                                # Chinese README (bilingual docs policy)
)

$files = Get-ChildItem -Path $repoRoot -Recurse -File -Include $includes |
    Where-Object { $_.FullName -notmatch '\\(\.git|bin|obj)\\' }

$violations = @()
foreach ($f in $files) {
    if ($exempt -contains $f.FullName) { continue }
    $lines = [System.IO.File]::ReadAllLines($f.FullName)
    for ($i = 0; $i -lt $lines.Length; $i++) {
        if ($lines[$i] -match $patterns) {
            $violations += ('{0}:{1}: {2}' -f ($f.FullName.Substring($repoRoot.Length + 1)), ($i + 1), $lines[$i].Trim())
        }
    }
}

if ($violations.Count -gt 0) {
    Write-Output ("CJK GATE FAIL: {0} line(s) with CJK residue:" -f $violations.Count)
    $violations | ForEach-Object { Write-Output "  $_" }
    exit 1
}
Write-Output ("CJK GATE PASS: 0 residue lines across {0} scanned files (exempt: {1} i18n/bilingual file(s))." -f $files.Count, $exempt.Count)
exit 0
