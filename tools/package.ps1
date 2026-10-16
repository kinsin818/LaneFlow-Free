# Packaging gate (release infrastructure): publish the product, lock-check the bundled
# kernel hash, assemble the exact release layout, emit SHA256SUMS, and zip the package.
# Fail-closed: any missing file or hash mismatch aborts with exit 1 — a broken release
# must never look shippable.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tools\package.ps1 [-OutDir dist]
param(
    [string]$OutDir = "dist"
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

# 1. Publish (framework-dependent, Release).
dotnet publish "$repoRoot\src\LaneFlow\LaneFlow.csproj" -c Release
if ($LASTEXITCODE -ne 0) { Write-Output "PACKAGE FAIL: publish failed"; exit 1 }
$publishDir = Join-Path $repoRoot "src\LaneFlow\bin\Release\net8.0-windows\publish"

# License texts and README are copied from the repo tree, not the publish output.
$repoFiles = @("LICENSE\MIT.txt", "LICENSE\gpl-3.0.txt", "LICENSE\sing-box.txt", "README.md")

# 2. Bundled kernel integrity: the packaged sing-box.exe must match the locked hash
#    (unmodified official binary; the hash is the distribution's own supply-chain claim).
$sumsLine = (Get-Content (Join-Path $repoRoot "core\SHA256SUMS.txt")) | Where-Object { $_ -match 'sing-box\.exe' } | Select-Object -First 1
$expected = $sumsLine.Split(' ')[0].Trim().ToLowerInvariant()
$kernel = Join-Path $publishDir "core\sing-box.exe"
if (-not (Test-Path $kernel)) { Write-Output "PACKAGE FAIL: bundled kernel missing from publish output"; exit 1 }
$actual = (Get-FileHash $kernel -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) {
    Write-Output "PACKAGE FAIL: kernel hash mismatch (expected $expected, got $actual)"
    exit 1
}

# 3. Exact release layout: 5 root files + core\sing-box.exe + zh satellite + license texts
#    (GPL binary distribution must ship the license and the offer of Corresponding Source)
#    + README (7 payload files + LICENSE + README).
$expectedFiles = @(
    "LaneFlow.deps.json",
    "LaneFlow.dll",
    "LaneFlow.exe",
    "LaneFlow.pdb",
    "LaneFlow.runtimeconfig.json",
    "core\sing-box.exe",
    "zh\LaneFlow.resources.dll",
    "LICENSE\MIT.txt",
    "LICENSE\gpl-3.0.txt",
    "LICENSE\sing-box.txt",
    "README.md"
)
$pkg = Join-Path $repoRoot "$OutDir\LaneFlow-free"
if (Test-Path $pkg) { Remove-Item $pkg -Recurse -Force }
New-Item -ItemType Directory -Path $pkg | Out-Null
foreach ($f in $expectedFiles) {
    if ($repoFiles -contains $f) {
        $src = Join-Path $repoRoot ($f -replace '/', '\')
    } else {
        $src = Join-Path $publishDir ($f -replace '/', '\')
    }
    if (-not (Test-Path $src)) { Write-Output "PACKAGE FAIL: missing $f"; exit 1 }
    $dst = Join-Path $pkg ($f -replace '/', '\')
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
    Copy-Item $src $dst
}

# 4. SHA256SUMS over the package contents (paths relative, forward-slash, sorted).
$sums = Get-ChildItem $pkg -Recurse -File | Sort-Object FullName | ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $rel = $_.FullName.Substring($pkg.Length + 1).Replace('\', '/')
    "{0}  {1}" -f $h, $rel
}
Set-Content -Path (Join-Path $pkg "SHA256SUMS.txt") -Value $sums

# 5. Zip (package name carries the kernel version and the commit for traceability).
$version = (Get-Content (Join-Path $repoRoot "core\VERSION.txt") -TotalCount 1).Trim()
$sha = (git -C $repoRoot rev-parse --short HEAD).Trim()
$zip = Join-Path $repoRoot "$OutDir\LaneFlow-free-$version-$sha.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $pkg '*') -DestinationPath $zip

Write-Output ("PACKAGE OK: {0} ({1} payload files + SHA256SUMS.txt)" -f $zip, $expectedFiles.Count)
exit 0
