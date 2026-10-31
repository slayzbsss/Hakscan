# Hakscan installer for Windows — one-liner (PowerShell):
#   irm https://raw.githubusercontent.com/slayzbsss/Hakscan/main/install.ps1 | iex
#
# Downloads the latest prebuilt Hakscan binary for your architecture and installs
# it to %LOCALAPPDATA%\Programs\Hakscan, adding that directory to your user PATH.
# No Go toolchain required.
#
# Options (env vars):
#   $env:HAKSCAN_VERSION = 'v4.6'   install a specific version instead of the latest

$ErrorActionPreference = 'Stop'
$ProgressPreference     = 'SilentlyContinue'  # faster Invoke-WebRequest

$repo = 'slayzbsss/Hakscan'
$bin  = 'hakscan'

function Info($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Die($m)  { Write-Host "error: $m" -ForegroundColor Red; exit 1 }

# --- detect arch ----------------------------------------------------------
switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { $arch = 'amd64' }
  'ARM64' { $arch = 'arm64' }
  'x86'   { Die 'unsupported 32-bit architecture.' }
  default { Die "unsupported architecture '$($env:PROCESSOR_ARCHITECTURE)'." }
}

# --- resolve version ------------------------------------------------------
if ($env:HAKSCAN_VERSION) {
  $tag = $env:HAKSCAN_VERSION
} else {
  Info 'Resolving latest release...'
  try {
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" `
             -Headers @{ 'User-Agent' = 'hakscan-installer' }
    $tag = $rel.tag_name
  } catch { Die "could not resolve the latest version from GitHub: $_" }
}
if (-not $tag) { Die 'empty version tag.' }
$ver = $tag.TrimStart('v')   # strip leading 'v' -> matches asset filename
Info "Installing hakscan $tag (windows/$arch)"

# --- download + extract ---------------------------------------------------
$asset = "${bin}_${ver}_windows_${arch}.zip"
$url   = "https://github.com/$repo/releases/download/$tag/$asset"

$tmp = Join-Path $env:TEMP ("hakscan-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
  $zip = Join-Path $tmp $asset
  Info "Downloading $asset"
  try { Invoke-WebRequest -Uri $url -OutFile $zip } catch { Die "download failed: $url" }

  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  $exe = Get-ChildItem -Path $tmp -Filter "$bin.exe" -Recurse | Select-Object -First 1
  if (-not $exe) { Die "binary '$bin.exe' not found inside the archive." }

  # --- install dir --------------------------------------------------------
  $dir = Join-Path $env:LOCALAPPDATA 'Programs\Hakscan'
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  Copy-Item $exe.FullName (Join-Path $dir "$bin.exe") -Force
  Info "Installed to $dir\$bin.exe"

  # --- add to user PATH ---------------------------------------------------
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (($userPath -split ';') -notcontains $dir) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
    $env:Path = "$env:Path;$dir"
    Info "Added $dir to your user PATH (restart your terminal to pick it up everywhere)."
  }
} finally {
  Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

try { & (Join-Path $dir "$bin.exe") version } catch { }
Write-Host "OK  Hakscan installed. Run: hakscan -h" -ForegroundColor Green
