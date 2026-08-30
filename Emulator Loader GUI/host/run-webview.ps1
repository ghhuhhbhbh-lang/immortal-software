# Launch Immortal Loader GUI inside Edge WebView2 app mode (no native compile needed).
$ErrorActionPreference = 'Stop'
$gui = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $gui 'index.html'))) {
  $gui = $PSScriptRoot
}
$index = (Resolve-Path (Join-Path $gui 'index.html')).Path
$url = 'file:///' + ($index -replace '\\', '/')

$edge = @(
  "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe",
  "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
  "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $edge) { throw 'Microsoft Edge not found (needed for WebView2 app mode).' }

Start-Process -FilePath $edge -ArgumentList @(
  "--app=$url",
  '--disable-features=TranslateUI',
  '--no-first-run'
)
Write-Host "Opened Immortal Loader in Edge app/WebView mode:"
Write-Host $url
