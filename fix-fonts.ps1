<#
.SYNOPSIS
  Repair corrupted UI fonts and rebuild font caches on Windows.

.RUNAS
  Run as Administrator.

.NOTES
  Designed for quick remediation in lab or VM environments.
#>

Write-Host "=== Font Repair Script ===" -ForegroundColor Cyan

# Stop font-related services if present
$svcNames = @(
  "FontCache", # Windows Font Cache Service (service name might be "FontCache" or "Windows Font Cache Service")
  "FontCache3.0.0.0", # Windows Presentation Foundation Font Cache 3.0.0.0 (service name sometimes)
  "WSearch" # Optional: Windows Search (stops if necessary for file locks) -- we won't stop automatically
)

function Stop-ServiceIfExists {
  param($Name)
  $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -ne 'Stopped') {
    Write-Host "Stopping service: $Name"
    try { Stop-Service -Name $Name -Force -ErrorAction Stop } catch { Write-Warning "Couldn't stop $Name: $_" }
  }
}

# Try common font cache service names
Stop-ServiceIfExists -Name "FontCache"
Stop-ServiceIfExists -Name "Windows Font Cache Service"
Stop-ServiceIfExists -Name "FontCache3.0.0.0"

# Delete font cache files
$paths = @(
  "$env:windir\ServiceProfiles\LocalService\AppData\Local\FontCache*",
  "$env:localappdata\FontCache*",
  "$env:windir\System32\FNTCACHE.DAT"
)

foreach ($p in $paths) {
  Write-Host "Removing files matching: $p"
  try {
    Get-ChildItem -Path $p -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue -Verbose:$false
  } catch { Write-Warning "Could not delete $p: $_" }
}

# Run DISM / SFC
Write-Host "Running DISM /Online /Cleanup-Image /RestoreHealth (this may take some minutes)..."
try {
  Start-Process -FilePath "DISM.exe" -ArgumentList "/Online","/Cleanup-Image","/RestoreHealth" -Wait -NoNewWindow
} catch { Write-Warning "DISM failed: $_" }

Write-Host "Running sfc /scannow..."
try {
  Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -Wait -NoNewWindow
} catch { Write-Warning "sfc failed: $_" }

# Ensure Segoe UI mapping in registry
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes"
$expectedName = "Segoe UI"
try {
  $val = Get-ItemProperty -Path $regPath -Name $expectedName -ErrorAction SilentlyContinue
  if (-not $val) {
    Write-Host "Segoe UI mapping missing. Restoring registry mapping..."
    New-ItemProperty -Path $regPath -Name $expectedName -PropertyType String -Value "Segoe UI" -Force | Out-Null
    Write-Host "Restored $expectedName -> 'Segoe UI'"
  } else {
    Write-Host "Segoe UI mapping exists."
  }
} catch {
  Write-Warning "Could not inspect/modify $regPath: $_"
}

# Restart font services we attempted to stop
function Start-ServiceIfExists {
  param($Name)
  $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -ne 'Running') {
    Write-Host "Starting service: $Name"
    try { Start-Service -Name $Name -ErrorAction Stop } catch { Write-Warning "Couldn't start $Name: $_" }
  }
}

Start-ServiceIfExists -Name "FontCache"
Start-ServiceIfExists -Name "Windows Font Cache Service"
Start-ServiceIfExists -Name "FontCache3.0.0.0"

Write-Host ""
Write-Host "Font repair actions attempted. A reboot is strongly recommended." -ForegroundColor Yellow
Write-Host "If UI still looks corrupted after reboot, consider restoring fonts from a known good image or rerunning DISM/sfc in WinRE."
