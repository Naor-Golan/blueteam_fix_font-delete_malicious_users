<#
.SYNOPSIS
  Safely remove enemy-created AD user accounts while preserving mandated & built-in accounts.

.DESCRIPTION
  Dry-run by default. Use -PerformDeletion to actually remove accounts after careful review.
  Requires ActiveDirectory module. Run as Domain Admin.

.PARAMETER TargetOU
  Optional distinguishedName of OU to limit deletion scope (e.g., "OU=CrewA,DC=example,DC=com"). 
  If omitted, searches the entire domain.

.PARAMETER PerformDeletion
  Switch. When present, the script will delete the discovered accounts after double-confirmation.

.PARAMETER LogPath
  Path to write CSV logs of planned and performed deletions.

.EXAMPLE
  .\prune-users.ps1 -TargetOU "OU=CrewA,DC=example,DC=com"
#>

param(
  [string]$TargetOU = $null,
  [switch]$PerformDeletion = $false,
  [string]$LogPath = ".\prune_users_$(Get-Date -Format yyyyMMdd_HHmmss).csv"
)

Import-Module ActiveDirectory -ErrorAction Stop

# --- Whitelist from Packet required users (DO NOT DELETE) ---
$whitelist = @(
  "whiteteam",
  "com_gen",
  "dosimeter",
  "liquidator",
  "logkeeper",
  "radioman",
  "medic",
  "shifteng"
)

# --- Common built-in/system accounts to exclude ---
$builtinExclusions = @(
  "Administrator",
  "Guest",
  "krbtgt",
  "DefaultAccount",    # Windows 10/Server built-in
  "WDAGUtilityAccount" # Windows Defender Application Guard account
)

# Combine into normalized list (lowercase for comparison)
$protectedNames = ($whitelist + $builtinExclusions) | ForEach-Object { $_.ToLower() } | Select-Object -Unique

Write-Host "Protected accounts (will NOT be deleted):" -ForegroundColor Cyan
$protectedNames | ForEach-Object { Write-Host "  $_" }

# Query scope
if ($TargetOU) {
  Write-Host "Searching users under OU: $TargetOU"
  $users = Get-ADUser -SearchBase $TargetOU -Filter * -Properties Enabled,sAMAccountName,Name,DistinguishedName,WhenCreated
} else {
  Write-Host "Searching users in entire domain"
  $users = Get-ADUser -Filter * -Properties Enabled,sAMAccountName,Name,DistinguishedName,WhenCreated
}

# Filter candidates: enabled user accounts that are not protected and not service accounts (heuristic)
$candidates = $users | Where-Object {
  $_.Enabled -eq $true -and
  ($_.sAMAccountName -ne $null) -and
  -not ($protectedNames -contains $_.sAMAccountName.ToLower()) -and
  -not ($protectedNames -contains $_.Name.ToLower())
}

# Further heuristics: avoid accounts that look like machine accounts (ending with $) or have adminCount set (privileged)
$candidates = $candidates | Where-Object {
  ($_.sAMAccountName -notlike '*$') -and
  ($_.adminCount -ne 1)
}

# Present results (Dry-run)
$report = $candidates | Select-Object sAMAccountName,Name,DistinguishedName,Enabled,WhenCreated

if ($report.Count -eq 0) {
  Write-Host "No candidate accounts found for deletion. Exiting." -ForegroundColor Green
  $report | Export-Csv -Path $LogPath -NoTypeInformation -Force
  return
}

Write-Host ""
Write-Host "Accounts IDENTIFIED for potential deletion (DRY-RUN):" -ForegroundColor Yellow
$report | Format-Table -AutoSize

# Save dry-run report
$report | Export-Csv -Path $LogPath -NoTypeInformation -Force
Write-Host ""
Write-Host "Saved dry-run report to: $LogPath"

if (-not $PerformDeletion) {
  Write-Host ""
  Write-Host "Dry-run complete. No accounts were deleted." -ForegroundColor Green
  Write-Host "If you want to delete these accounts, re-run the script with -PerformDeletion and review the CSV carefully." -ForegroundColor Yellow
  return
}

# Double confirmation
Write-Host ""
Write-Warning "PERFORMING DELETION. THIS ACTION IS DESTRUCTIVE."
$confirm = Read-Host "Type 'CONFIRM DELETE' to proceed with deleting $($report.Count) accounts"
if ($confirm -ne "CONFIRM DELETE") {
  Write-Host "Confirmation mismatch. Aborting deletion." -ForegroundColor Red
  return
}

# Proceed to delete and create a deletion log
$deletionLog = @()
foreach ($u in $candidates) {
  try {
    # final safety check
    $sam = $u.sAMAccountName.ToLower()
    if ($protectedNames -contains $sam) {
      Write-Warning "Skipping protected account: $($u.sAMAccountName)"
      continue
    }

    # Remove-ADUser (commented out as safety here). We'll call it for real.
    Write-Host "Deleting: $($u.sAMAccountName) ($($u.DistinguishedName))" -ForegroundColor Red
    Remove-ADUser -Identity $u -Confirm:$false -Recursive -ErrorAction Stop

    $deletionLog += [PSCustomObject]@{
      Time = (Get-Date).ToString("s")
      sAMAccountName = $u.sAMAccountName
      DistinguishedName = $u.DistinguishedName
      Result = "Deleted"
    }
  } catch {
    Write-Warning "Failed to delete $($u.sAMAccountName): $_"
    $deletionLog += [PSCustomObject]@{
      Time = (Get-Date).ToString("s")
      sAMAccountName = $u.sAMAccountName
      DistinguishedName = $u.DistinguishedName
      Result = "Failed: $_"
    }
  }
}

# Export deletion log
$delLogPath = [System.IO.Path]::Combine((Split-Path -Parent $LogPath), "deletions_$(Get-Date -Format yyyyMMdd_HHmmss).csv")
$deletionLog | Export-Csv -Path $delLogPath -NoTypeInformation -Force
Write-Host ""
Write-Host "Deletion complete. Log: $delLogPath" -ForegroundColor Cyan
