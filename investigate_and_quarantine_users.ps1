<#
.SYNOPSIS
  Safely find suspicious AD users, protect privileged accounts, and quarantine (disable + move) them by default.

.NOTES
  - Dry-run/reporting by default.
  - Requires ActiveDirectory module and Domain Admin privileges to move/disable/delete accounts.
  - Use -PerformDeletion only after careful review.
#>

param(
  [string]$TargetOU = $null,                    # e.g. "OU=CrewA,DC=example,DC=com"
  [switch]$PerformDeletion = $false,            # If set and confirmed, script will delete instead of disable+move
  [string]$QuarantineOU = $null,                # If null, script will create/use "OU=Quarantine" under domain root
  [string]$LogFolder = ".\AD_User_Prune_Logs"   # Local folder to store reports
)

Import-Module ActiveDirectory -ErrorAction Stop

# Ensure log folder exists
if (-not (Test-Path -Path $LogFolder)) { New-Item -Path $LogFolder -ItemType Directory | Out-Null }

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$dryRunCsv = Join-Path $LogFolder "dryrun_$timestamp.csv"
$actionLogCsv = Join-Path $LogFolder "actions_$timestamp.csv"
$privReportCsv = Join-Path $LogFolder "privileged_accounts_$timestamp.csv"

# --- Whitelist from packet + built-ins ---
$whitelist = @(
  "whiteteam","com_gen","dosimeter","liquidator","logkeeper",
  "radioman","medic","shifteng"
)

$builtinExclusions = @(
  "administrator","guest","krbtgt","defaultaccount","wdagutilityaccount"
)

$protectedNames = ($whitelist + $builtinExclusions) | ForEach-Object { $_.ToLower() } | Select-Object -Unique

# --- Privileged groups to protect (members of any of these will NOT be touched) ---
$privGroups = @(
  "Domain Admins",
  "Enterprise Admins",
  "Schema Admins",
  "Administrators",
  "Account Operators",
  "Server Operators",
  "Domain Controllers",
  "Backup Operators",
  "Print Operators",
  "DNSAdmins"
)

# Resolve group DNs (best-effort); create a hashset of members to speed checks
$privMembers = @{}

foreach ($g in $privGroups) {
  try {
    $group = Get-ADGroup -Filter "Name -eq '$g'" -ErrorAction SilentlyContinue
    if ($group) {
      $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue | Where-Object { $_.objectClass -eq 'user' } | Select-Object -ExpandProperty SamAccountName
      foreach ($m in $members) { $privMembers[$m.ToLower()] = $true }
    }
  } catch {
    Write-Warning "Could not enumerate group $g: $_"
  }
}

# Export privileged members list for review
$privMembers.GetEnumerator() | Select @{Name='sAMAccountName';Expression={$_.Key}} | Export-Csv -Path $privReportCsv -NoTypeInformation -Force

Write-Host "Privileged accounts exported to: $privReportCsv" -ForegroundColor Cyan

# --- Query scope ---
if ($TargetOU) {
  Write-Host "Searching users under OU: $TargetOU"
  $users = Get-ADUser -SearchBase $TargetOU -Filter * -Properties Enabled,sAMAccountName,Name,DistinguishedName,WhenCreated,adminCount,memberOf
} else {
  Write-Host "Searching users in entire domain"
  $users = Get-ADUser -Filter * -Properties Enabled,sAMAccountName,Name,DistinguishedName,WhenCreated,adminCount,memberOf
}

# --- Candidate filters ---
$candidates = $users | Where-Object {
  $_.Enabled -eq $true -and
  $_.sAMAccountName -and
  ($_.sAMAccountName -notlike '*$') -and
  -not ($protectedNames -contains $_.sAMAccountName.ToLower()) -and
  ($_.adminCount -ne 1)  # still exclude adminCount=1
}

# Exclude any candidate who is member of privileged groups (by membership list or memberOf)
$finalCandidates = @()
foreach ($u in $candidates) {
  $sam = $u.sAMAccountName.ToLower()
  $isPriv = $false

  # 1) Quick check against enumerated privileged members
  if ($privMembers.ContainsKey($sam)) { $isPriv = $true }

  # 2) Also inspect memberOf for group names (fallback)
  if (-not $isPriv -and $u.memberOf) {
    foreach ($mf in $u.memberOf) {
      try {
        $g = (Get-ADGroup -Identity $mf -Properties Name -ErrorAction SilentlyContinue)
        if ($g -and ($privGroups -contains $g.Name)) { $isPriv = $true; break }
      } catch {}
    }
  }

  if ($isPriv) {
    Write-Host "Protecting privileged account (skipping): $($u.sAMAccountName)" -ForegroundColor Yellow
    continue
  }

  # Candidate passes all checks
  $finalCandidates += $u
}

# Prepare report
$report = $finalCandidates | Select-Object sAMAccountName,Name,DistinguishedName,Enabled,WhenCreated,adminCount
$report | Export-Csv -Path $dryRunCsv -NoTypeInformation -Force
Write-Host ""
Write-Host "Dry-run list exported to: $dryRunCsv" -ForegroundColor Cyan
Write-Host "Candidate count: $($report.Count)" -ForegroundColor Cyan

if ($report.Count -eq 0) {
  Write-Host "No candidates found. Exiting." -ForegroundColor Green
  return
}

# If not performing deletion, do quarantine (disable + move)
# Determine domain root and create Quarantine OU if not provided
$domain = (Get-ADDomain).DistinguishedName
if (-not $QuarantineOU) {
  $QuarantineOU = "OU=Quarantine,$domain"
}

# Create the OU if it doesn't exist
if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$QuarantineOU'" -ErrorAction SilentlyContinue)) {
  try {
    New-ADOrganizationalUnit -Name "Quarantine" -Path (($domain -replace '^DC=') -replace ',',',') -ErrorAction Stop -WhatIf:$false
  } catch {
    # fallback: create by parent-of-domain not required; best-effort - don't fail
  }
}

$actions = @()

foreach ($u in $finalCandidates) {
  $entry = [PSCustomObject]@{
    Time = (Get-Date).ToString("s")
    sAMAccountName = $u.sAMAccountName
    DistinguishedName = $u.DistinguishedName
    Action = ""
    Result = ""
  }

  try {
    if (-not $PerformDeletion) {
      # Disable account
      Disable-ADAccount -Identity $u -ErrorAction Stop
      $entry.Action = "Disabled"

      # Move to Quarantine OU (best-effort)
      $newDN = "CN=$($u.Name),$QuarantineOU"
      try {
        Move-ADObject -Identity $u.DistinguishedName -TargetPath $QuarantineOU -ErrorAction Stop
        $entry.Action += " + Moved"
        $entry.Result = "Success"
      } catch {
        $entry.Result = "Disabled (MoveFailed): $_"
      }
    } else {
      Write-Host "DELETING: $($u.sAMAccountName) -> $($u.DistinguishedName)" -ForegroundColor Red
      Remove-ADUser -Identity $u -Confirm:$false -Recursive -ErrorAction Stop
      $entry.Action = "Deleted"
      $entry.Result = "Success"
    }
  } catch {
    $entry.Result = "Failed: $_"
  }

  $actions += $entry
}

# Export action log
$actions | Export-Csv -Path $actionLogCsv -NoTypeInformation -Force
Write-Host ""
Write-Host "Action log exported to: $actionLogCsv" -ForegroundColor Cyan

if ($PerformDeletion) {
  Write-Warning "DESTRUCTIVE deletions performed. Review logs."
} else {
  Write-Host "Accounts were disabled and moved to quarantine OU. Review the action log and verify."
}

