<#
.SYNOPSIS
    Stops and disables ASUS bloatware services on Windows 11.
.DESCRIPTION
    This script targets known ASUS/Armoury Crate background services that consume
    significant RAM (~800 MB). It first lists all matching services with their
    current status, then stops any running ones and sets them to Disabled so they
    do not restart on the next boot.
.NOTES
    Run as Administrator: right-click PowerShell → "Run as Administrator", then execute.
    Created for Vrindha AI SOC project.
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"

# List of ASUS bloatware service names (short names as shown in services.msc / Get-Service)
$targetServices = @(
    "ArmouryCrateService",
    "ArmouryCrateControlInterface",
    "AsusAppService",
    "AsusMsControl",
    "ASUSOptimization",
    "AsusPTPService",
    "AsusScreenXpertHostService",
    "ASUSSoftwareManager",
    "ASUSSwitch",
    "ASUSSystemAnalysis",
    "ASUSSystemDiagnosis",
    "asus",
    "asusm"
)

Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "  ASUS Bloatware Service Stopper" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host ""

# --- Phase 1: List all matching services ---
Write-Host "[Phase 1] Scanning for ASUS services..." -ForegroundColor Yellow
Write-Host ""

$foundServices = @()
$notFoundServices = @()

foreach ($svcName in $targetServices) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction Stop
        $foundServices += $svc
        $statusColor = if ($svc.Status -eq "Running") { "Red" } else { "Green" }
        Write-Host ("  Found: {0,-40} Status: {1}" -f $svc.Name, $svc.Status) -ForegroundColor $statusColor
    }
    catch {
        $notFoundServices += $svcName
        Write-Host ("  Not found: {0}" -f $svcName) -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host ("  Total found: {0} | Not found: {1}" -f $foundServices.Count, $notFoundServices.Count) -ForegroundColor White
Write-Host ""

if ($foundServices.Count -eq 0) {
    Write-Host "No ASUS bloatware services found on this system." -ForegroundColor Green
    Write-Host "Either they were already removed or the names have changed." -ForegroundColor Green
    exit 0
}

# --- Phase 2: Stop running services ---
Write-Host "[Phase 2] Stopping running services..." -ForegroundColor Yellow
Write-Host ""

$stoppedCount = 0
$stopFailedCount = 0

foreach ($svc in $foundServices) {
    if ($svc.Status -eq "Running") {
        Write-Host ("  Stopping {0}..." -f $svc.Name) -ForegroundColor White -NoNewline
        try {
            Stop-Service -Name $svc.Name -Force -ErrorAction Stop
            # Wait briefly for the service to actually stop
            $timeout = 10
            $elapsed = 0
            while ((Get-Service -Name $svc.Name).Status -ne "Stopped" -and $elapsed -lt $timeout) {
                Start-Sleep -Seconds 1
                $elapsed++
            }
            if ((Get-Service -Name $svc.Name).Status -eq "Stopped") {
                Write-Host " OK" -ForegroundColor Green
                $stoppedCount++
            }
            else {
                Write-Host " TIMEOUT (may still be stopping)" -ForegroundColor DarkYellow
                $stopFailedCount++
            }
        }
        catch {
            Write-Host " FAILED: $_" -ForegroundColor Red
            $stopFailedCount++
        }
    }
    else {
        Write-Host ("  Skipping {0} (already {1})" -f $svc.Name, $svc.Status) -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host ("  Stopped: {0} | Failed: {1}" -f $stoppedCount, $stopFailedCount) -ForegroundColor White
Write-Host ""

# --- Phase 3: Disable services from auto-starting ---
Write-Host "[Phase 3] Disabling services from auto-start..." -ForegroundColor Yellow
Write-Host ""

$disabledCount = 0
$disableFailedCount = 0

foreach ($svc in $foundServices) {
    try {
        $currentStart = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)" -Name Start -ErrorAction SilentlyContinue).Start
        if ($currentStart -eq 4) {
            Write-Host ("  {0} already disabled" -f $svc.Name) -ForegroundColor DarkGray
            $disabledCount++
            continue
        }
        Write-Host ("  Disabling {0}..." -f $svc.Name) -ForegroundColor White -NoNewline
        Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
        Write-Host " OK" -ForegroundColor Green
        $disabledCount++
    }
    catch {
        Write-Host " FAILED: $_" -ForegroundColor Red
        $disableFailedCount++
    }
}

Write-Host ""
Write-Host ("  Disabled: {0} | Failed: {1}" -f $disabledCount, $disableFailedCount) -ForegroundColor White
Write-Host ""

# --- Summary ---
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host ("  Services found:      {0}" -f $foundServices.Count)
Write-Host ("  Services stopped:    {0}" -f $stoppedCount)
Write-Host ("  Services disabled:   {0}" -f $disabledCount)
Write-Host ("  Stop failures:       {0}" -f $stopFailedCount)
Write-Host ("  Disable failures:    {0}" -f $disableFailedCount)
Write-Host ""

if ($stopFailedCount -eq 0 -and $disableFailedCount -eq 0) {
    Write-Host "  All ASUS bloatware services have been stopped and disabled." -ForegroundColor Green
    Write-Host "  You should see reduced RAM usage after a reboot." -ForegroundColor Green
}
else {
    Write-Host "  Some operations failed. Check the output above for details." -ForegroundColor Yellow
    Write-Host "  You may need to manually disable stubborn services in services.msc." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  A system reboot is recommended to fully release resources." -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
