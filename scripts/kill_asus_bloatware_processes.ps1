<#
.SYNOPSIS
    Kills ASUS bloatware processes on Windows 11.
.DESCRIPTION
    This script forcefully terminates known ASUS/Armoury Crate background processes
    that consume significant RAM (~800 MB). It lists matching processes, then kills them.
.NOTES
    Run as Administrator: right-click PowerShell → "Run as Administrator", then execute.
    Created for Vrindha AI SOC project.
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"

# List of ASUS bloatware process names (without .exe extension)
$targetProcesses = @(
    "ArmouryCrate.UserSessionHelper",
    "AsusSoftwareManagerAgent",
    "AsusSystemAnalysis",
    "AsusSystemDiagnosis",
    "AsusHotkey",
    "AsusOSD",
    "AsusScreenXpertUI",
    "ASSmartDisplayControl",
    "AsusSwitch"
)

Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "  ASUS Bloatware Process Killer" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host ""

# --- Phase 1: List all matching processes ---
Write-Host "[Phase 1] Scanning for ASUS processes..." -ForegroundColor Yellow
Write-Host ""

$foundProcesses = @()
$notFoundProcesses = @()

foreach ($procName in $targetProcesses) {
    try {
        $procs = Get-Process -Name $procName -ErrorAction Stop
        foreach ($proc in $procs) {
            $foundProcesses += $proc
            $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 1)
            Write-Host ("  Found: {0,-40} PID: {1,-6} RAM: {2} MB" -f $proc.ProcessName, $proc.Id, $memMB) -ForegroundColor Red
        }
    }
    catch {
        $notFoundProcesses += $procName
        Write-Host ("  Not running: {0}" -f $procName) -ForegroundColor DarkGray
    }
}

$totalMem = [math]::Round(($foundProcesses | Measure-Object WorkingSet64 -Sum).Sum / 1MB, 1)

Write-Host ""
Write-Host ("  Total found: {0} | Not running: {1}" -f $foundProcesses.Count, $notFoundProcesses.Count) -ForegroundColor White
Write-Host ("  Total RAM consumed: {0} MB" -f $totalMem) -ForegroundColor White
Write-Host ""

if ($foundProcesses.Count -eq 0) {
    Write-Host "No ASUS bloatware processes are currently running." -ForegroundColor Green
    Write-Host "Either they were already killed or the names have changed." -ForegroundColor Green
    exit 0
}

# --- Phase 2: Kill the processes ---
Write-Host "[Phase 2] Killing ASUS processes..." -ForegroundColor Yellow
Write-Host ""

$killedCount = 0
$killFailedCount = 0
$freedMem = 0.0

foreach ($proc in $foundProcesses) {
    $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 1)
    Write-Host ("  Killing {0} (PID {1}, {2} MB)..." -f $proc.ProcessName, $proc.Id, $memMB) -ForegroundColor White -NoNewline
    try {
        Stop-Process -Id $proc.Id -Force -ErrorAction Stop
        # Wait briefly for the process to actually exit
        $timeout = 5
        $elapsed = 0
        while (-not $proc.HasExited -and $elapsed -lt $timeout) {
            Start-Sleep -Seconds 1
            $elapsed++
        }
        if ($proc.HasExited) {
            Write-Host " OK" -ForegroundColor Green
            $killedCount++
            $freedMem += $memMB
        }
        else {
            Write-Host " TIMEOUT" -ForegroundColor DarkYellow
            $killFailedCount++
        }
    }
    catch {
        Write-Host " FAILED: $_" -ForegroundColor Red
        $killFailedCount++
    }
}

Write-Host ""
Write-Host ("  Killed: {0} | Failed: {1}" -f $killedCount, $killFailedCount) -ForegroundColor White
Write-Host ""

# --- Summary ---
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host ("  Processes found:     {0}" -f $foundProcesses.Count)
Write-Host ("  Processes killed:    {0}" -f $killedCount)
Write-Host ("  Kill failures:       {0}" -f $killFailedCount)
Write-Host ("  RAM freed (approx):  {0} MB" -f $freedMem)
Write-Host ""

if ($killFailedCount -eq 0) {
    Write-Host "  All ASUS bloatware processes have been terminated." -ForegroundColor Green
    Write-Host "  You should see immediate RAM relief." -ForegroundColor Green
}
else {
    Write-Host "  Some processes could not be killed. Check the output above." -ForegroundColor Yellow
    Write-Host "  You may need to manually end them in Task Manager." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Note: Some processes may restart automatically if their" -ForegroundColor DarkYellow
Write-Host "  parent service is still running. Run the service stopper" -ForegroundColor DarkYellow
Write-Host "  script first for best results." -ForegroundColor DarkYellow
Write-Host "=" * 60 -ForegroundColor Cyan
