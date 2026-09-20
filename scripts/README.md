# ASUS Bloatware Removal Scripts

PowerShell scripts to stop, disable, and kill ASUS bloatware services and processes on Windows 11.

## Files

| File | Purpose |
|------|---------|
| `stop_asus_bloatware_services.ps1` | Stops running ASUS services and disables them from auto-starting |
| `kill_asus_bloatware_processes.ps1` | Forcefully kills ASUS bloatware processes |

## How to Run

### Prerequisites
- Windows 11 (Home or Pro)
- Administrator privileges

### Steps

1. **Open PowerShell as Administrator**
   - Press `Win + S` and type `PowerShell`
   - Right-click **Windows PowerShell** → **Run as Administrator**
   - Click **Yes** on the UAC prompt

2. **Allow script execution** (if not already enabled)
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
   ```

3. **Run the service stopper first** (recommended order)
   ```powershell
   C:\Users\n4ndh\Documents\port\vrind\BACKEND\scripts\stop_asus_bloatware_services.ps1
   ```

4. **Then run the process killer**
   ```powershell
   C:\Users\n4ndh\Documents\port\vrind\BACKEND\scripts\kill_asus_bloatware_processes.ps1
   ```

5. **Reboot your system** to fully release resources
   ```powershell
   Restart-Computer
   ```

## What These Scripts Do

### Service Stopper (`stop_asus_bloatware_services.ps1`)
- Scans for 13 known ASUS bloatware services
- Lists each service with its current status
- Stops any running services
- Disables services from auto-starting on boot
- Provides a summary of actions taken

**Targeted services:**
- ArmouryCrateService
- ArmouryCrateControlInterface
- AsusAppService
- AsusMsControl
- ASUSOptimization
- AsusPTPService
- AsusScreenXpertHostService
- ASUSSoftwareManager
- ASUSSwitch
- ASUSSystemAnalysis
- ASUSSystemDiagnosis
- asus
- asusm

### Process Killer (`kill_asus_bloatware_processes.ps1`)
- Scans for 9 known ASUS bloatware processes
- Lists each process with its PID and RAM usage
- Forcefully terminates all matching processes
- Reports approximate RAM freed

**Targeted processes:**
- ArmouryCrate.UserSessionHelper
- AsusSoftwareManagerAgent
- AsusSystemAnalysis
- AsusSystemDiagnosis
- AsusHotkey
- AsusOSD
- AsusScreenXpertUI
- ASUSSmartDisplayControl
- AsusSwitch

## Expected Results
- **RAM savings:** ~800 MB (varies by system)
- **Fewer background processes** running
- **Faster boot times**
- **Reduced CPU usage** from ASUS services

## Safety Notes
- These scripts only target ASUS-branded services/processes
- They do not modify system files or the registry (except service startup type)
- If you need ASUS features later, re-enable services in `services.msc`
- Some ASUS functionality (RGB lighting, fan control, hotkeys) will be disabled

## Troubleshooting

**"Script cannot be loaded because running scripts is disabled"**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
```

**"Access Denied" errors**
- Make sure you're running PowerShell as Administrator

**Services keep coming back**
- Some ASUS services have self-healing mechanisms. Run both scripts, then reboot immediately.

**Need to restore ASUS functionality**
- Open `services.msc`, find the ASUS services, and set them to "Manual" or "Automatic"
