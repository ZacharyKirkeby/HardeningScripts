# Run as Administrator
$LogFile = "C:\Temp\ProcessAudit.txt"

function Log {
    Param ($Message)
    Add-Content -Path $LogFile -Value "[+] $Message"
}

Write-Host "Starting auditing"

# 1. Identify Unknown Processes
Log "Identifying running processes..."
$allProcesses = Get-Process | Select-Object Id, ProcessName, Path, StartInfo, MainWindowTitle, Description
$allProcesses | Format-Table -AutoSize | Out-File -Append $LogFile

# 2. Verify Executable Paths and Digital Signatures
Log "Checking process details..."
foreach ($proc in $allProcesses) {
    if ($proc.Path -and (Test-Path $proc.Path)) {
        $signature = Get-AuthenticodeSignature $proc.Path
        if ($signature.Status -ne 'Valid') {
            Log "Unsigned or Invalid Signature - $($proc.ProcessName) at $($proc.Path)"
        }
        if ($proc.Path -notlike "C:\Windows\System32\*") {
            Log "Suspicious Path: $($proc.ProcessName) running from $($proc.Path)"
        }
    } else {
        Log "Hidden Process - $($proc.ProcessName)"
    }
}

# 3. Check Command Lines for Suspicious Execution
Log "Checking process command lines..."
Get-WmiObject Win32_Process | Select-Object ProcessId, CommandLine | 
    Where-Object { $_.CommandLine -match "powershell|invoke|download|exec" } |
    Format-Table -AutoSize | Out-File -Append $LogFile

# 4. Analyze Network Connections
Log "Analyzing network connections..."
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
    Sort-Object RemoteAddress | Format-Table -AutoSize | Out-File -Append $LogFile

# 5. Check Open File Handles and Unusual Locks
Log "Checking open file handles..."
foreach ($proc in $allProcesses) {
    try {
        $handles = (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue).Modules
        if ($handles -match "lock") {
            Log "Potential Locked File: $($proc.ProcessName)"
        }
    } catch {
        Log "Error accessing process $($proc.ProcessName) - It may be protected."
    }
}

# 6. Review Scheduled Tasks
Log "Checking scheduled tasks..."
Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } |
    Select-Object TaskName, TaskPath, Actions | Format-Table -AutoSize | Out-File -Append $LogFile

# 7. Check Process Ancestry for Orphaned or Suspicious Parents
Log "Checking process ancestry..."
Get-WmiObject Win32_Process | Select-Object ProcessId, ParentProcessId, Name | 
    Sort-Object ParentProcessId | Format-Table -AutoSize | Out-File -Append $LogFile

# 8. Check Auto-Start Locations for Persistence Mechanisms
Log "Checking auto-start locations..."
$autoRunPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($path in $autoRunPaths) {
    if (Test-Path $path) {
        Get-ItemProperty -Path $path | Format-Table -AutoSize | Out-File -Append $LogFile
    }
}

Log "Process Audit Complete! Log saved to $LogFile"
