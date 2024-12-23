# Automated Hardening Script for Windows
# Each Section is labeled, it is highly recommended to review what changes will be made before using this

# Ensure the script is running with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Rerun as an administrator."
    exit
}

# Dump User List
Write-Output "Dumping User List..."
Get-LocalUser | Format-Table Name, Enabled, LastLogon, Description -AutoSize > UserList.txt
Write-Output "User list dumped to UserList.txt"
Get-Content UserList.txt

# Dump User Privileges
Write-Output "Dumping User Privileges..."
Get-LocalUser | ForEach-Object {
    $user = $_.Name
    $privileges = net user $user | Select-String "Privilege"
    Write-Output "User: $user"
    Write-Output $privileges
    Write-Output ""
} > UserPrivileges.txt
Write-Output "User privileges dumped to UserPrivileges.txt"

# Remove Guest Users
Write-Output "Removing Guest Users..."
$guestUsers = Get-LocalUser | Where-Object { $_.Description -match "guest" -or $_.Name -match "guest" }
foreach ($guest in $guestUsers) {
    try {
        Disable-LocalUser -Name $guest.Name
        Write-Output "Disabled Guest User: $($guest.Name)"
    } catch {
        Write-Error "Failed to disable guest user: $($guest.Name)"
    }
}
Write-Output "Guest users processed."

# Dump Groups
Write-Output "Dumping Groups..."
Get-LocalGroup | Format-Table Name, Description -AutoSize > GroupList.txt
Write-Output "Group list dumped to GroupList.txt"

# Dump Group Privileges
Write-Output "Dumping Group Privileges..."
Get-LocalGroup | ForEach-Object {
    $group = $_.Name
    $members = Get-LocalGroupMember -Group $group | Select-Object Name, ObjectClass
    Write-Output "Group: $group"
    Write-Output $members
    Write-Output ""
} > GroupPrivileges.txt
Write-Output "Group privileges dumped to GroupPrivileges.txt"
Get-Content GroupPrivileges.txt

Write-Output "User/Group Permissions Processed, Proceeding to next Stage"

# Password Rule Enforcement
Write-Output "Passwords must be 12 digits"
net accounts /minpwlen:12
Write-Output "Passwords must be changed every 30 days"
net accounts /maxpwage:30
Write-Output "Passwords can only be changed after 5 day has passed"
net accounts /minpwage:5
Write-Output "Display current password policy"
echo "CURRENT POLICY"

# Running Services

# Create output directory
$outputDir = "C:\ProcessDump"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}
Write-Output "Output directory: $outputDir"

# 1. Dump the list of current running processes
Write-Output "Dumping list of current running processes..."
Get-Process | Select-Object Name, Id, CPU, WorkingSet, StartTime | Export-Csv -Path "$outputDir\RunningProcesses.csv" -NoTypeInformation
Write-Output "Running processes saved to $outputDir\RunningProcesses.csv"

# 2. Dump the list of services (processes that could run)
Write-Output "Dumping list of services (running and stopped)..."
Get-Service | Select-Object Name, DisplayName, Status | Export-Csv -Path "$outputDir\Services.csv" -NoTypeInformation
Write-Output "Services saved to $outputDir\Services.csv"

# 3. Dump tasks queued to run (Scheduled Tasks)
Write-Output "Dumping tasks queued to run..."
schtasks.exe /Query /FO CSV /V | ConvertFrom-Csv | Export-Csv -Path "$outputDir\ScheduledTasks.csv" -NoTypeInformation
Write-Output "Scheduled tasks saved to $outputDir\ScheduledTasks.csv"

# 4. Dump run details in the registry
Write-Output "Dumping run details in the registry..."
$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
$runDetails = foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Get-ItemProperty -Path $key | Select-Object PSPath, *
    }
}
$runDetails | Export-Csv -Path "$outputDir\RegistryRunDetails.csv" -NoTypeInformation
Write-Output "Registry run details saved to $outputDir\RegistryRunDetails.csv"

Write-Output "Checking processes done, moving to register review"

# Check Registers

# Output Directory
$outputDir = "C:\RegistryChecks"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}
Write-Output "Output directory: $outputDir"

# Initialize results
$results = @()

# Function to scan a registry key
function Scan-RegistryKey {
    param (
        [string]$Path,
        [string]$Description
    )
    Write-Output "Checking $Description at $Path..."
    if (Test-Path $Path) {
        try {
            Get-ItemProperty -Path $Path | ForEach-Object {
                [PSCustomObject]@{
                    Path        = $Path
                    Description = $Description
                    KeyName     = $_.PSChildName
                    Value       = $_
                }
            } | ForEach-Object { $results += $_ }
        } catch {
            Write-Warning "Error accessing $Path: $_"
        }
    } else {
        Write-Output "Path $Path does not exist."
    }
}

# Scan critical registry keys
$criticalKeys = @(
    @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"; Description = "Auto-Start Programs (All Users)" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"; Description = "Auto-Start Programs (Current User)" },
    @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"; Description = "One-Time Auto-Start (All Users)" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"; Description = "One-Time Auto-Start (Current User)" },
    @{ Path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"; Description = "Winlogon Settings" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"; Description = "Explorer Shell Folders (Current User)" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"; Description = "User Shell Folders (Current User)" }
)

foreach ($key in $criticalKeys) {
    Scan-RegistryKey -Path $key.Path -Description $key.Description
}

# Check for hidden or suspicious registry keys using `reg query`
Write-Output "Checking for suspicious hidden registry keys..."
$hiddenKeys = @()
try {
    $hiddenKeys = reg query HKLM /s /f /t REG_SZ | Select-String -Pattern "\\ControlSet[0-9]+" -SimpleMatch
    $hiddenKeys | Out-File -FilePath "$outputDir\HiddenRegistryKeys.txt"
    Write-Output "Suspicious registry keys saved to $outputDir\HiddenRegistryKeys.txt"
} catch {
    Write-Warning "Failed to query hidden registry keys: $_"
}

# Export results
if ($results.Count -gt 0) {
    $results | Export-Csv -Path "$outputDir\RegistryCheckResults.csv" -NoTypeInformation
    Write-Output "Registry check results saved to $outputDir\RegistryCheckResults.csv"
} else {
    Write-Output "No unusual registry entries found."
}

Write-Output "Registry check completed."


# Tool Search

# Display message
Write-Host "Finding Hacktools across the entire machine..."

# Define search terms and corresponding messages
# add any other prohibited services/tools as needed
$searchTerms = @{
    "Cain"           = "Cain detected. Please take note, then press any key."
    "nmap"           = "Nmap detected. Please take note, then press any key."
    "keylogger"      = "Potential keylogger detected. Please take note, then press any key."
    "John"           = "John the Ripper detetcted. Please take note, then press any key."
    "Nikto"          = "Nikto detected, Please take note, then press any key."
    "Armitage"       = "Potential Armitage detected. Please take note, then press any key."
    "Metasploit"     = "Potential Metasploit framework detected. Please take note, then press any key."
    "Shellter"       = "Potential Shellter detected. Please take note, then press any key."
    "Mimikatz"       = "Mimikatz detected. Please investigate further."
    "rubeus"         = "Rubeus detected. Possible Kerberoasting tool found."
    "Impacket"       = "Impacket detected. Common in lateral movement and Kerberoasting attacks."
    "BloodHound"     = "BloodHound detected. Investigate for AD enumeration."
    "CobaltStrike"   = "Cobalt Strike beacon detected. Check for potential C2 connection."
    "Empire"         = "PowerShell Empire detected. Investigate for potential C2 activity."
    "Silver"         = "Silver C2 framework detected. Investigate further."
    "Invoke-Kerberoast" = "Invoke-Kerberoast script detected. Possible Kerberoasting activity."
    "SharpHound"     = "SharpHound detected. Investigate for AD enumeration."
    "PSExec"         = "PSExec tool detected. Common in lateral movement."
    "Kerberoast"     = "Kerberoast tool or keyword detected. Investigate further."
    "Golden Ticket"  = "Golden Ticket keyword found. Potential pass-the-ticket attack."
    "Beacon"         = "Cobalt Strike Beacon keyword found. Investigate for C2 activity."
    "Covenant"       = "Covenant C2 framework detected. Investigate further."
    "Sliver"         = "Sliver C2 framework detected. Investigate further."
}

# Define starting directory (entire system)
$startDirectory = "C:\"

# Loop through each search term
foreach ($term in $searchTerms.Keys) {
    Write-Host "Searching for: $term..."
    
    try {
        # Search the entire file system for matches
        $results = Get-ChildItem -Path $startDirectory -Recurse -ErrorAction SilentlyContinue | `
                   Select-String -Pattern $term -SimpleMatch -ErrorAction SilentlyContinue

        if ($results) {
            Write-Host $searchTerms[$term]
            Read-Host "Press Enter to continue"
            Clear-Host
        }
    } catch {
        Write-Warning "Error while searching for $term: $_"
    }
}

Write-Host "Search completed."