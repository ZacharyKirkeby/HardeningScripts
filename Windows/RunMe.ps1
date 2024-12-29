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

Write-Host "Malicious Tool Search completed."

# The following requires manual follow up:
# DLL Hash validation

# Display message
Write-Host "Scanning system DLLs and saving their hashes..."

# Parameters
$startDirectory = "C:\" # Directory to start scanning (can be adjusted to specific paths)
$logFile = "C:\DLL_Hashes.txt" # Path to save the hashes

# Initialize or clear the log file
if (Test-Path $logFile) { Remove-Item -Path $logFile }
"System DLL Hashes - Generated on $(Get-Date)" | Out-File -FilePath $logFile

# Function to compute the SHA256 hash of a file
function Get-FileHashValue {
    param (
        [string]$FilePath
    )
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash
    } catch {
        Write-Warning "Failed to compute hash for: $FilePath"
        return $null
    }
}

# Recursively scan all DLLs on the system and compute their hashes
try {
    Get-ChildItem -Path $startDirectory -Recurse -Include *.dll -ErrorAction SilentlyContinue | ForEach-Object {
        $dllPath = $_.FullName
        $dllHash = Get-FileHashValue -FilePath $dllPath
        
        # Only log if the hash was successfully computed
        if ($dllHash) {
            "$dllHash`t$dllPath" | Out-File -FilePath $logFile -Append
        }
    }
} catch {
    Write-Warning "An error occurred during the scan: $_"
}

Write-Host "Scan complete. DLL hashes saved to $logFile"
Write-Host "Compare hash list to know malicious files"

# Display message
Write-Host "DISABLING WEAK SERVICES"

# List of features to disable
# Review and change as needed based on system
$featuresToDisable = @(
    "IIS-WebServerRole",
    "IIS-WebServer",
    "IIS-CommonHttpFeatures",
    "IIS-HttpErrors",
    "IIS-HttpRedirect",
    "IIS-ApplicationDevelopment",
    "IIS-NetFxExtensibility",
    "IIS-NetFxExtensibility45",
    "IIS-HealthAndDiagnostics",
    "IIS-HttpLogging",
    "IIS-LoggingLibraries",
    "IIS-RequestMonitor",
    "IIS-HttpTracing",
    "IIS-Security",
    "IIS-URLAuthorization",
    "IIS-RequestFiltering",
    "IIS-IPSecurity",
    "IIS-Performance",
    "IIS-HttpCompressionDynamic",
    "IIS-WebServerManagementTools",
    "IIS-ManagementScriptingTools",
    "IIS-IIS6ManagementCompatibility",
    "IIS-Metabase",
    "IIS-HostableWebCore",
    "IIS-StaticContent",
    "IIS-DefaultDocument",
    "IIS-DirectoryBrowsing",
    "IIS-WebDAV",
    "IIS-WebSockets",
    "IIS-ApplicationInit",
    "IIS-ASPNET",
    "IIS-ASPNET45",
    "IIS-ASP",
    "IIS-CGI",
    "IIS-ISAPIExtensions",
    "IIS-ISAPIFilter",
    "IIS-ServerSideIncludes",
    "IIS-CustomLogging",
    "IIS-BasicAuthentication",
    "IIS-HttpCompressionStatic",
    "IIS-ManagementConsole",
    "IIS-ManagementService",
    "IIS-WMICompatibility",
    "IIS-LegacyScripts",
    "IIS-LegacySnapIn",
    "IIS-FTPServer",
    "IIS-FTPSvc",
    "IIS-FTPExtensibility",
    "TFTP",
    "TelnetClient",
    "TelnetServer"
)

# Loop through and disable each feature
foreach ($feature in $featuresToDisable) {
    try {
        Write-Host "Disabling feature: $feature"
        Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop
        Write-Host "$feature disabled successfully."
    } catch {
        Write-Warning "Failed to disable feature: $feature. Error: $_"
    }
}

# Notify completion
Write-Host "All specified features have been processed."

# Enable UAC
Write-Host "Enabling User Account Control (UAC)..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force
Write-Host "UAC has been enabled."

# Disable Remote Desktop Protocol (RDP)
Write-Host "Disabling Remote Desktop Protocol (RDP)..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -Force
Write-Host "RDP has been disabled."

# Disable SMBv1
Write-Host "Disabling SMBv1 protocol..."
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue
Write-Host "SMBv1 protocol has been disabled."

# Notify completion
Write-Host "All registry changes have been applied successfully."

# Firewall finally

Write-Host "Starting Windows Firewall Configuration..."

# Set Default Policies
Write-Host "Setting default inbound and outbound policies..."
New-NetFirewallRule -DisplayName "Block All Incoming by Default" -Direction Inbound -Action Block -Profile Any -Enabled True
New-NetFirewallRule -DisplayName "Allow All Outgoing by Default" -Direction Outbound -Action Allow -Profile Any -Enabled True

# Allow SSH (Port 22)
Write-Host "Allowing SSH on port 22..."
New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow

# Allow HTTPS (Port 443)
Write-Host "Allowing HTTPS on port 443..."
New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow

# Allow DNS (Port 53 UDP)
Write-Host "Allowing DNS on port 53 (UDP)..."
New-NetFirewallRule -DisplayName "Allow DNS" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow

# Block ICMP (Ping)
Write-Host "Blocking ICMP (Ping)..."
New-NetFirewallRule -DisplayName "Block ICMP" -Direction Inbound -Protocol ICMPv4 -Action Block
New-NetFirewallRule -DisplayName "Block ICMPv6" -Direction Inbound -Protocol ICMPv6 -Action Block

New-NetFirewallRule -DisplayName "Block SMB and NetBIOS" -Direction Inbound -Protocol TCP -LocalPort 135,137,138,139,445 -Action Block

Get-NetFirewallRule | Format-Table -Property DisplayName, Enabled, Direction, Action, Profile

Get-NetFirewallProfile | Select-Object -Property Name, LogAllowed, LogBlocked, LogFileName

# Enable Logging for Dropped Packets
Write-Host "Enabling logging for dropped packets..."
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed False -LogBlocked True -LogFileName "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"

Write-Host "Firewall configuration completed."

# SSH

$sshConfigPath = "C:\ProgramData\ssh\sshd_config"

# Check if SSH configuration file exists
if (-Not (Test-Path $sshConfigPath)) {
    Write-Host "SSH configuration file not found. Ensure OpenSSH Server is installed and configured."
    exit
}

# Backup the original configuration file
Write-Host "Creating backup of the SSH configuration file..."
Copy-Item -Path $sshConfigPath -Destination "$sshConfigPath.bak" -Force

# Define SSH hardening settings
$sshSettings = @"
# SSH Hardening Settings
PasswordAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
PubkeyAuthentication yes
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 0
"@

# Apply the SSH hardening settings
Write-Host "Applying SSH hardening settings..."
Add-Content -Path $sshConfigPath -Value $sshSettings

# Restart SSH service to apply changes
Write-Host "Restarting SSH service..."
Restart-Service -Name sshd

Write-Host "SSH hardening completed."

# PHP
# PHP Hardening

Write-Host "Starting PHP Hardening..."

# Path to PHP configuration file
$phpConfigPath = "C:\Path\To\php.ini"

# Check if PHP configuration file exists
if (-Not (Test-Path $phpConfigPath)) {
    Write-Host "PHP configuration file not found. Ensure PHP is installed and configured."
    exit
}

# Backup the original configuration file
Write-Host "Creating backup of the PHP configuration file..."
Copy-Item -Path $phpConfigPath -Destination "$phpConfigPath.bak" -Force

# Define PHP hardening settings
$phpSettings = @"
; PHP Hardening Settings
expose_php = Off
display_errors = Off
log_errors = On
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
file_uploads = Off
allow_url_fopen = Off
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1
"@

# Apply the PHP hardening settings
Write-Host "Applying PHP hardening settings..."
Add-Content -Path $phpConfigPath -Value $phpSettings

# Restart PHP service (example for IIS or PHP-FPM)
Write-Host "Restarting PHP service..."
Restart-Service -Name w3svc  # Replace 'w3svc' with the correct service name if using PHP-FPM or other setup

Write-Host "PHP hardening completed."

Write-Host "Basic Hardening Complete"
