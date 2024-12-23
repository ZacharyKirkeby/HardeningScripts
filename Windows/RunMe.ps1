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

Write-Output "All tasks completed. Check $outputDir for output files."

