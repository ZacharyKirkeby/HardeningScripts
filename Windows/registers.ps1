if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Rerun as an administrator."
    exit
}

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