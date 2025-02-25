# Requires -RunAsAdministrator
# Outputs to a file for review

function Test-SuspiciousValue {
    param (
        $Value
    )
    $suspiciousPatterns = @(
        '.*powershell.*-enc.*',
        '.*powershell.*-e .*',
        '.*powershell.*-nop.*bypass.*',
        '.*cmd.exe.*\/c.*',
        '.*cmd.exe.*\/k.*',
        '.*wscript.*',
        '.*cscript.*',
        '.*rundll32.*',
        '.*regsvr32.*',
        '.*mshta.*',
        '.*certutil.*-decode.*',
        '.*javascript:.*',
        '.*vbscript:.*',
        '.*mshtml.*',
        '.*scrobj.*',
        '.*shell32.*',
        '.*scriptlet.*',
        '.*http:\/\/.*exe',
        '.*https:\/\/.*exe',
        '.*ftp:\/\/.*exe',
        '.*\\\\.*\\.*\.exe',
        '.*\\temp\\.*\.exe',
        '.*\\appdata\\.*\.exe',
        '.*\\programdata\\.*\.exe',
        '.*mimilib.*',
        '.*mimikatz.*',
        '.*cobaltstrike.*',
        '.*metasploit.*',
        '.*\\windows\\temp\\.*\.dll',
        '.*\\users\\.*\\appdata\\local\\temp\\.*\.dll'
    )

    if ($Value -is [string]) {
        foreach ($pattern in $suspiciousPatterns) {
            if ($Value -match $pattern) {
                return $true
            }
        }
    }
    return $false
}

$registryPaths = @{
    "Run Keys" = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    )
    "Services" = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services",
        "HKLM:\SYSTEM\ControlSet001\Services"
    )
    "Startup" = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"
    )
    "File Associations" = @(
        "HKLM:\SOFTWARE\Classes",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    )
    "Winlogon" = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    )
    "Active Setup" = @(
        "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components"
    )
    "Boot Execute" = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    )
}

$desktopPath = [Environment]::GetFolderPath('Desktop')
if (-not (Test-Path $desktopPath)) {
    $desktopPath = $env:USERPROFILE
}
if (-not (Test-Path $desktopPath)) {
    New-Item -ItemType Directory -Force -Path $desktopPath | Out-Null
}
$outputFile = Join-Path $desktopPath "SuspiciousRegistry_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

try {
    "Registry Security Audit - $(Get-Date)`n" | Set-Content $outputFile -ErrorAction Stop
    "Suspicious Findings:`n" | Add-Content $outputFile -ErrorAction Stop

    $suspiciousFound = $false

    foreach ($category in $registryPaths.Keys) {
        $categoryHeader = $false
        
        foreach ($path in $registryPaths[$category]) {
            try {
                $values = Get-ItemProperty -Path $path -ErrorAction Stop
                
                foreach ($value in $values.PSObject.Properties) {
                    if ($value.Name -match "^PS") { continue }
                    
                    if (Test-SuspiciousValue -Value $value.Value) {
                        if (-not $categoryHeader) {
                            "`n=== $category ===" | Add-Content $outputFile
                            $categoryHeader = $true
                        }
                        
                        $suspiciousFound = $true
                        @"
Location: $path
Name: $($value.Name)
Value: $($value.Value)
Last Modified: $((Get-Item $path).LastWriteTime)
`n
"@ | Add-Content $outputFile
                    }
                }
            }
            catch {
                continue
            }
        }
    }

    if (-not $suspiciousFound) {
        "No suspicious registry entries found." | Add-Content $outputFile
    }

    # Add summary
    "`nScan completed at: $(Get-Date)" | Add-Content $outputFile
    Write-Host "Scan complete. Results saved to: $outputFile"
}
catch {
    Write-Host "Error creating or writing to output file: $($_.Exception.Message)"
    Write-Host "Attempted path: $outputFile"
}