if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Rerun as an administrator."
    exit
}

$outputDir = "C:\ProcessDump"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}
Write-Output "Output directory: $outputDir"


Write-Output "Dumping list of current running processes..."
Get-Process | Select-Object Name, Id, CPU, WorkingSet, StartTime | Export-Csv -Path "$outputDir\RunningProcesses.csv" -NoTypeInformation
Write-Output "Running processes saved to $outputDir\RunningProcesses.csv"


Write-Output "Dumping list of services (running and stopped)..."
Get-Service | Select-Object Name, DisplayName, Status | Export-Csv -Path "$outputDir\Services.csv" -NoTypeInformation
Write-Output "Services saved to $outputDir\Services.csv"

Write-Output "Dumping tasks queued to run..."
schtasks.exe /Query /FO CSV /V | ConvertFrom-Csv | Export-Csv -Path "$outputDir\ScheduledTasks.csv" -NoTypeInformation
Write-Output "Scheduled tasks saved to $outputDir\ScheduledTasks.csv"

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

Write-Output "Checking processes done"