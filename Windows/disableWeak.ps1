if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Rerun as an administrator."
    exit
}

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
Write-Host "All specified features have been processed."