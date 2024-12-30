if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Rerun as an administrator."
    exit
}

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