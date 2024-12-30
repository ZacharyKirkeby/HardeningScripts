if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Rerun as an administrator."
    exit
}

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