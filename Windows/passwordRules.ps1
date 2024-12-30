if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Rerun as an administrator."
    exit
}

# Password Rule Enforcement
Write-Output "Passwords must be 12 digits"
net accounts /minpwlen:12
Write-Output "Passwords must be changed every 30 days"
net accounts /maxpwage:30
Write-Output "Passwords can only be changed after 5 day has passed"
net accounts /minpwage:5
Write-Output "Display current password policy"
echo "CURRENT POLICY"