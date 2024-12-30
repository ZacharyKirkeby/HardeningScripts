if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Rerun as an administrator."
    exit
}

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