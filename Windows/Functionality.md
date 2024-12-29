# Functionality

The following is a non exhaustive list of functions performed by this script:

- Dumps User List
- Dumps User Privileges
- Removes guest users
- Dumps Groups
- Dumps Group Privileges
- Password Length Enforcement
- Password Complexity Enforcement
- Account Lockout Policy
- Dumps Service List
- Dumps scheduled tasks
- Dumps run registers
- Check windows registers
- Dump Registers
- Checks for Malicious Tools
    - Check for C2 references
    - Check for common hacking tools
    - Check for kerboroasting references
- Hash Validation
- Disable Weak services
- Enable UAC
- Disable RDP (CHANGE THIS IF NEEDED)
- Disable SMB1

## Lists

### Services to disable: 

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

### Tools of Concern
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