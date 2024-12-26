# HardeningScripts
A collection of scripts, primarily meant for competition purposes, for hardening windows/assorted linux envirnments

## Overview

Assorted scripts and tools to secure windows/linux machines based off of common configurations desired for collegiate cybersecurity competitions as well as general best practices. The scripts will require administrator credentials on run and will require specific modifications based on your use case and needs. This is far from perfect and simply provides an automated starting point. No modifications are made to users at present time, that information is presented to see what changes are needed based on traditional competition needs for certian user/privilege combinations. 

### Machines

The hardening scripts should generally be usable across Windows/Linux installations/distributions, but has specifically been designed with the following machines in mind based on competitions such as CCDC, HiveStorm, and CyberForce. 

#### Windows
- [ ] Windows 11
- [ ] Windows 10
- [ ] Windows Server 2022
- [ ] Windows Server 2019
- [ ] Windows Server 2016

#### Linux
- [ ] Mint
- [ ] Ubuntu
- [ ] CentOS

### Functionality

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

- Dumps Firewall Config
- Updates Firewall Config
- Updates SSH Configs
- Updates software
- Updates versions (as applicable)
- 
