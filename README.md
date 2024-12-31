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

In it's current form, both scripts must be run as an administrator. Automated configurations, namely disabling services, updates, and changes to rules will all occur automatically. Users, groups, hashes, and other tasks requiring a degree of manual review will be saved to files for review to ensure appropriate compliance. 

Each runMe file does everything that has been programmed. For smaller operatios, individual files for individual actions like threat hunting, password rules, or user group review has been added. 

### TODO

- [ ] Active Directory rules
- [ ] CMD varient
    - [ x ] primitive version 
- [ ] interactive menu