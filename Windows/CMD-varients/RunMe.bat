@echo off
:: Automated Hardening Script for Windows
:: Ensure the script is run as an administrator
:: Save this file as a .bat or .cmd file

:: Check for administrative privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Please run this script as an administrator.
    pause
    exit /b
)

:: Output directories
set outputDir=C:\ProcessDump
set registryDir=C:\RegistryChecks

:: Create output directories
if not exist "%outputDir%" mkdir "%outputDir%"
if not exist "%registryDir%" mkdir "%registryDir%"

:: Dump user list
echo Dumping User List...
net user > "%outputDir%\UserList.txt"
type "%outputDir%\UserList.txt"

:: Remove Guest User
echo Removing Guest Users...
net user guest /active:no
echo Guest account disabled.

:: Dump groups
echo Dumping Groups...
net localgroup > "%outputDir%\GroupList.txt"
type "%outputDir%\GroupList.txt"

:: Set password policies
echo Setting password policies...
net accounts /minpwlen:12
net accounts /maxpwage:30
net accounts /minpwage:5
net accounts

:: Dump running processes
echo Dumping running processes...
tasklist > "%outputDir%\RunningProcesses.txt"

:: Dump services
echo Dumping services...
sc query > "%outputDir%\Services.txt"

:: Dump scheduled tasks
echo Dumping scheduled tasks...
schtasks /Query /FO CSV > "%outputDir%\ScheduledTasks.csv"

:: Disable Remote Desktop Protocol (RDP)
echo Disabling Remote Desktop Protocol (RDP)...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f

:: Disable SMBv1
echo Disabling SMBv1 protocol...
dism /online /disable-feature /featurename:SMB1Protocol /norestart

:: Enable User Account Control (UAC)
echo Enabling User Account Control (UAC)...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f

:: Notify completion
echo Hardening script completed successfully.
pause
