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

@echo off
setlocal EnableDelayedExpansion

echo Checking shortcuts for suspicious modifications...
echo.

:: Define locations to check
set "DESKTOP=%USERPROFILE%\Desktop"
set "STARTMENU=%APPDATA%\Microsoft\Windows\Start Menu"
set "QUICKLAUNCH=%APPDATA%\Microsoft\Internet Explorer\Quick Launch"
set "TASKBAR=%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"

:: Create a temporary VBS script to read shortcut properties
set "vbscript=%TEMP%\read_shortcut.vbs"
echo Set objShell = CreateObject("WScript.Shell") > "%vbscript%"
echo Set objArgs = WScript.Arguments >> "%vbscript%"
echo Set objShortcut = objShell.CreateShortcut(objArgs(0)) >> "%vbscript%"
echo WScript.Echo objShortcut.TargetPath ^& "|" ^& objShortcut.Arguments >> "%vbscript%"

:: Function to check shortcuts in a directory
:CheckDir
set "checkdir=%~1"
if not exist "%checkdir%" goto :EOF
echo Checking shortcuts in: %checkdir%
echo.

for /r "%checkdir%" %%F in (*.lnk) do (
    for /f "delims=" %%L in ('cscript //nologo "%vbscript%" "%%F"') do (
        set "linkinfo=%%L"
        set "suspicious="
        
        :: Check for suspicious targets
        echo !linkinfo! | findstr /i "cmd.exe powershell.exe temp tmp launch script" >nul && set "suspicious=1"
        
        if defined suspicious (
            echo SUSPICIOUS SHORTCUT FOUND:
            echo Shortcut: %%~nxF
            echo Location: %%F
            echo Target: !linkinfo!
            echo.
        )
    )
)
goto :EOF

:: Check each directory
call :CheckDir "%DESKTOP%"
call :CheckDir "%STARTMENU%"
call :CheckDir "%QUICKLAUNCH%"
call :CheckDir "%TASKBAR%"

:: Clean up
del "%vbscript%" 2>nul

echo Shortcut check complete.
pause

:: Notify completion
echo Hardening script completed successfully.
pause
