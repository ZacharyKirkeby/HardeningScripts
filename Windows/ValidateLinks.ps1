# Function to check shortcut target paths
function Test-ShortcutIntegrity {
    param (
        [string[]]$FolderPaths = @(
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu",
            "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch",
            "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
        )
    )

    $shell = New-Object -ComObject WScript.Shell
    
    try {
        foreach ($folderPath in $FolderPaths) {
            if (Test-Path $folderPath) {
                Write-Host "`nChecking shortcuts in: $folderPath"
                $shortcuts = Get-ChildItem -Path $folderPath -Filter "*.lnk" -Recurse
                
                foreach ($shortcut in $shortcuts) {
                    $link = $shell.CreateShortcut($shortcut.FullName)
                    
                    # Check for suspicious targets
                    $suspiciousTargets = @(
                        'cmd.exe',
                        'powershell.exe',
                        'temp',
                        'tmp',
                        'launch',
                        'script'
                    )
                    
                    $isSuspicious = $false
                    foreach ($target in $suspiciousTargets) {
                        if ($link.TargetPath -like "*$target*") {
                            $isSuspicious = $true
                            break
                        }
                    }
                    
                    if ($isSuspicious) {
                        Write-Host "`nSUSPICIOUS SHORTCUT FOUND:" -ForegroundColor Red
                        Write-Host "Shortcut: $($shortcut.Name)" -ForegroundColor Yellow
                        Write-Host "Location: $($shortcut.FullName)"
                        Write-Host "Points to: $($link.TargetPath)"
                        Write-Host "Arguments: $($link.Arguments)"
                    }
                }
            }
        }
    }
    finally {
        if ($shell) {
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
        }
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

# Run the check
Test-ShortcutIntegrity