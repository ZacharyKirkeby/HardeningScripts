# parameters
function Compare-FilePermissionsToMask{ 
  param (
    [string] $directoryPath,
    [string] $user,
    [string] $expectedPermission
  )
# get all files in the directory and sub directories
$files = Get-ChildItem -Path $directoryPath -Recurse -File
foreach ($file in $files) {
  $perms GET-Ac1 -Path $file.FullName
  $matchingPermission= $acl. Access | Where-Object { $_.IdentityReference -eq $user}
  if ($matchingPermission) {
    if ($matching Permission.FileSystemRights -eq $expectedPermission) {
      Write-Host "File: $($file.FullName) matches expected permissions
    }
  else {
    Write-Host "File: $($file.FullName) does not have perms for user: $user"
    }
  }
}
