Import-Module ActiveDirectory

$NewPassword = ConvertTo-SecureString "NewPassword123!" -AsPlainText -Force

Get-ADUser -Filter {Description -eq "zCCDC Scoring User"} | ForEach-Object {
    Set-ADAccountPassword -Identity $_.SamAccountName -NewPassword $NewPassword -Reset
    Set-ADUser -Identity $_.SamAccountName -KerberosEncryptionType None -CannotChangePassword $false -PasswordNeverExpires $false -AccountNotDelegated $true -DoesNotRequirePreAuth $false -AllowReversiblePasswordEncryption $false -PasswordNotRequired $false -TrustedForDelegation $false -AccountDisabled $true
    Write-Host "$($_.SamAccountName)"
}
