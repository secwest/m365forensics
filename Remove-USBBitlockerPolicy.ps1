# Disable BitLocker USB/Removable Drive Encryption Requirements
# Run this script as Administrator after applying the hardening script

function Log {
    param($message, $type = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] "
    
    switch ($type) {
        "INFO" { 
            $logMessage += "[*] $message"
            Write-Host $logMessage 
        }
        "SUCCESS" { 
            $logMessage += "[+] $message"
            Write-Host $logMessage -ForegroundColor Green 
        }
        "WARN" { 
            $logMessage += "[!] $message"
            Write-Host $logMessage -ForegroundColor Yellow 
        }
        "ERROR" { 
            $logMessage += "[X] $message"
            Write-Host $logMessage -ForegroundColor Red 
        }
    }
}

function Set-RegistryValue {
    param($Path, $Name, $Value, $Type = 'DWord')
    try {
        if (-not (Test-Path $Path)) {
            New-Item $Path -Force | Out-Null
            Log "Created registry path: $Path"
        }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Log "Set $Path\$Name = $Value" "SUCCESS"
    }
    catch {
        Log "Failed to set $Path\$Name - $($_.Exception.Message)" "ERROR"
    }
}

function Remove-RegistryValue {
    param($Path, $Name)
    try {
        if (Test-Path $Path) {
            $property = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($property) {
                Remove-ItemProperty -Path $Path -Name $Name -Force
                Log "Removed $Path\$Name" "SUCCESS"
            } else {
                Log "$Path\$Name does not exist" "INFO"
            }
        } else {
            Log "Registry path $Path does not exist" "INFO"
        }
    }
    catch {
        Log "Failed to remove $Path\$Name - $($_.Exception.Message)" "ERROR"
    }
}

Write-Host @"
╔════════════════════════════════════════════════════════════════╗
║          DISABLE USB ENCRYPTION REQUIREMENTS                   ║
║                                                                ║
║  This script disables BitLocker requirements for external     ║
║  USB drives while keeping other security hardening intact.    ║
╚════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Log "Starting USB encryption requirement removal..." "INFO"

# BitLocker policy paths
$blPolicyBase = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$blRemovablePath = "$blPolicyBase\RDVPassphrase"
$blRemovableRecoveryPath = "$blPolicyBase\RDVRecovery"
$blRemovableEncryptionPath = "$blPolicyBase\RDVActiveDirectoryBackup"

# 1. Disable "Control use of BitLocker on removable drives" policy
Log "Disabling BitLocker control on removable drives..." "INFO"
Remove-RegistryValue -Path $blPolicyBase -Name "RDVConfigureReq"
Remove-RegistryValue -Path $blPolicyBase -Name "RDVAllowBDE"
Remove-RegistryValue -Path $blPolicyBase -Name "RDVDisallowBDE"

# 2. Disable "Deny write access to removable drives not protected by BitLocker"
Log "Removing write access denial for unencrypted removable drives..." "INFO"
Remove-RegistryValue -Path $blPolicyBase -Name "RDVDenyWriteAccess"

# 3. Disable passphrase requirements for removable drives
Log "Disabling passphrase requirements for removable drives..." "INFO"
Remove-RegistryValue -Path $blRemovablePath -Name "RDVPassphrase"
Remove-RegistryValue -Path $blRemovablePath -Name "RDVEnforcePassphrase"

# 4. Disable recovery key requirements for removable drives
Log "Disabling recovery key requirements for removable drives..." "INFO"
Remove-RegistryValue -Path $blRemovableRecoveryPath -Name "RDVManageReq"
Remove-RegistryValue -Path $blRemovableRecoveryPath -Name "RDVRecovery"

# 5. Disable encryption method enforcement for removable drives
Log "Disabling encryption method enforcement for removable drives..." "INFO"
Remove-RegistryValue -Path $blPolicyBase -Name "RDVEncryptionType"
Remove-RegistryValue -Path $blPolicyBase -Name "RDVEncryptionMethod"

# 6. Explicitly allow unencrypted removable drives
Log "Explicitly allowing unencrypted removable drives..." "INFO"
Set-RegistryValue -Path $blPolicyBase -Name "RDVDenyWriteAccess" -Value 0 -Type DWord

# 7. Disable hardware encryption requirements for removable drives
Log "Disabling hardware encryption requirements..." "INFO"
Remove-RegistryValue -Path $blPolicyBase -Name "RDVHardwareEncryption"

# 8. Check current Group Policy settings that might override registry
Log "Checking for Group Policy conflicts..." "INFO"
try {
    $gpoResult = gpresult /r /scope:computer 2>&1
    if ($gpoResult -match "BitLocker.*removable") {
        Log "Group Policy may still be enforcing BitLocker on removable drives" "WARN"
        Log "You may need to modify the Group Policy directly" "WARN"
    }
} catch {
    Log "Could not check Group Policy settings" "WARN"
}

# 9. Update Group Policy to apply changes
Log "Refreshing Group Policy..." "INFO"
try {
    gpupdate /force | Out-Null
    Log "Group Policy refreshed" "SUCCESS"
} catch {
    Log "Failed to refresh Group Policy" "WARN"
}

# 10. Check BitLocker status
Log "Checking current BitLocker configuration..." "INFO"
try {
    $mpPrefs = Get-MpPreference -ErrorAction SilentlyContinue
    $blVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    
    Log "Current BitLocker volumes:" "INFO"
    foreach ($vol in $blVolumes) {
        if ($vol.MountPoint -eq "C:") {
            Log "  $($vol.MountPoint) (System): $($vol.ProtectionStatus)" "INFO"
        } else {
            Log "  $($vol.MountPoint) (Removable): $($vol.ProtectionStatus)" "INFO"
        }
    }
} catch {
    Log "Could not retrieve BitLocker status" "WARN"
}

Write-Host @"
╔════════════════════════════════════════════════════════════════╗
║                     COMPLETION STEPS                           ║
║                                                                ║
║  1. Restart your computer to ensure all changes take effect   ║
║                                                                ║
║  2. Test by inserting a USB drive - it should not require     ║
║     encryption                                                 ║
║                                                                ║
║  3. If USB drives still require encryption, check:            ║
║     - Group Policy Editor (gpedit.msc)                        ║
║     - Computer Config > Admin Templates > Windows Components  ║
║       > BitLocker Drive Encryption > Removable Data Drives    ║
║                                                                ║
║  4. Your system BitLocker (C: drive) remains protected        ║
╚════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Green

Log "USB encryption requirement removal completed" "SUCCESS"
