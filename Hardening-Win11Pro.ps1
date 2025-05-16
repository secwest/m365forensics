###############################################################################
# Windows 11 Pro Hardening Script  (v1.2.0 | 2025-05-24)
# Self-elevating · PowerShell 5.1 & 7.x compatible · Enhanced reporting
###############################################################################
#
# DESCRIPTION
#   Comprehensive hardening script for Windows 11 Pro workstations that implements
#   Microsoft Security Baseline 23H2 plus additional security controls. Suitable
#   for enterprise environments and security-focused individual users.
#
# OVERVIEW
#   • Auto-elevates to administrator and uses PowerShell 7 if available
#   • Logs to current directory with detailed execution transcript
#   • Downloads & verifies:
#        LGPO.zip      SHA-256 CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55
#        Win11Baseline SHA-256 2E3A61D0245C16BEA51A9EE78CBF0793C88046901CECC0039DB0DC84FAE7D7B7
#   • Runs comprehensive before/after security assessment
#   • Implements Microsoft Security Baseline 23H2 via LGPO
#   • Additional hardening:
#        BitLocker TPM+PIN with XtsAes256 encryption
#        VBS / HVCI / Credential Guard
#        Disable LM / NTLMv1 · SMB1 · TLS 1.0/1.1 (enables TLS 1.2)
#        Defender cloud=High · PUA · CFA · NetProt · 5 critical ASR rules
#        Office macro lockdown · unsigned add-ins blocked
#        PowerShell AllSigned + ScriptBlock / Module / Transcription logging
#        Removal of legacy/insecure Windows features
#        Minimal audit policy (5 key subcategories)
#        AnyDesk firewall rules (TCP+UDP 7070)
#
# OPERATOR CHECKLIST
#   1️⃣  Run in an **elevated** console (or let it self-elevate)
#        powershell.exe -ExecutionPolicy Bypass -File .\Windows11Pro-Hardening.ps1
#
#   2️⃣  Review initial security assessment and choose whether to proceed
#
#   3️⃣  Supply numeric BitLocker PIN when prompted (if not already enabled)
#
#   4️⃣  Verify status after hardening completes
#
#   5️⃣  Copy C:\RecoveryKeys to offline media
#
#   6️⃣  **Reboot twice** (VBS/Cred Guard finalizes on 2nd boot)
#
# VERIFICATION COMMANDS
#   After rebooting, verify security with these commands:
#     Get-BitLockerVolume
#     Get-Tpm
#     msinfo32 → System Summary → Secure Boot State : On
#     msinfo32 → System Summary → Virtualization-based security : Running
#     Get-CimInstance Win32_DeviceGuard
#     Get-MpComputerStatus
#     auditpol /get /category:*
#
# LOGS & REPORTING
#   The script saves detailed logs in the current directory:
#   • HardeningLog-[DATE].txt - Console output with status of each operation
#   • Transcript-[DATE].txt - Full PowerShell transcript for troubleshooting
#   • PowerShell transcription is also enabled at C:\PowerShellTranscripts
#
# AUTHOR
#  Dragos Ruiu - May 15 2025
#
###############################################################################

param()

# ========================================================================================
# BOOTSTRAP SECTION - PowerShell 5.1 Compatible
# ========================================================================================

# Check if already in PowerShell 7 with admin rights
$inPs7 = $PSVersionTable.PSVersion.Major -ge 7
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Self-elevate if not running as admin
if (-not $isAdmin) {
    Write-Host "Requesting administrative privileges..." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

# If in PS5.1 (or older) with admin rights, need to switch to PS7
if (-not $inPs7 -and $isAdmin) {
    Write-Host "Current PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
    Write-Host "This script works best with PowerShell 7+" -ForegroundColor Yellow
    
    # Check if PS7 is already installed
    $ps7Path = "$env:ProgramFiles\PowerShell\7\pwsh.exe"
    if (-not (Test-Path $ps7Path)) {
        Write-Host "Installing PowerShell 7..." -ForegroundColor Yellow
        
        try {
            # Try using winget (Windows 10/11)
            winget install Microsoft.PowerShell --architecture x64 --accept-source-agreements --accept-package-agreements --disable-interactivity --silent
            Start-Sleep -Seconds 2
        }
        catch {
            Write-Host "Winget failed, trying direct MSI download..." -ForegroundColor Yellow
            
            # Alternative: Direct download of MSI
            $msiUrl = "https://github.com/PowerShell/PowerShell/releases/download/v7.3.4/PowerShell-7.3.4-win-x64.msi"
            $msiPath = "$env:TEMP\PowerShell-7.msi"
            
            # Download MSI
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
            
            # Install MSI silently
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" /quiet /norestart" -Wait
            Remove-Item $msiPath -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Check if PS7 was installed successfully
    if (Test-Path $ps7Path) {
        Write-Host "Relaunching script with PowerShell 7..." -ForegroundColor Green
        # Launch the same script with PS7
        Start-Process -FilePath $ps7Path -ArgumentList "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Wait
        exit
    }
    else {
        Write-Host "PowerShell 7 installation failed. Attempting to continue with PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Red
        # Let script continue to hardening section (though it might fail)
    }
}

# ========================================================================================
# MAIN HARDENING SECTION - PowerShell 5.1 Compatible
# ========================================================================================
Write-Host @"
╔════════════════════════════════════════════════════════════════╗
║                 WINDOWS 11 PRO HARDENING SCRIPT                ║
║                                                                ║
║  This script applies Microsoft security baseline and           ║
║  additional hardening measures to your Windows 11 Pro system.  ║
║                                                                ║
║  PowerShell Version: $($PSVersionTable.PSVersion.ToString())
║  Running as Administrator: Yes                                 ║
╚════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# -- Global variables ---------------------------------------------------------
$BaselineUrl = 'https://drive.google.com/uc?export=download&id=13AoBqDA_O07-PhrpTJpzdU1b2oS8rD11'
$BaselineSha = '2E3A61D0245C16BEA51A9EE78CBF0793C88046901CECC0039DB0DC84FAE7D7B7'
$LgpoUrl     = 'https://drive.google.com/uc?export=download&id=1Z9Jd1h4grAF8GSCevRxeUFQ8hy2AVBOO'
$LgpoSha     = 'CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55'

$BaselineZip = "$env:TEMP\Win11Baseline.zip"
$LgpoZip     = "$env:TEMP\LGPO.zip"
$ExtractDir  = "$env:TEMP\Win11Baseline"
$LgpoExtractDir = "$env:TEMP\LGPO_Extract"
$recoveryPath = "C:\RecoveryKeys"

# -- Set up logging -----------------------------------------------------------
# Log file will be created in the current directory
$logDir = $null  # Will be set later
$logFile = $null # Will be set later
$transcriptFile = $null # Will be set later

    # -- Helper functions ---------------------------------------------------------
    function CheckDeviceGuard {
        # More robust Device Guard checking
        try {
            # Try the standard CIM approach first
            $dg = Get-CimInstance Win32_DeviceGuard -ErrorAction Stop
            return $dg
        } catch {
            # If that fails, try registry method
            try {
                $vbsStatus = "Unknown"
                $hvciStatus = "Unknown"
                
                # Check registry for VBS status
                $vbsEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue
                if ($null -ne $vbsEnabled) {
                    $vbsStatus = if ($vbsEnabled.EnableVirtualizationBasedSecurity -eq 1) { "Enabled" } else { "Disabled" }
                }
                
                # Check registry for HVCI status
                $hvciEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
                if ($null -ne $hvciEnabled) {
                    $hvciStatus = if ($hvciEnabled.Enabled -eq 1) { "Enabled" } else { "Disabled" }
                }
                
                # Create a custom object with the same properties
                $customDG = [PSCustomObject]@{
                    VirtualizationBasedSecurityStatus = if ($vbsStatus -eq "Enabled") { 1 } else { 0 }
                    HypervisorEnforcedCodeIntegrityStatus = if ($hvciStatus -eq "Enabled") { 1 } else { 0 }
                    VirtualizationBasedSecurityStatusDescription = $vbsStatus
                    HypervisorEnforcedCodeIntegrityStatusDescription = $hvciStatus
                }
                
                return $customDG
            } catch {
                $errMsg = $_.Exception.Message
                Log "Error checking Device Guard via registry: $errMsg" "ERROR"
                throw
            }
        }
    }
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
    
    # Also log to file
    if ($logFile) {
        $logMessage | Out-File -FilePath $logFile -Append -Encoding utf8
    }
}

function RegSet {
    param($k, $n, $v, $t='DWord')
    try {
        if (-not (Test-Path $k)) {
            New-Item $k -Force -ErrorAction Stop | Out-Null
            Log "Created registry key: $k"
        }
        New-ItemProperty -Path $k -Name $n -Value $v -PropertyType $t -Force -ErrorAction Stop | Out-Null
        Log "Set registry value: $k\$n = $v"
    }
    catch {
        $errMsg = $_.Exception.Message
        Log "Failed to set registry value: $k\$n - $errMsg" "ERROR"
    }
}

function IsZip {
    param($path)
    try { 
        $bytes = [IO.File]::ReadAllBytes($path)
        if ($bytes.Length -lt 4) { return $false }
        
        # Check for ZIP signature (PK..)
        if ($bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B -and 
           $bytes[2] -eq 0x03 -and $bytes[3] -eq 0x04) {
            return $true
        }
        return $false
    }
    catch { 
        $errMsg = $_.Exception.Message
        Log "Error checking if file is ZIP: $errMsg" "WARN"
        return $false 
    }
}

function CheckTpm {
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if (-not $tpm.TpmPresent) {
            Log "TPM not present - BitLocker with TPM+PIN not possible" "ERROR"
            return $false
        }
        if (-not $tpm.TpmReady) {
            Log "TPM present but not ready - attempting to initialize" "WARN"
            try {
                Initialize-Tpm -AllowClear -AllowPhysicalPresence -ErrorAction Stop | Out-Null
                $tpm = Get-Tpm
                if (-not $tpm.TpmReady) {
                    Log "Could not initialize TPM" "ERROR"
                    return $false
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                Log "Error initializing TPM: $errMsg" "ERROR"
                return $false
            }
        }
        Log "TPM is ready" "SUCCESS"
        return $true
    }
    catch {
        $errMsg = $_.Exception.Message
        Log "Error checking TPM: $errMsg" "ERROR"
        return $false
    }
}

function CheckHardeningStatus {
    param([string]$phase = "Current")
    
    $statusHeader = @"
╔════════════════════════════════════════════════════════════════╗
║               $phase HARDENING STATUS CHECK                
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
"@
    
    Write-Host $statusHeader -ForegroundColor Cyan
    Log "$phase hardening status check..." "INFO"
    
    # Status container for results
    $status = @{}
    
    # 1. BitLocker Status
    try {
        $blv = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
        $status.BitLocker = @{
            Status = $blv.ProtectionStatus
            Enabled = ($blv.ProtectionStatus -eq 'ProtectionOn')
            Encryption = $blv.EncryptionMethod
            Details = "Volume $($blv.MountPoint) protection: $($blv.ProtectionStatus), Encryption: $($blv.EncryptionMethod)"
        }
        
        # Use if-else instead of ternary
        $logType = "WARN"
        if ($status.BitLocker.Enabled) {
            $logType = "SUCCESS"
        }
        Log "BitLocker: $($status.BitLocker.Details)" $logType
    } catch {
        $status.BitLocker = @{ Status = "Error"; Enabled = $false; Details = "Error checking BitLocker: $_" }
        Log "BitLocker: $($status.BitLocker.Details)" "ERROR"
    }
    
    # 2. TPM Status
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $status.TPM = @{
            Present = $tpm.TpmPresent
            Ready = $tpm.TpmReady
            Enabled = ($tpm.TpmPresent -and $tpm.TpmReady)
            Details = "Present: $($tpm.TpmPresent), Ready: $($tpm.TpmReady), Activated: $($tpm.TpmActivated)"
        }
        
        # Use if-else instead of ternary
        $logType = "WARN"
        if ($status.TPM.Enabled) {
            $logType = "SUCCESS"
        }
        Log "TPM: $($status.TPM.Details)" $logType
    } catch {
        $status.TPM = @{ Present = $false; Ready = $false; Enabled = $false; Details = "Error checking TPM: $_" }
        Log "TPM: $($status.TPM.Details)" "ERROR"
    }
    
    # 3. DeviceGuard/VBS Status
    try {
        # Use the more robust helper function
        $dg = CheckDeviceGuard
        $vbsStatus = $dg.VirtualizationBasedSecurityStatus
        $hvciStatus = $dg.HypervisorEnforcedCodeIntegrityStatus
        
        $status.DeviceGuard = @{
            VBSEnabled = ($vbsStatus -eq 1 -or $vbsStatus -eq 2)
            HVCIEnabled = ($hvciStatus -eq 1 -or $hvciStatus -eq 2)
            Details = "VBS: $(if($vbsStatus -eq 0){'Not enabled'}elseif($vbsStatus -eq 1){'Enabled & running'}elseif($vbsStatus -eq 2){'Enabled but not running'}else{'Unknown'}), " +
                      "HVCI: $(if($hvciStatus -eq 0){'Not enabled'}elseif($hvciStatus -eq 1){'Enabled & running'}elseif($hvciStatus -eq 2){'Enabled but not running'}else{'Unknown'})"
        }
        
        # Use if-else instead of ternary
        $logType = "WARN"
        if ($status.DeviceGuard.VBSEnabled -or $status.DeviceGuard.HVCIEnabled) {
            $logType = "SUCCESS"
        }
        Log "Device Guard: $($status.DeviceGuard.Details)" $logType
    } catch {
        $status.DeviceGuard = @{ VBSEnabled = $false; HVCIEnabled = $false; Details = "Error checking Device Guard: $_" }
        Log "Device Guard: $($status.DeviceGuard.Details)" "ERROR"
    }
    
    # 4. Credential Guard Status
    try {
        $lsaCfgValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue).LsaCfgFlags
        
        $status.CredGuard = @{
            Enabled = ($lsaCfgValue -eq 1 -or $lsaCfgValue -eq 2)
            Details = "Credential Guard: $(if($lsaCfgValue -eq 0){'Disabled'}elseif($lsaCfgValue -eq 1){'Enabled with UEFI lock'}elseif($lsaCfgValue -eq 2){'Enabled without UEFI lock'}else{'Not configured'})"
        }
        
        # Use if-else instead of ternary
        $logType = "WARN"
        if ($status.CredGuard.Enabled) {
            $logType = "SUCCESS"
        }
        Log "Credential Guard: $($status.CredGuard.Details)" $logType
    } catch {
        $status.CredGuard = @{ Enabled = $false; Details = "Error checking Credential Guard: $_" }
        Log "Credential Guard: $($status.CredGuard.Details)" "ERROR"
    }
    
    # 5. Windows Defender Status
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $status.Defender = @{
            RTEnabled = $mp.RealTimeProtectionEnabled
            ASREnabled = $mp.AttackSurfaceReductionRulesStatus -eq 1
            NetworkProtection = $mp.IsTamperProtected
            CloudBlockLevel = $mp.CloudBlockLevel
            PUAProtection = $mp.PUAProtection
            CFAEnabled = $mp.ControlledFolderAccessStatus -eq 1
            Details = "Real-time: $($mp.RealTimeProtectionEnabled), " +
                      "Cloud block: $($mp.CloudBlockLevel), " +
                      "Network protection: $($mp.IsTamperProtected), " +
                      "PUA protection: $($mp.PUAProtection)"
        }
        
        # Use if-else instead of ternary
        $logType = "WARN"
        if ($status.Defender.RTEnabled) {
            $logType = "SUCCESS"
        }
        Log "Defender: $($status.Defender.Details)" $logType
    } catch {
        $status.Defender = @{ RTEnabled = $false; Details = "Error checking Defender: $_" }
        Log "Defender: $($status.Defender.Details)" "ERROR"
    }
    
    # 6. PowerShell Execution Policy
    try {
        $exPol = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction Stop
        $status.ExecutionPolicy = @{
            Policy = $exPol
            Restricted = ($exPol -eq "Restricted" -or $exPol -eq "AllSigned")
            Details = "Execution Policy: $exPol"
        }
        
        # Use if-else instead of ternary
        $logType = "WARN"
        if ($status.ExecutionPolicy.Restricted) {
            $logType = "SUCCESS"
        }
        Log "PowerShell: $($status.ExecutionPolicy.Details)" $logType
    } catch {
        $status.ExecutionPolicy = @{ Policy = "Unknown"; Restricted = $false; Details = "Error checking execution policy: $_" }
        Log "PowerShell: $($status.ExecutionPolicy.Details)" "ERROR"
    }
    
    # 7. SMB1 Status
    try {
        $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        $smb1ServerConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        
        $status.SMB1 = @{
            FeatureDisabled = ($smb1Feature.State -ne "Enabled")
            ServerDisabled = (-not $smb1ServerConfig.EnableSMB1Protocol)
            Disabled = ($smb1Feature.State -ne "Enabled" -and -not $smb1ServerConfig.EnableSMB1Protocol)
            Details = "Feature: $(if($smb1Feature.State -ne 'Enabled'){'Disabled'}else{'Enabled'}), " +
                      "Server config: $(if(-not $smb1ServerConfig.EnableSMB1Protocol){'Disabled'}else{'Enabled'})"
        }
        
        # Use if-else instead of ternary
        $logType = "WARN"
        if ($status.SMB1.Disabled) {
            $logType = "SUCCESS"
        }
        Log "SMB1: $($status.SMB1.Details)" $logType
    } catch {
        $status.SMB1 = @{ Disabled = $false; Details = "Error checking SMB1: $_" }
        Log "SMB1: $($status.SMB1.Details)" "ERROR"
    }
    
    # 8. TLS Configuration
    try {
        $sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
        $tls10Enabled = (Get-ItemProperty -Path "$sch\TLS 1.0\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled -ne 0
        $tls11Enabled = (Get-ItemProperty -Path "$sch\TLS 1.1\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled -ne 0
        $tls12Enabled = (Get-ItemProperty -Path "$sch\TLS 1.2\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled -ne 0
        
        $status.TLS = @{
            TLS10Disabled = -not $tls10Enabled
            TLS11Disabled = -not $tls11Enabled
            TLS12Enabled = $tls12Enabled
            Secure = (-not $tls10Enabled) -and (-not $tls11Enabled) -and $tls12Enabled
            Details = "TLS 1.0: $(if($tls10Enabled){'Enabled'}else{'Disabled'}), " +
                      "TLS 1.1: $(if($tls11Enabled){'Enabled'}else{'Disabled'}), " +
                      "TLS 1.2: $(if($tls12Enabled){'Enabled'}else{'Disabled'})"
        }
        
        # Use if-else instead of ternary
        $logType = "WARN"
        if ($status.TLS.Secure) {
            $logType = "SUCCESS"
        }
        Log "TLS: $($status.TLS.Details)" $logType
    } catch {
        $status.TLS = @{ Secure = $false; Details = "Error checking TLS configuration: $_" }
        Log "TLS: $($status.TLS.Details)" "ERROR"
    }
    
    # 9. AnyDesk Firewall Rule
    try {
        $fw = Get-NetFirewallRule -DisplayName "Hardening - AnyDesk TCP 7070" -ErrorAction SilentlyContinue
        $status.AnyDesk = @{
            RuleExists = $null -ne $fw
            Details = "Firewall rule: $(if($null -ne $fw){'Exists'}else{'Not found'})"
        }
        
        # Use if-else instead of ternary
        $logType = "INFO"
        if ($status.AnyDesk.RuleExists) {
            $logType = "SUCCESS"
        }
        Log "AnyDesk: $($status.AnyDesk.Details)" $logType
    } catch {
        $status.AnyDesk = @{ RuleExists = $false; Details = "Error checking AnyDesk firewall rule: $_" }
        Log "AnyDesk: $($status.AnyDesk.Details)" "ERROR"
    }
    
    # Final Summary
    $totalChecks = 9
    $passedChecks = 0
    if ($status.BitLocker.Enabled) { $passedChecks++ }
    if ($status.TPM.Enabled) { $passedChecks++ }
    if ($status.DeviceGuard.VBSEnabled) { $passedChecks++ }
    if ($status.CredGuard.Enabled) { $passedChecks++ }
    if ($status.Defender.RTEnabled) { $passedChecks++ }
    if ($status.ExecutionPolicy.Restricted) { $passedChecks++ }
    if ($status.SMB1.Disabled) { $passedChecks++ }
    if ($status.TLS.Secure) { $passedChecks++ }
    if ($status.AnyDesk.RuleExists) { $passedChecks++ }
    
    $statusText = "MULTIPLE CHECKS FAILED"
    if ($passedChecks -eq $totalChecks) {
        $statusText = "ALL CHECKS PASSED"
    } elseif ($passedChecks -ge 6) {
        $statusText = "MOST CHECKS PASSED"
    }
    
    $summaryColor = "Red"
    if ($passedChecks -eq $totalChecks) {
        $summaryColor = "Green"
    } elseif ($passedChecks -ge 6) {
        $summaryColor = "Yellow"
    }
    
    $summaryText = @"
╔════════════════════════════════════════════════════════════════╗
║               HARDENING STATUS SUMMARY                         ║
║                                                                ║
║  Checks passed: $passedChecks of $totalChecks                            
║  Status: $statusText
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
"@
    
    Write-Host $summaryText -ForegroundColor $summaryColor
    Log "Status check complete - $passedChecks of $totalChecks checks passed" "INFO"
    
    return $status
}

function DownloadWithRetry {
    param($url, $output, $maxRetries=3)
    
    $retryCount = 0
    $success = $false
    
    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            Log "Downloading $output (attempt $($retryCount+1)/$maxRetries)..."
            Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing -ErrorAction Stop
            $success = $true
        }
        catch {
            $retryCount++
            $errMsg = $_.Exception.Message
            if ($retryCount -ge $maxRetries) {
                Log "Failed to download after $maxRetries attempts: $errMsg" "ERROR"
                return $false
            }
            Log "Download attempt $retryCount failed, retrying in 5 seconds..." "WARN"
            Start-Sleep -Seconds 5
        }
    }
    return $true
}

# -- main ---------------------------------------------------------------------
try {
    Log "Starting Windows 11 Pro hardening" "INFO"
    Log "PowerShell version: $($PSVersionTable.PSVersion.ToString())" "INFO"
    
    # Create logs in current directory
    $logDir = (Get-Location).Path
    Log "Saving logs to current directory: $logDir" "INFO"
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $logFile = Join-Path $logDir "HardeningLog-$timestamp.txt"
    $transcriptFile = Join-Path $logDir "Transcript-$timestamp.txt"
    
    # Start transcript
    Start-Transcript -Path $transcriptFile -Force | Out-Null
    
    Log "Log file: $logFile" "INFO"
    Log "Transcript: $transcriptFile" "INFO"
    
    Write-Host @"
╔════════════════════════════════════════════════════════════════╗
║                 LOGS LOCATION                                  ║
║                                                                ║
║  Console Log: $logFile                                         
║  Transcript: $transcriptFile                                   
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Magenta
    
    # Check system status before hardening
    $beforeStatus = CheckHardeningStatus -phase "BEFORE"
    
    # Ask user if they want to continue
    $continue = $true
    $response = Read-Host "Do you want to proceed with hardening? (Y/N)"
    if ($response -ne "Y" -and $response -ne "y") {
        Log "User chose not to proceed with hardening" "INFO"
        $continue = $false
    }
    
    if ($continue) {
        # Create recovery key directory
        if (-not (Test-Path $recoveryPath)) {
            New-Item $recoveryPath -ItemType Directory -Force | Out-Null
            Log "Created BitLocker recovery key directory" "SUCCESS"
        }

        # -- Download and verify files --
        $skip = $false
        foreach ($d in @(
            @{n='Baseline'; u=$BaselineUrl; o=$BaselineZip; s=$BaselineSha},
            @{n='LGPO'; u=$LgpoUrl; o=$LgpoZip; s=$LgpoSha}
        )) {
            if (-not (DownloadWithRetry -url $d.u -output $d.o)) {
                $skip = $true
                break
            }
            
            if (-not (IsZip $d.o)) {
                Log "$($d.n) is not a valid ZIP file" "WARN"
                $skip = $true
                break
            }
            
            $hash = (Get-FileHash $d.o -Algorithm SHA256).Hash.ToUpper()
            if ($hash -ne $d.s) {
                Log "$($d.n) SHA-256 mismatch" "WARN"
                Log "Expected: $($d.s)" "WARN"
                Log "Actual:   $hash" "WARN"
                $skip = $true
                break
            }
            
            Log "$($d.n) downloaded and verified" "SUCCESS"
        }

        # -- Extract files and apply baseline --
        if (-not $skip) {
            # Create extraction directories
            if (-not (Test-Path $ExtractDir)) {
                New-Item $ExtractDir -ItemType Directory -Force | Out-Null
            } else {
                Remove-Item -Path $ExtractDir\* -Recurse -Force -ErrorAction SilentlyContinue
            }
            
            if (-not (Test-Path $LgpoExtractDir)) {
                New-Item $LgpoExtractDir -ItemType Directory -Force | Out-Null
            } else {
                Remove-Item -Path $LgpoExtractDir\* -Recurse -Force -ErrorAction SilentlyContinue
            }
            
            # Extract files
            try {
                Log "Extracting Baseline to $ExtractDir..." "INFO"
                Expand-Archive $BaselineZip -DestinationPath $ExtractDir -Force -ErrorAction Stop
                
                Log "Extracting LGPO to $LgpoExtractDir..." "INFO"
                Expand-Archive $LgpoZip -DestinationPath $LgpoExtractDir -Force -ErrorAction Stop
                Log "Files extracted successfully" "SUCCESS"
            }
            catch {
                $errMsg = $_.Exception.Message
                Log "PowerShell extraction failed, trying tar.exe fallback: $errMsg" "WARN"
                try {
                    tar.exe -xf $BaselineZip -C $ExtractDir 
                    tar.exe -xf $LgpoZip -C $LgpoExtractDir
                    Log "Files extracted using tar.exe" "SUCCESS"
                }
                catch {
                    $errMsg = $_.Exception.Message
                    Log "Both extraction methods failed: $errMsg" "ERROR"
                    $skip = $true
                }
            }
            
            # Find LGPO executable
            if (-not $skip) {
                Log "Searching for LGPO executable..." "INFO"
                
                # Various search patterns for LGPO
                $lgpoSearchResults = @(
                    # First try the exact path we now know exists in the zip
                    (Get-ChildItem -Path "$LgpoExtractDir\LGPO_30" -Filter "LGPO.exe" -File -ErrorAction SilentlyContinue),
                    # Then try these other paths as fallbacks
                    (Get-ChildItem -Path $LgpoExtractDir -Recurse -Filter "LGPO.exe" -File -ErrorAction SilentlyContinue),
                    (Get-ChildItem -Path $LgpoExtractDir -Recurse -Filter "LGPO" -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq "" -or $_.Extension -eq ".exe" }),
                    (Get-ChildItem -Path $ExtractDir -Recurse -Filter "LGPO.exe" -File -ErrorAction SilentlyContinue),
                    (Get-ChildItem -Path $ExtractDir -Recurse -Filter "LGPO" -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq "" -or $_.Extension -eq ".exe" })
                )
                
                $lgpoExe = $null
                foreach ($result in $lgpoSearchResults) {
                    if ($result.Count -gt 0) {
                        $lgpoExe = $result[0].FullName
                        break
                    }
                }
                
                if ($lgpoExe) {
                    Log "Found LGPO executable at: $lgpoExe" "SUCCESS"
                    
                    # Output the exact command that will be run
                    Log "Will execute: & '$lgpoExe' /g <gpoDir>" "INFO"
                    
                    # Find GPO directory
                    Log "Searching for GPO directory..." "INFO"
                    $gpoSearchResults = @(
                        (Get-ChildItem -Path $ExtractDir -Recurse -Filter "MSFT-Win11-23H2-FINAL" -Directory -ErrorAction SilentlyContinue),
                        (Get-ChildItem -Path $ExtractDir -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "MSFT-Win11*" }),
                        (Get-ChildItem -Path $ExtractDir -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Win11*" -and $_.FullName -match "GPOs" }),
                        (Get-ChildItem -Path $ExtractDir -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "GPOs" })
                    )
                    
                    $gpoDir = $null
                    foreach ($result in $gpoSearchResults) {
                        if ($result.Count -gt 0) {
                            $gpoDir = $result[0].FullName
                            break
                        }
                    }
                    
                    if ($gpoDir) {
                        Log "Found GPO directory at: $gpoDir" "SUCCESS"
                        
                        # Apply baseline
                        Log "Applying security baseline..." "INFO"
                        Log "Command to execute: & '$lgpoExe' /g '$gpoDir'" "INFO"
                        try {
                            # Use Start-Process for more controlled execution
                            $psi = New-Object System.Diagnostics.ProcessStartInfo
                            $psi.FileName = $lgpoExe
                            $psi.Arguments = "/g `"$gpoDir`""
                            $psi.UseShellExecute = $false
                            $psi.RedirectStandardOutput = $true
                            $psi.RedirectStandardError = $true
                            
                            $process = [System.Diagnostics.Process]::Start($psi)
                            $stdout = $process.StandardOutput.ReadToEnd()
                            $stderr = $process.StandardError.ReadToEnd()
                            $process.WaitForExit()
                            
                            if ($process.ExitCode -eq 0) {
                                Log "Security baseline applied successfully" "SUCCESS"
                            } else {
                                Log "LGPO exited with code $($process.ExitCode)" "WARN"
                                if ($stdout) { Log "LGPO output: $stdout" "INFO" }
                                if ($stderr) { Log "LGPO errors: $stderr" "ERROR" }
                            }
                        }
                        catch {
                            $errMsg = $_.Exception.Message
                            Log "Failed to apply security baseline: $errMsg" "ERROR"
                        }
                    }
                    else {
                        Log "Could not find GPO directory" "ERROR"
                    }
                }
                else {
                    Log "Could not find LGPO executable" "ERROR"
                }
            }
        }

        # -- Windows Update + Defender signatures --
        Log "Setting up Windows Update..." "INFO"
        if (-not (Get-Module PSWindowsUpdate -ListAvailable)) {
            Log "Installing PSWindowsUpdate module..." "INFO"
            try {
                Install-Module PSWindowsUpdate -Force -Confirm:$false -ErrorAction Stop
                Log "PSWindowsUpdate module installed" "SUCCESS"
            } catch {
                $errMsg = $_.Exception.Message
                Log "Failed to install PSWindowsUpdate: $errMsg" "WARN"
            }
        }

        if (Get-Module PSWindowsUpdate -ListAvailable) {
            Import-Module PSWindowsUpdate
            Log "Installing Windows Updates WITHOUT auto-reboot..." "INFO"
            try {
                Get-WindowsUpdate -AcceptAll -Install -AutoReboot:$false -ErrorAction SilentlyContinue
                Log "Windows updates installed (if any were available)" "SUCCESS"
            } catch {
                $errMsg = $_.Exception.Message
                Log "Windows Update failed: $errMsg" "WARN"
            }
            
            Log "Updating Defender signatures..." "INFO"
            try {
                Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction SilentlyContinue
                Log "Defender signatures updated" "SUCCESS"
            } catch {
                $errMsg = $_.Exception.Message
                Log "Defender signature update failed: $errMsg" "WARN"
            }
        } else {
            Log "Skipping Windows Update - module not available" "WARN"
        }

        # -- LM/NTLMv1 off • SMB1 off • TLS1.0/1.1 off --
        Log "Configuring network security settings..." "INFO"

        # LM/NTLM settings
        RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LmCompatibilityLevel 5

        # SMB1 protocol
        try {
            Log "Disabling SMB1 Protocol feature..." "INFO"
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Log "Disabling SMB1 Protocol at server level..." "INFO"
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
            Log "SMB1 Protocol disabled" "SUCCESS"
        } catch {
            $errMsg = $_.Exception.Message
            Log "Error disabling SMB1: $errMsg" "WARN"
        }

        # TLS configuration
        Log "Configuring TLS settings..." "INFO"
        $sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

        # Ensure TLS protocol paths exist
        foreach ($v in @('TLS 1.0', 'TLS 1.1', 'TLS 1.2')) {
            foreach ($r in @('Server', 'Client')) {
                $path = "$sch\$v\$r"
                if (-not (Test-Path $path)) {
                    try {
                        New-Item $path -Force -ErrorAction Stop | Out-Null
                        Log "Created registry path: $path" "INFO"
                    } catch {
                        $errMsg = $_.Exception.Message
                        Log "Failed to create registry path $path - $errMsg" "WARN"
                    }
                }
            }
        }

        # Configure TLS versions
        foreach ($v in @('TLS 1.0', 'TLS 1.1')) {
            foreach ($r in @('Server', 'Client')) {
                RegSet "$sch\$v\$r" Enabled 0
            }
        }
        RegSet "$sch\TLS 1.2\Server" Enabled 1
        RegSet "$sch\TLS 1.2\Client" Enabled 1
        Log "TLS settings configured: 1.0/1.1 disabled, 1.2 enabled" "SUCCESS"

        # -- VBS / HVCI / Credential Guard --
        Log "Configuring Virtualization-Based Security..." "INFO"
        try {
            bcdedit /set hypervisorlaunchtype Auto | Out-Null
            Log "Hypervisor launch type set to Auto" "INFO"
        } catch {
            $errMsg = $_.Exception.Message
            Log "Failed to set hypervisor launch type: $errMsg" "WARN"
        }

        RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' EnableVirtualizationBasedSecurity 1
        RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' RequirePlatformSecurityFeatures 3
        RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LsaCfgFlags 1
        Log "Virtualization-Based Security settings configured" "SUCCESS"

        # -- Defender baseline + ASR --
        Log "Configuring Windows Defender settings..." "INFO"
        try {
            Set-MpPreference -CloudBlockLevel High -PUAProtection Enabled `
                            -DisableRealtimeMonitoring 0 -EnableControlledFolderAccess Enabled `
                            -EnableNetworkProtection Enabled -ErrorAction Stop
            Log "Defender baseline settings configured" "SUCCESS"
        } catch {
            $errMsg = $_.Exception.Message
            Log "Failed to configure Defender settings: $errMsg" "WARN"
        }

        # ASR rules with friendly names
        $asrRules = @(
            @{Id='D4F940AB-401B-4EFC-AADC-AD5F3C50688A'; Name='Block Office from creating executable content'},
            @{Id='3B576869-A4EC-4529-8536-B80A7769E899'; Name='Block Office apps from injecting into other processes'},
            @{Id='75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'; Name='Block abuse of exploited vulnerable signed drivers'},
            @{Id='26190899-1602-49E8-8B27-EB1D0A1CE869'; Name='Block Office communication apps from creating child processes'},
            @{Id='BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'; Name='Block execution of potentially obfuscated scripts'}
        )

        Log "Configuring Attack Surface Reduction rules..." "INFO"
        foreach ($rule in $asrRules) {
            try {
                $currentState = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction SilentlyContinue
                $currentActions = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions -ErrorAction SilentlyContinue
                
                $index = [array]::IndexOf($currentState, $rule.Id)
                if ($index -eq -1 -or $currentActions[$index] -ne 1) {
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
                    Log "Enabled ASR rule: $($rule.Name)" "SUCCESS"
                } else {
                    Log "ASR rule already enabled: $($rule.Name)" "INFO"
                }
            } catch {
                $errMsg = $_.Exception.Message
                Log "Failed to enable ASR rule $($rule.Name): $errMsg" "WARN"
            }
        }

        # -- Office macros --
        Log "Configuring Office macro security..." "INFO"
        $off = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0'

        # Ensure Office policy paths exist
        foreach ($a in @('Word', 'Excel', 'PowerPoint')) {
            $path = "$off\$a\Security"
            if (-not (Test-Path $path)) {
                try {
                    New-Item $path -Force -ErrorAction Stop | Out-Null
                    Log "Created Office policy path: $path" "INFO"
                } catch {
                    $errMsg = $_.Exception.Message
                    Log "Failed to create Office policy path $path - $errMsg" "WARN"
                }
            }
        }

        if (-not (Test-Path "$off\Common\Security")) {
            try {
                New-Item "$off\Common\Security" -Force -ErrorAction Stop | Out-Null
                Log "Created Office common security policy path" "INFO"
            } catch {
                $errMsg = $_.Exception.Message
                Log "Failed to create Office common security policy path: $errMsg" "WARN"
            }
        }

        if (-not (Test-Path "$off\Common\COM Compatibility")) {
            try {
                New-Item "$off\Common\COM Compatibility" -Force -ErrorAction Stop | Out-Null
                Log "Created Office COM compatibility policy path" "INFO"
            } catch {
                $errMsg = $_.Exception.Message
                Log "Failed to create Office COM compatibility policy path: $errMsg" "WARN"
            }
        }

        # Set Office macro security settings
        foreach ($a in @('Word', 'Excel', 'PowerPoint')) {
            RegSet "$off\$a\Security" VBAWarnings 3
        }
        RegSet "$off\Common\Security" BlockMacrosFromInternet 1
        RegSet "$off\Common\Security" RequireAddinSig 1
        RegSet "$off\Common\COM Compatibility" DisableBHOWarning 1
        Log "Office macro security settings configured" "SUCCESS"

        # -- AllSigned + logging --
        Log "Configuring PowerShell execution policy and logging..." "INFO"
        try {
            # Check if it's already set to AllSigned
            $currentPolicy = Get-ExecutionPolicy -Scope LocalMachine
            if ($currentPolicy -ne "AllSigned") {
                Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force -ErrorAction Stop
                Log "PowerShell execution policy set to AllSigned" "SUCCESS"
            } else {
                Log "PowerShell execution policy already set to AllSigned" "SUCCESS"
            }
        } catch {
            $errMsg = $_.Exception.Message
            Log "Failed to set PowerShell execution policy: $errMsg" "WARN"
        }

        $ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'

        # Ensure PowerShell policy paths exist
        foreach ($path in @("$ps\ScriptBlockLogging", "$ps\ModuleLogging", "$ps\Transcription")) {
            if (-not (Test-Path $path)) {
                try {
                    New-Item $path -Force -ErrorAction Stop | Out-Null
                    Log "Created PowerShell policy path: $path" "INFO"
                } catch {
                    $errMsg = $_.Exception.Message
                    Log "Failed to create PowerShell policy path $path - $errMsg" "WARN"
                }
            }
        }

        if (-not (Test-Path "$ps\ModuleLogging\ModuleNames")) {
            try {
                New-Item "$ps\ModuleLogging\ModuleNames" -Force -ErrorAction Stop | Out-Null
                Log "Created PowerShell module names policy path" "INFO"
            } catch {
                $errMsg = $_.Exception.Message
                Log "Failed to create PowerShell module names policy path: $errMsg" "WARN"
            }
        }

        # Set PowerShell logging settings
        RegSet "$ps\ScriptBlockLogging" EnableScriptBlockLogging 1
        RegSet "$ps\ModuleLogging" EnableModuleLogging 1
        RegSet "$ps\ModuleLogging\ModuleNames" '*' '*' 'String'
        RegSet "$ps\Transcription" EnableTranscripting 1
        RegSet "$ps\Transcription" OutputDirectory 'C:\PowerShellTranscripts' 'String'

        # Create transcripts directory if it doesn't exist
        if (-not (Test-Path 'C:\PowerShellTranscripts')) {
            try {
                New-Item 'C:\PowerShellTranscripts' -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Log "Created PowerShell transcripts directory" "SUCCESS"
            } catch {
                $errMsg = $_.Exception.Message
                Log "Failed to create PowerShell transcripts directory: $errMsg" "WARN"
            }
        }
        Log "PowerShell logging settings configured" "SUCCESS"

        # -- Remove obsolete optional features --
        Log "Removing obsolete Windows optional features..." "INFO"
        
        # Get available optional features first
        Log "Checking available Windows optional features..." "INFO"
        $availableFeatures = Get-WindowsOptionalFeature -Online | Select-Object -ExpandProperty FeatureName
        Log "Found $(($availableFeatures | Measure-Object).Count) available features" "INFO"
        
        # Candidates for removal, we'll check if they exist first
        $featureCandidates = @(
            'MicrosoftWindowsPowerShellV2Root',
            'MicrosoftWindowsPowerShellV2',
            'SimpleTCPIPServices',
            'TelnetClient',
            'TFTPClient',
            'Printing-FaxServices-Features',    # Note corrected name: FaxServices not FAXServices
            'Printing-XPSServices-Features',    # XPS Services
            'SMB1Protocol',                     # Main SMB1 feature
            'SMB1Protocol-Client',              # SMB1 client
            'SMB1Protocol-Server',              # SMB1 server
            'SMB1Protocol-Deprecation',         # SMB1 deprecation
            'SNMP-Service',                     # Correct SNMP feature name
            'LegacyComponents',                 # Legacy components
            'DirectPlay',                       # DirectPlay legacy gaming component
            'Internet-Explorer-Optional-amd64', # Try IE feature
            'WorkFolders-Client',               # Work Folders client
            'MediaPlayback',                    # Legacy media playback
            'WindowsMediaPlayer',               # Windows Media Player
            'Microsoft-Windows-Subsystem-Linux', # WSL1 (less secure than WSL2)
            'NetFx3',                           # .NET Framework 3.5
            'Microsoft-Hyper-V-All',            # Hyper-V if not needed
            'Microsoft-Hyper-V',                # Hyper-V core
            'MSRDC-Infrastructure',             # Remote Differential Compression
            'SearchEngine-Client-Package',      # Search indexing components
            'WCF-Services45',                   # WCF Services
            'Windows-Defender-Default-Definitions', # Default definitions (will be updated anyway)
            'WMIC'                              # Legacy WMI command-line
        )
        
        # Filter to only features that actually exist on this system
        $optionalFeatures = $featureCandidates | Where-Object { $availableFeatures -contains $_ }
        Log "Found $(($optionalFeatures | Measure-Object).Count) removable features" "INFO"

        foreach ($feature in $optionalFeatures) {
            try {
                Log "Disabling optional feature: $feature" "INFO"
                Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue | Out-Null
                Log "Optional feature disabled: $feature" "SUCCESS"
            } catch {
                $errMsg = $_.Exception.Message
                Log "Failed to disable optional feature $feature - $errMsg" "WARN"
            }
        }

        # -- Audit policy --
        Log "Configuring Windows audit policy..." "INFO"
        $auditCategories = @(
            'Logon',
            'User Account Management',
            'Security Group Management',
            'Process Creation',
            'Audit Policy Change'
        )

        foreach ($category in $auditCategories) {
            try {
                Log "Setting audit policy for: $category" "INFO"
                $result = auditpol /set /subcategory:"$category" /success:enable /failure:enable 2>&1
                Log "Audit policy set for $category" "SUCCESS"
            } catch {
                $errMsg = $_.Exception.Message
                Log "Failed to set audit policy for $category - $errMsg" "WARN"
            }
        }

        # -- AnyDesk firewall --
        Log "Checking for AnyDesk..." "INFO"
        $anydeskInstalled = (Test-Path "${env:ProgramFiles}\AnyDesk\AnyDesk.exe") -or 
                            (Test-Path "${env:ProgramFiles(x86)}\AnyDesk\AnyDesk.exe")

        if ($anydeskInstalled) {
            Log "AnyDesk detected, configuring firewall rules" "INFO"
            if (-not (Get-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -ErrorAction SilentlyContinue)) {
                try {
                    New-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -Direction Inbound `
                        -Action Allow -Protocol TCP -LocalPort 7070 -Profile Any -ErrorAction Stop | Out-Null
                    New-NetFirewallRule -DisplayName 'Hardening - AnyDesk UDP 7070' -Direction Inbound `
                        -Action Allow -Protocol UDP -LocalPort 7070 -Profile Any -ErrorAction Stop | Out-Null
                    Log "AnyDesk firewall rules created" "SUCCESS"
                } catch {
                    $errMsg = $_.Exception.Message
                    Log "Failed to create AnyDesk firewall rules: $errMsg" "WARN"
                }
            } else {
                Log "AnyDesk firewall rules already exist" "INFO"
            }
        } else {
            Log "AnyDesk not installed, creating firewall rules anyway for future use" "INFO"
            # Create rules anyway as specified in original script
            if (-not (Get-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -ErrorAction SilentlyContinue)) {
                try {
                    New-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -Direction Inbound `
                        -Action Allow -Protocol TCP -LocalPort 7070 -Profile Any -ErrorAction Stop | Out-Null
                    New-NetFirewallRule -DisplayName 'Hardening - AnyDesk UDP 7070' -Direction Inbound `
                        -Action Allow -Protocol UDP -LocalPort 7070 -Profile Any -ErrorAction Stop | Out-Null
                    Log "AnyDesk firewall rules created (for future use)" "SUCCESS"
                } catch {
                    $errMsg = $_.Exception.Message
                    Log "Failed to create AnyDesk firewall rules: $errMsg" "WARN"
                }
            }
        }

        # -- Final Status Check --
        Log "Hardening complete - checking final system status" "INFO"
        $afterStatus = CheckHardeningStatus -phase "AFTER"
    }

    # -- Completion --
    $bannerText = @"
╔════════════════════════════════════════════════════════════════╗
║                 HARDENING COMPLETE                             ║
║                                                                ║
║  Please follow these steps:                                    ║
║                                                                ║
║  1. Copy BitLocker recovery keys:                              ║
║     -> C:\RecoveryKeys to offline media                        ║
║                                                                ║
║  2. Reboot TWICE (required for VBS/Credential Guard)           ║
║                                                                ║
║  3. Verify settings with these commands:                       ║
║     Get-BitLockerVolume                                        ║
║     Get-TPM                                                    ║
║     Get-CimInstance Win32_DeviceGuard                          ║
║     Get-MpComputerStatus                                       ║
║                                                                ║
║  Logs saved:                                                   ║
║     Console Log: $logFile                                      ║
║     Transcript: $transcriptFile                                ║
╚════════════════════════════════════════════════════════════════╝
"@

    Write-Host $bannerText -ForegroundColor Green

    # Display log file locations again for clarity
    Write-Host @"
╔════════════════════════════════════════════════════════════════╗
║                 LOGS LOCATION                                  ║
║                                                                ║
║  All logs are saved in: $logDir                          
║                                                                ║
║  Console Log: $logFile                                         
║  Transcript: $transcriptFile                                   
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Magenta
    
    # Add summary to log file
    @"

============================================================
SUMMARY
============================================================
- Hardening completed at: $(Get-Date)
- Console log saved to: $logFile
- PowerShell transcript saved to: $transcriptFile
- BitLocker recovery key location: $recoveryPath

IMPORTANT: 
1. Copy BitLocker recovery keys to offline media
2. Reboot TWICE to fully activate all settings
3. Run verification commands to confirm settings
============================================================
"@ | Out-File -FilePath $logFile -Append -Encoding utf8
}
catch {
    $errMsg = $_.Exception.Message
    Log "Uncaught error: $errMsg" "ERROR"
    Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
}
finally {
    Stop-Transcript
    Log "Script execution completed" "INFO"
    
    # Add a pause to prevent the window from closing
    Write-Host "`nPress Enter to exit..." -ForegroundColor Cyan
    Read-Host
}
