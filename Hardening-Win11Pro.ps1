###############################################################################
# Windows 11 Pro Hardening Script - Self-elevating and PowerShell 7 compatible
# This script will:
# 1. Check for administrative privileges
# 2. Install PowerShell 7 if needed
# 3. Launch the hardening portion with PowerShell 7
#
# USAGE: powershell.exe -ExecutionPolicy Bypass -File .\Windows11Pro-Hardening.ps1
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
# MAIN HARDENING SECTION - PowerShell 7 Compatible
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
    $logMessage | Out-File -FilePath $logFile -Append -Encoding utf8
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
        
        Log "BitLocker: $($status.BitLocker.Details)" ($status.BitLocker.Enabled ? "SUCCESS" : "WARN")
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
        
        Log "TPM: $($status.TPM.Details)" ($status.TPM.Enabled ? "SUCCESS" : "WARN")
    } catch {
        $status.TPM = @{ Present = $false; Ready = $false; Enabled = $false; Details = "Error checking TPM: $_" }
        Log "TPM: $($status.TPM.Details)" "ERROR"
    }
    
    # 3. DeviceGuard/VBS Status
    try {
        $dg = Get-CimInstance Win32_DeviceGuard -ErrorAction Stop
        $vbsStatus = $dg.VirtualizationBasedSecurityStatus
        $hvciStatus = $dg.HypervisorEnforcedCodeIntegrityStatus
        
        $status.DeviceGuard = @{
            VBSEnabled = ($vbsStatus -eq 1 -or $vbsStatus -eq 2)
            HVCIEnabled = ($hvciStatus -eq 1 -or $hvciStatus -eq 2)
            Details = "VBS: $(if($vbsStatus -eq 0){'Not enabled'}elseif($vbsStatus -eq 1){'Enabled & running'}elseif($vbsStatus -eq 2){'Enabled but not running'}else{'Unknown'}), " +
                      "HVCI: $(if($hvciStatus -eq 0){'Not enabled'}elseif($hvciStatus -eq 1){'Enabled & running'}elseif($hvciStatus -eq 2){'Enabled but not running'}else{'Unknown'})"
        }
        
        Log "Device Guard: $($status.DeviceGuard.Details)" (($status.DeviceGuard.VBSEnabled -or $status.DeviceGuard.HVCIEnabled) ? "SUCCESS" : "WARN")
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
        
        Log "Credential Guard: $($status.CredGuard.Details)" ($status.CredGuard.Enabled ? "SUCCESS" : "WARN")
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
        
        Log "Defender: $($status.Defender.Details)" ($status.Defender.RTEnabled ? "SUCCESS" : "WARN")
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
        
        Log "PowerShell: $($status.ExecutionPolicy.Details)" ($status.ExecutionPolicy.Restricted ? "SUCCESS" : "WARN")
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
        
        Log "SMB1: $($status.SMB1.Details)" ($status.SMB1.Disabled ? "SUCCESS" : "WARN")
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
        
        Log "TLS: $($status.TLS.Details)" ($status.TLS.Secure ? "SUCCESS" : "WARN")
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
        
        Log "AnyDesk: $($status.AnyDesk.Details)" ($status.AnyDesk.RuleExists ? "SUCCESS" : "INFO")
    } catch {
        $status.AnyDesk = @{ RuleExists = $false; Details = "Error checking AnyDesk firewall rule: $_" }
        Log "AnyDesk: $($status.AnyDesk.Details)" "ERROR"
    }
    
    # Final Summary
    $totalChecks = 9
    $passedChecks = @($status.BitLocker.Enabled, 
                      $status.TPM.Enabled, 
                      $status.DeviceGuard.VBSEnabled, 
                      $status.CredGuard.Enabled,
                      $status.Defender.RTEnabled,
                      $status.ExecutionPolicy.Restricted,
                      $status.SMB1.Disabled,
                      $status.TLS.Secure,
                      $status.AnyDesk.RuleExists) | Where-Object { $_ -eq $true } | Measure-Object | Select-Object -ExpandProperty Count
    
    $summaryText = @"
╔════════════════════════════════════════════════════════════════╗
║               HARDENING STATUS SUMMARY                         ║
║                                                                ║
║  Checks passed: $passedChecks of $totalChecks                            
║  Status: $(if($passedChecks -eq $totalChecks){'ALL CHECKS PASSED'}elseif($passedChecks -ge 6){'MOST CHECKS PASSED'}else{'MULTIPLE CHECKS FAILED'})
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
"@
    
    Write-Host $summaryText -ForegroundColor $(if($passedChecks -eq $totalChecks){'Green'}elseif($passedChecks -ge 6){'Yellow'}else{'Red'})
    Log "Status check complete - $passedChecks of $totalChecks checks passed" "INFO"
    
    return $status
}

# -- Main hardening section ---------------------------------------------------
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

    # -- BitLocker --
    Log "Checking BitLocker status..." "INFO"
    try {
        $blvStatus = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
        if ($blvStatus.ProtectionStatus -ne 'ProtectionOn') {
            Log "BitLocker not enabled on C: drive, proceeding with setup" "INFO"
            
            if (CheckTpm) {
                $validPin = $false
                while (-not $validPin) {
                    $pin = Read-Host "Enter numeric BitLocker PIN (6-20 digits)" -AsSecureString
                    
                    # Convert SecureString to plain text for validation
                    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pin)
                    $pinText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
                    
                    # Match exactly 6-20 digits
                    if ($pinText -match "^\d{6,20}$") {
                        $validPin = $true
                    }
                    else {
                        Log "PIN must be 6-20 digits, numeric only" "WARN"
                    }
                }
                
                try {
                    Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                                 -TPMandPinProtector -Pin $pin -RecoveryKeyPath $recoveryPath -ErrorAction Stop
                    Log "BitLocker enabled successfully" "SUCCESS"
                    Log "BitLocker keys -> $recoveryPath (move offline IMMEDIATELY)" "WARN"
                }
                catch {
                    $errMsg = $_.Exception.Message
                    Log "Failed to enable BitLocker: $errMsg" "ERROR"
                }
            }
            else {
                Log "Skipping BitLocker - TPM requirements not met" "WARN"
            }
        }
        else {
            Log "BitLocker already enabled on C: drive" "SUCCESS"
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Log "Error checking BitLocker status: $errMsg" "ERROR"
    }

    # -- Final Status Check --
    Log "Hardening complete - checking final system status" "INFO"
    $afterStatus = CheckHardeningStatus -phase "AFTER"

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
