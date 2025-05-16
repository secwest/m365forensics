###############################################################################
# Windows 11 Pro Hardening Script - Self-elevating and PowerShell 7 compatible
# This script will:
# 1. Check for administrative privileges
# 2. Install PowerShell 7 if needed
# 3. Launch the hardening portion with PowerShell 7
#
# USAGE: powershell.exe -ExecutionPolicy Bypass -File .\Windows11Pro-Hardening.ps1
###############################################################################

<#
.SYNOPSIS
    Windows 11 Pro hardening script with automatic PowerShell 7 upgrade
.DESCRIPTION
    Comprehensive Windows 11 Pro hardening script that self-elevates, installs
    PowerShell 7 if needed, and applies a full set of security hardening measures
.NOTES
    Run with: powershell.exe -ExecutionPolicy Bypass -File .\Windows11Pro-Hardening.ps1
#>

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

# If in PS7 with admin rights, run the hardening portion directly
if ($inPs7 -and $isAdmin) {
    Write-Host "Running hardening script in PowerShell 7..." -ForegroundColor Green
    # Let script continue to main hardening section
}
# If in PS5.1 (or older) with admin rights, need to switch to PS7
elseif ($isAdmin) {
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

# -- Google-Drive sources -----------------------------------------------------
$BaselineUrl = 'https://drive.google.com/uc?export=download&id=13AoBqDA_O07-PhrpTJpzdU1b2oS8rD11'
$BaselineSha = '2E3A61D0245C16BEA51A9EE78CBF0793C88046901CECC0039DB0DC84FAE7D7B7'
$LgpoUrl     = 'https://drive.google.com/uc?export=download&id=1Z9Jd1h4grAF8GSCevRxeUFQ8hy2AVBOO'
$LgpoSha     = 'CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55'

$BaselineZip = "$env:TEMP\Win11Baseline.zip"
$LgpoZip     = "$env:TEMP\LGPO.zip"
$ExtractDir  = "$env:TEMP\Win11Baseline"
$recoveryPath = "C:\RecoveryKeys"

# -- tiny helpers -------------------------------------------------------------
function Log {
    param($t, $m)
    if ($t -eq 'INFO') {
        Write-Host "[*] $m"
    }
    elseif ($t -eq 'WARN') {
        Write-Host "[!] $m" -ForegroundColor Yellow
    }
    elseif ($t -eq 'FAIL') {
        Write-Host "[X] $m" -ForegroundColor Red
    }
    elseif ($t -eq 'SUCCESS') {
        Write-Host "[+] $m" -ForegroundColor Green
    }
}

function RegSet {
    param($k, $n, $v, $t='DWord')
    try {
        if (-not (Test-Path $k)) {
            New-Item $k -Force -ErrorAction Stop | Out-Null
            Log 'INFO' "Created registry key: $k"
        }
        New-ItemProperty -Path $k -Name $n -Value $v -PropertyType $t -Force -ErrorAction Stop | Out-Null
        Log 'INFO' "Set registry value: $k\$n = $v"
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'FAIL' "Failed to set registry value: $k\$n - $errMsg"
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
        Log 'WARN' "Error checking if file is ZIP: $errMsg"
        return $false 
    }
}

function CheckTpm {
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if (-not $tpm.TpmPresent) {
            Log 'FAIL' "TPM not present - BitLocker with TPM+PIN not possible"
            return $false
        }
        if (-not $tpm.TpmReady) {
            Log 'WARN' "TPM present but not ready - attempting to initialize"
            try {
                Initialize-Tpm -AllowClear -AllowPhysicalPresence -ErrorAction Stop | Out-Null
                $tpm = Get-Tpm
                if (-not $tpm.TpmReady) {
                    Log 'FAIL' "Could not initialize TPM"
                    return $false
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                Log 'FAIL' "Error initializing TPM: $errMsg"
                return $false
            }
        }
        Log 'SUCCESS' "TPM is ready"
        return $true
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'FAIL' "Error checking TPM: $errMsg"
        return $false
    }
}

function DownloadWithRetry {
    param($url, $output, $maxRetries=3)
    
    $retryCount = 0
    $success = $false
    
    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            Log 'INFO' "Downloading $output (attempt $($retryCount+1)/$maxRetries)..."
            Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing -ErrorAction Stop
            $success = $true
        }
        catch {
            $retryCount++
            $errMsg = $_.Exception.Message
            if ($retryCount -ge $maxRetries) {
                Log 'FAIL' "Failed to download after $maxRetries attempts: $errMsg"
                return $false
            }
            Log 'WARN' "Download attempt $retryCount failed, retrying in 5 seconds..."
            Start-Sleep -Seconds 5
        }
    }
    return $true
}

function VerifyHardening {
    Log 'INFO' "Verifying hardening settings..."
    
    # Check BitLocker
    try {
        $blv = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
        if ($blv.ProtectionStatus -eq 'ProtectionOn') {
            Log 'SUCCESS' "BitLocker enabled on C: drive"
        }
        else {
            Log 'WARN' "BitLocker not enabled on C: drive"
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'WARN' "Could not verify BitLocker status: $errMsg"
    }
    
    # Check TPM
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if ($tpm.TpmReady) {
            Log 'SUCCESS' "TPM is ready"
        }
        else {
            Log 'WARN' "TPM not ready"
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'WARN' "Could not verify TPM status: $errMsg"
    }
    
    # Check Device Guard
    try {
        $dg = Get-CimInstance Win32_DeviceGuard -ErrorAction Stop
        if ($dg.VirtualizationBasedSecurityStatus -eq 1) {
            Log 'SUCCESS' "Virtualization-based security is running"
        }
        else {
            Log 'WARN' "Virtualization-based security is not running"
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'WARN' "Could not verify Device Guard status: $errMsg"
    }
    
    # Check Defender
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.RealTimeProtectionEnabled) {
            Log 'SUCCESS' "Defender real-time protection enabled"
        }
        else {
            Log 'WARN' "Defender real-time protection disabled"
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'WARN' "Could not verify Defender status: $errMsg"
    }
    
    # Check AnyDesk firewall rule
    try {
        $fw = Get-NetFirewallRule -DisplayName "Hardening - AnyDesk TCP 7070" -ErrorAction SilentlyContinue
        if ($fw) {
            Log 'SUCCESS' "AnyDesk firewall rule exists"
        }
        else {
            Log 'WARN' "AnyDesk firewall rule missing"
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'WARN' "Could not verify firewall rules: $errMsg"
    }
}

# -- main ---------------------------------------------------------------------
trap { 
    $errMsg = $_.Exception.Message
    Log 'FAIL' $errMsg
    try { Stop-Transcript } catch {} 
    exit 1 
}

# Create script banner
$psVersion = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor).$($PSVersionTable.PSVersion.Patch)"
Write-Host @"
╔════════════════════════════════════════════════════════════════╗
║                 WINDOWS 11 PRO HARDENING SCRIPT                ║
║                                                                ║
║  This script applies Microsoft security baseline and           ║
║  additional hardening measures to your Windows 11 Pro system.  ║
║                                                                ║
║  PowerShell Version: $psVersion                                $(if($psVersion.Length -lt 8){" "})║
║  Running as Administrator: Yes                                 ║
╚════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Create necessary directories
if (-not (Test-Path $recoveryPath)) {
    New-Item $recoveryPath -ItemType Directory -Force | Out-Null
    Log 'INFO' "Created BitLocker recovery key directory"
}

# transcript
$logDir = 'C:\HardeningLogs'
if (-not (Test-Path $logDir)) {
    New-Item $logDir -ItemType Directory -Force | Out-Null
}
$log = Join-Path $logDir ("HardeningLog-{0:yyyyMMdd-HHmmss}.txt" -f (Get-Date))
Start-Transcript -Path $log -Force | Out-Null
Log 'INFO' "Transcript -> $log"
Log 'INFO' "PowerShell $($PSVersionTable.PSVersion)"

# 0 ▸ download / verify baseline + LGPO
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
        Log 'WARN' "$($d.n) is not a valid ZIP file"
        $skip = $true
        break
    }
    
    $hash = (Get-FileHash $d.o -Algorithm SHA256).Hash.ToUpper()
    if ($hash -ne $d.s) {
        Log 'WARN' "$($d.n) SHA-256 mismatch"
        Log 'WARN' "Expected: $($d.s)"
        Log 'WARN' "Actual:   $hash"
        $skip = $true
        break
    }
    
    Log 'SUCCESS' "$($d.n) downloaded and verified"
}

if (-not $skip) {
    if (Test-Path $ExtractDir) {
        Remove-Item $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    try {
        Log 'INFO' "Extracting Baseline and LGPO files..."
        Expand-Archive $BaselineZip -DestinationPath $ExtractDir -Force -ErrorAction Stop
        Expand-Archive $LgpoZip -DestinationPath $ExtractDir -Force -ErrorAction Stop
        Log 'SUCCESS' "Files extracted successfully"
    }
    catch { 
        $errMsg = $_.Exception.Message
        Log 'WARN' "PowerShell extraction failed, trying tar.exe fallback: $errMsg"
        try {
            tar.exe -xf $BaselineZip -C $ExtractDir 
            tar.exe -xf $LgpoZip -C $ExtractDir
            Log 'SUCCESS' "Files extracted using tar.exe"
        }
        catch {
            $errMsg = $_.Exception.Message
            Log 'FAIL' "Both extraction methods failed: $errMsg"
            $skip = $true
        }
    }
    
    if (-not $skip) {
        $gpo = Get-ChildItem "$ExtractDir\Windows 11*" -Directory -ErrorAction SilentlyContinue | 
               Where-Object { $_.Name -match '23H2' } |
               ForEach-Object { Join-Path $_.FullName 'GPOs\MSFT-Win11-23H2-FINAL' } | 
               Select-Object -First 1
        
        if ($gpo) { 
            $lgpoExe = "$ExtractDir\LGPO\LGPO.exe"
            if (Test-Path $lgpoExe) {
                Log 'INFO' 'Importing baseline via LGPO.exe...'
                try {
                    $result = & "$lgpoExe" /g $gpo 2>&1
                    Log 'SUCCESS' 'Security baseline imported successfully'
                }
                catch {
                    $errMsg = $_.Exception.Message
                    Log 'FAIL' "LGPO.exe failed: $errMsg"
                }
            }
            else {
                Log 'FAIL' "LGPO.exe not found at $lgpoExe"
            }
        }
        else {
            Log 'FAIL' "Could not find GPO directory in extracted files"
        }
    }
}

# 1 ▸ Windows Update + Defender sigs
Log 'INFO' 'Setting up Windows Update...'
if (-not (Get-Module PSWindowsUpdate -ListAvailable)) {
    Log 'INFO' "Installing PSWindowsUpdate module..."
    try {
        Install-Module PSWindowsUpdate -Force -Confirm:$false -ErrorAction Stop
        Log 'SUCCESS' "PSWindowsUpdate module installed"
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'WARN' "Failed to install PSWindowsUpdate: $errMsg"
    }
}

if (Get-Module PSWindowsUpdate -ListAvailable) {
    Import-Module PSWindowsUpdate
    Log 'INFO' "Installing Windows Updates WITHOUT auto-reboot..."
    try {
        Get-WindowsUpdate -AcceptAll -Install -AutoReboot:$false -ErrorAction SilentlyContinue
        Log 'SUCCESS' "Windows updates installed (if any were available)"
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'WARN' "Windows Update failed: $errMsg"
    }
    
    Log 'INFO' "Updating Defender signatures..."
    try {
        Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction SilentlyContinue
        Log 'SUCCESS' "Defender signatures updated"
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'WARN' "Defender signature update failed: $errMsg"
    }
}
else {
    Log 'WARN' "Skipping Windows Update - module not available"
}

# 2 ▸ BitLocker
Log 'INFO' "Checking BitLocker status..."
try {
    $blvStatus = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
    if ($blvStatus.ProtectionStatus -ne 'ProtectionOn') {
        Log 'INFO' "BitLocker not enabled on C: drive, proceeding with setup"
        
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
                    Log 'WARN' "PIN must be 6-20 digits, numeric only"
                }
            }
            
            try {
                Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                             -TPMandPinProtector -Pin $pin -RecoveryKeyPath $recoveryPath -ErrorAction Stop
                Log 'SUCCESS' "BitLocker enabled successfully"
                Log 'WARN' "BitLocker keys -> $recoveryPath (move offline IMMEDIATELY)"
            }
            catch {
                $errMsg = $_.Exception.Message
                Log 'FAIL' "Failed to enable BitLocker: $errMsg"
            }
        }
        else {
            Log 'WARN' "Skipping BitLocker - TPM requirements not met"
        }
    }
    else {
        Log 'SUCCESS' "BitLocker already enabled on C: drive"
    }
}
catch {
    $errMsg = $_.Exception.Message
    Log 'FAIL' "Error checking BitLocker status: $errMsg"
}

# 3 ▸ LM/NTLMv1 off • SMB1 off • TLS1.0/1.1 off
Log 'INFO' "Configuring network security settings..."

# LM/NTLM settings
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LmCompatibilityLevel 5

# SMB1 protocol
try {
    Log 'INFO' "Disabling SMB1 Protocol feature..."
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Log 'INFO' "Disabling SMB1 Protocol at server level..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
    Log 'SUCCESS' "SMB1 Protocol disabled"
}
catch {
    $errMsg = $_.Exception.Message
    Log 'WARN' "Error disabling SMB1: $errMsg"
}

# TLS configuration
Log 'INFO' "Configuring TLS settings..."
$sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

# Ensure TLS protocol paths exist
foreach ($v in @('TLS 1.0', 'TLS 1.1', 'TLS 1.2')) {
    foreach ($r in @('Server', 'Client')) {
        $path = "$sch\$v\$r"
        if (-not (Test-Path $path)) {
            try {
                New-Item $path -Force -ErrorAction Stop | Out-Null
                Log 'INFO' "Created registry path: $path"
            }
            catch {
                $errMsg = $_.Exception.Message
                Log 'WARN' "Failed to create registry path $path - $errMsg"
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
Log 'SUCCESS' "TLS settings configured: 1.0/1.1 disabled, 1.2 enabled"

# 4 ▸ VBS / HVCI / Credential Guard
Log 'INFO' "Configuring Virtualization-Based Security..."
try {
    bcdedit /set hypervisorlaunchtype Auto | Out-Null
    Log 'INFO' "Hypervisor launch type set to Auto"
}
catch {
    $errMsg = $_.Exception.Message
    Log 'WARN' "Failed to set hypervisor launch type: $errMsg"
}

RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' EnableVirtualizationBasedSecurity 1
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' RequirePlatformSecurityFeatures 3
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LsaCfgFlags 1
Log 'SUCCESS' "Virtualization-Based Security settings configured"

# 5 ▸ Defender baseline + ASR
Log 'INFO' "Configuring Windows Defender settings..."
try {
    Set-MpPreference -CloudBlockLevel High -PUAProtection Enabled `
                    -DisableRealtimeMonitoring 0 -EnableControlledFolderAccess Enabled `
                    -EnableNetworkProtection Enabled -ErrorAction Stop
    Log 'SUCCESS' "Defender baseline settings configured"
}
catch {
    $errMsg = $_.Exception.Message
    Log 'WARN' "Failed to configure Defender settings: $errMsg"
}

# ASR rules with friendly names
$asrRules = @(
    @{Id='D4F940AB-401B-4EFC-AADC-AD5F3C50688A'; Name='Block Office from creating executable content'},
    @{Id='3B576869-A4EC-4529-8536-B80A7769E899'; Name='Block Office apps from injecting into other processes'},
    @{Id='75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'; Name='Block abuse of exploited vulnerable signed drivers'},
    @{Id='26190899-1602-49E8-8B27-EB1D0A1CE869'; Name='Block Office communication apps from creating child processes'},
    @{Id='BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'; Name='Block execution of potentially obfuscated scripts'}
)

Log 'INFO' "Configuring Attack Surface Reduction rules..."
foreach ($rule in $asrRules) {
    try {
        $currentState = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction SilentlyContinue
        $currentActions = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions -ErrorAction SilentlyContinue
        
        $index = [array]::IndexOf($currentState, $rule.Id)
        if ($index -eq -1 -or $currentActions[$index] -ne 1) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
            Log 'SUCCESS' "Enabled ASR rule: $($rule.Name)"
        }
        else {
            Log 'INFO' "ASR rule already enabled: $($rule.Name)"
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'WARN' "Failed to enable ASR rule $($rule.Name): $errMsg"
    }
}

# 6 ▸ Office macros
Log 'INFO' "Configuring Office macro security..."
$off = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0'

# Ensure Office policy paths exist
foreach ($a in @('Word', 'Excel', 'PowerPoint')) {
    $path = "$off\$a\Security"
    if (-not (Test-Path $path)) {
        try {
            New-Item $path -Force -ErrorAction Stop | Out-Null
            Log 'INFO' "Created Office policy path: $path"
        }
        catch {
            $errMsg = $_.Exception.Message
            Log 'WARN' "Failed to create Office policy path $path - $errMsg"
        }
    }
}

if (-not (Test-Path "$off\Common\Security")) {
    try {
        New-Item "$off\Common\Security" -Force -ErrorAction Stop | Out-Null
        Log 'INFO' "Created Office common security policy path"
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'WARN' "Failed to create Office common security policy path: $errMsg"
    }
}

if (-not (Test-Path "$off\Common\COM Compatibility")) {
    try {
        New-Item "$off\Common\COM Compatibility" -Force -ErrorAction Stop | Out-Null
        Log 'INFO' "Created Office COM compatibility policy path"
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'WARN' "Failed to create Office COM compatibility policy path: $errMsg"
    }
}

# Set Office macro security settings
foreach ($a in @('Word', 'Excel', 'PowerPoint')) {
    RegSet "$off\$a\Security" VBAWarnings 3
}
RegSet "$off\Common\Security" BlockMacrosFromInternet 1
RegSet "$off\Common\Security" RequireAddinSig 1
RegSet "$off\Common\COM Compatibility" DisableBHOWarning 1
Log 'SUCCESS' "Office macro security settings configured"

# 7 ▸ AllSigned + logging
Log 'INFO' "Configuring PowerShell execution policy and logging..."
try {
    Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force -ErrorAction Stop
    Log 'SUCCESS' "PowerShell execution policy set to AllSigned"
}
catch {
    $errMsg = $_.Exception.Message
    Log 'WARN' "Failed to set PowerShell execution policy: $errMsg"
}

$ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'

# Ensure PowerShell policy paths exist
foreach ($path in @("$ps\ScriptBlockLogging", "$ps\ModuleLogging", "$ps\Transcription")) {
    if (-not (Test-Path $path)) {
        try {
            New-Item $path -Force -ErrorAction Stop | Out-Null
            Log 'INFO' "Created PowerShell policy path: $path"
        }
        catch {
            $errMsg = $_.Exception.Message
            Log 'WARN' "Failed to create PowerShell policy path $path - $errMsg"
        }
    }
}

if (-not (Test-Path "$ps\ModuleLogging\ModuleNames")) {
    try {
        New-Item "$ps\ModuleLogging\ModuleNames" -Force -ErrorAction Stop | Out-Null
        Log 'INFO' "Created PowerShell module names policy path"
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'WARN' "Failed to create PowerShell module names policy path: $errMsg"
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
        Log 'SUCCESS' "Created PowerShell transcripts directory"
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'WARN' "Failed to create PowerShell transcripts directory: $errMsg"
    }
}
Log 'SUCCESS' "PowerShell logging settings configured"

# 8 ▸ Remove obsolete optional features
Log 'INFO' "Removing obsolete Windows optional features..."
$optionalFeatures = @(
    'MicrosoftWindowsPowerShellV2Root',
    'SimpleTCPIPServices',
    'TelnetClient',
    'TFTPClient'
)

foreach ($feature in $optionalFeatures) {
    try {
        Log 'INFO' "Disabling optional feature: $feature"
        Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Log 'SUCCESS' "Optional feature disabled: $feature"
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'WARN' "Failed to disable optional feature $feature - $errMsg"
    }
}

# 9 ▸ Audit policy
Log 'INFO' "Configuring Windows audit policy..."
$auditCategories = @(
    'Logon',
    'User Account Management',
    'Security Group Management',
    'Process Creation',
    'Audit Policy Change'
)

foreach ($category in $auditCategories) {
    try {
        Log 'INFO' "Setting audit policy for: $category"
        $result = auditpol /set /subcategory:"$category" /success:enable /failure:enable 2>&1
        Log 'SUCCESS' "Audit policy set for $category"
    }
    catch {
        $errMsg = $_.Exception.Message
        Log 'WARN' "Failed to set audit policy for $category - $errMsg"
    }
}

# 10 ▸ AnyDesk firewall
Log 'INFO' "Checking for AnyDesk..."
$anydeskInstalled = (Test-Path "${env:ProgramFiles}\AnyDesk\AnyDesk.exe") -or 
                    (Test-Path "${env:ProgramFiles(x86)}\AnyDesk\AnyDesk.exe")

if ($anydeskInstalled) {
    Log 'INFO' "AnyDesk detected, configuring firewall rules"
    if (-not (Get-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -ErrorAction SilentlyContinue)) {
        try {
            New-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -Direction Inbound `
                -Action Allow -Protocol TCP -LocalPort 7070 -Profile Any -ErrorAction Stop | Out-Null
            New-NetFirewallRule -DisplayName 'Hardening - AnyDesk UDP 7070' -Direction Inbound `
                -Action Allow -Protocol UDP -LocalPort 7070 -Profile Any -ErrorAction Stop | Out-Null
            Log 'SUCCESS' "AnyDesk firewall rules created"
        }
        catch {
            $errMsg = $_.Exception.Message
            Log 'WARN' "Failed to create AnyDesk firewall rules: $errMsg"
        }
    }
    else {
        Log 'INFO' "AnyDesk firewall rules already exist"
    }
}
else {
    Log 'INFO' "AnyDesk not installed, creating firewall rules anyway for future use"
    # Create rules anyway as specified in original script
    if (-not (Get-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -ErrorAction SilentlyContinue)) {
        try {
            New-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -Direction Inbound `
                -Action Allow -Protocol TCP -LocalPort 7070 -Profile Any -ErrorAction Stop | Out-Null
            New-NetFirewallRule -DisplayName 'Hardening - AnyDesk UDP 7070' -Direction Inbound `
                -Action Allow -Protocol UDP -LocalPort 7070 -Profile Any -ErrorAction Stop | Out-Null
            Log 'SUCCESS' "AnyDesk firewall rules created (for future use)"
        }
        catch {
            $errMsg = $_.Exception.Message
            Log 'WARN' "Failed to create AnyDesk firewall rules: $errMsg"
        }
    }
}

# -- Verification --------------------------------------------------------
VerifyHardening

# -- finish -------------------------------------------------------------
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
║  Transcript saved: $log                                        ║
╚════════════════════════════════════════════════════════════════╝
"@

Write-Host $bannerText -ForegroundColor Green

Stop-Transcript | Out-Null
Log 'INFO' "Transcript saved -> $log"
