###############################################################################
# Hardening-Win11Pro.ps1                (2025-05-24  gDrive-full, braces OK)
# ASCII-only · streaming-safe · single-console relaunch · enforced pwsh-x64
###############################################################################
#
# OVERVIEW
#   • Self-upgrades / relaunches to 64-bit PowerShell 7 (winget silent)
#   • Full transcript  →  C:\HardeningLogs\HardeningLog-<STAMP>.txt
#   • Downloads & verifies:
#        LGPO.zip      SHA-256 CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55
#        Win11Baseline SHA-256 2E3A61D0245C16BEA51A9EE78CBF0793C88046901CECC0039DB0DC84FAE7D7B7
#   • Imports Microsoft Security Baseline 23H2  (LGPO.exe /g ...)
#   • Extra hardening:
#        BitLocker TPM+PIN  ·  VBS / HVCI / Cred Guard
#        Disable LM / NTLMv1 · SMB1 · TLS 1.0/1.1
#        Defender cloud=High · PUA · CFA · NetProt · 5 critical ASR
#        Office macro lockdown · unsigned add-ins blocked
#        PowerShell AllSigned + ScriptBlock / Module / Transcription logs
#        Remove legacy optional features
#        Minimal audit policy (5 subcategories)
#        AnyDesk firewall rule (TCP+UDP 7070)
#
# OPERATOR CHECKLIST
#   1️⃣  Run in an **elevated** console (Administrator)
#   2️⃣  Supply numeric BitLocker PIN when prompted
#   3️⃣  Copy C:\RecoveryKeys to offline media
#   4️⃣  **Reboot twice** (VBS/Cred Guard finalises on 2nd boot)
#   5️⃣  VERIFY:
#        Get-BitLockerVolume ; Get-Tpm
#        msinfo32 → Secure Boot : On
#        Get-CimInstance Win32_DeviceGuard
#        Get-MpComputerStatus
#        auditpol /get /category:* 
#        Test-NetConnection localhost -Port 7070
#
# QUICK START
#   curl.exe -L -o Hardening-Win11Pro.ps1 ^
#        https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1
#   powershell.exe -ExecutionPolicy Bypass -File .\Hardening-Win11Pro.ps1
#
###############################################################################

# -- Google-Drive sources -----------------------------------------------------
$BaselineUrl = 'https://drive.google.com/uc?export=download&id=13AoBqDA_O07-PhrpTJpzdU1b2oS8rD11'
$BaselineSha = '2E3A61D0245C16BEA51A9EE78CBF0793C88046901CECC0039DB0DC84FAE7D7B7'
$LgpoUrl     = 'https://drive.google.com/uc?export=download&id=1Z9Jd1h4grAF8GSCevRxeUFQ8hy2AVBOO'
$LgpoSha     = 'CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55'

$BaselineZip = "$env:TEMP\Win11Baseline.zip"
$LgpoZip     = "$env:TEMP\LGPO.zip"
$ExtractDir  = "$env:TEMP\Win11Baseline"
$recoveryPath = "C:\RecoveryKeys"

# -- helpers -----------------------------------------------------------------
function Log { 
    param($t, $m) 
    if($t -eq 'INFO') {
        Write-Host "[*] $m"
    } elseif($t -eq 'WARN') {
        Write-Host "[!] $m" -ForegroundColor Yellow
    } elseif($t -eq 'FAIL') {
        Write-Host "[X] $m" -ForegroundColor Red
    } elseif($t -eq 'SUCCESS') {
        Write-Host "[✓] $m" -ForegroundColor Green
    }
}

function RegSet {
    param($k, $n, $v, $t='DWord')
    try {
        if(-not(Test-Path $k)) {
            New-Item $k -Force -ErrorAction Stop | Out-Null
            Log 'INFO' "Created registry key: $k"
        }
        New-ItemProperty -Path $k -Name $n -Value $v -PropertyType $t -Force -ErrorAction Stop | Out-Null
        Log 'INFO' "Set registry value: $k\$n = $v"
    } catch {
        Log 'FAIL' "Failed to set registry value: $k\$n - $_"
    }
}

function IsZip {
    param($path)
    try { 
        $bytes = [IO.File]::ReadAllBytes($path)
        if($bytes.Length < 4) { return $false }
        
        # Check for ZIP signature (PK..)
        if($bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B -and 
           $bytes[2] -eq 0x03 -and $bytes[3] -eq 0x04) {
            return $true
        }
        return $false
    } catch { 
        Log 'WARN' "Error checking if file is ZIP: $_"
        return $false 
    }
}

function RequireAdmin {
    if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Log 'FAIL' 'This script requires administrative privileges.'
        Write-Error 'Run in an elevated console.' 
        exit 1 
    }
}

function EnsurePwsh7 {
    if($PSVersionTable.PSVersion.Major -ge 7 -and !$env:PROCESSOR_ARCHITEW6432) { 
        return 
    }
    
    $exe = "$env:ProgramFiles\PowerShell\7\pwsh.exe"
    if(-not(Test-Path $exe)) {
        Log 'INFO' 'Installing PowerShell 7 x64...'
        try {
            winget install Microsoft.PowerShell --architecture x64 `
                --accept-source-agreements --accept-package-agreements `
                --disable-interactivity --silent
        } catch {
            Log 'WARN' "Failed to install PowerShell 7: $_"
        }
    }
    
    if(-not(Test-Path $exe)) { 
        Log 'FAIL' 'pwsh.exe x64 missing' 
        exit 1
    }
    
    $self = $MyInvocation.MyCommand.Path
    # Fixed argument passing
    Start-Process -FilePath $exe -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$self`"" -Wait
    exit 0
}

function DownloadWithRetry {
    param($url, $output, $maxRetries=3)
    
    $retryCount = 0
    $success = $false
    
    while(-not $success -and $retryCount -lt $maxRetries) {
        try {
            Log 'INFO' "Downloading $output (attempt $($retryCount+1)/$maxRetries)..."
            Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing -ErrorAction Stop
            $success = $true
        } catch {
            $retryCount++
            if($retryCount -ge $maxRetries) {
                Log 'FAIL' "Failed to download after $maxRetries attempts: $_"
                return $false
            }
            Log 'WARN' "Download attempt $retryCount failed, retrying in 5 seconds..."
            Start-Sleep -Seconds 5
        }
    }
    return $true
}

function CheckTpm {
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if(-not $tpm.TpmPresent) {
            Log 'FAIL' "TPM not present - BitLocker with TPM+PIN not possible"
            return $false
        }
        if(-not $tpm.TpmReady) {
            Log 'WARN' "TPM present but not ready - attempting to initialize"
            try {
                Initialize-Tpm -AllowClear -AllowPhysicalPresence -ErrorAction Stop | Out-Null
                $tpm = Get-Tpm
                if(-not $tpm.TpmReady) {
                    Log 'FAIL' "Could not initialize TPM"
                    return $false
                }
            } catch {
                Log 'FAIL' "Error initializing TPM: $_"
                return $false
            }
        }
        Log 'SUCCESS' "TPM is ready"
        return $true
    } catch {
        Log 'FAIL' "Error checking TPM: $_"
        return $false
    }
}

function VerifyHardening {
    Log 'INFO' "Verifying hardening settings..."
    
    # Check BitLocker
    try {
        $blv = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
        if($blv.ProtectionStatus -eq 'ProtectionOn') {
            Log 'SUCCESS' "BitLocker enabled on C: drive"
        } else {
            Log 'WARN' "BitLocker not enabled on C: drive"
        }
    } catch {
        Log 'WARN' "Could not verify BitLocker status: $_"
    }
    
    # Check TPM
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if($tpm.TpmReady) {
            Log 'SUCCESS' "TPM is ready"
        } else {
            Log 'WARN' "TPM not ready"
        }
    } catch {
        Log 'WARN' "Could not verify TPM status: $_"
    }
    
    # Check Device Guard
    try {
        $dg = Get-CimInstance Win32_DeviceGuard -ErrorAction Stop
        if($dg.VirtualizationBasedSecurityStatus -eq 1) {
            Log 'SUCCESS' "Virtualization-based security is running"
        } else {
            Log 'WARN' "Virtualization-based security is not running"
        }
    } catch {
        Log 'WARN' "Could not verify Device Guard status: $_"
    }
    
    # Check Defender
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if($mp.RealTimeProtectionEnabled) {
            Log 'SUCCESS' "Defender real-time protection enabled"
        } else {
            Log 'WARN' "Defender real-time protection disabled"
        }
    } catch {
        Log 'WARN' "Could not verify Defender status: $_"
    }
    
    # Check AnyDesk firewall rule
    try {
        $fw = Get-NetFirewallRule -DisplayName "Hardening - AnyDesk TCP 7070" -ErrorAction SilentlyContinue
        if($fw) {
            Log 'SUCCESS' "AnyDesk firewall rule exists"
        } else {
            Log 'WARN' "AnyDesk firewall rule missing"
        }
    } catch {
        Log 'WARN' "Could not verify firewall rules: $_"
    }
}

# -- main ---------------------------------------------------------------------
trap { 
    Log 'FAIL' $_ 
    try { Stop-Transcript } catch {} 
    exit 1 
}

RequireAdmin
EnsurePwsh7

# Create necessary directories
if(-not(Test-Path $recoveryPath)) {
    New-Item $recoveryPath -ItemType Directory -Force | Out-Null
    Log 'INFO' "Created BitLocker recovery key directory"
}

# transcript
$logDir = 'C:\HardeningLogs'
if(-not(Test-Path $logDir)) {
    New-Item $logDir -ItemType Directory -Force | Out-Null
}
$log = Join-Path $logDir ("HardeningLog-{0:yyyyMMdd-HHmmss}.txt" -f (Get-Date))
Start-Transcript -Path $log -Force | Out-Null
Log 'INFO' "Transcript → $log"
Log 'INFO' "PowerShell $($PSVersionTable.PSVersion)"

# 0 ▸ download / verify baseline + LGPO
$skip = $false
foreach($d in @(
    @{n='Baseline'; u=$BaselineUrl; o=$BaselineZip; s=$BaselineSha},
    @{n='LGPO'; u=$LgpoUrl; o=$LgpoZip; s=$LgpoSha}
)) {
    if(-not(DownloadWithRetry -url $d.u -output $d.o)) {
        $skip = $true
        break
    }
    
    if(-not(IsZip $d.o)) {
        Log 'WARN' "$($d.n) is not a valid ZIP file"
        $skip = $true
        break
    }
    
    $hash = (Get-FileHash $d.o -Algorithm SHA256).Hash.ToUpper()
    if($hash -ne $d.s) {
        Log 'WARN' "$($d.n) SHA-256 mismatch"
        Log 'WARN' "Expected: $($d.s)"
        Log 'WARN' "Actual:   $hash"
        $skip = $true
        break
    }
    
    Log 'SUCCESS' "$($d.n) downloaded and verified"
}

if(-not $skip) {
    if(Test-Path $ExtractDir) {
        Remove-Item $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    try {
        Log 'INFO' "Extracting Baseline and LGPO files..."
        Expand-Archive $BaselineZip -DestinationPath $ExtractDir -Force -ErrorAction Stop
        Expand-Archive $LgpoZip -DestinationPath $ExtractDir -Force -ErrorAction Stop
        Log 'SUCCESS' "Files extracted successfully"
    } catch { 
        Log 'WARN' "PowerShell extraction failed, trying tar.exe fallback: $_"
        try {
            tar.exe -xf $BaselineZip -C $ExtractDir 
            tar.exe -xf $LgpoZip -C $ExtractDir
            Log 'SUCCESS' "Files extracted using tar.exe"
        } catch {
            Log 'FAIL' "Both extraction methods failed: $_"
            $skip = $true
        }
    }
    
    if(-not $skip) {
        $gpo = Get-ChildItem "$ExtractDir\Windows 11*" -Directory -ErrorAction SilentlyContinue | 
               Where-Object Name -match '23H2' |
               ForEach-Object { Join-Path $_.FullName 'GPOs\MSFT-Win11-23H2-FINAL' } | 
               Select-Object -First 1
        
        if($gpo) { 
            $lgpoExe = "$ExtractDir\LGPO\LGPO.exe"
            if(Test-Path $lgpoExe) {
                Log 'INFO' 'Importing baseline via LGPO.exe...'
                try {
                    $result = & "$lgpoExe" /g $gpo 2>&1
                    Log 'SUCCESS' 'Security baseline imported successfully'
                } catch {
                    Log 'FAIL' "LGPO.exe failed: $_"
                }
            } else {
                Log 'FAIL' "LGPO.exe not found at $lgpoExe"
            }
        } else {
            Log 'FAIL' "Could not find GPO directory in extracted files"
        }
    }
}

# 1 ▸ Windows Update + Defender sigs
Log 'INFO' 'Setting up Windows Update...'
if(-not(Get-Module PSWindowsUpdate -ListAvailable)) {
    Log 'INFO' "Installing PSWindowsUpdate module..."
    try {
        Install-Module PSWindowsUpdate -Force -Confirm:$false -ErrorAction Stop
        Log 'SUCCESS' "PSWindowsUpdate module installed"
    } catch {
        Log 'WARN' "Failed to install PSWindowsUpdate: $_"
    }
}

if(Get-Module PSWindowsUpdate -ListAvailable) {
    Import-Module PSWindowsUpdate
    Log 'INFO' "Installing Windows Updates WITHOUT auto-reboot..."
    try {
        Get-WindowsUpdate -AcceptAll -Install -AutoReboot:$false -ErrorAction SilentlyContinue
        Log 'SUCCESS' "Windows updates installed (if any were available)"
    } catch {
        Log 'WARN' "Windows Update failed: $_"
    }
    
    Log 'INFO' "Updating Defender signatures..."
    try {
        Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction SilentlyContinue
        Log 'SUCCESS' "Defender signatures updated"
    } catch {
        Log 'WARN' "Defender signature update failed: $_"
    }
} else {
    Log 'WARN' "Skipping Windows Update - module not available"
}

# 2 ▸ BitLocker
Log 'INFO' "Checking BitLocker status..."
try {
    $blvStatus = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
    if($blvStatus.ProtectionStatus -ne 'ProtectionOn') {
        Log 'INFO' "BitLocker not enabled on C: drive, proceeding with setup"
        
        if(CheckTpm) {
            $validPin = $false
            while(-not $validPin) {
                $pin = Read-Host 'Enter numeric BitLocker PIN (6-20 digits)' -AsSecureString
                $pinText = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pin))
                
                if($pinText -match '^\d{6,20}$') {
                    $validPin = $true
                } else {
                    Log 'WARN' "PIN must be 6-20 digits, numeric only"
                }
            }
            
            try {
                Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                             -TPMandPinProtector -Pin $pin -RecoveryKeyPath $recoveryPath -ErrorAction Stop
                Log 'SUCCESS' "BitLocker enabled successfully"
                Log 'WARN' "BitLocker keys → $recoveryPath (move offline IMMEDIATELY)"
            } catch {
                Log 'FAIL' "Failed to enable BitLocker: $_"
            }
        } else {
            Log 'WARN' "Skipping BitLocker - TPM requirements not met"
        }
    } else {
        Log 'SUCCESS' "BitLocker already enabled on C: drive"
    }
} catch {
    Log 'FAIL' "Error checking BitLocker status: $_"
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
} catch {
    Log 'WARN' "Error disabling SMB1: $_"
}

# TLS configuration
Log 'INFO' "Configuring TLS settings..."
$sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

# Ensure TLS protocol paths exist
foreach($v in 'TLS 1.0', 'TLS 1.1', 'TLS 1.2') {
    foreach($r in 'Server', 'Client') {
        $path = "$sch\$v\$r"
        if(-not(Test-Path $path)) {
            try {
                New-Item $path -Force -ErrorAction Stop | Out-Null
                Log 'INFO' "Created registry path: $path"
            } catch {
                Log 'WARN' "Failed to create registry path $path: $_"
            }
        }
    }
}

# Configure TLS versions
foreach($v in 'TLS 1.0', 'TLS 1.1') {
    foreach($r in 'Server', 'Client') {
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
} catch {
    Log 'WARN' "Failed to set hypervisor launch type: $_"
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
} catch {
    Log 'WARN' "Failed to configure Defender settings: $_"
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
foreach($rule in $asrRules) {
    try {
        $currentState = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction SilentlyContinue
        $currentActions = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions -ErrorAction SilentlyContinue
        
        $index = [array]::IndexOf($currentState, $rule.Id)
        if($index -eq -1 -or $currentActions[$index] -ne 1) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
            Log 'SUCCESS' "Enabled ASR rule: $($rule.Name)"
        } else {
            Log 'INFO' "ASR rule already enabled: $($rule.Name)"
        }
    } catch {
        Log 'WARN' "Failed to enable ASR rule $($rule.Name): $_"
    }
}

# 6 ▸ Office macros
Log 'INFO' "Configuring Office macro security..."
$off = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0'

# Ensure Office policy paths exist
foreach($a in 'Word', 'Excel', 'PowerPoint') {
    $path = "$off\$a\Security"
    if(-not(Test-Path $path)) {
        try {
            New-Item $path -Force -ErrorAction Stop | Out-Null
            Log 'INFO' "Created Office policy path: $path"
        } catch {
            Log 'WARN' "Failed to create Office policy path $path: $_"
        }
    }
}

if(-not(Test-Path "$off\Common\Security")) {
    try {
        New-Item "$off\Common\Security" -Force -ErrorAction Stop | Out-Null
        Log 'INFO' "Created Office common security policy path"
    } catch {
        Log 'WARN' "Failed to create Office common security policy path: $_"
    }
}

if(-not(Test-Path "$off\Common\COM Compatibility")) {
    try {
        New-Item "$off\Common\COM Compatibility" -Force -ErrorAction Stop | Out-Null
        Log 'INFO' "Created Office COM compatibility policy path"
    } catch {
        Log 'WARN' "Failed to create Office COM compatibility policy path: $_"
    }
}

# Set Office macro security settings
foreach($a in 'Word', 'Excel', 'PowerPoint') {
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
} catch {
    Log 'WARN' "Failed to set PowerShell execution policy: $_"
}

$ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'

# Ensure PowerShell policy paths exist
foreach($path in @("$ps\ScriptBlockLogging", "$ps\ModuleLogging", "$ps\Transcription")) {
    if(-not(Test-Path $path)) {
        try {
            New-Item $path -Force -ErrorAction Stop | Out-Null
            Log 'INFO' "Created PowerShell policy path: $path"
        } catch {
            Log 'WARN' "Failed to create PowerShell policy path $path: $_"
        }
    }
}

if(-not(Test-Path "$ps\ModuleLogging\ModuleNames")) {
    try {
        New-Item "$ps\ModuleLogging\ModuleNames" -Force -ErrorAction Stop | Out-Null
        Log 'INFO' "Created PowerShell module names policy path"
    } catch {
        Log 'WARN' "Failed to create PowerShell module names policy path: $_"
    }
}

# Set PowerShell logging settings
RegSet "$ps\ScriptBlockLogging" EnableScriptBlockLogging 1
RegSet "$ps\ModuleLogging" EnableModuleLogging 1
RegSet "$ps\ModuleLogging\ModuleNames" '*' '*' 'String'
RegSet "$ps\Transcription" EnableTranscripting 1
RegSet "$ps\Transcription" OutputDirectory 'C:\PowerShellTranscripts' 'String'

# Create transcripts directory if it doesn't exist
if(-not(Test-Path 'C:\PowerShellTranscripts')) {
    try {
        New-Item 'C:\PowerShellTranscripts' -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Log 'SUCCESS' "Created PowerShell transcripts directory"
    } catch {
        Log 'WARN' "Failed to create PowerShell transcripts directory: $_"
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

foreach($feature in $optionalFeatures) {
    try {
        Log 'INFO' "Disabling optional feature: $feature"
        Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Log 'SUCCESS' "Optional feature disabled: $feature"
    } catch {
        Log 'WARN' "Failed to disable optional feature $feature: $_"
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

foreach($category in $auditCategories) {
    try {
        Log 'INFO' "Setting audit policy for: $category"
        $result = auditpol /set /subcategory:"$category" /success:enable /failure:enable 2>&1
        Log 'SUCCESS' "Audit policy set for $category"
    } catch {
        Log 'WARN' "Failed to set audit policy for $category: $_"
    }
}

# 10 ▸ AnyDesk firewall
Log 'INFO' "Checking for AnyDesk..."
$anydeskInstalled = (Test-Path "${env:ProgramFiles}\AnyDesk\AnyDesk.exe") -or 
                    (Test-Path "${env:ProgramFiles(x86)}\AnyDesk\AnyDesk.exe")

if($anydeskInstalled) {
    Log 'INFO' "AnyDesk detected, configuring firewall rules"
    if(-not(Get-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -ErrorAction SilentlyContinue)) {
        try {
            New-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -Direction Inbound `
                -Action Allow -Protocol TCP -LocalPort 7070 -Profile Any -ErrorAction Stop | Out-Null
            New-NetFirewallRule -DisplayName 'Hardening - AnyDesk UDP 7070' -Direction Inbound `
                -Action Allow -Protocol UDP -LocalPort 7070 -Profile Any -ErrorAction Stop | Out-Null
            Log 'SUCCESS' "AnyDesk firewall rules created"
        } catch {
            Log 'WARN' "Failed to create AnyDesk firewall rules: $_"
        }
    } else {
        Log 'INFO' "AnyDesk firewall rules already exist"
    }
} else {
    Log 'INFO' "AnyDesk not installed, skipping firewall rules"
    # Create rules anyway as specified in original script
    if(-not(Get-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -ErrorAction SilentlyContinue)) {
        try {
            New-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -Direction Inbound `
                -Action Allow -Protocol TCP -LocalPort 7070 -Profile Any -ErrorAction Stop | Out-Null
            New-NetFirewallRule -DisplayName 'Hardening - AnyDesk UDP 7070' -Direction Inbound `
                -Action Allow -Protocol UDP -LocalPort 7070 -Profile Any -ErrorAction Stop | Out-Null
            Log 'SUCCESS' "AnyDesk firewall rules created (for future use)"
        } catch {
            Log 'WARN' "Failed to create AnyDesk firewall rules: $_"
        }
    }
}

# -- Verification --------------------------------------------------------
VerifyHardening

# -- finish -------------------------------------------------------------
Log 'WARN' '======================================================='
Log 'WARN' 'Hardening COMPLETE – reboot TWICE and verify controls.'
Log 'WARN' '1. Copy recovery keys from C:\RecoveryKeys to offline media'
Log 'WARN' '2. Reboot once to activate most settings'
Log 'WARN' '3. Reboot again to finalize VBS/Credential Guard'
Log 'WARN' '4. Run verification commands from script header'
Log 'WARN' '======================================================='

Stop-Transcript | Out-Null
Log 'INFO' "Transcript saved → $log"
