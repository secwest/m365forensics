<# =====================================================================
Hardening-Win11Pro.ps1       ASCII-only, streaming-safe, single-console relaunch
---------------------------------------------------------------------------
Baseline hardening for an *un-managed* Windows 11 Pro 23H2/24H1 workstation.

SELF-UPGRADE FLOW
    • If launched under Windows PowerShell 5.1 it
        – Installs PowerShell 7 silently with winget
        – Relaunches itself **in the same console** under pwsh 7
             · From file   → calls the same file
             · From stdin  → saves itself to %TEMP%, calls that, deletes it

OPERATOR REMINDERS
    1. Run from an **elevated** console (Administrator).
    2. **BitLocker recovery keys** are saved in *C:\RecoveryKeys* – copy them offline.
    3. Reboot the system **twice** after the script completes (VBS / Cred Guard).
    4. Verify controls with the checklist at the bottom of this header.

────────────────────────────────────────────────────────────────────────────
GET THE SCRIPT
  # Download then execute (preferred)
  curl.exe -L -o Hardening-Win11Pro.ps1 ^
    https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1
  powershell.exe -ExecutionPolicy Bypass -File .\Hardening-Win11Pro.ps1

  # Stream (no file kept, auto-relaunch after pwsh 7 install)
  Set-ExecutionPolicy Bypass -Scope Process -Force
  curl.exe -L https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1 |
    powershell.exe -ExecutionPolicy Bypass -
────────────────────────────────────────────────────────────────────────────
VERIFY AFTER TWO REBOOTS
  Get-BitLockerVolume
  Get-Tpm
  msinfo32   # Secure Boot state: On
  Get-CimInstance Win32_DeviceGuard
  Get-MpComputerStatus
  auditpol /get /category:*
  Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -Max 5
────────────────────────────────────────────────────────────────────────────
License : MIT-0  •  Author : Dragos Ruiu  •  Date : 2025-05-15
===================================================================== #>

# ---------------------------- helper utilities ----------------------------
function Require-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal `
         ([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Error 'Run this script from an elevated prompt.' ; exit 1
    }
}

function Log-Info { param($m) ; Write-Host "[*] $m" }
function Log-Warn { param($m) ; Write-Host "[!] $m" -Foreground Yellow }
function Log-Fail { param($m) ; Write-Host "[X] $m" -Foreground Red    }

function Set-RegValue { param($Path,$Name,$Type='DWord',$Value)
    if (-not (Test-Path $Path)) { New-Item $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
}

function Ensure-Pwsh7 {
    if ($PSVersionTable.PSVersion.Major -ge 7) { return }

    Log-Info 'PowerShell 7 not detected — installing via winget'
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Log-Fail 'winget missing; install PowerShell 7 manually then rerun.' ; exit 1
    }

    winget install --id Microsoft.PowerShell --source winget `
                   --accept-source-agreements --accept-package-agreements --silent

    $pwsh = "$env:ProgramFiles\PowerShell\7\pwsh.exe"
    if (-not (Test-Path $pwsh)) { Log-Fail 'pwsh.exe not found after install.' ; exit 1 }

    if ($PSCommandPath) {
        & $pwsh -ExecutionPolicy Bypass -File $PSCommandPath
    } else {
        $tmp = Join-Path $env:TEMP "HardenWin11_$([guid]::NewGuid()).ps1"
        [IO.File]::WriteAllText($tmp,$MyInvocation.MyCommand.Definition,[Text.Encoding]::ASCII)
        & $pwsh -ExecutionPolicy Bypass -File $tmp
        Remove-Item -Force $tmp
    }
    exit   # leave 5.1 host only after pwsh 7 run completes
}

# ------------------------------- MAIN -------------------------------------
Require-Admin
Ensure-Pwsh7
Log-Info "Running under PowerShell $($PSVersionTable.PSVersion)"

# 1. Patch OS + Defender
Log-Info 'Installing cumulative updates (PSWindowsUpdate)'
if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
    Install-Module PSWindowsUpdate -Force -Confirm:$false
}
Import-Module PSWindowsUpdate
Get-WindowsUpdate -AcceptAll -Install -AutoReboot
Update-MpSignature -UpdateSource MicrosoftUpdateServer

# 2. BitLocker (TPM + PIN)
$pinSecure = Read-Host -AsSecureString 'Enter NUMERIC BitLocker PIN (6-20 digits)'
$pinPlain  = [Runtime.InteropServices.Marshal]::PtrToStringUni(
               [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pinSecure))
try {
    Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                     -TpmProtector -PinProtector -Pin $pinPlain `
                     -RecoveryKeyPath 'C:\RecoveryKeys'
    Log-Warn 'BitLocker keys saved in C:\RecoveryKeys – copy them offline.'
} catch { Log-Fail "BitLocker enablement failed: $_" }

# 3. Disable LM/NTLMv1, SMB1, weak TLS
Log-Info 'Disabling LM/NTLMv1, SMB1, TLS 1.0/1.1'
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 'DWord' 5
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
$sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
foreach ($p in 'TLS 1.0','TLS 1.1') { Set-RegValue "$sch\$p\Server" 'Enabled' 'DWord' 0 }
Set-RegValue "$sch\TLS 1.2\Server" 'Enabled' 'DWord' 1
Set-RegValue "$sch\TLS 1.2\Client" 'Enabled' 'DWord' 1

# 4. VBS / HVCI / Credential Guard
Log-Info 'Enabling VBS, HVCI, Credential Guard'
bcdedit /set hypervisorlaunchtype Auto | Out-Null
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
             'EnableVirtualizationBasedSecurity' 'DWord' 1
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
             'RequirePlatformSecurityFeatures'   'DWord' 3
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
             'LsaCfgFlags'                       'DWord' 1

# 5. Defender baseline + ASR
Log-Info 'Configuring Defender baseline and ASR'
Set-MpPreference -CloudBlockLevel High -PUAProtection Enabled -DisableRealtimeMonitoring 0 `
                 -ScanScheduleQuickScanTime 5 -ScanAvgCPULoadFactor 20 `
                 -EnableControlledFolderAccess Enabled -EnableNetworkProtection Enabled
$asr = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A','3B576869-A4EC-4529-8536-B80A7769E899',`
       '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84','26190899-1602-49E8-8B27-EB1D0A1CE869',`
       'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
Add-MpPreference -AttackSurfaceReductionRules_Ids $asr `
                 -AttackSurfaceReductionRules_Actions Enabled

# 6. Office macro lockdown
Log-Info 'Applying Office macro lockdown'
$office = 'HKCU:\Software\Policies\Microsoft\Office\16.0'
Set-RegValue "$office\Excel\Security"      'VBAWarnings' 'DWord' 4
Set-RegValue "$office\Word\Security"       'VBAWarnings' 'DWord' 4
Set-RegValue "$office\PowerPoint\Security" 'VBAWarnings' 'DWord' 4
Set-RegValue "$office\Common\Security"     'BlockMacrosFromInternet' 'DWord' 1
Set-RegValue "$office\Common\Security"     'RequireAddinSig'         'DWord' 1
Set-RegValue "$office\Common\COM Compatibility" 'DisableBHOWarning'  'DWord' 1

# 7. PowerShell logging + ExecutionPolicy
Log-Info 'Enabling PowerShell advanced logging'
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force
Set-RegValue 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' `
             'EnableScriptBlockLogging' 'DWord' 1
Set-RegValue 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' `
             'EnableModuleLogging'      'DWord' 1
Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
             'EnableTranscripting' 'DWord' 1
Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
             'OutputDirectory' 'String' 'C:\PSLogs'
if (-not (Test-Path C:\PSLogs)) { New-Item C:\PSLogs -ItemType Directory | Out-Null }

# 8. Remove legacy optional features
Log-Info 'Removing unused Windows optional features'
'FaxServicesClientPackage','XPSViewer','PrintFaxAndScan',
'MicrosoftPaint','WorkFolders-Client',
'Browsing-tools-Internet-Explorer-Optional-amd64','WebClient' |
  ForEach-Object { Disable-WindowsOptionalFeature -Online -FeatureName $_ -NoRestart -ErrorAction SilentlyContinue }

# 9. Minimal audit policy
Log-Info 'Applying minimal advanced audit policy'
'auditpol /set /subcategory:"System: Security System Extension" /success:enable /failure:enable',
'auditpol /set /subcategory:"Logon/Logoff: Logon"              /success:enable /failure:enable',
'auditpol /set /subcategory:"Object Access: Removable Storage" /success:enable /failure:enable',
'auditpol /set /subcategory:"Account Logon: Credential Validation" /success:enable /failure:enable',
'auditpol /set /subcategory:"Policy Change: Audit Policy Change"   /success:enable /failure:enable' |
  ForEach-Object { Invoke-Expression $_ }

Log-Warn 'Hardening COMPLETE – move BitLocker keys offline and reboot TWICE.'
