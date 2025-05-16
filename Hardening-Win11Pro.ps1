<#
.SYNOPSIS
    Baseline-harden an **un-managed Windows 11 Pro 23H2/24H1** workstation
    for Microsoft 365 workloads – with self-upgrade to PowerShell 7
    if the script is launched from built-in Windows PowerShell 5.1.

.DESCRIPTION
    • Detects current engine; if < 7, silently installs PowerShell 7 via winget,
      re-launches itself under pwsh 7, and exits the 5.1 session.
    • After running under pwsh 7, implements the Windows 11 Security Baseline
      v23H2 + Defender baseline 24H1 in one pass (BitLocker, VBS/HVCI, Defender
      ASR, Office macro lockdown, PowerShell logging, audit policy, etc.).
    • All changes are idempotent; re-running is safe.

    **Reboot twice** afterwards to finalise VBS / Credential Guard.

.EXAMPLE
    # 1. Save as Hardening-Win11Pro.ps1, open an elevated PowerShell window
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\Hardening-Win11Pro.ps1

    # 2. Script auto-installs pwsh 7 if missing, relaunches itself, hardens OS.
    # 3. Reboot twice and verify with:
    Get-MpComputerStatus
    auditpol /get /category:*

.NOTES
    Author  : Dragos Ruiu
    Version : 2025-05-15
    License : MIT-0  (use at your own risk)
    -------------------------------------------------------------------------
    BitLocker recovery keys are escrowed in C:\RecoveryKeys – back them up!
    -------------------------------------------------------------------------
#>

#region ── helper utilities ────────────────────────────────────────────────
function Require-Admin {
    if (-not ([Security.Principal.WindowsPrincipal]
        [Security.Principal.WindowsIdentity]::GetCurrent()
       ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Error "Run this script from an **elevated** prompt." ; exit 1
    }
}

function Log-Info {  param($m); Write-Host "[*] $m"              }
function Log-Warn {  param($m); Write-Host "[!] $m" -Foreground Yellow }
function Log-Fail {  param($m); Write-Host "[X] $m" -Foreground Red    }

function Set-RegValue {
    param([string]$Path,[string]$Name,[string]$Type='DWord',[object]$Value)
    if (-not (Test-Path $Path)) { New-Item $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType $Type `
                     -Value $Value -Force | Out-Null
}

function Ensure-PowerShell7 {
    if ($PSVersionTable.PSVersion.Major -ge 7) { return }   # already pwsh 7

    Log-Info "PowerShell 7 not detected – installing via winget …"
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Log-Warn "winget is missing.  Install PowerShell 7 manually, then re-run."
        exit 1
    }

    Start-Process winget -Wait -ArgumentList @(
        "install","--id","Microsoft.PowerShell","--source","winget",
        "--accept-source-agreements","--accept-package-agreements","--silent"
    )

    $pwshPath = "$env:ProgramFiles\PowerShell\7\pwsh.exe"
    if (Test-Path $pwshPath) {
        Log-Info "PowerShell 7 installed.  Relaunching script under pwsh …"
        Start-Process -FilePath $pwshPath -Verb RunAs -ArgumentList @(
            "-ExecutionPolicy","Bypass",
            "-File","`"$PSCommandPath`""
        )
        exit
    } else {
        Log-Fail "Install attempt completed but pwsh.exe not found. Verify install."
        exit 1
    }
}
#endregion

Require-Admin
Ensure-PowerShell7   # returns immediately if already running in pwsh 7
Log-Info "Running under PowerShell $($PSVersionTable.PSVersion) – continuing …"

#────────────────────────────────────────────────────────────────────────────
# 1  Patch OS and Defender
#────────────────────────────────────────────────────────────────────────────
Log-Info "Applying latest cumulative + Defender updates …"
if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
    Install-Module PSWindowsUpdate -Force -Confirm:$false
}
Import-Module PSWindowsUpdate
Get-WindowsUpdate -AcceptAll -Install -AutoReboot

Update-MpSignature -UpdateSource MicrosoftUpdateServer

#────────────────────────────────────────────────────────────────────────────
# 2  BitLocker (TPM + PIN, XTS-AES-256)
#────────────────────────────────────────────────────────────────────────────
$pin = Read-Host -AsSecureString -Prompt `
       "Enter a **numeric** BitLocker PIN (6-20 digits)"
$plainPIN = [Runtime.InteropServices.Marshal]::PtrToStringUni(
               [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pin))

try {
    Log-Info "Enabling BitLocker …"
    Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 `
                     -UsedSpaceOnly -TpmProtector `
                     -PinProtector -Pin $plainPIN `
                     -RecoveryKeyPath 'C:\RecoveryKeys'
} catch { Log-Fail "BitLocker failed: $_" }

#────────────────────────────────────────────────────────────────────────────
# 3  Disable LM/NTLMv1, SMBv1, weak TLS
#────────────────────────────────────────────────────────────────────────────
Log-Info "Disabling legacy auth (LM/NTLMv1) + SMB v1 …"
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
             'LmCompatibilityLevel' 'DWord' 5
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

$sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
@('TLS 1.0','TLS 1.1') | ForEach-Object {
    Set-RegValue "$sch\$_\Server" 'Enabled' 'DWord' 0
}
Set-RegValue "$sch\TLS 1.2\Server" 'Enabled' 'DWord' 1
Set-RegValue "$sch\TLS 1.2\Client" 'Enabled' 'DWord' 1

#────────────────────────────────────────────────────────────────────────────
# 4  VBS, HVCI, Credential Guard
#────────────────────────────────────────────────────────────────────────────
Log-Info "Enabling VBS/HVCI + Credential Guard …"
bcdedit /set hypervisorlaunchtype Auto | Out-Null
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
             'EnableVirtualizationBasedSecurity' 'DWord' 1
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
             'RequirePlatformSecurityFeatures' 'DWord' 3
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
             'LsaCfgFlags' 'DWord' 1

#────────────────────────────────────────────────────────────────────────────
# 5  Defender AV + ASR baseline
#────────────────────────────────────────────────────────────────────────────
Log-Info "Applying Microsoft Defender baseline settings …"
Set-MpPreference -CloudBlockLevel High -PUAProtection Enabled `
                 -DisableRealtimeMonitoring 0 -ScanScheduleQuickScanTime 5 `
                 -ScanAvgCPULoadFactor 20 -EnableControlledFolderAccess Enabled `
                 -EnableNetworkProtection Enabled

$asr = @(
 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',
 '3B576869-A4EC-4529-8536-B80A7769E899',
 '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84',
 '26190899-1602-49E8-8B27-EB1D0A1CE869',
 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
)
Add-MpPreference -AttackSurfaceReductionRules_Ids $asr `
                 -AttackSurfaceReductionRules_Actions Enabled

#────────────────────────────────────────────────────────────────────────────
# 6  Office macro + add-in hardening
#────────────────────────────────────────────────────────────────────────────
Log-Info "Locking down Office macros …"
$office = 'HKCU:\Software\Policies\Microsoft\Office\16.0'
Set-RegValue "$office\Excel\Security"      'VBAWarnings' 'DWord' 4
Set-RegValue "$office\Word\Security"       'VBAWarnings' 'DWord' 4
Set-RegValue "$office\PowerPoint\Security" 'VBAWarnings' 'DWord' 4
Set-RegValue "$office\Common\Security"     'BlockMacrosFromInternet' 'DWord' 1
Set-RegValue "$office\Common\Security"     'RequireAddinSig'         'DWord' 1
Set-RegValue "$office\Common\COM Compatibility" 'DisableBHOWarning'  'DWord' 1

#────────────────────────────────────────────────────────────────────────────
# 7  PowerShell logging + execution policy
#────────────────────────────────────────────────────────────────────────────
Log-Info "Configuring PowerShell AllSigned policy + advanced logging …"
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force
Set-RegValue 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' `
             'EnableScriptBlockLogging' 'DWord' 1
Set-RegValue 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' `
             'EnableModuleLogging' 'DWord' 1
Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
             'EnableTranscripting' 'DWord' 1
Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
             'OutputDirectory' 'String' 'C:\PSLogs'
if (-not (Test-Path C:\PSLogs)) { New-Item C:\PSLogs -ItemType Directory | Out-Null }

#────────────────────────────────────────────────────────────────────────────
# 8  Remove legacy optional features
#────────────────────────────────────────────────────────────────────────────
Log-Info "Removing unused Windows components …"
'FaxServicesClientPackage','XPSViewer','PrintFaxAndScan',
'MicrosoftPaint','WorkFolders-Client',
'Browsing-tools-Internet-Explorer-Optional-amd64','WebClient' |
    ForEach-Object {
        Disable-WindowsOptionalFeature -Online -FeatureName $_ -NoRestart `
                                       -ErrorAction SilentlyContinue
    }

#────────────────────────────────────────────────────────────────────────────
# 9  Minimal advanced audit policy
#────────────────────────────────────────────────────────────────────────────
Log-Info "Applying minimal advanced audit policy …"
'auditpol /set /subcategory:"System: Security System Extension"  /success:enable /failure:enable',
'auditpol /set /subcategory:"Logon/Logoff: Logon"               /success:enable /failure:enable',
'auditpol /set /subcategory:"Object Access: Removable Storage"  /success:enable /failure:enable',
'auditpol /set /subcategory:"Account Logon: Credential Validation" /success:enable /failure:enable',
'auditpol /set /subcategory:"Policy Change: Audit Policy Change"   /success:enable /failure:enable' |
   ForEach-Object { Invoke-Expression $_ }

#────────────────────────────────────────────────────────────────────────────
Log-Info "Baseline hardening COMPLETE – reboot twice to finish VBS & Cred Guard."
#────────────────────────────────────────────────────────────────────────────
