<# =====================================================================
 Hardening-Win11Pro.ps1                                    ASCII-only
 Streaming-safe • single-console relaunch • robust self-upgrade to pwsh 7
 -----------------------------------------------------------------------
 Baseline hardening for an **un-managed Windows 11 Pro 23H2/24H1** PC.

 WHAT IT DOES
   • Installs PowerShell 7 if the script starts in Windows PowerShell 5.1
     – winget silent install, relaunches itself **in the same console**
       · From file   → re-executes the file
       · From stdin  → writes itself to %TEMP%, runs that copy, removes it
   • Enables BitLocker (TPM + PIN, XTS-AES-256) – keys land in C:\RecoveryKeys
   • Disables legacy auth (LM/NTLMv1, SMB 1, TLS 1.0/1.1)
   • Turns on VBS / HVCI / Credential Guard
   • Applies Defender baseline + five critical ASR rules
   • Locks down Office macros + unsigned add-ins
   • Sets PowerShell AllSigned + script-block/module/transcription logging
   • Removes stale optional features  (ignored if not present)
   • Configures a minimal but high value advanced audit policy

 OPERATOR REMINDERS
   1  Run from an **elevated** console (Administrator).
   2  Copy **BitLocker recovery keys** from *C:\RecoveryKeys* to offline storage.
   3  Reboot **TWICE** after the script completes – VBS / Cred Guard finish.
   4  Verify controls with the checklist below.

 GET & RUN
   # Download to file (preferred)
   curl.exe -L -o Hardening-Win11Pro.ps1 ^
     https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1
   powershell.exe -ExecutionPolicy Bypass -File .\Hardening-Win11Pro.ps1

   # Stream (no file remains)
   Set-ExecutionPolicy Bypass -Scope Process -Force
   curl.exe -L https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1 |
     powershell.exe -ExecutionPolicy Bypass -

 VERIFY AFTER TWO REBOOTS
   Get-BitLockerVolume
   Get-Tpm
   msinfo32   → “Secure Boot State : On”
   Get-CimInstance Win32_DeviceGuard
   Get-MpComputerStatus
   auditpol /get /category:*
   Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -Max 5

 MIT-0 • Author : Dragos Ruiu • Last update : 2025-05-16
===================================================================== #>

# ───── helper utilities ────────────────────────────────────────────────
function Require-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal `
                 ([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Error 'Run this script from an **elevated** console.' ; exit 1
    }
}

function Log-Info { param($m) ; Write-Host "[*] $m" }
function Log-Warn { param($m) ; Write-Host "[!] $m" -Foreground Yellow }
function Log-Fail { param($m) ; Write-Host "[X] $m" -Foreground Red    }

function Set-Reg {  # safe wrapper  Set-Reg <path> <name> <value> [type]
    param($Path,$Name,$Value,[string]$Type='DWord')
    if (-not (Test-Path $Path)) { New-Item $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value `
                     -PropertyType $Type -Force | Out-Null
}

# ───── self-upgrade to PowerShell 7 ────────────────────────────────────
function Ensure-Pwsh7 {
    if ($PSVersionTable.PSVersion.Major -ge 7) { return }   # already pwsh 7

    Log-Info 'Installing PowerShell 7 silently (winget)'
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Log-Fail 'winget missing; install PowerShell 7 manually and rerun.' ; exit 1
    }

    winget install --id Microsoft.PowerShell --accept-source-agreements `
                   --accept-package-agreements --silent

    $pwsh = @(
      "$([Environment]::GetEnvironmentVariable('ProgramW6432'))\PowerShell\7\pwsh.exe",
      "$env:ProgramFiles\PowerShell\7\pwsh.exe" ) | Where-Object { Test-Path $_ } |
      Select-Object -First 1

    if (-not $pwsh) { Log-Fail 'pwsh.exe not found after installation.' ; exit 1 }

    if ($PSCommandPath) {                 # launched from file
        & $pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
    } else {                              # launched from stdin
        $tmp = Join-Path $env:TEMP "HardenWin11_$([guid]::NewGuid()).ps1"
        [IO.File]::WriteAllText($tmp,$MyInvocation.MyCommand.Definition,[Text.Encoding]::ASCII)
        & $pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File $tmp
        Remove-Item $tmp
    }
    exit                                  # leave 5.1 host after pwsh pass
}

# ───── MAIN ────────────────────────────────────────────────────────────
Require-Admin
Ensure-Pwsh7
Log-Info "Running under pwsh $($PSVersionTable.PSVersion)"

# 1 ─ OS & Defender updates
Log-Info 'Applying latest cumulative updates (PSWindowsUpdate)'
if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
    Install-Module PSWindowsUpdate -Force -Confirm:$false
}
Import-Module PSWindowsUpdate
Get-WindowsUpdate -AcceptAll -Install -AutoReboot
Update-MpSignature -UpdateSource MicrosoftUpdateServer

# 2 ─ BitLocker (TPM + PIN, XTS-AES-256)
$pin = Read-Host -AsSecureString 'Numeric BitLocker PIN (6-20 digits)'
Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                 -TpmProtector -PinProtector -Pin $pin -RecoveryKeyPath C:\RecoveryKeys
Log-Warn 'Recovery keys stored in C:\RecoveryKeys — copy to offline vault.'

# 3 ─ Disable legacy auth & weak crypto
Log-Info 'Disabling LM/NTLMv1, SMB 1, TLS 1.0/1.1'
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LmCompatibilityLevel 5
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
$proto='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
'TLS 1.0','TLS 1.1' | ForEach-Object { Set-Reg "$proto\$_\Server" Enabled 0 }
Set-Reg "$proto\TLS 1.2\Server" Enabled 1 ; Set-Reg "$proto\TLS 1.2\Client" Enabled 1

# 4 ─ VBS • HVCI • Credential Guard
Log-Info 'Enabling VBS, HVCI, Credential Guard'
bcdedit /set hypervisorlaunchtype Auto | Out-Null
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' EnableVirtualizationBasedSecurity 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' RequirePlatformSecurityFeatures 3
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LsaCfgFlags 1

# 5 ─ Defender baseline + critical ASR
Log-Info 'Configuring Microsoft Defender baseline'
Set-MpPreference -CloudBlockLevel High -PUAProtection Enabled -DisableRealtimeMonitoring 0 `
                 -ScanScheduleQuickScanTime 5 -ScanAvgCPULoadFactor 20 `
                 -EnableControlledFolderAccess Enabled -EnableNetworkProtection Enabled
$asr = @(
 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A', # Office child process
 '3B576869-A4EC-4529-8536-B80A7769E899', # LSASS creds
 '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84', # Office macro write
 '26190899-1602-49E8-8B27-EB1D0A1CE869', # Adobe child process
 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'  # Exec from email|web
)
Add-MpPreference -AttackSurfaceReductionRules_Ids $asr `
                 -AttackSurfaceReductionRules_Actions Enabled

# 6 ─ Office macro lockdown
Log-Info 'Hardening Office macro surface'
$office = 'HKCU:\Software\Policies\Microsoft\Office\16.0'
'Excel','Word','PowerPoint' | ForEach-Object { Set-Reg "$office\$_\Security" VBAWarnings 4 }
Set-Reg "$office\Common\Security" BlockMacrosFromInternet 1
Set-Reg "$office\Common\Security" RequireAddinSig 1
Set-Reg "$office\Common\COM Compatibility" DisableBHOWarning 1

# 7 ─ PowerShell logging + AllSigned
Log-Info 'Enabling PowerShell advanced logging'
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force >$null 2>&1
Set-Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' EnableScriptBlockLogging 1
Set-Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' EnableModuleLogging 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' EnableTranscripting 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
        OutputDirectory 'C:\PSLogs' String
if (-not (Test-Path C:\PSLogs)) { New-Item C:\PSLogs -ItemType Directory | Out-Null }

# 8 ─ Remove legacy optional features (ignore if missing)
Log-Info 'Removing unused Windows optional features'
$features = 'FaxServicesClientPackage','XPS-Viewer','Printing-ScanToPDFServices-Features',
            'MicrosoftPaint','WorkFolders-Client','IIS-WebClient'
foreach ($feat in $features) {
    try { Disable-WindowsOptionalFeature -Online -FeatureName $feat -NoRestart -ErrorAction Stop }
    catch {}
}

# 9 ─ Minimal advanced audit policy
Log-Info 'Applying minimal advanced audit policy'
$aud = @{
  'System'        = 'Security System Extension'
  'Logon/Logoff'  = 'Logon'
  'Object Access' = 'Removable Storage'
  'Account Logon' = 'Credential Validation'
  'Policy Change' = 'Audit Policy Change'
}
$aud.GetEnumerator() | ForEach-Object {
    auditpol /set /subcategory:"$($_.Key): $($_.Value)" /success:enable /failure:enable | Out-Null
}

Log-Warn 'Hardening COMPLETE — reboot twice and secure your recovery keys.'
