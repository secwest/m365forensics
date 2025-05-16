<# =====================================================================
Harden-Win11Pro.ps1      ASCII-only, streaming-safe, self-relaunching
-----------------------------------------------------------------------
Baseline-harden an **un-managed Windows 11 Pro 23H2/24H1** workstation.

► Self-upgrade logic
      • If the script starts under builtin Windows PowerShell 5.1, it
          – Silently installs PowerShell 7 via winget
          – Relaunches itself under **pwsh 7**
               · From a *file* → launches the same file
               · From *stdin* → stores its own text in a temp file,
                                 launches that, deletes it at exit

► Operator reminders
      1. Run from an **elevated** console (Administrator).
      2. **BitLocker recovery keys** are escrowed in *C:\RecoveryKeys*.
         Copy them to an offline vault immediately and record the PIN.
      3. Allow **two full reboots** after the script completes; VBS /
         Credential Guard are fully active only after the second restart.
      4. Optional: delete this script / console history on production hosts.

► Getting the script
      # Download-to-file (preferred):
      curl.exe -L -o Harden-Win11Pro.ps1 `
        https://raw.githubusercontent.com/secwest/m365forensics/main/Harden-Win11Pro.ps1
      powershell.exe -ExecutionPolicy Bypass -File .\Harden-Win11Pro.ps1

      # Stream (no file, auto-relaunches after installing pwsh 7):
      Set-ExecutionPolicy Bypass -Scope Process -Force
      curl.exe -L https://raw.githubusercontent.com/secwest/m365forensics/main/Harden-Win11Pro.ps1 |
        powershell.exe -ExecutionPolicy Bypass -

────────────────────────────────────────────────────────────────────────────
VERIFICATION CHECKLIST   (run after **two** reboots)
────────────────────────────────────────────────────────────────────────────
1  BitLocker           : Get-BitLockerVolume | fl VolumeStatus,EncryptionMethod
2  TPM & Secure Boot   : Confirm “TPM Present = True” → Get-Tpm
                         Confirm Secure Boot in msinfo32 (System Summary)
3  VBS / Cred Guard    : Get-CimInstance -ClassName Win32_DeviceGuard |
                         ft SecurityServicesRunning,VirtualizationBasedSecurityStatus
4  HVCI (Memory Integrity)
                       : Windows Security ▶ Device Security ▶ Core Isolation
5  Defender AV engine  : Get-MpComputerStatus | ft AMServiceEnabled,AntivirusEnabled
6  ASR rules           : Get-MpPreference |
                         Select-Object -Expand AttackSurfaceReductionRules_Ids
7  Network protection  : (Get-MpPreference).EnableNetworkProtection  # should be 1
8  PowerShell logging  : Check Event Viewer ▶ App & Svc Logs ▶ Microsoft-Windows-PowerShell
9  Audit policy        : auditpol /get /category:* | findstr /I "Removable Storage"
10 Optional baseline   : Security Compliance Toolkit ▶ Baseline scan → expect ~100 %
────────────────────────────────────────────────────────────────────────────

License : MIT-0  |  Author : ChatGPT (o3)  |  Date : 2025-05-15
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

function Set-RegValue {
    param($Path,$Name,$Type='DWord',$Value)
    if (-not (Test-Path $Path)) { New-Item $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
}

function Ensure-Pwsh7 {
    if ($PSVersionTable.PSVersion.Major -ge 7) { return }

    Log-Info 'PowerShell 7 not detected – installing via winget'
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Log-Fail 'winget is missing; install PowerShell 7 manually then rerun.' ; exit 1
    }

    Start-Process winget -Wait -ArgumentList `
        'install','--id','Microsoft.PowerShell','--source','winget',`
        '--accept-source-agreements','--accept-package-agreements','--silent'

    $pwsh = "$env:ProgramFiles\PowerShell\7\pwsh.exe"
    if (-not (Test-Path $pwsh)) {
        Log-Fail 'pwsh.exe not found after installation.' ; exit 1
    }

    if ($PSCommandPath) {           # launched from file
        Start-Process -FilePath $pwsh -Verb RunAs -ArgumentList `
            '-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`""
    } else {                        # streamed via stdin
        $tmp = [IO.Path]::Combine($env:TEMP,"HardenWin11_$([guid]::NewGuid()).ps1")
        $self = $MyInvocation.MyCommand.Definition
        [IO.File]::WriteAllText($tmp,$self,[Text.Encoding]::ASCII)
        $env:HARDEN_TEMP_FILE = $tmp
        Start-Process -FilePath $pwsh -Verb RunAs -ArgumentList `
            '-ExecutionPolicy','Bypass','-File',"`"$tmp`""
    }
    exit
}

# ---------------------------- main routine --------------------------------
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
$securePin = Read-Host -AsSecureString 'Enter NUMERIC BitLocker PIN (6-20 digits)'
$plainPin  = [Runtime.InteropServices.Marshal]::PtrToStringUni(
               [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePin))
try {
    Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                     -TpmProtector -PinProtector -Pin $plainPin `
                     -RecoveryKeyPath 'C:\RecoveryKeys'
    Log-Warn 'BitLocker keys saved in C:\RecoveryKeys – move them offline.'
} catch { Log-Fail "BitLocker enablement failed: $_" }

# 3. Disable LM/NTLMv1, SMB 1, weak TLS
Log-Info 'Disabling legacy auth and SMB 1'
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 'DWord' 5
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
$sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
foreach ($p in 'TLS 1.0','TLS 1.1') { Set-RegValue "$sch\$p\Server" 'Enabled' 'DWord' 0 }
Set-RegValue "$sch\TLS 1.2\Server" 'Enabled' 'DWord' 1
Set-RegValue "$sch\TLS 1.2\Client" 'Enabled' 'DWord' 1

# 4. VBS / HVCI / Credential Guard
Log-Info 'Enabling VBS-HVCI and Credential Guard'
bcdedit /set hypervisorlaunchtype Auto | Out-Null
Set-RegValue 'HKLM:\SYSTEM\CCS\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity' 'DWord' 1
Set-RegValue 'HKLM:\SYSTEM\CCS\Control\DeviceGuard' 'RequirePlatformSecurityFeatures'   'DWord' 3
Set-RegValue 'HKLM:\SYSTEM\CCS\Control\Lsa'         'LsaCfgFlags'                       'DWord' 1

# 5. Defender AV baseline + ASR rules
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
Log-Info 'Hardening Office macro surface'
$office='HKCU:\Software\Policies\Microsoft\Office\16.0'
Set-RegValue "$office\Excel\Security"      'VBAWarnings' 'DWord' 4
Set-RegValue "$office\Word\Security"       'VBAWarnings' 'DWord' 4
Set-RegValue "$office\PowerPoint\Security" 'VBAWarnings' 'DWord' 4
Set-RegValue "$office\Common\Security"     'BlockMacrosFromInternet' 'DWord' 1
Set-RegValue "$office\Common\Security"     'RequireAddinSig'         'DWord' 1
Set-RegValue "$office\Common\COM Compatibility" 'DisableBHOWarning'  'DWord' 1

# 7. PowerShell logging + AllSigned
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

# 8. Remove legacy Windows components
Log-Info 'Removing unused optional features'
'FaxServicesClientPackage','XPSViewer','PrintFaxAndScan',
'MicrosoftPaint','WorkFolders-Client',
'Browsing-tools-Internet-Explorer-Optional-amd64','WebClient' |
  ForEach-Object { Disable-WindowsOptionalFeature -Online -FeatureName $_ -NoRestart -ErrorAction SilentlyContinue }

# 9. Minimal advanced audit policy
Log-Info 'Applying minimal audit policy'
'auditpol /set /subcategory:"System: Security System Extension" /success:enable /failure:enable',
'auditpol /set /subcategory:"Logon/Logoff: Logon"              /success:enable /failure:enable',
'auditpol /set /subcategory:"Object Access: Removable Storage" /success:enable /failure:enable',
'auditpol /set /subcategory:"Account Logon: Credential Validation" /success:enable /failure:enable',
'auditpol /set /subcategory:"Policy Change: Audit Policy Change"   /success:enable /failure:enable' |
  ForEach-Object { Invoke-Expression $_ }

# -------------------------- clean-up temp file ----------------------------
if ($env:HARDEN_TEMP_FILE) {
    try { Remove-Item -Force $env:HARDEN_TEMP_FILE } catch {}
    Remove-Item Env:HARDEN_TEMP_FILE
}

Log-Warn 'Hardening COMPLETE – copy BitLocker keys offline, then reboot TWICE.'
