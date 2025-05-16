<# =====================================================================
 Hardening-Win11Pro.ps1
 ASCII-only • streaming-safe • single-console relaunch
 -----------------------------------------------------------------------
 Baseline hardening for an **un-managed Windows 11 Pro 23H2/24H1** host.

 ➊ Self-upgrade — installs PowerShell 7 when launched from Windows PowerShell 5.1
 ➋ Hardening steps
    • BitLocker  (TPM + PIN, XTS-AES-256, Used-Space)
    • Disable LM/NTLMv1, SMB 1, TLS 1.0/1.1
    • Enable VBS, HVCI, Credential Guard
    • Defender baseline + critical ASR rules
    • Office macro lockdown
    • PowerShell AllSigned + full logging
    • Minimal advanced audit policy
    • Remove legacy optional features

 OPERATOR REMINDERS
   1  Run in an *elevated* console (Administrator).
   2  Copy **BitLocker keys** from *C:\RecoveryKeys* to offline storage.
   3  Reboot **twice** after completion (VBS / CG fully active).
   4  Verify with commands listed at the bottom.

 GET & RUN
   # Download→file (preferred)
   curl.exe -L -o Hardening-Win11Pro.ps1 ^
     https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1
   powershell.exe -ExecutionPolicy Bypass -File .\Hardening-Win11Pro.ps1

   # Stream (no file left behind)
   Set-ExecutionPolicy Bypass -Scope Process -Force
   curl.exe -L https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1 |
     powershell.exe -ExecutionPolicy Bypass -
────────────────────────────────────────────────────────────────────────────
 VERIFY AFTER TWO REBOOTS
   Get-BitLockerVolume
   Get-Tpm
   msinfo32  → Secure Boot = On
   Get-CimInstance Win32_DeviceGuard
   Get-MpComputerStatus
   auditpol /get /subcategory:"Removable Storage"
   Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -Max 5
────────────────────────────────────────────────────────────────────────────
 Author : Dragos Ruiu • MIT-0 • updated 2025-05-17
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

function Set-Reg {
    param(
      [string]$Path, [string]$Name, [object]$Value,
      [ValidateSet('DWord','QWord','String','ExpandString')] [string]$Type = 'DWord'
    )
    if (-not (Test-Path $Path)) { New-Item $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

# ───── self-upgrade to PowerShell 7 ─────────────────────────────────────
function Ensure-Pwsh7 {
    if ($PSVersionTable.PSVersion.Major -ge 7) { return }   # already pwsh 7

    Log-Info 'PowerShell 7 not detected — installing silently'
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Log-Fail 'winget missing; install PowerShell 7 manually and rerun.' ; exit 1
    }

    winget install --id Microsoft.PowerShell `
                   --accept-source-agreements --accept-package-agreements --silent

    $pwsh = @(
      "$([Environment]::GetEnvironmentVariable('ProgramW6432'))\PowerShell\7\pwsh.exe",
      "$env:ProgramFiles\PowerShell\7\pwsh.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $pwsh) { Log-Fail 'pwsh.exe not found after installation.' ; exit 1 }

    if ($PSCommandPath) {
        & $pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
    } else {
        $tmp = Join-Path $env:TEMP ("Harden_"+[guid]::NewGuid()+'.ps1')
        [IO.File]::WriteAllText($tmp,$MyInvocation.MyCommand.Definition,[Text.Encoding]::ASCII)
        & $pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File $tmp
        Remove-Item $tmp -Force
    }
    exit
}

# ───── MAIN ────────────────────────────────────────────────────────────
Require-Admin
Ensure-Pwsh7
Log-Info "Running under pwsh $($PSVersionTable.PSVersion)"

# 1 ▸ OS + Defender updates
if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
    Install-Module PSWindowsUpdate -Force -Confirm:$false
}
Import-Module PSWindowsUpdate
Get-WindowsUpdate -AcceptAll -Install -AutoReboot
Update-MpSignature -UpdateSource MicrosoftUpdateServer

# 2 ▸ BitLocker (TPM + PIN, XTS-AES-256)
$pin = Read-Host -Prompt 'Numeric BitLocker PIN (6-20 digits)'
Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                 -TpmAndPinProtector -Pin $pin -RecoveryKeyPath C:\RecoveryKeys
Log-Warn 'Recovery keys saved in C:\RecoveryKeys — move them offline.'

# 3 ▸ Legacy auth + crypto surface
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LmCompatibilityLevel 5
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
$proto='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
'TLS 1.0','TLS 1.1' | ForEach-Object { Set-Reg "$proto\$_\Server" Enabled 0 }
Set-Reg "$proto\TLS 1.2\Server" Enabled 1 ; Set-Reg "$proto\TLS 1.2\Client" Enabled 1

# 4 ▸ VBS / HVCI / Credential Guard
bcdedit /set hypervisorlaunchtype Auto | Out-Null
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' EnableVirtualizationBasedSecurity 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' RequirePlatformSecurityFeatures 3
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LsaCfgFlags 1

# 5 ▸ Microsoft Defender baseline + critical ASR
Set-MpPreference -CloudBlockLevel High -PUAProtection Enabled -DisableRealtimeMonitoring 0 `
                 -ScanScheduleQuickScanTime 5 -ScanAvgCPULoadFactor 20 `
                 -EnableControlledFolderAccess Enabled -EnableNetworkProtection Enabled
$asr = @(
  'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',
  '3B576869-A4EC-4529-8536-B80A7769E899',
  '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84',
  '26190899-1602-49E8-8B27-EB1D0A1CE869',
  'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
)
Add-MpPreference -AttackSurfaceReductionRules_Ids $asr `
                 -AttackSurfaceReductionRules_Actions Enabled

# 6 ▸ Office macro lockdown
$office='HKCU:\Software\Policies\Microsoft\Office\16.0'
'Excel','Word','PowerPoint' | ForEach-Object { Set-Reg "$office\$_\Security" VBAWarnings 4 }
Set-Reg "$office\Common\Security" BlockMacrosFromInternet 1
Set-Reg "$office\Common\Security" RequireAddinSig 1
Set-Reg "$office\Common\COM Compatibility" DisableBHOWarning 1

# 7 ▸ PowerShell logging + AllSigned
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force 2>$null
Set-Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' EnableScriptBlockLogging 1
Set-Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' EnableModuleLogging 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' EnableTranscripting 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
        OutputDirectory 'C:\PSLogs' String
if (-not (Test-Path C:\PSLogs)) { New-Item C:\PSLogs -ItemType Directory | Out-Null }

# 8 ▸ Remove unused optional features (ignore missing)
$features = 'FaxServicesClientPackage','XPS-Viewer','Printing-ScanToPDFServices-Features',
            'MicrosoftPaint','WorkFolders-Client','IIS-WebClient'
foreach ($f in $features) {
    try { Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction Stop }
    catch {}
}

# 9 ▸ Minimal advanced audit policy
$sub = 'Security System Extension','Logon','Removable Storage',
       'Credential Validation','Audit Policy Change'
$sub | ForEach-Object {
    auditpol /set /subcategory:"$_" /success:enable /failure:enable | Out-Null
}

Log-Warn 'Hardening COMPLETE — reboot twice and secure your recovery keys.'
