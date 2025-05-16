<# =====================================================================
 Hardening-Win11Pro.ps1                                (v2025-05-20 “Full”)
 ASCII-only · streaming-safe · single-console relaunch · pwsh x64 enforced
────────────────────────────────────────────────────────────────────────────
 PURPOSE
   Bring a fresh **Windows 11 Pro 23H2/24H1** workstation up to:

     • The official **Microsoft Security Baseline** (Win 11 23H2 FINAL)
     • Additional hardening Microsoft recommends but does not enforce:
         – BitLocker TPM + PIN, XTS-AES-256, used-space-only
         – VBS / HVCI / Credential Guard
         – Disable LM / NTLMv1, SMB 1, TLS 1.0 / 1.1 (server & client)
         – Defender baseline + five critical ASR rules, CFA, NetProt
         – Office macro lockdown & unsigned add-in block
         – PowerShell AllSigned + script-block, module, transcript logging
         – Remove legacy optional features
         – Minimal advanced audit policy
         – **AnyDesk** direct-connect firewall rule (TCP/UDP 7070 by default)

 ❶ SELF-UPGRADE
      • If launched in Windows PowerShell 5.1, silently installs **64-bit
        PowerShell 7**, then relaunches itself **in the same window**.
      • Works for both file execution and stdin streaming.

 ❷ RUNTIME LOGGING
      • Captures every command + output with **Start-Transcript** in
        `C:\HardeningLogs\Win11-Harden_<yyyyMMdd_HHmmss>.log`.

 ❸ HARDENING STEPS (see numbered sections in MAIN).

 OPERATOR CHECKLIST
      ▸ Run from an **elevated** console.  
      ▸ Supply a numeric BitLocker PIN when prompted.  
      ▸ Copy keys from *C:\RecoveryKeys* to offline storage afterwards.  
      ▸ Reboot **twice** (VBS / Credential Guard completes).  
      ▸ Verify:
            Get-BitLockerVolume
            Get-Tpm
            msinfo32   → Secure Boot = On
            Get-CimInstance Win32_DeviceGuard
            Get-MpComputerStatus
            auditpol /get /category:*

 HOW TO RUN
 ──────────────────────────────────────────────────────────────────────────
   ▸ **Download to file (preferred)**  
       curl.exe -L -o Hardening-Win11Pro.ps1 ^
         https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1
       powershell.exe -ExecutionPolicy Bypass -File .\Hardening-Win11Pro.ps1

   ▸ **Streaming — no file left behind**  
       Set-ExecutionPolicy Bypass -Scope Process -Force
       curl.exe -L https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1 |
         powershell.exe -ExecutionPolicy Bypass -

     (Streaming path writes a temp copy to %TEMP%, relaunches under pwsh 7,
      then deletes the temp file; only the transcript remains.)

 MIT-0  •  Author : Dragos Ruiu
========================================================================= #>

# ───────── helper utilities ─────────────────────────────────────────────
function Require-Admin {
    $p = [Security.Principal.WindowsPrincipal] `
         [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Error 'Run this script from an **elevated** console.' ; exit 1
    }
}
function Log-Info { param($m) ; Write-Host "[*] $m" }
function Log-Warn { param($m) ; Write-Host "[!] $m" -Foreground Yellow }
function Log-Fail { param($m) ; Write-Host "[X] $m" -Foreground Red }

function Set-Reg {
    param($Path,$Name,$Value,
          [ValidateSet('DWord','QWord','String','ExpandString')]$Type='DWord')
    if (-not (Test-Path $Path)) { New-Item $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

# ───────── enforce 64-bit PowerShell 7 ──────────────────────────────────
function Ensure-Pwsh7 {
    if ($PSVersionTable.PSVersion.Major -ge 7 -and !$env:PROCESSOR_ARCHITEW6432) { return }

    $pwsh = "$([Environment]::GetEnvironmentVariable('ProgramW6432'))\PowerShell\7\pwsh.exe"
    if (-not (Test-Path $pwsh)) {
        Log-Info 'Installing 64-bit PowerShell 7 (winget silent)'
        winget install Microsoft.PowerShell --architecture x64 `
              --accept-source-agreements --accept-package-agreements --silent
    }
    if (-not (Test-Path $pwsh)) { Log-Fail 'pwsh.exe x64 not found.' ; exit 1 }

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

# ───────── MAIN ────────────────────────────────────────────────────────
Require-Admin
Ensure-Pwsh7

# start transcript
$logDir = 'C:\HardeningLogs'
if (-not (Test-Path $logDir)) { New-Item $logDir -ItemType Directory | Out-Null }
$logFile = Join-Path $logDir ("Win11-Harden_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Start-Transcript -LiteralPath $logFile -Force | Out-Null
Log-Info "Transcript → $logFile"
Log-Info "pwsh version $($PSVersionTable.PSVersion)"

# 0 ▸ Import Microsoft Security Baseline via LGPO
$sctZip = "$env:TEMP\SCT.zip"
$sctDir = "$env:TEMP\SCT"
if (-not (Test-Path "$sctDir\LGPO\LGPO.exe")) {
    Log-Info 'Downloading Microsoft Security Compliance Toolkit …'
    Invoke-WebRequest -Uri https://aka.ms/SCTdownload -OutFile $sctZip -UseBasicParsing
    Expand-Archive $sctZip -DestinationPath $sctDir
}
$baseline = Get-ChildItem "$sctDir\Windows 11*" -Directory |
            Where-Object { $_.Name -match '23H2' } | Select-Object -First 1
if ($baseline) {
    $gpoPath = Join-Path $baseline.FullName 'GPOs\MSFT-Win11-23H2-FINAL'
    Log-Info "Applying Microsoft baseline ($($baseline.Name))"
    & "$sctDir\LGPO\LGPO.exe" /g "$gpoPath"
} else {
    Log-Warn 'Win11 baseline folder not found in SCT – LGPO import skipped.'
}

# 1 ▸ OS & Defender updates
if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
    Install-Module PSWindowsUpdate -Force -Confirm:$false
}
Import-Module PSWindowsUpdate
Log-Info 'Installing cumulative updates …'
Get-WindowsUpdate -AcceptAll -Install -AutoReboot
Update-MpSignature -UpdateSource MicrosoftUpdateServer

# 2 ▸ BitLocker (TPM + PIN)
$pin = Read-Host -AsSecureString 'Numeric BitLocker PIN (6–20 digits)'
Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                 -TpmAndPinProtector -Pin $pin -RecoveryKeyPath C:\RecoveryKeys
Log-Warn 'BitLocker keys saved in C:\RecoveryKeys — move them offline.'

# 3 ▸ Disable LM/NTLMv1, SMB 1, TLS 1.0/1.1 (server & client)
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LmCompatibilityLevel 5
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
$sch='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
'TLS 1.0','TLS 1.1' | ForEach-Object{
    Set-Reg "$sch\$_\Server" Enabled 0
    Set-Reg "$sch\$_\Client" Enabled 0
}
Set-Reg "$sch\TLS 1.2\Server" Enabled 1
Set-Reg "$sch\TLS 1.2\Client" Enabled 1

# 4 ▸ VBS / HVCI / Credential Guard
bcdedit /set hypervisorlaunchtype Auto | Out-Null
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' EnableVirtualizationBasedSecurity 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' RequirePlatformSecurityFeatures 3
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LsaCfgFlags 1

# 5 ▸ Defender baseline + critical ASR
Set-MpPreference -CloudBlockLevel High -PUAProtection Enabled -DisableRealtimeMonitoring 0 `
                 -ScanScheduleQuickScanTime 5 -ScanAvgCPULoadFactor 20 `
                 -EnableControlledFolderAccess Enabled -EnableNetworkProtection Enabled
$asr = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A','3B576869-A4EC-4529-8536-B80A7769E899',`
       '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84','26190899-1602-49E8-8B27-EB1D0A1CE869',`
       'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
Add-MpPreference -AttackSurfaceReductionRules_Ids $asr `
                 -AttackSurfaceReductionRules_Actions Enabled

# 6 ▸ Office macro lockdown
$office='HKCU:\Software\Policies\Microsoft\Office\16.0'
'Excel','Word','PowerPoint' | ForEach-Object{ Set-Reg "$office\$_\Security" VBAWarnings 4 }
Set-Reg "$office\Common\Security"          BlockMacrosFromInternet 1
Set-Reg "$office\Common\Security"          RequireAddinSig 1
Set-Reg "$office\Common\COM Compatibility" DisableBHOWarning 1

# 7 ▸ PowerShell AllSigned + full logging
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force 2>$null
Set-Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' EnableScriptBlockLogging 1
Set-Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' EnableModuleLogging 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' EnableTranscripting 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
        OutputDirectory 'C:\PSLogs' String
if (-not (Test-Path C:\PSLogs)) { New-Item C:\PSLogs -ItemType Directory | Out-Null }

# 8 ▸ Remove legacy optional features (ignore if absent)
$features='FaxServicesClientPackage','XPS-Viewer','Printing-ScanToPDFServices-Features',
          'MicrosoftPaint','WorkFolders-Client','IIS-WebClient'
foreach ($f in $features){
    try { Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction Stop }
    catch {}
}

# 9 ▸ Minimal advanced audit policy
$sub='Security System Extension','Logon','Removable Storage','Credential Validation','Audit Policy Change'
foreach ($s in $sub){ auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null }

# 10 ▸ AnyDesk direct-connect firewall rule
$defaultPort = 7070
$custom = Read-Host "AnyDesk direct-connect port [$defaultPort]"
$port   = if ($custom -match '^\d+$') { [int]$custom } else { $defaultPort }
if (-not (Get-NetFirewallRule -DisplayName "AnyDesk Direct TCP $port" -ErrorAction SilentlyContinue)) {
    Log-Info "Adding inbound rules for AnyDesk port $port"
    New-NetFirewallRule -DisplayName "AnyDesk Direct TCP $port" -Direction Inbound `
        -Action Allow -Protocol TCP -LocalPort $port -Profile Domain,Private,Public | Out-Null
    New-NetFirewallRule -DisplayName "AnyDesk Direct UDP $port" -Direction Inbound `
        -Action Allow -Protocol UDP -LocalPort $port -Profile Domain,Private,Public | Out-Null
}

# ───────── finish ───────────────────────────────────────────────────────
Log-Warn 'Hardening COMPLETE — reboot twice and secure your recovery keys.'
Stop-Transcript | Out-Null
Log-Info "Transcript saved → $logFile"
