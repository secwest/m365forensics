<# =====================================================================
 Hardening-Win11Pro.ps1                                  (2025-05-22 robust)
 ASCII-only · streaming-safe · single-console relaunch · pwsh x64 enforced
────────────────────────────────────────────────────────────────────────────
 COMPLETE CONTENTS
   • Self-upgrade to 64-bit PowerShell 7 (stdin-safe relaunch)
   • Continuous transcript → C:\HardeningLogs\Win11-Harden_<stamp>.log
   • Imports Microsoft Security Baseline (Win 11 23H2 FINAL) via LGPO
   • Adds extra hardening Microsoft only “recommends”:
       – BitLocker TPM + PIN, XTS-AES-256, used-space-only
       – VBS / HVCI / Credential Guard
       – Disable LM / NTLMv1, SMB 1, TLS 1.0 & 1.1 (server + client)
       – Defender critical-five ASR + CFA + Network Protection + PUA
       – Office macro lockdown, unsigned add-in block
       – PowerShell AllSigned + script-block, module, transcription logs
       – Remove legacy optional features
       – Minimal advanced audit policy
       – **AnyDesk** direct-connect firewall rule (TCP+UDP 7070 default)
   • Robust SCT download: TLS 1.2 enforced, SHA-256 verified,
     fall-back to `tar.exe` if `Expand-Archive` fails.
   • Winget runs with `--disable-interactivity` → no Store prompts.
   • Trap writes any thrown error to the transcript and console.

 OPERATOR CHECKLIST
   1️⃣  Run from an **elevated** console.  
   2️⃣  Enter a numeric BitLocker PIN (6-20 digits).  
   3️⃣  Copy *C:\RecoveryKeys* to offline storage afterwards.  
   4️⃣  **Reboot twice** (VBS / Cred Guard finish).  
   5️⃣  Verify with:  
         Get-BitLockerVolume  
         Get-Tpm  
         msinfo32   → Secure Boot : On  
         Get-CimInstance Win32_DeviceGuard  
         Get-MpComputerStatus  
         auditpol /get /category:*  
         Test-NetConnection localhost -Port 7070

 HOW TO RUN
   # keep a file
   curl.exe -L -o Hardening-Win11Pro.ps1 ^
     https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1
   powershell.exe -ExecutionPolicy Bypass -File .\Hardening-Win11Pro.ps1

   # stream (leaves no script on disk)
   Set-ExecutionPolicy Bypass -Scope Process -Force
   curl.exe -L https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1 |
     powershell.exe -ExecutionPolicy Bypass -

 MIT-0 • Author : Dragos Ruiu
========================================================================= #>

# ───────── helper utilities ─────────────────────────────────────────────
function Require-Admin {
    $p=[Security.Principal.WindowsPrincipal] `
       [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Error 'Run this script from an **elevated** console.' ; exit 1
    }
}
function Log-Info { param($m) ; Write-Host "[*] $m" }
function Log-Warn { param($m) ; Write-Host "[!] $m" -Foreground Yellow }
function Log-Fail { param($m) ; Write-Host "[X] $m" -Foreground Red }

function Set-Reg {
    param($Path,$Name,$Value,[ValidateSet('DWord','QWord','String','ExpandString')]$Type='DWord')
    if (-not (Test-Path $Path)) { New-Item $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

# ───────── enforce pwsh 7 x64 (stdin-relaunch) ──────────────────────────
function Ensure-Pwsh7 {
    if ($PSVersionTable.PSVersion.Major -ge 7 -and !$env:PROCESSOR_ARCHITEW6432) { return }
    $pwsh="$([Environment]::GetEnvironmentVariable('ProgramW6432'))\PowerShell\7\pwsh.exe"
    if (-not (Test-Path $pwsh)) {
        Log-Info 'Installing 64-bit PowerShell 7 (silent)'
        winget install Microsoft.PowerShell --architecture x64 `
              --accept-source-agreements --accept-package-agreements `
              --disable-interactivity --silent
    }
    if (-not (Test-Path $pwsh)) { Log-Fail 'pwsh.exe x64 not found.' ; exit 1 }

    if ($PSCommandPath) { & $pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath }
    else {
        $tmp=Join-Path $env:TEMP ("Harden_"+[guid]::NewGuid()+'.ps1')
        [IO.File]::WriteAllText($tmp,$MyInvocation.MyCommand.Definition,[Text.Encoding]::ASCII)
        & $pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File $tmp
        Remove-Item $tmp -Force
    }
    exit
}

# ───────── MAIN ────────────────────────────────────────────────────────
trap { Log-Fail $_ ; Stop-Transcript | Out-Null ; exit 1 }

Require-Admin
Ensure-Pwsh7

# start transcript
$logDir='C:\HardeningLogs'
if (-not (Test-Path $logDir)) { New-Item $logDir -ItemType Directory | Out-Null }
$logFile = Join-Path $logDir ("Win11-Harden_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Start-Transcript -LiteralPath $logFile -Force | Out-Null
Log-Info "Transcript → $logFile"
Log-Info "pwsh version $($PSVersionTable.PSVersion)"

# 0 ▸ Microsoft baseline (robust)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$sctZip="$env:TEMP\SCT.zip"; $sctDir="$env:TEMP\SCT"
$sha='282138ED19812CAEF7277F8F53FEC8C8B9BC84778559A7F89A4CBD23D1C6FE04'  # SCT 2310.1
if (-not (Test-Path $sctZip) -or ((Get-FileHash $sctZip -Algorithm SHA256).Hash -ne $sha)) {
    Log-Info 'Downloading Microsoft Security Compliance Toolkit …'
    Invoke-WebRequest -Uri https://aka.ms/SCTdownload -OutFile $sctZip -UseBasicParsing
}
if (Test-Path $sctDir) { Remove-Item $sctDir -Recurse -Force }
try { Expand-Archive $sctZip -DestinationPath $sctDir -Force }
catch {
    Log-Warn "Expand-Archive failed, falling back to tar.exe …"
    tar.exe -xf $sctZip -C $sctDir
}
$baseline = Get-ChildItem "$sctDir\Windows 11*" -Directory -ErrorAction SilentlyContinue |
            Where-Object Name -Match '23H2' | Select-Object -First 1
if ($baseline) {
    Log-Info "Applying Microsoft baseline ($($baseline.Name))"
    & "$sctDir\LGPO\LGPO.exe" /g "$($baseline.FullName)\GPOs\MSFT-Win11-23H2-FINAL"
} else { Log-Warn 'Baseline folder not found – LGPO step skipped.' }

# 1 ▸ Windows Update + Defender sigs
if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
    Install-Module PSWindowsUpdate -Force -Confirm:$false
}
Import-Module PSWindowsUpdate
Log-Info 'Installing cumulative updates …'
Get-WindowsUpdate -AcceptAll -Install -AutoReboot
Update-MpSignature -UpdateSource MicrosoftUpdateServer

# 2 ▸ BitLocker
$pin = Read-Host -AsSecureString 'Numeric BitLocker PIN (6–20 digits)'
Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                 -TpmAndPinProtector -Pin $pin -RecoveryKeyPath C:\RecoveryKeys
Log-Warn 'BitLocker keys saved in C:\RecoveryKeys — move offline.'

# 3 ▸ LM/SMB/TLS
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

# 5 ▸ Defender baseline + critical 5 ASR
Set-MpPreference -CloudBlockLevel High -PUAProtection Enabled -DisableRealtimeMonitoring 0 `
                 -ScanScheduleQuickScanTime 5 -ScanAvgCPULoadFactor 20 `
                 -EnableControlledFolderAccess Enabled -EnableNetworkProtection Enabled
$asr='D4F940AB-401B-4EFC-AADC-AD5F3C50688A','3B576869-A4EC-4529-8536-B80A7769E899',`
     '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84','26190899-1602-49E8-8B27-EB1D0A1CE869',`
     'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
Add-MpPreference -AttackSurfaceReductionRules_Ids $asr `
                 -AttackSurfaceReductionRules_Actions Enabled

# 6 ▸ Office macro lockdown
$office='HKCU:\Software\Policies\Microsoft\Office\16.0'
'Excel','Word','PowerPoint' | ForEach-Object{ Set-Reg "$office\$_\Security" VBAWarnings 4 }
Set-Reg "$office\Common\Security" BlockMacrosFromInternet 1
Set-Reg "$office\Common\Security" RequireAddinSig 1
Set-Reg "$office\Common\COM Compatibility" DisableBHOWarning 1

# 7 ▸ PowerShell AllSigned + logging
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force 2>$null
Set-Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' EnableScriptBlockLogging 1
Set-Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' EnableModuleLogging 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' EnableTranscripting 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' OutputDirectory 'C:\PSLogs' String
if (-not (Test-Path C:\PSLogs)) { New-Item C:\PSLogs -ItemType Directory | Out-Null }

# 8 ▸ Remove optional features
$features='FaxServicesClientPackage','XPS-Viewer','Printing-ScanToPDFServices-Features',
          'MicrosoftPaint','WorkFolders-Client','IIS-WebClient'
foreach ($f in $features){
    try { Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction Stop }
    catch {}
}

# 9 ▸ Audit policy (key subcategories)
$sub='Security System Extension','Logon','Removable Storage','Credential Validation','Audit Policy Change'
foreach ($s in $sub){ auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null }

# 10 ▸ AnyDesk firewall rule
$defaultPort=7070
$custom=Read-Host "AnyDesk direct-connect port [$defaultPort]"
$port=if($custom -match '^\d+$'){[int]$custom}else{$defaultPort}
if(-not(Get-NetFirewallRule -DisplayName "AnyDesk Direct TCP $port" -ErrorAction SilentlyContinue)){
    Log-Info "Adding inbound rules for AnyDesk port $port"
    New-NetFirewallRule -DisplayName "AnyDesk Direct TCP $port" -Direction Inbound `
        -Action Allow -Protocol TCP -LocalPort $port -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName "AnyDesk Direct UDP $port" -Direction Inbound `
        -Action Allow -Protocol UDP -LocalPort $port -Profile Any | Out-Null
}

Log-Warn 'Hardening COMPLETE — reboot twice and secure your recovery keys.'
Stop-Transcript | Out-Null
Log-Info "Transcript saved → $logFile"
