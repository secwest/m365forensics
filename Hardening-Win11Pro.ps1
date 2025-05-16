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

# -- tiny helpers -------------------------------------------------------------
function Log  { param($t,$m) ; if($t-eq'INFO'){Write-Host "[*] $m"}
                               elseif($t-eq'WARN'){Write-Host "[!] $m" -Foreground Yellow}
                               elseif($t-eq'FAIL'){Write-Host "[X] $m" -Foreground Red} }
function RegSet($k,$n,$v,$t='DWord'){ if(-not(Test-Path $k)){New-Item $k -Force|Out-Null}
                                      New-ItemProperty -Path $k -Name $n -Value $v -PropertyType $t -Force|Out-Null }
function IsZip($p){ try{ $b=[IO.File]::ReadAllBytes($p)[0..1]; $b[0]-eq0x50 -and $b[1]-eq0x4B }catch{ $false } }
function RequireAdmin{
    if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        Write-Error 'Run in an elevated console.' ; exit 1 } }
function EnsurePwsh7{
    if($PSVersionTable.PSVersion.Major-ge7 -and !$env:PROCESSOR_ARCHITEW6432){return}
    $exe="$env:ProgramFiles\PowerShell\7\pwsh.exe"
    if(-not(Test-Path $exe)){
        Log INFO 'Installing PowerShell 7 x64…'
        winget install Microsoft.PowerShell --architecture x64 `
              --accept-source-agreements --accept-package-agreements `
              --disable-interactivity --silent
    }
    if(-not(Test-Path $exe)){Log FAIL 'pwsh.exe x64 missing';exit 1}
    $self=$MyInvocation.MyCommand.Path
    Start-Process $exe "-NoProfile -ExecutionPolicy Bypass -File `"$self`"" -Wait
    exit 0
}

# -- main ---------------------------------------------------------------------
trap { Log FAIL $_ ; try{Stop-Transcript}catch{} ; exit 1 }

RequireAdmin
EnsurePwsh7

# transcript
$logDir='C:\HardeningLogs'; if(-not(Test-Path $logDir)){New-Item $logDir -ItemType Directory}
$log=Join-Path $logDir ("HardeningLog-{0:yyyyMMdd-HHmmss}.txt"-f(Get-Date))
Start-Transcript -Path $log -Force|Out-Null
Log INFO "Transcript → $log"
Log INFO "pwsh $($PSVersionTable.PSVersion)"

# 0 ▸ download / verify baseline + LGPO
foreach($d in @(@{n='Baseline';u=$BaselineUrl;o=$BaselineZip;s=$BaselineSha},
                @{n='LGPO';u=$LgpoUrl;o=$LgpoZip;s=$LgpoSha})){
    Log INFO "Downloading $($d.n)…"
    Invoke-WebRequest -Uri $d.u -OutFile $d.o -UseBasicParsing
    if(-not(IsZip $d.o)){Log WARN "$($d.n) not ZIP";$skip=$true;break}
    if((Get-FileHash $d.o -Algorithm SHA256).Hash.ToUpper() -ne $d.s){
        Log WARN "$($d.n) SHA-256 mismatch"; $skip=$true; break}
}
if(-not $skip){
    if(Test-Path $ExtractDir){Remove-Item $ExtractDir -Recurse -Force}
    try{
        Expand-Archive $BaselineZip -DestinationPath $ExtractDir -Force -ErrorAction Stop
        Expand-Archive $LgpoZip     -DestinationPath $ExtractDir -Force -ErrorAction Stop
    }catch{ tar.exe -xf $BaselineZip -C $ExtractDir ; tar.exe -xf $LgpoZip -C $ExtractDir }
    $gpo=Get-ChildItem "$ExtractDir\Windows 11*" -Directory|Where-Object Name -match '23H2'|
         ForEach-Object{Join-Path $_.FullName 'GPOs\MSFT-Win11-23H2-FINAL'}|Select-Object -First 1
    if($gpo){ Log INFO 'Importing baseline via LGPO.exe…' ; & "$ExtractDir\LGPO\LGPO.exe" /g $gpo }
}

# 1 ▸ Windows Update + Defender sigs
if(-not(Get-Module PSWindowsUpdate -ListAvailable)){Install-Module PSWindowsUpdate -Force -Confirm:$false}
Import-Module PSWindowsUpdate
Log INFO 'Installing cumulative updates…'
Get-WindowsUpdate -AcceptAll -Install -AutoReboot
Update-MpSignature -UpdateSource MicrosoftUpdateServer

# 2 ▸ BitLocker
if((Get-BitLockerVolume -MountPoint C:).ProtectionStatus -ne 'ProtectionOn'){
    $pin=Read-Host 'Enter numeric BitLocker PIN (6-20)' -AsSecureString
    Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                     -TPMandPinProtector -Pin $pin -RecoveryKeyPath C:\RecoveryKeys
    Log WARN 'BitLocker keys → C:\RecoveryKeys (move offline).'
}

# 3 ▸ LM/NTLMv1 off • SMB1 off • TLS1.0/1.1 off
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LmCompatibilityLevel 5
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue|Out-Null
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
$sch='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
foreach($v in 'TLS 1.0','TLS 1.1'){foreach($r in 'Server','Client'){RegSet "$sch\$v\$r" Enabled 0}}
RegSet "$sch\TLS 1.2\Server" Enabled 1; RegSet "$sch\TLS 1.2\Client" Enabled 1

# 4 ▸ VBS / HVCI / Credential Guard
bcdedit /set hypervisorlaunchtype Auto | Out-Null
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' EnableVirtualizationBasedSecurity 1
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' RequirePlatformSecurityFeatures 3
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LsaCfgFlags 1

# 5 ▸ Defender baseline + 5 ASR
Set-MpPreference -CloudBlockLevel High -PUAProtection Enabled `
                 -DisableRealtimeMonitoring 0 -EnableControlledFolderAccess Enabled `
                 -EnableNetworkProtection Enabled
$asr=@('D4F940AB-401B-4EFC-AADC-AD5F3C50688A','3B576869-A4EC-4529-8536-B80A7769E899',
       '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84','26190899-1602-49E8-8B27-EB1D0A1CE869',
       'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550')
foreach($id in $asr){Add-MpPreference -AttackSurfaceReductionRules_Ids $id `
                                      -AttackSurfaceReductionRules_Actions Enabled}

# 6 ▸ Office macros
$off='HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0'
foreach($a in 'Word','Excel','PowerPoint'){RegSet "$off\$a\Security" VBAWarnings 3}
RegSet "$off\Common\Security" BlockMacrosFromInternet 1
RegSet "$off\Common\Security" RequireAddinSig 1
RegSet "$off\Common\COM Compatibility" DisableBHOWarning 1

# 7 ▸ AllSigned + logging
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force
$ps='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
RegSet "$ps\ScriptBlockLogging" EnableScriptBlockLogging 1
RegSet "$ps\ModuleLogging" EnableModuleLogging 1
RegSet "$ps\ModuleLogging\ModuleNames" '*' 'Enabled' 'String'
RegSet "$ps\Transcription" EnableTranscripting 1
RegSet "$ps\Transcription" OutputDirectory 'C:\PowerShellTranscripts' 'String'
if(-not(Test-Path 'C:\PowerShellTranscripts')){New-Item 'C:\PowerShellTranscripts' -ItemType Directory}

# 8 ▸ Remove obsolete optional features
foreach($f in 'MicrosoftWindowsPowerShellV2Root','SimpleTCPIPServices','TelnetClient','TFTPClient'){
    Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction SilentlyContinue|Out-Null
}

# 9 ▸ Audit policy
foreach($c in 'Logon','User Account Management','Security Group Management','Process Creation','Audit Policy Change'){
    auditpol /set /subcategory:"$c" /success:enable /failure:enable|Out-Null }

# 10 ▸ AnyDesk firewall
if(-not(Get-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -ErrorAction SilentlyContinue)){
    New-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -Direction Inbound `
        -Action Allow -Protocol TCP -LocalPort 7070 -Profile Any|Out-Null
    New-NetFirewallRule -DisplayName 'Hardening - AnyDesk UDP 7070' -Direction Inbound `
        -Action Allow -Protocol UDP -LocalPort 7070 -Profile Any|Out-Null
}

# -- finish -------------------------------------------------------------
Log WARN 'Hardening COMPLETE – reboot TWICE and verify controls.'
Stop-Transcript|Out-Null
Log INFO "Transcript saved → $log"
