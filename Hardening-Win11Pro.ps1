###############################################################################
# Hardening-Win11Pro.ps1                  2025-05-24   gDrive-full   ASCII-clean
# single-console · streaming-safe · self-upgrading to pwsh-x64 · full baseline
###############################################################################
# OVERVIEW
#   1. Self-upgrade → PowerShell 7 x64 (winget silent) then relaunch
#   2. Full transcript  ->  C:\HardeningLogs\HardeningLog-<STAMP>.txt
#   3. Download from Google Drive + verify SHA-256:
#        LGPO.zip       CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55
#        Win11Baseline  2E3A61D0245C16BEA51A9EE78CBF0793C88046901CECC0039DB0DC84FAE7D7B7
#   4. Import Microsoft Security Baseline 23H2   (LGPO.exe /g …)
#   5. Extra hardening: BitLocker TPM+PIN, VBS/HVCI/CG, disable LM/SMB1/TLS10,
#      Defender cloud+PUA+CFA+NetProt+5 ASR, Office macro lockdown, PS logging,
#      legacy feature removal, minimal audit policy, AnyDesk 7070 firewall rule
#
# OPERATOR CHECKLIST
#   1. Run in an elevated console
#   2. Enter numeric BitLocker PIN when prompted
#   3. Copy C:\RecoveryKeys to offline storage
#   4. Reboot twice
#   5. Verify:
#        Get-BitLockerVolume ; Get-Tpm
#        msinfo32  -> Secure Boot : On
#        Get-CimInstance Win32_DeviceGuard
#        Get-MpComputerStatus
#        auditpol /get /category:*   ;  Test-NetConnection localhost -Port 7070
#
# QUICK START
#   curl.exe -L -o Hardening-Win11Pro.ps1 ^
#        https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1
#   powershell.exe -ExecutionPolicy Bypass -File .\Hardening-Win11Pro.ps1
###############################################################################

# ---------------------------------------------------------------------------
# Google-Drive ZIP sources + expected hashes
# ---------------------------------------------------------------------------
$BaselineUrl = 'https://drive.google.com/uc?export=download&id=13AoBqDA_O07-PhrpTJpzdU1b2oS8rD11'
$BaselineSha = '2E3A61D0245C16BEA51A9EE78CBF0793C88046901CECC0039DB0DC84FAE7D7B7'
$LgpoUrl     = 'https://drive.google.com/uc?export=download&id=1Z9Jd1h4grAF8GSCevRxeUFQ8hy2AVBOO'
$LgpoSha     = 'CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55'

$BaselineZip = "$env:TEMP\Win11Baseline.zip"
$LgpoZip     = "$env:TEMP\LGPO.zip"
$ExtractDir  = "$env:TEMP\Win11Baseline"

# ---------------------------------------------------------------------------
# Helper functions (all ASCII)
# ---------------------------------------------------------------------------
function Log { param([string]$Type,[string]$Msg)
    switch ($Type) {
        'INFO' { Write-Host "[*] $Msg" }
        'WARN' { Write-Host "[!] $Msg" -ForegroundColor Yellow }
        'FAIL' { Write-Host "[X] $Msg" -ForegroundColor Red }
    }
}
function RegSet {
    param([string]$Key,[string]$Name,[object]$Value,[string]$Type='DWord')
    if (-not (Test-Path $Key)) { New-Item -Path $Key -Force | Out-Null }
    New-ItemProperty -Path $Key -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}
function IsZip { param($Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)[0..1]
        return ($bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B)  # "PK"
    } catch { return $false }
}
function Require-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal `
         ([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error 'Run this script from an elevated console.' ; exit 1
    }
}
function Ensure-Pwsh7 {
    if ($PSVersionTable.PSVersion.Major -ge 7 -and -not $env:PROCESSOR_ARCHITEW6432) { return }
    $exe = "$env:ProgramFiles\PowerShell\7\pwsh.exe"
    if (-not (Test-Path $exe)) {
        Log INFO 'Installing PowerShell 7 x64 (silent)…'
        winget install Microsoft.PowerShell --architecture x64 `
              --accept-source-agreements --accept-package-agreements `
              --disable-interactivity --silent
    }
    if (-not (Test-Path $exe)) { Log FAIL 'pwsh.exe x64 not found.' ; exit 1 }
    $self = $MyInvocation.MyCommand.Path
    Start-Process -FilePath $exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$self`"" -Wait
    exit 0
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
trap { Log FAIL $_ ; try { Stop-Transcript } catch {} ; exit 1 }

Require-Admin
Ensure-Pwsh7

# Transcript start
$logDir = 'C:\HardeningLogs'
if (-not (Test-Path $logDir)) { New-Item $logDir -ItemType Directory | Out-Null }
$logFile = Join-Path $logDir ("HardeningLog-{0:yyyyMMdd-HHmmss}.txt" -f (Get-Date))
Start-Transcript -Path $logFile -Force | Out-Null
Log INFO "Transcript -> $logFile"
Log INFO "pwsh version $($PSVersionTable.PSVersion)"

# 0 ▸ Download and verify ZIPs
$skipBaseline = $false
$toGet = @(
    @{Name='Baseline'; Url=$BaselineUrl; Out=$BaselineZip; Sha=$BaselineSha},
    @{Name='LGPO'    ; Url=$LgpoUrl    ; Out=$LgpoZip    ; Sha=$LgpoSha}
)
foreach ($item in $toGet) {
    Log INFO "Downloading $($item.Name)…"
    Invoke-WebRequest -Uri $item.Url -OutFile $item.Out -UseBasicParsing
    if (-not (IsZip $item.Out)) { Log WARN "$($item.Name) is not ZIP" ; $skipBaseline = $true ; break }
    $hash = (Get-FileHash $item.Out -Algorithm SHA256).Hash.ToUpper()
    if ($hash -ne $item.Sha) { Log WARN "$($item.Name) hash mismatch" ; $skipBaseline = $true ; break }
}

if (-not $skipBaseline) {
    if (Test-Path $ExtractDir) { Remove-Item $ExtractDir -Recurse -Force }
    try {
        Expand-Archive -Path $BaselineZip -DestinationPath $ExtractDir -Force
        Expand-Archive -Path $LgpoZip -DestinationPath $ExtractDir -Force
    } catch {
        Log WARN 'Expand-Archive failed, using tar.exe fallback…'
        tar.exe -xf $BaselineZip -C $ExtractDir
        tar.exe -xf $LgpoZip -C $ExtractDir
    }
    $gpoDir = Get-ChildItem "$ExtractDir\Windows 11*" -Directory |
              Where-Object { $_.Name -match '23H2' } |
              ForEach-Object { Join-Path $_.FullName 'GPOs\MSFT-Win11-23H2-FINAL' } |
              Select-Object -First 1
    if ($gpoDir) {
        Log INFO 'Importing Microsoft baseline via LGPO.exe…'
        & "$ExtractDir\LGPO\LGPO.exe" /g $gpoDir
    }
}

# 1 ▸ Windows Update + AV signatures
if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
    Install-Module PSWindowsUpdate -Force -Confirm:$false
}
Import-Module PSWindowsUpdate
Log INFO 'Installing cumulative Windows updates…'
Get-WindowsUpdate -AcceptAll -Install -AutoReboot
Update-MpSignature -UpdateSource MicrosoftUpdateServer

# 2 ▸ BitLocker
$bl = Get-BitLockerVolume -MountPoint 'C:'
if ($bl.ProtectionStatus -ne 'ProtectionOn') {
    $pin = Read-Host 'Enter numeric BitLocker PIN (6-20 digits)' -AsSecureString
    Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                     -TPMandPinProtector -Pin $pin -RecoveryKeyPath C:\RecoveryKeys
    Log WARN 'BitLocker keys saved in C:\RecoveryKeys (move offline).'
} else {
    Log INFO 'BitLocker already enabled.'
}

# 3 ▸ Disable LM/NTLMv1, SMB1, TLS1.0/1.1
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LmCompatibilityLevel 5
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
$sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
foreach ($v in 'TLS 1.0','TLS 1.1') {
    foreach ($r in 'Server','Client') { RegSet "$sch\$v\$r" Enabled 0 }
}
RegSet "$sch\TLS 1.2\Server" Enabled 1
RegSet "$sch\TLS 1.2\Client" Enabled 1

# 4 ▸ VBS, HVCI, Credential Guard
bcdedit /set hypervisorlaunchtype Auto | Out-Null
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' EnableVirtualizationBasedSecurity 1
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' RequirePlatformSecurityFeatures 3
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LsaCfgFlags 1

# 5 ▸ Defender + ASR rules
Set-MpPreference -CloudBlockLevel High -PUAProtection Enabled `
                 -DisableRealtimeMonitoring 0 -EnableControlledFolderAccess Enabled `
                 -EnableNetworkProtection Enabled
$asrIDs = @(
 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',
 '3B576869-A4EC-4529-8536-B80A7769E899',
 '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84',
 '26190899-1602-49E8-8B27-EB1D0A1CE869',
 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
)
foreach ($id in $asrIDs) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $id `
                     -AttackSurfaceReductionRules_Actions Enabled
}

# 6 ▸ Office macro lockdown
$officePol = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0'
foreach ($app in 'Word','Excel','PowerPoint') {
    RegSet "$officePol\$app\Security" VBAWarnings 3
}
RegSet "$officePol\Common\Security" BlockMacrosFromInternet 1
RegSet "$officePol\Common\Security" RequireAddinSig 1
RegSet "$officePol\Common\COM Compatibility" DisableBHOWarning 1

# 7 ▸ ExecutionPolicy AllSigned + PS logging
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force
$psPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
RegSet "$psPol\ScriptBlockLogging" EnableScriptBlockLogging 1
RegSet "$psPol\ModuleLogging" EnableModuleLogging 1
RegSet "$psPol\ModuleLogging\ModuleNames" '*' 'Enabled' 'String'
RegSet "$psPol\Transcription" EnableTranscripting 1
RegSet "$psPol\Transcription" OutputDirectory 'C:\PowerShellTranscripts' 'String'
if (-not (Test-Path 'C:\PowerShellTranscripts')) {
    New-Item 'C:\PowerShellTranscripts' -ItemType Directory | Out-Null
}

# 8 ▸ Remove obsolete optional features
$obsolete = 'MicrosoftWindowsPowerShellV2Root','SimpleTCPIPServices','TelnetClient','TFTPClient'
foreach ($f in $obsolete) {
    Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction SilentlyContinue | Out-Null
}

# 9 ▸ Minimal audit policy
$cats = 'Logon','User Account Management','Security Group Management','Process Creation','Audit Policy Change'
foreach ($c in $cats) {
    auditpol /set /subcategory:"$c" /success:enable /failure:enable | Out-Null
}

# 10 ▸ AnyDesk firewall rule
if (-not (Get-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -Direction Inbound `
        -Action Allow -Protocol TCP -LocalPort 7070 -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName 'Hardening - AnyDesk UDP 7070' -Direction Inbound `
        -Action Allow -Protocol UDP -LocalPort 7070 -Profile Any | Out-Null
}

# ---------------------------------------------------------------------------
# End
# ---------------------------------------------------------------------------
Log WARN 'Hardening COMPLETE – reboot TWICE, then verify.'
Stop-Transcript | Out-Null
Log INFO "Transcript saved -> $logFile"
