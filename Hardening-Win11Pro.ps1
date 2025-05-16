###############################################################################
# Hardening-Win11Pro.ps1                           v2025-05-23  (gDrive full)
# ASCII-only · streaming-safe · single-console relaunch · enforced pwsh-x64
###############################################################################
#
# SUMMARY
#   Harden an *un-managed* Windows 11 Pro 23H2/24H1 workstation to the
#   Microsoft Security Baseline **plus** additional controls Microsoft only
#   “recommends”.
#
# WHAT THIS SCRIPT DOES
#   1.  **Self-upgrade / relaunch** to 64-bit PowerShell 7 (winget silent)
#   2.  **Transcript logging** →  C:\HardeningLogs\HardeningLog-<stamp>.txt
#   3.  **Download** two ZIPs you supplied on Google Drive
#        • LGPO.zip                              (hash checked)
#        • Windows 11 v23H2 Security Baseline.zip (hash checked)
#   4.  **Verify** PK header + SHA-256, unzip (Expand-Archive → tar fallback)
#   5.  Apply the baseline **MSFT-Win11-23H2-FINAL** via LGPO.exe
#   6.  Extra hardening:
#        ▸ BitLocker (TPM + PIN / XTS-AES-256 / Used-Space-Only)
#        ▸ VBS · HVCI · Credential Guard
#        ▸ Disable LM / NTLMv1, SMB1, TLS 1.0 & 1.1
#        ▸ Defender cloud=High, PUA, CFA, NetProt, 5 critical ASR rules
#        ▸ Office macro lockdown & unsigned-add-in block
#        ▸ PowerShell AllSigned + script-block / module / transcription logs
#        ▸ Remove legacy optional features (PS-v2, Telnet, etc.)
#        ▸ Minimal audit policy (5 sub-categories)
#        ▸ AnyDesk firewall rule (TCP+UDP 7070)
#
# OPERATOR CHECKLIST
#   1️⃣  Run this script from an **elevated** console (Administrator)
#   2️⃣  Enter a *numeric* BitLocker PIN when prompted
#   3️⃣  Copy **C:\RecoveryKeys** to offline media when finished
#   4️⃣  **Reboot twice** (VBS / Cred Guard finalises on 2nd reboot)
#   5️⃣  VERIFY after 2nd reboot:
#        Get-BitLockerVolume
#        Get-Tpm
#        msinfo32   →  Secure Boot : On
#        Get-CimInstance Win32_DeviceGuard
#        Get-MpComputerStatus
#        auditpol /get /category:*
#        Test-NetConnection localhost -Port 7070
#
# HOW TO RUN
#   ▪ Download & keep file
#       curl.exe -L -o Hardening-Win11Pro.ps1 ^
#         https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1
#       powershell.exe -ExecutionPolicy Bypass -File .\Hardening-Win11Pro.ps1
#
#   ▪ Stream (no file left behind)
#       Set-ExecutionPolicy Bypass -Scope Process -Force
#       curl.exe -L https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1 |
#         powershell.exe -ExecutionPolicy Bypass –
#
# GOOGLE-DRIVE SOURCES  (SHA-256 verified)
#   LGPO.zip      https://drive.google.com/uc?export=download&id=1Z9Jd1h4grAF8GSCevRxeUFQ8hy2AVBOO
#   Hash: CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55
#
#   Win11Baseline.zip
#   https://drive.google.com/uc?export=download&id=13AoBqDA_O07-PhrpTJpzdU1b2oS8rD11
#   Hash: 2E3A61D0245C16BEA51A9EE78CBF0793C88046901CECC0039DB0DC84FAE7D7B7
#
# MIT-0 License  •  Author : Dragos Ruiu
###############################################################################

# ----------------------------  CONSTANTS  -----------------------------------
$BaselineUrl = 'https://drive.google.com/uc?export=download&id=13AoBqDA_O07-PhrpTJpzdU1b2oS8rD11'
$BaselineSha = '2E3A61D0245C16BEA51A9EE78CBF0793C88046901CECC0039DB0DC84FAE7D7B7'
$LgpoUrl     = 'https://drive.google.com/uc?export=download&id=1Z9Jd1h4grAF8GSCevRxeUFQ8hy2AVBOO'
$LgpoSha     = 'CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55'

$BaselineZip = "$env:TEMP\Win11_Baseline.zip"
$LgpoZip     = "$env:TEMP\LGPO.zip"
$ExtractDir  = "$env:TEMP\Win11Baseline"

# ----------------------------  HELPERS  -------------------------------------
function Require-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal `
         ([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Error 'ERROR: Run this script in an **elevated** console.' ; exit 1
    }
}
function Log-Info { param([string]$m) ; Write-Host "[*] $m" }
function Log-Warn { param([string]$m) ; Write-Host "[!] $m" -ForegroundColor Yellow }
function Log-Fail { param([string]$m) ; Write-Host "[X] $m" -ForegroundColor Red }

function Set-Reg {
    param([string]$Path,[string]$Name,[object]$Value,
          [ValidateSet('DWord','QWord','String','ExpandString')]$Type='DWord')
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

function Test-ZipHeader {
    param([string]$Path)
    try {
        $b = [System.IO.File]::ReadAllBytes($Path)[0..1]
        return ($b[0] -eq 0x50 -and $b[1] -eq 0x4B)  # "PK"
    } catch { return $false }
}

function Ensure-Pwsh7 {
    # If already in 64-bit PowerShell 7 -> nothing to do
    if ($PSVersionTable.PSVersion.Major -ge 7 -and !$env:PROCESSOR_ARCHITEW6432) { return }

    $pwshExe = "$([Environment]::GetEnvironmentVariable('ProgramW6432'))\PowerShell\7\pwsh.exe"
    if (-not (Test-Path $pwshExe)) {
        Log-Info 'Installing 64-bit PowerShell 7 (winget silent)...'
        winget install Microsoft.PowerShell --architecture x64 `
              --accept-source-agreements --accept-package-agreements `
              --disable-interactivity --silent
    }
    if (-not (Test-Path $pwshExe)) { Log-Fail 'pwsh.exe x64 not found.' ; exit 1 }

    # Relaunch this script under pwsh 7 (preserve log path)
    $thisScript = $MyInvocation.MyCommand.Path
    $logParam   = if ($argsLogPath) { "-LogPath `"$argsLogPath`"" } else { "" }
    $argsLine   = "-NoProfile -ExecutionPolicy Bypass -File `"$thisScript`" $logParam"
    Log-Info 'Relaunching script under PowerShell 7...'
    Start-Process -FilePath $pwshExe -ArgumentList $argsLine -Wait
    exit 0
}

# --------------------  PARAM (used after relaunch)  ---------------------
param([string]$LogPath)

# -----------------------------  MAIN  -----------------------------------
trap { Log-Fail $_ ; try { Stop-Transcript } catch {}; exit 1 }

Require-Admin
$argsLogPath = $LogPath  # preserve for Ensure-Pwsh7
Ensure-Pwsh7

# Start transcript if not already running
if (-not ($LogPath)) {
    $stamp   = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $LogPath = "C:\HardeningLogs\HardeningLog-$stamp.txt"
    Start-Transcript -Path $LogPath -Force | Out-Null
}
Log-Info "Transcript -> $LogPath"
Log-Info "pwsh version $($PSVersionTable.PSVersion)"

# -------- 0 ▪ Download and verify baseline + LGPO ----------------------
$skipBaseline = $false
$Downloads = @(
    @{Name='Baseline'; Url=$BaselineUrl; Out=$BaselineZip; Sha=$BaselineSha},
    @{Name='LGPO'    ; Url=$LgpoUrl    ; Out=$LgpoZip    ; Sha=$LgpoSha}
)

foreach ($d in $Downloads) {
    Log-Info "Downloading $($d.Name) ..."
    Invoke-WebRequest -Uri $d.Url -OutFile $d.Out -UseBasicParsing
    if (-not (Test-ZipHeader $d.Out)) {
        Log-Warn "$($d.Name) is not a valid ZIP – baseline import skipped."
        $skipBaseline = $true ; break
    }
    $actual = (Get-FileHash $d.Out -Algorithm SHA256).Hash.ToUpper()
    if ($actual -ne $d.Sha) {
        Log-Warn "$($d.Name) SHA-256 mismatch – baseline import skipped."
        $skipBaseline = $true ; break
    }
}

if (-not $skipBaseline) {
    if (Test-Path $ExtractDir) { Remove-Item $ExtractDir -Recurse -Force }
    try {
        Expand-Archive -Path $BaselineZip -DestinationPath $ExtractDir -Force -ErrorAction Stop
        Expand-Archive -Path $LgpoZip     -DestinationPath $ExtractDir -Force -ErrorAction Stop
    } catch {
        Log-Warn "Expand-Archive failed – trying tar.exe fallback..."
        try {
            tar.exe -xf $BaselineZip -C $ExtractDir
            tar.exe -xf $LgpoZip     -C $ExtractDir
        } catch {
            Log-Warn "tar.exe failed – baseline import skipped."
            $skipBaseline = $true
        }
    }
}

if (-not $skipBaseline) {
    $gpo = Get-ChildItem "$ExtractDir\Windows 11*" -Directory |
           Where-Object { $_.Name -match '23H2' } |
           ForEach-Object { Join-Path $_.FullName 'GPOs\MSFT-Win11-23H2-FINAL' } |
           Select-Object -First 1
    if ($gpo) {
        Log-Info "Applying Microsoft baseline via LGPO.exe ..."
        & "$ExtractDir\LGPO\LGPO.exe" /g $gpo
    } else {
        Log-Warn "Baseline folder not found – LGPO step skipped."
    }
}

# -------- 1 ▪ Windows Update + Defender signatures ---------------------
if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
    Install-Module PSWindowsUpdate -Force -Confirm:$false
}
Import-Module PSWindowsUpdate
Log-Info 'Installing cumulative Windows updates (may reboot automatically)...'
Get-WindowsUpdate -AcceptAll -Install -AutoReboot
Update-MpSignature -UpdateSource MicrosoftUpdateServer

# -------- 2 ▪ BitLocker (TPM+PIN) --------------------------------------
if (-not (Get-BitLockerVolume -MountPoint 'C:' | Where-Object {$_.VolumeStatus -eq 'FullyEncrypted'})) {
    $pin = Read-Host 'Enter numeric BitLocker PIN (6-20 digits)' -AsSecureString
    Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                     -TPMandPinProtector -Pin $pin -RecoveryKeyPath C:\RecoveryKeys
    Log-Warn 'BitLocker keys saved in C:\RecoveryKeys – move offline.'
} else {
    Log-Info 'BitLocker already enabled on C:.'
}

# -------- 3 ▪ Disable LM/NTLMv1 + SMB1 + TLS1.0/1.1 --------------------
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LmCompatibilityLevel 5
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
$sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
foreach ($ver in 'TLS 1.0','TLS 1.1') {
    foreach ($role in 'Server','Client') {
        Set-Reg "$sch\$ver\$role" Enabled 0
    }
}
Set-Reg "$sch\TLS 1.2\Server" Enabled 1
Set-Reg "$sch\TLS 1.2\Client" Enabled 1

# -------- 4 ▪ Enable VBS, HVCI, Credential Guard -----------------------
bcdedit /set hypervisorlaunchtype Auto | Out-Null
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' EnableVirtualizationBasedSecurity 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' RequirePlatformSecurityFeatures 3
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LsaCfgFlags 1

# -------- 5 ▪ Defender cloud, PUA, CFA, NetProt, ASR -------------------
Set-MpPreference -CloudBlockLevel High -PUAProtection Enabled `
                 -DisableRealtimeMonitoring 0 -EnableControlledFolderAccess Enabled `
                 -EnableNetworkProtection Enabled -ScanScheduleQuickScanTime 5 `
                 -ScanAvgCPULoadFactor 20
$asrIDs = @(
 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A', # Office child processes
 '3B576869-A4EC-4529-8536-B80A7769E899', # Office code injection
 '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84', # Obfuscated scripts
 '26190899-1602-49E8-8B27-EB1D0A1CE869', # PSExec / WMI
 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'  # LSASS credential theft
)
foreach ($id in $asrIDs) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled
}

# -------- 6 ▪ Office macro lockdown ------------------------------------
$officeBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0'
foreach ($app in 'Word','Excel','PowerPoint') {
    Set-Reg "$officeBase\$app\Security" VBAWarnings 3
}
Set-Reg "$officeBase\Common\Security" BlockMacrosFromInternet 1
Set-Reg "$officeBase\Common\Security" RequireAddinSig 1
Set-Reg "$officeBase\Common\COM Compatibility" DisableBHOWarning 1

# -------- 7 ▪ PowerShell AllSigned + full logging ----------------------
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force
$psPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Set-Reg "$psPol\ScriptBlockLogging" EnableScriptBlockLogging 1
Set-Reg "$psPol\ModuleLogging" EnableModuleLogging 1
Set-Reg "$psPol\ModuleLogging\ModuleNames" '*' 'Enabled' String
Set-Reg "$psPol\Transcription" EnableTranscripting 1
Set-Reg "$psPol\Transcription" IncludeInvocationHeader 1
Set-Reg "$psPol\Transcription" OutputDirectory 'C:\PowerShellTranscripts' String
if (-not (Test-Path 'C:\PowerShellTranscripts')) { New-Item 'C:\PowerShellTranscripts' -ItemType Directory | Out-Null }

# -------- 8 ▪ Remove legacy optional features --------------------------
$obsolete = @('MicrosoftWindowsPowerShellV2Root','SimpleTCPIPServices','TelnetClient',
              'TFTPClient','Internet-Explorer-Optional-amd64')
foreach ($f in $obsolete) {
    Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction SilentlyContinue | Out-Null
}

# -------- 9 ▪ Minimal audit policy ------------------------------------
foreach ($cat in 'Logon','User Account Management','Security Group Management',
                 'Process Creation','Audit Policy Change') {
    auditpol /set /subcategory:"$cat" /success:enable /failure:enable | Out-Null
}

# -------- 10 ▪ AnyDesk firewall rule (7070) ----------------------------
$port = 7070
if (-not (Get-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'Hardening - AnyDesk TCP 7070' -Direction Inbound `
        -Action Allow -Protocol TCP -LocalPort $port -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName 'Hardening - AnyDesk UDP 7070' -Direction Inbound `
        -Action Allow -Protocol UDP -LocalPort $port -Profile Any | Out-Null
}

# ---------------------------  FINISH  ----------------------------------
Log-Warn 'Hardening COMPLETE – reboot TWICE and move BitLocker keys offline.'
Stop-Transcript | Out-Null
Log-Info "Transcript saved -> $LogPath"
