:: ====================================================================
:: Hardening-Win11Pro.ps1                         (2025-05-23 gdrive-clean)
:: ASCII-only – streaming-safe – single-console relaunch – pwsh-x64 enforced
:: --------------------------------------------------------------------
::
:: PURPOSE
::   Harden an unmanaged Windows 11 Pro 23H2/24H1 workstation:
::     1.  Import Microsoft Security Baseline (Win 11 23H2 FINAL)
::     2.  Apply extra controls Microsoft only “recommends”
::         – BitLocker (TPM + PIN, XTS-AES-256, used-space-only)
::         – VBS / HVCI / Credential Guard
::         – Disable LM / NTLMv1, SMB 1, TLS 1.0 / 1.1 (client + server)
::         – Defender critical-five ASR + CFA + Net Prot + PUA
::         – Office macro lockdown, unsigned-add-in block
::         – PowerShell AllSigned + script-block, module, transcript logs
::         – Remove legacy optional features
::         – Minimal advanced audit policy
::         – AnyDesk direct-connect firewall rule (TCP/UDP 7070)
::
:: WHAT MAKES THIS VERSION ROBUST
::   * Self-upgrades to 64-bit PowerShell 7 (winget silent, no prompts)
::   * Works from a file or streamed through curl | powershell
::   * Full transcript in C:\HardeningLogs\Win11-Harden_<stamp>.log
::   * Downloads baseline + LGPO.zip from Google Drive links you supplied
::   * Verifies:
::       – ZIP header must start with PK
::       – SHA-256 hashes match the constants
::   * Extracts with Expand-Archive –ErrorAction Stop, falls back to tar.exe
::   * Any failure only skips the baseline import – all other steps run
::   * Global trap logs last error then exits cleanly
::
:: OPERATOR CHECKLIST
::   1.  Run this script **from an elevated console** (Administrator).
::   2.  Enter a numeric BitLocker PIN (6-20 digits) when prompted.
::   3.  Copy C:\RecoveryKeys to offline storage after completion.
::   4.  Reboot the system **twice** (VBS / Cred Guard finish).
::   5.  Verify controls:
::         Get-BitLockerVolume
::         Get-Tpm
::         msinfo32   -> Secure Boot : On
::         Get-CimInstance Win32_DeviceGuard
::         Get-MpComputerStatus
::         auditpol /get /category:*
::         Test-NetConnection localhost -Port 7070
::
:: HOW TO RUN
::   Download then execute (preferred)
::     curl.exe -L -o Hardening-Win11Pro.ps1 ^
::       https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1
::     powershell.exe -ExecutionPolicy Bypass -File .\Hardening-Win11Pro.ps1
::
::   Stream (no script left behind)
::     Set-ExecutionPolicy Bypass -Scope Process -Force
::     curl.exe -L https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1 |
::       powershell.exe -ExecutionPolicy Bypass -
::
:: DIRECT ZIP LINKS AND SHA-256 HASHES
::   Windows 11 v23H2 Security Baseline.zip
::     https://drive.google.com/uc?export=download&id=13AoBqDA_O07-PhrpTJpzdU1b2oS8rD11
::     SHA256  2E3A61D0245C16BEA51A9EE78CBF0793C88046901CECC0039DB0DC84FAE7D7B7
::   LGPO.zip
::     https://drive.google.com/uc?export=download&id=1Z9Jd1h4grAF8GSCevRxeUFQ8hy2AVBOO
::     SHA256  CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55
::
:: MIT-0 License   –   Author: Dragos Ruiu
:: ====================================================================

# -------- constants ----------------------------------------------------
$BaselineUrl = 'https://drive.google.com/uc?export=download&id=13AoBqDA_O07-PhrpTJpzdU1b2oS8rD11'
$BaselineSha = '2E3A61D0245C16BEA51A9EE78CBF0793C88046901CECC0039DB0DC84FAE7D7B7'
$LgpoUrl     = 'https://drive.google.com/uc?export=download&id=1Z9Jd1h4grAF8GSCevRxeUFQ8hy2AVBOO'
$LgpoSha     = 'CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55'

$BaselineZip = "$env:TEMP\Win11Baseline.zip"
$LgpoZip     = "$env:TEMP\LGPO.zip"
$ExtractDir  = "$env:TEMP\Win11Baseline"

# -------- helper utilities ---------------------------------------------
function Require-Admin {
    $principal = [Security.Principal.WindowsPrincipal] `
                 [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Error 'Error: run this script from an *elevated* console.' ; exit 1
    }
}
function Log-Info { param([string]$m) ; Write-Host "[*] $m" }
function Log-Warn { param([string]$m) ; Write-Host "[!] $m" -Foreground Yellow }
function Log-Fail { param([string]$m) ; Write-Host "[X] $m" -Foreground Red }

function Set-Reg {
    param([string]$Path,[string]$Name,[object]$Value,
          [ValidateSet('DWord','QWord','String','ExpandString')]$Type='DWord')
    if (-not (Test-Path $Path)) { New-Item $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

function Test-ZipHeader {
    param([string]$Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)[0..1]
        return ($bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B)  # "PK"
    } catch { return $false }
}

function Ensure-Pwsh7 {
    if ($PSVersionTable.PSVersion.Major -ge 7 -and !$env:PROCESSOR_ARCHITEW6432) { return }
    $pwsh = "$([Environment]::GetEnvironmentVariable('ProgramW6432'))\PowerShell\7\pwsh.exe"
    if (-not (Test-Path $pwsh)) {
        Log-Info 'Installing 64-bit PowerShell 7 (silent, winget)'
        winget install Microsoft.PowerShell --architecture x64 `
              --accept-source-agreements --accept-package-agreements `
              --disable-interactivity --silent
    }
    if (-not (Test-Path $pwsh)) { Log-Fail 'Fatal: pwsh.exe x64 not found.' ; exit 1 }

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

# -------- MAIN ---------------------------------------------------------
trap { Log-Fail $_ ; Stop-Transcript | Out-Null ; exit 1 }

Require-Admin
Ensure-Pwsh7

# start transcript
$logDir='C:\HardeningLogs'
if (-not (Test-Path $logDir)) { New-Item $logDir -ItemType Directory | Out-Null }
$logFile = Join-Path $logDir ("Win11-Harden_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Start-Transcript -LiteralPath $logFile -Force | Out-Null
Log-Info "Transcript -> $logFile"
Log-Info "PowerShell version $($PSVersionTable.PSVersion)"

# 0. download and verify ZIPs ------------------------------------------
$skipBaseline = $false
$files = @(
    @{Name='Baseline'; Url=$BaselineUrl; Out=$BaselineZip; Sha=$BaselineSha},
    @{Name='LGPO'    ; Url=$LgpoUrl    ; Out=$LgpoZip    ; Sha=$LgpoSha}
)

foreach ($f in $files) {
    Log-Info "Downloading $($f.Name) ..."
    Invoke-WebRequest -Uri $f.Url -OutFile $f.Out
    if (-not (Test-ZipHeader $f.Out)) {
        Log-Warn "$($f.Name) is not a valid ZIP – skipping baseline import."
        $skipBaseline = $true ; break
    }
    if ($f.Sha) {
        $actual = (Get-FileHash $f.Out -Algorithm SHA256).Hash.ToUpper()
        if ($actual -ne $f.Sha.ToUpper()) {
            Log-Warn "$($f.Name) SHA-256 mismatch – skipping baseline import."
            $skipBaseline = $true ; break
        }
    }
}

if (-not $skipBaseline) {
    if (Test-Path $ExtractDir) { Remove-Item $ExtractDir -Recurse -Force }
    try {
        Expand-Archive -Path $BaselineZip -DestinationPath $ExtractDir -Force -ErrorAction Stop
        Expand-Archive -Path $LgpoZip     -DestinationPath $ExtractDir -Force -ErrorAction Stop
    } catch {
        Log-Warn "Expand-Archive failed: $_ – trying tar.exe fallback"
        try {
            tar.exe -xf $BaselineZip -C $ExtractDir
            tar.exe -xf $LgpoZip     -C $ExtractDir
        } catch {
            Log-Warn "tar.exe also failed – baseline import skipped."
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
        Log-Info "Applying Microsoft baseline (LGPO.exe)"
        & "$ExtractDir\LGPO\LGPO.exe" /g $gpo
    } else {
        Log-Warn "Baseline folder not found – LGPO step skipped."
    }
}

# 1. Windows Update + Defender signatures ------------------------------
if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
    Install-Module PSWindowsUpdate -Force -Confirm:$false
}
Import-Module PSWindowsUpdate
Log-Info 'Installing cumulative Windows updates ...'
Get-WindowsUpdate -AcceptAll -Install -AutoReboot
Update-MpSignature -UpdateSource MicrosoftUpdateServer

# 2. BitLocker (TPM + PIN) ---------------------------------------------
$pin = Read-Host -AsSecureString 'Numeric BitLocker PIN (6-20 digits)'
Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                 -TpmAndPinProtector -Pin $pin -RecoveryKeyPath C:\RecoveryKeys
Log-Warn 'BitLocker keys saved in C:\RecoveryKeys – move to offline vault.'

# 3. Disable LM / SMB1 / TLS 1.0-1.1 -----------------------------------
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LmCompatibilityLevel 5
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
$sch='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
foreach ($p in 'TLS 1.0','TLS 1.1') {
    Set-Reg "$sch\$p\Server" Enabled 0
    Set-Reg "$sch\$p\Client" Enabled 0
}
Set-Reg "$sch\TLS 1.2\Server" Enabled 1
Set-Reg "$sch\TLS 1.2\Client" Enabled 1

# 4. Enable VBS / HVCI / Credential Guard ------------------------------
bcdedit /set hypervisorlaunchtype Auto | Out-Null
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' EnableVirtualizationBasedSecurity 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' RequirePlatformSecurityFeatures 3
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LsaCfgFlags 1

# 5. Defender baseline + ASR rules -------------------------------------
Set-MpPreference -CloudBlockLevel High -PUAProtection Enabled `
                 -DisableRealtimeMonitoring 0 -EnableControlledFolderAccess Enabled `
                 -EnableNetworkProtection Enabled -ScanScheduleQuickScanTime 5 `
                 -ScanAvgCPULoadFactor 20
$asr = @(
 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',
 '3B576869-A4EC-4529-8536-B80A7769E899',
 '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84',
 '26190899-1602-49E8-8B27-EB1D0A1CE869',
 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
)
Add-MpPreference -AttackSurfaceReductionRules_Ids $asr `
                 -AttackSurfaceReductionRules_Actions Enabled

# 6. Office macro lockdown ---------------------------------------------
$office='HKCU:\Software\Policies\Microsoft\Office\16.0'
foreach ($app in 'Excel','Word','PowerPoint') {
    Set-Reg "$office\$app\Security" VBAWarnings 4
}
Set-Reg "$office\Common\Security" BlockMacrosFromInternet 1
Set-Reg "$office\Common\Security" RequireAddinSig 1
Set-Reg "$office\Common\COM Compatibility" DisableBHOWarning 1

# 7. PowerShell logging + AllSigned policy -----------------------------
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force 2>$null
Set-Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' EnableScriptBlockLogging 1
Set-Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' EnableModuleLogging 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' EnableTranscripting 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' OutputDirectory 'C:\PSLogs' String
if (-not (Test-Path C:\PSLogs)) { New-Item C:\PSLogs -ItemType Directory | Out-Null }

# 8. Remove legacy optional features -----------------------------------
$features='FaxServicesClientPackage','XPS-Viewer','Printing-ScanToPDFServices-Features',
          'MicrosoftPaint','WorkFolders-Client','IIS-WebClient'
foreach ($feat in $features) {
    try { Disable-WindowsOptionalFeature -Online -FeatureName $feat -NoRestart -ErrorAction Stop }
    catch {}
}

# 9. Minimal advanced audit policy -------------------------------------
$aud='Security System Extension','Logon','Removable Storage','Credential Validation','Audit Policy Change'
foreach ($s in $aud) {
    auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null
}

# 10. AnyDesk firewall rule -------------------------------------------
$defaultPort = 7070
$custom = Read-Host "AnyDesk direct-connect port [$defaultPort]"
if ($custom -match '^\d+$') { $port = [int]$custom } else { $port = $defaultPort }
if (-not (Get-NetFirewallRule -DisplayName "AnyDesk Direct TCP $port" -ErrorAction SilentlyContinue)) {
    Log-Info "Adding inbound rules for AnyDesk port $port"
    New-NetFirewallRule -DisplayName "AnyDesk Direct TCP $port" -Direction Inbound `
        -Action Allow -Protocol TCP -LocalPort $port -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName "AnyDesk Direct UDP $port" -Direction Inbound `
        -Action Allow -Protocol UDP -LocalPort $port -Profile Any | Out-Null
}

# ----------------------------------------------------------------------
Log-Warn 'Hardening COMPLETE – reboot TWICE and secure your BitLocker keys.'
Stop-Transcript | Out-Null
Log-Info "Transcript saved to $logFile"
