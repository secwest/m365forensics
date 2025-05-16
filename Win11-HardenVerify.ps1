<#  =====================================================================
 Hardening-Win11Pro.ps1                                            (v2025-05-23 gdrive-full)
 ASCII-only │ streaming-safe │ single-console relaunch │ enforced pwsh-x64
────────────────────────────────────────────────────────────────────────────
 █  PURPOSE
   Harden an **un-managed Windows 11 Pro 23H2/24H1** workstation to
   Microsoft’s published security baseline *plus* the extra controls that
   Microsoft calls “recommended but not enforced”.

 █  WHAT THIS SCRIPT DOES

   ➊ Self-upgrade
      ▪ Detects if running in Windows PowerShell 5.1 (x86/x64).
      ▪ Silently installs **64-bit PowerShell 7** with *winget*  
        (`--disable-interactivity`) then **re-launches itself in the same
        console**. Works for both *file execution* and *stdin streaming*.

   ➋ Logging
      ▪ Starts a PowerShell transcript in  
        **C:\HardeningLogs\Win11-Harden_<yyyyMMdd_HHmmss>.log**  
        before any changes are made.

   ➌ Baseline import
      ▪ Downloads two ZIPs provided on Google Drive  
        • *Windows 11 v23H2 Security Baseline.zip*  
        • *LGPO.zip* (contains LGPO.exe).  
      ▪ Verifies each ZIP:
        – first two bytes must be **PK** (ZIP magic)  
        – SHA-256 must match the constants below.  
      ▪ Extracts them with `Expand-Archive -ErrorAction Stop` and falls
        back to **tar.exe** if extraction fails.
      ▪ Runs **LGPO.exe** to import the baseline GPO
        “MSFT-Win11-23H2-FINAL” into the local policy store.
      ▪ If *anything* goes wrong the baseline is politely skipped,
        a warning is logged, and the rest of the hardening continues.

   ➍ Extra hardening
      1. Windows Update + Defender engine/signatures  
      2. BitLocker (TPM + PIN, XTS-AES-256, used-space-only)  
      3. Disable LM/NTLMv1, SMB 1, TLS 1.0 & 1.1 (server *and* client)  
      4. Enable VBS, HVCI, Credential Guard  
      5. Defender: cloud = High, CFA, NetProt, PUA, critical-five ASR  
      6. Office macro lockdown & unsigned-add-in block  
      7. PowerShell **AllSigned** + script-block, module, transcript logs  
      8. Remove legacy optional features (Fax, XPS, Paint, etc.)  
      9. Minimal high-value advanced audit policy  
     10. **AnyDesk** direct-connect firewall rule (TCP/UDP 7070 default)

   ➎ Finish
      ▪ Shows a final warning banner to reboot twice.
      ▪ Transcript is closed and the location logged.

 █  OPERATOR CHECKLIST
      1. Run from an **elevated** console (Administrator).  
      2. Supply a *numeric* BitLocker PIN (6-20) when prompted.  
      3. After completion copy **C:\RecoveryKeys** to offline storage.  
      4. **Reboot twice** (VBS / Credential Guard completes).  
      5. Verify controls:  
           Get-BitLockerVolume  
           Get-Tpm  
           msinfo32   →  Secure Boot : On  
           Get-CimInstance Win32_DeviceGuard  
           Get-MpComputerStatus  
           auditpol /get /category:*  
           Test-NetConnection localhost -Port 7070

 █  HOW TO RUN
   ▪ Download & keep a file
       curl.exe -L -o Hardening-Win11Pro.ps1 ^
         https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1
       powershell.exe -ExecutionPolicy Bypass -File .\Hardening-Win11Pro.ps1

   ▪ Stream (no script left on disk)
       Set-ExecutionPolicy Bypass -Scope Process -Force
       curl.exe -L https://raw.githubusercontent.com/secwest/m365forensics/main/Hardening-Win11Pro.ps1 |
         powershell.exe -ExecutionPolicy Bypass -

 █  VERIFICATION AFTER REBOOT
   Get-BitLockerVolume ; Get-Tpm
   msinfo32 → Secure Boot : On
   Get-CimInstance Win32_DeviceGuard
   Get-MpComputerStatus
   auditpol /get /category:*
   Test-NetConnection localhost -Port 7070

 █  SHA-256 HASHES (calculated with Get-FileHash)
   ▪ Windows 11 v23H2 Security Baseline.zip =  
     **2E3A61D0245C16BEA51A9EE78CBF0793C88046901CECC0039DB0DC84FAE7D7B7**
   ▪ LGPO.zip =  
     **CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55**

 MIT-0 License │ Author : Dragos Ruiu
 ===================================================================== #>

# ───────── CONSTANTS (edit here if you host new files) ──────────────────
$BaselineUrl = 'https://drive.google.com/uc?export=download&id=13AoBqDA_O07-PhrpTJpzdU1b2oS8rD11'
$BaselineSha = '2E3A61D0245C16BEA51A9EE78CBF0793C88046901CECC0039DB0DC84FAE7D7B7'
$LgpoUrl     = 'https://drive.google.com/uc?export=download&id=1Z9Jd1h4grAF8GSCevRxeUFQ8hy2AVBOO'
$LgpoSha     = 'CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55'

$BaselineZip = "$env:TEMP\Win11Baseline.zip"
$LgpoZip     = "$env:TEMP\LGPO.zip"
$ExtractDir  = "$env:TEMP\Win11Baseline"

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

# quick ZIP signature test – true if first two bytes are 0x50 0x4B (“PK”)
function Test-ZipHeader {
    param([string]$Path)
    try {
        $b = [System.IO.File]::ReadAllBytes($Path)[0..1]
        return ($b[0] -eq 0x50 -and $b[1] -eq 0x4B)
    } catch { return $false }
}

# ensure 64-bit PowerShell 7, relaunch if installed
function Ensure-Pwsh7 {
    if ($PSVersionTable.PSVersion.Major -ge 7 -and !$env:PROCESSOR_ARCHITEW6432) { return }

    $pwsh = "$([Environment]::GetEnvironmentVariable('ProgramW6432'))\PowerShell\7\pwsh.exe"
    if (-not (Test-Path $pwsh)) {
        Log-Info 'Installing 64-bit PowerShell 7 (silent)'
        winget install Microsoft.PowerShell --architecture x64 `
              --accept-source-agreements --accept-package-agreements `
              --disable-interactivity --silent
    }
    if (-not (Test-Path $pwsh)) { Log-Fail 'pwsh.exe x64 not found.' ; exit 1 }

    if ($PSCommandPath) { & $pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath }
    else {
        $tmp = Join-Path $env:TEMP ("Harden_"+[guid]::NewGuid()+'.ps1')
        [IO.File]::WriteAllText($tmp,$MyInvocation.MyCommand.Definition,[Text.Encoding]::ASCII)
        & $pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File $tmp
        Remove-Item $tmp -Force
    }
    exit
}

# ───────── MAIN RUN ─────────────────────────────────────────────────────
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

# 0 ▸ Download + verify baseline & LGPO
$skipBaseline = $false
foreach ($file in @(
    @{Name='Baseline'; Url=$BaselineUrl; Out=$BaselineZip; Sha=$BaselineSha},
    @{Name='LGPO'    ; Url=$LgpoUrl    ; Out=$LgpoZip    ; Sha=$LgpoSha   }
)) {
    Log-Info "Downloading $($file.Name) ZIP …"
    Invoke-WebRequest -Uri $file.Url -OutFile $file.Out

    if (-not (Test-ZipHeader $file.Out)) {
        Log-Warn "$($file.Name) file is not a ZIP – skipping baseline import."
        $skipBaseline = $true ; break
    }

    if ($file.Sha) {
        $actual = (Get-FileHash $file.Out -Algorithm SHA256).Hash.ToUpper()
        if ($actual -ne $file.Sha.ToUpper()) {
            Log-Warn "$($file.Name) SHA-256 mismatch – skipping baseline import."
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
        Log-Warn "Expand-Archive failed: $_ – trying tar fallback"
        try {
            tar.exe -xf $BaselineZip -C $ExtractDir
            tar.exe -xf $LgpoZip     -C $ExtractDir
        } catch {
            Log-Warn "tar.exe also failed – baseline import skipped." ; $skipBaseline = $true
        }
    }
}

if (-not $skipBaseline) {
    $gpoPath = Get-ChildItem "$ExtractDir\Windows 11*" -Directory |
               Where-Object Name -Match '23H2' |
               ForEach-Object { Join-Path $_.FullName 'GPOs\MSFT-Win11-23H2-FINAL' } |
               Select-Object -First 1
    if ($gpoPath) {
        Log-Info "Applying Microsoft baseline with LGPO.exe"
        & "$ExtractDir\LGPO\LGPO.exe" /g $gpoPath
    } else {
        Log-Warn 'Baseline folder not found – LGPO step skipped.'
    }
}

# 1 ▸ Windows Update + Defender engine/signatures
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

# 3 ▸ Disable LM / SMB1 / TLS 1.0-1.1
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

# 4 ▸ Enable VBS / HVCI / Credential Guard
bcdedit /set hypervisorlaunchtype Auto | Out-Null
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' EnableVirtualizationBasedSecurity 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' RequirePlatformSecurityFeatures 3
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LsaCfgFlags 1

# 5 ▸ Defender baseline + five critical ASR
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

# 7 ▸ PowerShell AllSigned + transcript / module / scriptblock logs
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force 2>$null
Set-Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' EnableScriptBlockLogging 1
Set-Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' EnableModuleLogging 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' EnableTranscripting 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' OutputDirectory 'C:\PSLogs' String
if (-not (Test-Path C:\PSLogs)) { New-Item C:\PSLogs -ItemType Directory | Out-Null }

# 8 ▸ Remove legacy optional features (ignore failures)
$features='FaxServicesClientPackage','XPS-Viewer','Printing-ScanToPDFServices-Features',
          'MicrosoftPaint','WorkFolders-Client','IIS-WebClient'
foreach ($f in $features){
    try { Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction Stop }
    catch {}
}

# 9 ▸ Minimal advanced audit policy
$sub='Security System Extension','Logon','Removable Storage','Credential Validation','Audit Policy Change'
foreach ($s in $sub){
    auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null
}

# 10 ▸ AnyDesk direct-connect firewall rule
$defaultPort = 7070
$custom = Read-Host "AnyDesk direct-connect port [$defaultPort]"
$port   = ($custom -match '^\d+$') ? [int]$custom : $defaultPort
if (-not (Get-NetFirewallRule -DisplayName "AnyDesk Direct TCP $port" -ErrorAction SilentlyContinue)) {
    Log-Info "Adding inbound rules for AnyDesk port $port"
    New-NetFirewallRule -DisplayName "AnyDesk Direct TCP $port" -Direction Inbound `
        -Action Allow -Protocol TCP -LocalPort $port -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName "AnyDesk Direct UDP $port" -Direction Inbound `
        -Action Allow -Protocol UDP -LocalPort $port -Profile Any | Out-Null
}

# ───────── finish ───────────────────────────────────────────────────────
Log-Warn 'Hardening COMPLETE — reboot twice and secure your recovery keys.'
Stop-Transcript | Out-Null
Log-Info  "Transcript saved → $logFile"
