<# =====================================================================
 Win11-HardenVerify.ps1                               (2025-05-20 “Full”)
 Matches the *Hardening-Win11Pro.ps1* v2025-05-20 script.

 • Handles missing classes (DeviceGuard) and $null arrays (Defender ASR)
 • Auto-detects available audit subcategories
 • Confirms LGPO baseline import, SMB1 removal, TLS 1.0/1.1 client+server,
   AnyDesk firewall rule, and legacy-feature removals
 • Saves a JSON snapshot alongside human-readable output
======================================================================= #>

$report = [ordered]@{}

# ───── BitLocker ────────────────────────────────────────────────────────
$bl = Get-BitLockerVolume -MountPoint C:
$report.BitLocker = [ordered]@{
    VolumeStatus       = $bl.VolumeStatus
    EncryptionMethod   = $bl.EncryptionMethod
    EncryptionPercent  = $bl.EncryptionPercentage
}
# ───── Secure Boot & TPM ───────────────────────────────────────────────
$report.SecureBoot = if ((Get-CimInstance Win32_ComputerSystem).SecureBootState -eq 1) { 'On' } else { 'Off' }
$report.TPM        = (Get-Tpm).TpmPresent

# ───── Device Guard / Cred Guard ───────────────────────────────────────
try {
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -Class Win32_DeviceGuard
    $report.DeviceGuard = @{
        VBS   = $dg.VirtualizationBasedSecurityStatus        # 1 = enabled
        HVCI  = ($dg.SecurityServicesRunning -contains 1)
        CredG = ($dg.SecurityServicesRunning -contains 2)
    }
} catch {
    $report.DeviceGuard = 'Class missing (VBS/CG disabled or Secure Boot off)'
}
# ───── Defender + ASR ──────────────────────────────────────────────────
$mp   = Get-MpComputerStatus
$pref = Get-MpPreference
$asr  = @()
if ($pref.AttackSurfaceReductionRules_Ids) {
    for ($i = 0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
        $asr += "$($pref.AttackSurfaceReductionRules_Ids[$i]) : $($pref.AttackSurfaceReductionRules_Actions[$i])"
    }
}
$report.Defender = @{
    RealTime      = $mp.AMServiceEnabled
    NetworkProt   = $pref.EnableNetworkProtection
    CFA           = $pref.EnableControlledFolderAccess
    PUA           = $pref.PUAProtection
    ASR_rules     = if ($asr) { $asr } else { 'No ASR config found' }
}
# ───── PowerShell logging ──────────────────────────────────────────────
$eng = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine
$report.PowerShellLogging = @{
    ScriptBlock = $eng.EnableScriptBlockLogging
    ModuleLog   = $eng.EnableModuleLogging
    Transcript  = (Test-Path C:\PSLogs)
}
# ───── Audit policy (dynamic) ──────────────────────────────────────────
$need = 'Security System Extension','Logon','Removable Storage','Credential Validation','Audit Policy Change'
$present = (auditpol /list /subcategory:* | Select-String -NotMatch '^\s*$').Line.Trim()
$report.AuditPolicy = @{}
foreach ($s in $need) {
    if ($present -contains $s) {
        $st = (auditpol /get /subcategory:"$s" /r | Select-String $s).Line.Split()[-1]
        $report.AuditPolicy[$s] = $st
    } else {
        $report.AuditPolicy[$s] = 'NotPresent'
    }
}
# ───── Optional-feature check ──────────────────────────────────────────
$features = 'FaxServicesClientPackage','XPS-Viewer','Printing-ScanToPDFServices-Features',
            'MicrosoftPaint','WorkFolders-Client','IIS-WebClient'
$opt  = Get-WindowsOptionalFeature -Online
$report.OptionalFeatures = @{
    UnexpectedEnabled = ($opt |
        Where-Object { $features -contains $_.FeatureName -and $_.State -ne 'Disabled' }
        ).FeatureName
}
# ───── TLS / SMB / NTLM surface ──────
