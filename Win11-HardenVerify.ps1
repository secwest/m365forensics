<#
   Win11-HardenVerify.ps1
   - Handles missing WMI class (DeviceGuard) gracefully
   - Works even if Defender ASR arrays are $null
   - Auto-detects available audit subcategories
#>

$report = [ordered]@{}

# BitLocker
$bl = Get-BitLockerVolume -MountPoint C:
$report.BitLocker = [ordered]@{
    VolumeStatus = $bl.VolumeStatus
    EncryptionMethod = $bl.EncryptionMethod
    EncryptionPct = $bl.EncryptionPercentage
}

# Secure Boot & TPM
$report.SecureBoot = if ((Get-CimInstance Win32_ComputerSystem).SecureBootState -eq 1) { 'On' } else { 'Off' }
$report.TPM        = (Get-Tpm).TpmPresent

# Device Guard / Cred Guard
try {
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -Class Win32_DeviceGuard
    $report.DeviceGuard = @{
        VBS          = $dg.VirtualizationBasedSecurityStatus      # 1 = Enabled
        HVCI         = ($dg.SecurityServicesRunning -contains 1)
        CredentialGU = ($dg.SecurityServicesRunning -contains 2)
    }
} catch {
    $report.DeviceGuard = 'Class not present (VBS/CG disabled or Secure Boot off)'
}

# Defender + ASR
$mp   = Get-MpComputerStatus
$pref = Get-MpPreference
$asrIds = $pref.AttackSurfaceReductionRules_Ids
$asrAct = $pref.AttackSurfaceReductionRules_Actions
$asrTable = @()
if ($asrIds) {
    for ($i=0; $i -lt $asrIds.Count; $i++) {
        $asrTable += "$($asrIds[$i]) : $($asrAct[$i])"
    }
}
$report.Defender = @{
    RealTime    = $mp.AMServiceEnabled
    NetworkProt = $pref.EnableNetworkProtection
    CFA         = $pref.EnableControlledFolderAccess
    PUA         = $pref.PUAProtection
    ASR_rules   = if ($asrTable) { $asrTable } else { 'No ASR config found' }
}

# PowerShell logging
$eng = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine
$report.PowerShellLogging = @{
    ScriptBlock = $eng.EnableScriptBlockLogging
    ModuleLog   = $eng.EnableModuleLogging
    Transcript  = (Test-Path C:\PSLogs)
}

# Audit policy (query what exists)
$need = 'Security System Extension','Logon','Removable Storage','Credential Validation','Audit Policy Change'
$available = (auditpol /list /subcategory:* | Select-String -NotMatch '^$').Line.Trim()
$report.AuditPolicy = @{}
foreach ($s in $need) {
    if ($available -contains $s) {
        $status = (auditpol /get /subcategory:"$s" /r |
                   Select-String "$s").Line.Split()[-1]
        $report.AuditPolicy[$s] = $status
    } else {
        $report.AuditPolicy[$s] = 'NotPresent'
    }
}

# Optional features
$features='FaxServicesClientPackage','XPS-Viewer','Printing-ScanToPDFServices-Features',
          'MicrosoftPaint','WorkFolders-Client','IIS-WebClient'
$opt = Get-WindowsOptionalFeature -Online
$report.OptionalFeatures = @{
    UnexpectedEnabled = ($opt | Where-Object { $features -contains $_.FeatureName -and $_.State -ne 'Disabled'}).FeatureName
}

# Output
$report | ConvertTo-Json -Depth 4 | Set-Content .\Win11Harden-Verify.json -Encoding UTF8
$report | Format-List
Write-Host "`n✔ Verification complete — JSON written to Win11Harden-Verify.json" -Foreground Green
