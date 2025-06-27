# Enable-EnhancedLogging.ps1
# Install or uninstall enhanced logging & protections with optional extras
# Usage:  .\Enable-EnhancedLogging.ps1 [-Mode Install|Uninstall] [-IncludeSysmon]

param(
  [ValidateSet('Install','Uninstall')]
  [string]$Mode = 'Install',
  [switch]$IncludeSysmon
)

$LogFile               = 'C:\Temp\EnhancedLoggingSetup.log'
$ErrorActionPreference = 'Continue'

# Sysmon paths
$BaseDir      = Split-Path -Parent $MyInvocation.MyCommand.Path
$SysmonDir    = Join-Path $BaseDir 'Sysmon'
$SysmonZip    = Join-Path $SysmonDir 'Sysmon.zip'
$SysmonExe    = Join-Path $SysmonDir 'Sysmon.exe'
$SysmonConfig = Join-Path $SysmonDir 'sysmon-config.xml'

# Ensure log dir & init
$logDir = Split-Path $LogFile
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
"`r`n=== Enhanced Logging Script $(Get-Date) Mode=$Mode ===`r`n" | Out-File $LogFile -Encoding UTF8

function Write-Log {
  param([string]$Msg,[ValidateSet('White','Green','Yellow','Cyan','Magenta','Red','DarkCyan')] [string]$Color='White')
  $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $line = "[$ts][$Mode] $Msg"
  Write-Host $line -ForegroundColor $Color
  Add-Content -Path $LogFile -Value $line
}

# Core & extra audit categories
$coreAudits   = 'Process Creation','File System','Registry'
$optionalAud  = 'Module Load','Process Termination','DPAPI Activity','Handle Manipulation','Kernel Object','Logon','Special Logon','Directory Service Access'
# will hold enabled extras for disable summary
$extrasEnabled = @()

$regPath    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$regName    = 'KernelAuditIncludeCommandLine'
$sbLogPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$modLogPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
$transPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
$smartLog   = 'Microsoft-Windows-SmartScreen/Operational'
$appLockerRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'

function Prompt-Disable {
  param([string]$Desc,[scriptblock]$Action)
  Write-Host "Disable $Desc? (Y/N)" -ForegroundColor Cyan
  if ((Read-Host) -match '^[Yy]') { Write-Log "Disabling $Desc" 'Yellow'; & $Action } else { Write-Log "Skipped $Desc" 'Magenta' }
}

function Set-AuditCat {
  param([string]$Cat,[string]$Mode)
  & auditpol /get /subcategory:"$Cat" *> $null
  if ($LASTEXITCODE -eq 0) {
    $cmd = "auditpol /set /subcategory:`"$Cat`" /success:$Mode /failure:$Mode"
    Invoke-Expression $cmd | Out-Null
    return $true
  }
  else {
    Write-Log "Subcategory '$Cat' unsupported; skipping" 'Yellow'
    return $false
  }
}

function Enable-CoreAudits {
  foreach ($cat in $coreAudits) { if (Set-AuditCat $cat 'enable') { Write-Log "Audit enabled: $cat" 'Green' } }
}
function Disable-CoreAudits { foreach ($cat in $coreAudits) { if (Set-AuditCat $cat 'disable') { Write-Log "Audit disabled: $cat" 'Green' } } }

function Enable-ExtrasPrompt {
  foreach ($cat in $optionalAud) {
    if ((Read-Host "Enable extra audit '$cat'? (Y/N)") -match '^[Yy]') {
      if (Set-AuditCat $cat 'enable') { $extrasEnabled += $cat; Write-Log "Extra audit enabled: $cat" 'Green' }
    }
  }
}
function Disable-Extras { foreach ($cat in $optionalAud) { if ($cat -in $extrasEnabled) { Set-AuditCat $cat 'disable' | Out-Null; Write-Log "Extra audit disabled: $cat" 'Green' } } }

function Enable-CommandLine { New-ItemProperty -Path $regPath -Name $regName -Value 1 -PropertyType DWord -Force | Out-Null; Write-Log 'CmdLine inclusion enabled' 'Green' }
function Disable-CommandLine { Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue }

function Enable-PSLogging {
  New-Item $sbLogPath -Force | Out-Null;  New-ItemProperty $sbLogPath EnableScriptBlockLogging -Value 1 -Type DWord -Force | Out-Null
  New-Item $modLogPath -Force | Out-Null; New-ItemProperty $modLogPath EnableModuleLogging -Value 1 -Type DWord -Force | Out-Null; New-ItemProperty $modLogPath ModuleNames -Type MultiString -Value '*' -Force | Out-Null
  Write-Log 'PowerShell logging enabled' 'Green'
}
function Disable-PSLogging { Remove-Item -Path $sbLogPath,$modLogPath -Recurse -Force -ErrorAction SilentlyContinue }

function Enable-Transcription {
  if ((Read-Host 'Enable PowerShell transcription? (Y/N)') -match '^[Yy]') {
    New-Item $transPath -Force | Out-Null; New-ItemProperty $transPath EnableTranscripting -Value 1 -Type DWord -Force | Out-Null
    New-ItemProperty $transPath OutputDirectory -Value 'C:\Temp\PSTranscripts' -Type String -Force | Out-Null
    $extrasEnabled += 'PS Transcription'
    Write-Log 'PS transcription enabled' 'Green'
  }
}
function Disable-Transcription { Remove-Item -Path $transPath -Recurse -Force -ErrorAction SilentlyContinue }

function Enable-AppLockerAudit {
  if ((Read-Host 'Enable AppLocker audit mode? (Y/N)') -match '^[Yy]') {
    New-Item -Path $appLockerRoot -Force | Out-Null; New-ItemProperty $appLockerRoot EnforcementMode -Type DWord -Value 1 -Force | Out-Null
    $extrasEnabled += 'AppLocker Audit'
    Write-Log 'AppLocker audit mode enabled' 'Green'
  }
}
function Disable-AppLocker { Remove-Item -Path $appLockerRoot -Recurse -Force -ErrorAction SilentlyContinue }

function Enable-SmartScreenLog {
  if ((Read-Host 'Enable SmartScreen operational log? (Y/N)') -match '^[Yy]') {
    wevtutil sl $smartLog /e:true
    $extrasEnabled += 'SmartScreen Log'
    Write-Log 'SmartScreen logging enabled' 'Green'
  }
}
function Disable-SmartScreenLog { wevtutil sl $smartLog /e:false }

function Enable-DefenderASRAudit {
  if ((Read-Host 'Enable Defender ASR rules (Audit only)? (Y/N)') -match '^[Yy]') {
    $ruleIds = 'D4F940AB-401B-4EfC-AADC-AD5F3C50688A','3B576869-A4EC-4529-8536-B80A7769E899'
    try {
      Set-MpPreference -AttackSurfaceReductionRules_AuditMode $ruleIds
      $extrasEnabled += 'ASR Audit'
      Write-Log 'ASR rules audit-only enabled' 'Green'
    }
    catch {
      Write-Log 'ASR audit mode parameter not supported on this OS; skipping' 'Yellow'
    }
  }
}

function Disable-ASR { $ruleIds = 'D4F940AB-401B-4EfC-AADC-AD5F3C50688A','3B576869-A4EC-4529-8536-B80A7769E899'; Remove-MpPreference -AttackSurfaceReductionRules_AuditMode $ruleIds } { $ruleIds = 'D4F940AB-401B-4EfC-AADC-AD5F3C50688A','3B576869-A4EC-4529-8536-B80A7769E899'; Remove-MpPreference -AttackSurfaceReductionRules_AuditMode $ruleIds }

function Enable-DefenderCore { Set-MpPreference -EnableControlledFolderAccess Enabled; Set-MpPreference -EnableNetworkProtection Enabled; Write-Log 'Defender core features enabled' 'Green' }
function Disable-DefenderCore { Set-MpPreference -EnableControlledFolderAccess Disabled; Set-MpPreference -EnableNetworkProtection Disabled }

function Install-Features {
  Write-Log '== Enabling core features ==' 'Cyan'
  Enable-CoreAudits; Enable-ExtrasPrompt; Enable-CommandLine; Enable-PSLogging; Enable-Transcription; Enable-AppLockerAudit; Enable-SmartScreenLog; Enable-DefenderCore; Enable-DefenderASRAudit
  # Sysmon
  $doSN = $IncludeSysmon -or ((Read-Host 'Install Sysmon? (Y/N)') -match '^[Yy]')
  if ($doSN) {
    Write-Log 'Installing Sysmon...' 'Yellow'
    if (-not (Test-Path $SysmonDir)) { New-Item $SysmonDir -ItemType Directory -Force | Out-Null }
    Invoke-WebRequest -UseBasicParsing -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $SysmonZip
    Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force
    @"
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <ProcessCreate onmatch="include" />
    <NetworkConnect onmatch="include" />
  </EventFiltering>
</Sysmon>
"@ | Out-File -FilePath $SysmonConfig -Encoding ASCII
    & $SysmonExe -accepteula -i $SysmonConfig
    $extrasEnabled += 'Sysmon'
    Write-Log 'Sysmon installed' 'Green'
  }
  Write-Log 'Install complete' 'Cyan'
  Show-DisableSummary
}

function Show-DisableSummary {
  Write-Host "`n======== Disable Commands Summary ========" -ForegroundColor Magenta
  Write-Host "Audit policies:" -ForegroundColor Magenta
  ($coreAudits + $optionalAud | Sort-Object -Unique) | ForEach-Object { Write-Host "  auditpol /set /subcategory:'$_' /success:disable /failure:disable" -ForegroundColor White }
  Write-Host "`nCommandLine inclusion:" -ForegroundColor Magenta; Write-Host "  Remove-ItemProperty -Path $regPath -Name $regName" -ForegroundColor White
  Write-Host "`nPowerShell logging:" -ForegroundColor Magenta; Write-Host "  Remove-Item -Path $sbLogPath -Recurse -Force" -ForegroundColor White; Write-Host "  Remove-Item -Path $modLogPath -Recurse -Force" -ForegroundColor White; Write-Host "  Remove-Item -Path $transPath -Recurse -Force" -ForegroundColor White
  Write-Host "`nDefender core:" -ForegroundColor Magenta; Write-Host '  Set-MpPreference -EnableControlledFolderAccess Disabled' -ForegroundColor White; Write-Host '  Set-MpPreference -EnableNetworkProtection Disabled' -ForegroundColor White
  Write-Host "`nASR audit rules:" -ForegroundColor Magenta; Write-Host '  Remove-MpPreference -AttackSurfaceReductionRules_AuditMode <GUIDs>' -ForegroundColor White
  Write-Host "`nSmartScreen log:" -ForegroundColor Magenta; Write-Host "  wevtutil sl $smartLog /e:false" -ForegroundColor White
  Write-Host "`nAppLocker Audit:" -ForegroundColor Magenta; Write-Host "  Remove-Item -Path $appLockerRoot -Recurse -Force" -ForegroundColor White
  Write-Host "`nUninstall Sysmon:" -ForegroundColor Magenta; Write-Host "  & '$SysmonExe' -u -accepteula" -ForegroundColor White
}

function Uninstall-Features {
  Write-Log '== Disabling features ==' 'Cyan'
  Prompt-Disable 'Core audit policies' { Disable-CoreAudits }
  Prompt-Disable 'Extra audit policies' { Disable-Extras }
  Prompt-Disable 'CommandLine inclusion' { Disable-CommandLine }
  Prompt-Disable 'PowerShell logging & transcription' { Disable-PSLogging; Disable-Transcription }
  Prompt-Disable 'Defender core features' { Disable-DefenderCore }
  Prompt-Disable 'ASR Audit rules' { Disable-ASR }
  Prompt-Disable 'SmartScreen logging' { Disable-SmartScreenLog }
  Prompt-Disable 'AppLocker audit mode' { Disable-AppLocker }
  if (Test-Path $SysmonExe) { Prompt-Disable 'Sysmon service' { & $SysmonExe -u -accepteula } }
  Write-Log 'Uninstall complete' 'Cyan'
}

if ($Mode -eq 'Install') { Install-Features } else { Uninstall-Features }

Write-Host "`nLog file: $LogFile`n" -ForegroundColor Green
