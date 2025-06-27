# Enable-EnhancedLogging.ps1
# Install or uninstall enhanced logging & protections
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
  $ts="$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
  $line="[$ts][$Mode] $Msg"
  Write-Host $line -ForegroundColor $Color
  Add-Content -Path $LogFile -Value $line
}

# Settings
$auditCategories = 'Process Creation','Module Load','File System','Registry'
$regPath    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$regName    = 'KernelAuditIncludeCommandLine'
$sbLogPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$modLogPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'

function Prompt-Disable {
  param([string]$Desc,[scriptblock]$Action)
  Write-Host "Disable $Desc? (Y/N)" -ForegroundColor Cyan
  if ((Read-Host) -match '^[Yy]') { Write-Log "Disabling $Desc" 'Yellow'; & $Action } else { Write-Log "Skipped $Desc" 'Magenta' }
}

function Enable-Audits {
  foreach ($cat in $auditCategories) {
    & auditpol /get /subcategory:"$cat" *> $null
    if ($LASTEXITCODE -ne 0) { Write-Log "Subcategory '$cat' unsupported; skipping" 'Yellow'; continue }
    $cmd="auditpol /set /subcategory:`"$cat`" /success:enable /failure:enable"
    Write-Log "Exec: $cmd" 'DarkCyan'
    try { Invoke-Expression $cmd | Out-Null; Write-Log "Audit enabled: $cat" 'Green' }
    catch { Write-Log "Error enabling audit ${cat}: $_" 'Yellow' }
  }
}
function Disable-Audits {
  foreach ($cat in $auditCategories) {
    & auditpol /get /subcategory:"$cat" *> $null; if ($LASTEXITCODE -ne 0) {continue}
    $cmd="auditpol /set /subcategory:`"$cat`" /success:disable /failure:disable"
    Write-Log "Exec: $cmd" 'DarkCyan'
    try { Invoke-Expression $cmd | Out-Null; Write-Log "Audit disabled: $cat" 'Green' }
    catch { Write-Log "Error disabling audit ${cat}: $_" 'Yellow' }
  }
}

function Enable-CommandLineInclusion { Write-Log "Exec: New-ItemProperty $regPath $regName" 'DarkCyan'; New-ItemProperty -Path $regPath -Name $regName -Value 1 -PropertyType DWord -Force | Out-Null; Write-Log 'CommandLine inclusion enabled' 'Green' }
function Disable-CommandLineInclusion { Write-Log 'Removing CommandLine inclusion' 'DarkCyan'; Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue }

function Enable-PSLogging {
  foreach ($pth in $sbLogPath,$modLogPath) { New-Item -Path $pth -Force | Out-Null }
  New-ItemProperty -Path $sbLogPath -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force | Out-Null
  New-ItemProperty -Path $modLogPath -Name EnableModuleLogging -PropertyType DWord -Value 1 -Force | Out-Null
  New-ItemProperty -Path $modLogPath -Name ModuleNames -PropertyType MultiString -Value '*' -Force | Out-Null
  Write-Log 'PowerShell logging enabled' 'Green'
}
function Disable-PSLogging { Remove-Item -Path $sbLogPath,$modLogPath -Recurse -Force -ErrorAction SilentlyContinue; Write-Log 'PowerShell logging disabled' 'Green' }

function Enable-Defender { Set-MpPreference -EnableControlledFolderAccess Enabled; Set-MpPreference -EnableNetworkProtection Enabled; Write-Log 'Defender features enabled' 'Green' }
function Disable-Defender { Set-MpPreference -EnableControlledFolderAccess Disabled; Set-MpPreference -EnableNetworkProtection Disabled; Write-Log 'Defender features disabled' 'Green' }

function Install-Features {
  Write-Log '== Enabling features ==' 'Cyan'
  Enable-Audits; Enable-CommandLineInclusion; Enable-PSLogging; Enable-Defender
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
    Write-Log 'Sysmon installed' 'Green'
  }
  Write-Log 'Install complete' 'Cyan'
  Write-Host "`nUse these to disable individual features:`n" -ForegroundColor Magenta
  Write-Host 'Audit policies:' -ForegroundColor Magenta; $auditCategories|%{Write-Host "  auditpol /set /subcategory:'$_' /success:disable /failure:disable" -ForegroundColor White}
  Write-Host '`nCommandLine inclusion:' -ForegroundColor Magenta; Write-Host "  Remove-ItemProperty -Path $regPath -Name $regName" -ForegroundColor White
  Write-Host '`nPowerShell logging:' -ForegroundColor Magenta; Write-Host "  Remove-Item -Path $sbLogPath -Recurse -Force" -ForegroundColor White; Write-Host "  Remove-Item -Path $modLogPath -Recurse -Force" -ForegroundColor White
  Write-Host '`nDefender features:' -ForegroundColor Magenta; Write-Host '  Set-MpPreference -EnableControlledFolderAccess Disabled' -ForegroundColor White; Write-Host '  Set-MpPreference -EnableNetworkProtection Disabled' -ForegroundColor White
  Write-Host '`nUninstall Sysmon:' -ForegroundColor Magenta; Write-Host "  `& '$SysmonExe' -u -accepteula" -ForegroundColor White
}

function Uninstall-Features {
  Write-Log '== Disabling features ==' 'Cyan'
  Prompt-Disable 'Audit policies' { Disable-Audits }
  Prompt-Disable 'CommandLine inclusion' { Disable-CommandLineInclusion }
  Prompt-Disable 'PowerShell logging' { Disable-PSLogging }
  Prompt-Disable 'Defender features' { Disable-Defender }
  if (Test-Path $SysmonExe) { Prompt-Disable 'Sysmon service' { & $SysmonExe -u -accepteula } }
  Write-Log 'Uninstall complete' 'Cyan'
}

if ($Mode -eq 'Install') { Install-Features } else { Uninstall-Features }

Write-Host "`nLog file: $LogFile`n" -ForegroundColor Green
