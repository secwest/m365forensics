# Enable-EnhancedLogging.ps1
# Installs or uninstalls enhanced logging and protections.
# Modes: Install (default) or Uninstall

param(
  [ValidateSet('Install','Uninstall')]
  [string]$Mode = 'Install',
  [switch]$IncludeSysmon  # In Install mode, skip prompt and install Sysmon
)

# Configuration
$LogFile               = 'C:\Temp\EnhancedLoggingSetup.log'
$ErrorActionPreference = 'Continue'

# Sysmon paths
$BaseDir      = Split-Path -Parent $MyInvocation.MyCommand.Path
$SysmonDir    = Join-Path $BaseDir 'Sysmon'
$SysmonZip    = Join-Path $SysmonDir 'Sysmon.zip'
$SysmonExe    = Join-Path $SysmonDir 'Sysmon.exe'
$SysmonConfig = Join-Path $SysmonDir 'sysmon-config.xml'

# Ensure log directory exists
$logDir = Split-Path $LogFile
if (-not (Test-Path $logDir)) {
  New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
# Initialize log
"`r`n=== Enhanced Logging Script started on $(Get-Date) Mode=$Mode ===`r`n" |
  Out-File -FilePath $LogFile -Encoding UTF8

# Write-Log: timestamped console and file output
function Write-Log {
  param(
    [string]$Message,
    [ValidateSet('White','Green','Yellow','Cyan','Magenta','Red','DarkCyan')] [string]$Color = 'White'
  )
  $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $line = "[$ts][$Mode] $Message"
  Write-Host $line -ForegroundColor $Color
  Add-Content -Path $LogFile -Value $line
}

# Settings
$auditSettings = @{
  'Process Creation' = '/success:enable /failure:enable'
  'Module Load'      = '/success:enable /failure:enable'
  'File System'      = '/success:enable /failure:enable'
  'Registry'         = '/success:enable /failure:enable'
}
$regPath    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$regName    = 'KernelAuditIncludeCommandLine'
$sbLogPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$modLogPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'

# Prompt-Disable: interactive disable confirmation
function Prompt-Disable {
  param(
    [string]$Desc,
    [scriptblock]$Action
  )
  Write-Host "Disable $Desc? (Y/N)" -ForegroundColor Cyan
  $resp = Read-Host
  if ($resp -match '^[Yy]') {
    Write-Log "Disabling $Desc" 'Yellow'
    & $Action
    Write-Log "Disabled $Desc" 'Green'
  } else {
    Write-Log "Skipped $Desc" 'Magenta'
  }
}

# Install-Features: enable all settings
function Install-Features {
  Write-Log 'Install mode: starting' 'Cyan'

  # 1) Audit policies
  foreach ($cat in $auditSettings.Keys) {
    $cmd = "auditpol /set /subcategory:`"$cat`" $($auditSettings[$cat])"
    Write-Log ("Exec: {0}" -f $cmd) 'DarkCyan'
    Invoke-Expression $cmd | Out-Null
    Write-Log ("Audit enabled: {0}" -f $cat) 'Green'
  }

  # 2) Include command-line data
  $cmd = "New-ItemProperty -Path $regPath -Name $regName -Value 1 -PropertyType DWord -Force"
  Write-Log ("Exec: {0}" -f $cmd) 'DarkCyan'
  Invoke-Expression $cmd | Out-Null
  Write-Log 'CommandLine inclusion enabled' 'Green'

  # 3) PowerShell logging
  foreach ($path in @($sbLogPath,$modLogPath)) {
    $cmd = "New-Item -Path `"$path`" -Force"
    Write-Log ("Exec: {0}" -f $cmd) 'DarkCyan'
    Invoke-Expression $cmd | Out-Null
  }
  $propCmds = @(  
    "New-ItemProperty -Path `"$sbLogPath`" -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force",
    "New-ItemProperty -Path `"$modLogPath`" -Name EnableModuleLogging      -PropertyType DWord -Value 1 -Force",
    "New-ItemProperty -Path `"$modLogPath`" -Name ModuleNames             -PropertyType MultiString -Value '*' -Force"
  )
  foreach ($pc in $propCmds) {
    Write-Log ("Exec: {0}" -f $pc) 'DarkCyan'
    Invoke-Expression $pc | Out-Null
  }
  Write-Log 'PowerShell logging enabled' 'Green'

  # 4) Defender preferences
  $defCmds = @(  
    'Set-MpPreference -EnableControlledFolderAccess Enabled',
    'Set-MpPreference -EnableNetworkProtection Enabled'
  )
  foreach ($dc in $defCmds) {
    Write-Log ("Exec: {0}" -f $dc) 'DarkCyan'
    Invoke-Expression $dc | Out-Null
    Write-Log ("Defender: {0}" -f $dc) 'Green'
  }

  # 5) Sysmon installation
  $installSysmon = $IncludeSysmon -or (Read-Host 'Install Sysmon? (Y/N)' -match '^[Yy]')
  if ($installSysmon) {
    Write-Log 'Installing Sysmon...' 'Yellow'
    if (-not (Test-Path $SysmonDir)) {
      New-Item -Path $SysmonDir -ItemType Directory -Force | Out-Null
    }
    $dl    = "Invoke-WebRequest -UseBasicParsing -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile '$SysmonZip'"
    Write-Log ("Exec: {0}" -f $dl) 'DarkCyan'
    Invoke-Expression $dl
    $unzip = "Expand-Archive -LiteralPath '$SysmonZip' -DestinationPath '$SysmonDir' -Force"
    Write-Log ("Exec: {0}" -f $unzip) 'DarkCyan'
    Invoke-Expression $unzip
    $xml = @"
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <ProcessCreate onmatch="include" />
    <NetworkConnect onmatch="include" />
  </EventFiltering>
</Sysmon>
"@
    $xml | Out-File -FilePath $SysmonConfig -Encoding ASCII
    $cmd  = "`"$SysmonExe`" -accepteula -i `"$SysmonConfig`""
    Write-Log ("Exec: {0}" -f $cmd) 'DarkCyan'
    Invoke-Expression $cmd | Out-Null
    Write-Log 'Sysmon installed' 'Green'
  } else {
    Write-Log 'Sysmon install skipped' 'Yellow'
  }

  Write-Log 'Install complete' 'Cyan'

  # Summary disable commands
  Write-Host "`n=== Disable Commands ===" -ForegroundColor Magenta
  Write-Host "# Audit categories:" -ForegroundColor Magenta
  $auditSettings.Keys | ForEach-Object { Write-Host "  auditpol /set /subcategory:'$_' /success:disable /failure:disable" -ForegroundColor White }
  Write-Host "`n# CommandLine inclusion:" -ForegroundColor Magenta
  Write-Host "  Remove-ItemProperty -Path $regPath -Name $regName" -ForegroundColor White
  Write-Host "`n# PowerShell logging:" -ForegroundColor Magenta
  Write-Host "  Remove-Item -Path $sbLogPath -Recurse -Force" -ForegroundColor White
  Write-Host "  Remove-Item -Path $modLogPath -Recurse -Force" -ForegroundColor White
  Write-Host "`n# Defender features:" -ForegroundColor Magenta
  Write-Host "  Set-MpPreference -EnableControlledFolderAccess Disabled" -ForegroundColor White
  Write-Host "  Set-MpPreference -EnableNetworkProtection Disabled" -ForegroundColor White
  Write-Host "`n# Uninstall Sysmon:" -ForegroundColor Magenta
  Write-Host "  `"$SysmonExe`" -u -accepteula" -ForegroundColor White
}

# Uninstall-Features: disable interactively
function Uninstall-Features {
  Write-Log 'Starting Uninstall mode...' 'Cyan'
  foreach ($cat in $auditSettings.Keys) {
    Prompt-Disable "audit policy '$cat'" { Invoke-Expression "auditpol /set /subcategory:'$cat' /success:disable /failure:disable" }
  }
  Prompt-Disable 'CommandLine inclusion'             { Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue }
  Prompt-Disable 'PowerShell ScriptBlockLogging'     { Remove-Item -Path $sbLogPath -Recurse -Force }
  Prompt-Disable 'PowerShell ModuleLogging'          { Remove-Item -Path $modLogPath -Recurse -Force }
  Prompt-Disable 'ControlledFolderAccess'            { Set-MpPreference -EnableControlledFolderAccess Disabled }
  Prompt-Disable 'NetworkProtection'                 { Set-MpPreference -EnableNetworkProtection Disabled }
  if (Test-Path $SysmonExe) {
    Prompt-Disable 'Sysmon service' { & $SysmonExe -u -accepteula | Out-Null }
  }
  Write-Log 'Uninstall complete' 'Cyan'
}

# Main
if ($Mode -eq 'Install') { Install-Features } else { Uninstall-Features }

# Final log path
Write-Host "`nLog file: $LogFile`n" -ForegroundColor Green
