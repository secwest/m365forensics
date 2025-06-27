# Enable-EnhancedLogging.ps1
# Installs or uninstalls enhanced logging and protections.
# Usage:
#   .\Enable-EnhancedLogging.ps1 [-Mode Install|Uninstall] [-IncludeSysmon]

param(
  [ValidateSet('Install','Uninstall')]
  [string]$Mode = 'Install',
  [switch]$IncludeSysmon
)

# Configuration
$LogFile               = 'C:\Temp\EnhancedLoggingSetup.log'
$ErrorActionPreference = 'Continue'

# Sysmon paths
$ScriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Path
$SysmonDir    = Join-Path $ScriptFolder 'Sysmon'
$SysmonZip    = Join-Path $SysmonDir 'Sysmon.zip'
$SysmonExe    = Join-Path $SysmonDir 'Sysmon.exe'
$SysmonConfig = Join-Path $SysmonDir 'sysmon-config.xml'

# Ensure log directory
$LogFolder = Split-Path $LogFile
if (-not (Test-Path $LogFolder)) {
  New-Item $LogFolder -ItemType Directory -Force | Out-Null
}
# Initialize Log
"`r`n=== Enhanced Logging Script started on $(Get-Date) Mode=$Mode ===`r`n" |
  Out-File -FilePath $LogFile -Encoding UTF8

function Write-Log {
  param(
    [string]$Msg,
    [ValidateSet('White','Green','Yellow','Cyan','Magenta','Red')] [string]$Color = 'White'
  )
  $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $line = "[$ts][$Mode] $Msg"
  Write-Host $line -ForegroundColor $Color
  Add-Content -Path $LogFile -Value $line
}

# Audit categories
$auditCategories = @(
  'Process Creation',
  'Module Load',
  'File System',
  'Registry'
)
$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$regName = 'KernelAuditIncludeCommandLine'
$sbLogPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$modLogPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'

function Enable-Audits {
  foreach ($cat in $auditCategories) {
    $cmd = "auditpol /set /subcategory:`"$cat`" /success:enable /failure:enable"
    Write-Log ("Exec: {0}" -f $cmd) 'Cyan'
    Invoke-Expression $cmd | Out-Null
    Write-Log ("Audit enabled: $cat") 'Green'
  }
}

function Disable-Audits {
  foreach ($cat in $auditCategories) {
    $cmd = "auditpol /set /subcategory:`"$cat`" /success:disable /failure:disable"
    Write-Log ("Exec: {0}" -f $cmd) 'Cyan'
    Invoke-Expression $cmd | Out-Null
    Write-Log ("Audit disabled: $cat") 'Green'
  }
}

function Enable-CommandLineInclusion {
  Write-Log "Exec: New-ItemProperty -Path $regPath -Name $regName -Value 1 -PropertyType DWord -Force" 'Cyan'
  New-ItemProperty -Path $regPath -Name $regName -Value 1 -PropertyType DWord -Force | Out-Null
  Write-Log 'CommandLine inclusion enabled' 'Green'
}

function Disable-CommandLineInclusion {
  Write-Log "Exec: Remove-ItemProperty -Path $regPath -Name $regName" 'Cyan'
  Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
  Write-Log 'CommandLine inclusion disabled' 'Green'
}

function Enable-PSLogging {
  Write-Log "Exec: New-Item -Path $sbLogPath -Force" 'Cyan'
  New-Item -Path $sbLogPath -Force | Out-Null
  Write-Log "Exec: New-ItemProperty -Path $sbLogPath -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force" 'Cyan'
  New-ItemProperty -Path $sbLogPath -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force | Out-Null
  Write-Log "Exec: New-Item -Path $modLogPath -Force" 'Cyan'
  New-Item -Path $modLogPath -Force | Out-Null
  Write-Log "Exec: New-ItemProperty -Path $modLogPath -Name EnableModuleLogging -PropertyType DWord -Value 1 -Force" 'Cyan'
  New-ItemProperty -Path $modLogPath -Name EnableModuleLogging -PropertyType DWord -Value 1 -Force | Out-Null
  Write-Log "Exec: New-ItemProperty -Path $modLogPath -Name ModuleNames -PropertyType MultiString -Value '*' -Force" 'Cyan'
  New-ItemProperty -Path $modLogPath -Name ModuleNames -PropertyType MultiString -Value '*' -Force | Out-Null
  Write-Log 'PowerShell logging enabled' 'Green'
}

function Disable-PSLogging {
  Write-Log "Exec: Remove-Item -Path $sbLogPath -Recurse -Force" 'Cyan'
  Remove-Item -Path $sbLogPath -Recurse -Force -ErrorAction SilentlyContinue
  Write-Log "Exec: Remove-Item -Path $modLogPath -Recurse -Force" 'Cyan'
  Remove-Item -Path $modLogPath -Recurse -Force -ErrorAction SilentlyContinue
  Write-Log 'PowerShell logging disabled' 'Green'
}

function Enable-Defender {
  Write-Log "Exec: Set-MpPreference -EnableControlledFolderAccess Enabled" 'Cyan'
  Set-MpPreference -EnableControlledFolderAccess Enabled
  Write-Log "Exec: Set-MpPreference -EnableNetworkProtection Enabled" 'Cyan'
  Set-MpPreference -EnableNetworkProtection Enabled
  Write-Log 'Defender features enabled' 'Green'
}

function Disable-Defender {
  Write-Log "Exec: Set-MpPreference -EnableControlledFolderAccess Disabled" 'Cyan'
  Set-MpPreference -EnableControlledFolderAccess Disabled
  Write-Log "Exec: Set-MpPreference -EnableNetworkProtection Disabled" 'Cyan'
  Set-MpPreference -EnableNetworkProtection Disabled
  Write-Log 'Defender features disabled' 'Green'
}

function Install-Features {
  Write-Log '== Enabling features ==' 'Cyan'
  Enable-Audits
  Enable-CommandLineInclusion
  Enable-PSLogging
  Enable-Defender
  # Sysmon
  $doSN = $IncludeSysmon -or (Read-Host 'Install Sysmon? (Y/N)' -match '^[Yy]')
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
  } else {
    Write-Log 'Sysmon install skipped' 'Yellow'
  }
  Write-Log 'Install complete' 'Cyan'
  Write-Host "`nUse these to disable individual features:`n" -ForegroundColor Magenta
  Write-Host "auditpol /set /subcategory:'<Category>' /success:disable /failure:disable" -ForegroundColor White
  Write-Host "Remove-ItemProperty -Path $regPath -Name $regName" -ForegroundColor White
  Write-Host "Remove-Item -Path $sbLogPath -Recurse -Force" -ForegroundColor White
  Write-Host "Remove-Item -Path $modLogPath -Recurse -Force" -ForegroundColor White
  Write-Host "Set-MpPreference -EnableControlledFolderAccess Disabled" -ForegroundColor White
  Write-Host "Set-MpPreference -EnableNetworkProtection Disabled" -ForegroundColor White
  Write-Host "`"$SysmonExe`" -u -accepteula" -ForegroundColor White
}

function Uninstall-Features {
  Write-Log '== Disabling features ==' 'Cyan'
  Prompt-Disable 'Audit policies' { Disable-Audits }
  Prompt-Disable 'CommandLine inclusion' { Disable-CommandLineInclusion }
  Prompt-Disable 'PowerShell logging' { Disable-PSLogging }
  Prompt-Disable 'Defender features' { Disable-Defender }
  if (Test-Path $SysmonExe) {
    Prompt-Disable 'Sysmon service' { & $SysmonExe -u -accepteula }
  }
  Write-Log 'Uninstall complete' 'Cyan'
}

# Main
if ($Mode -eq 'Install') { Install-Features } else { Uninstall-Features }

Write-Host "`nLog file: $LogFile`n" -ForegroundColor Green
