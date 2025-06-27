# Enable-EnhancedLogging.ps1

# ------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------
$LogFile        = "C:\Temp\EnhancedLoggingSetup.log"
$ErrorActionPreference = "Continue"

# Paths for Sysmon install
$BaseDir        = $PSScriptRoot
$SysmonDir      = Join-Path $BaseDir "Sysmon"
$SysmonZip      = Join-Path $SysmonDir "Sysmon.zip"
$SysmonExe      = Join-Path $SysmonDir "Sysmon.exe"
$SysmonConfig   = Join-Path $SysmonDir "sysmon-config.xml"

# Ensure log directory exists
$logDir = Split-Path $LogFile
if (-not (Test-Path $logDir)) {
  New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
# Ensure clean log
"`r`n=== Enhanced Logging Setup started on $(Get-Date) ===`r`n" |
  Out-File -FilePath $LogFile -Encoding UTF8

function Write-Log {
  param([string]$Message)
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "$ts - $Message"
  Write-Host $line
  Add-Content -Path $LogFile -Value $line
}

Write-Log "Beginning setup..."

# ------------------------------------------------------------------------
# 1) Prompt to install Sysmon
# ------------------------------------------------------------------------
$installSysmon = Read-Host "Install Sysmon with basic config? (Y/N)"
if ($installSysmon -match '^[Yy]') {
  try {
    Write-Log "Preparing Sysmon directory..."
    if (-not (Test-Path $SysmonDir)) {
      New-Item -Path $SysmonDir -ItemType Directory -Force | Out-Null
    }

    Write-Log "Downloading Sysmon.zip..."
    Invoke-WebRequest -UseBasicParsing `
      "https://download.sysinternals.com/files/Sysmon.zip" `
      -OutFile $SysmonZip -ErrorAction Stop

    Write-Log "Extracting Sysmon.exe..."
    Expand-Archive -LiteralPath $SysmonZip -DestinationPath $SysmonDir -Force

    Write-Log "Writing minimal Sysmon config..."
    @"
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <ProcessCreate onmatch="include" />
    <NetworkConnect onmatch="include" />
  </EventFiltering>
</Sysmon>
"@ | Out-File -FilePath $SysmonConfig -Encoding ASCII

    Write-Log "Installing Sysmon service..."
    & $SysmonExe -accepteula -i $SysmonConfig | Out-Null
    Write-Log "Sysmon installed."
  }
  catch {
    Write-Log "ERROR installing Sysmon: $_"
  }
}
else {
  Write-Log "Skipping Sysmon installation."
}

# ------------------------------------------------------------------------
# 2) Advanced Audit Policies
# ------------------------------------------------------------------------
$auditSettings = @{
  "Process Creation" = "/success:enable /failure:enable"
  "Module Load"      = "/success:enable /failure:enable"
  "File System"      = "/success:enable /failure:enable"
  "Registry"         = "/success:enable /failure:enable"
}

foreach ($subcat in $auditSettings.Keys) {
  try {
    Write-Log "Enabling audit for '$subcat'..."
    auditpol /set /subcategory:"$subcat" $auditSettings[$subcat] | Out-Null
    Write-Log "Audit '$subcat' enabled."
  }
  catch {
    Write-Log "ERROR enabling audit '$subcat': $_"
  }
}

# ------------------------------------------------------------------------
# 3) Include CommandLine in 4688 events
# ------------------------------------------------------------------------
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$regName = "KernelAuditIncludeCommandLine"
try {
  $current = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
  if ($current.$regName -eq 1) {
    Write-Log "CommandLine inclusion already enabled."
  }
  else {
    Write-Log "Enabling CommandLine inclusion..."
    New-ItemProperty -Path $regPath -Name $regName -Value 1 -PropertyType DWord -Force | Out-Null
    Write-Log "CommandLine inclusion enabled."
  }
}
catch {
  Write-Log "ERROR setting CommandLine inclusion: $_"
}

# ------------------------------------------------------------------------
# 4) PowerShell ScriptBlock & Module Logging
# ------------------------------------------------------------------------
$sbLogPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$modLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"

try {
  Write-Log "Enabling ScriptBlockLogging..."
  New-Item -Path $sbLogPath -Force | Out-Null
  New-ItemProperty -Path $sbLogPath -Name "EnableScriptBlockLogging" -PropertyType DWord -Value 1 -Force | Out-Null
  Write-Log "ScriptBlockLogging enabled."
}
catch {
  Write-Log "ERROR enabling ScriptBlockLogging: $_"
}

try {
  Write-Log "Enabling ModuleLogging for all modules..."
  New-Item -Path $modLogPath -Force | Out-Null
  New-ItemProperty -Path $modLogPath -Name "EnableModuleLogging" -PropertyType DWord -Value 1 -Force | Out-Null
  New-ItemProperty -Path $modLogPath -Name "ModuleNames"         -PropertyType MultiString -Value "*" -Force | Out-Null
  Write-Log "ModuleLogging enabled."
}
catch {
  Write-Log "ERROR enabling ModuleLogging: $_"
}

# ------------------------------------------------------------------------
# 5) Defender Preferences
# ------------------------------------------------------------------------
try {
  Write-Log "Enabling Controlled Folder Access..."
  Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
  Write-Log "Controlled Folder Access enabled."
}
catch {
  Write-Log "ERROR enabling Controlled Folder Access: $_"
}

try {
  Write-Log "Enabling Network Protection..."
  Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
  Write-Log "Network Protection enabled."
}
catch {
  Write-Log "ERROR enabling Network Protection: $_"
}

Write-Log "==== Setup complete. Now offering interactive disable options. ===="

# ------------------------------------------------------------------------
# Interactive disable prompts
# ------------------------------------------------------------------------
function Prompt-Disable {
  param(
    [string]$Description,
    [scriptblock]$Action
  )
  $resp = Read-Host "Disable $Description? (Y/N)"
  if ($resp -match '^[Yy]') {
    try {
      & $Action
      Write-Log "Disabled: $Description"
    }
    catch {
      Write-Log "ERROR disabling $Description: $_"
    }
  }
  else {
    Write-Log "Skipped disabling: $Description"
  }
}

# 1) Advanced audits
foreach ($subcat in $auditSettings.Keys) {
  Prompt-Disable "audit policy '$subcat'" {
    auditpol /set /subcategory:"$subcat" /success:disable /failure:disable | Out-Null
  }
}

# 2) CommandLine inclusion
Prompt-Disable "CommandLine inclusion in 4688 events" {
  Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
}

# 3) ScriptBlockLogging
Prompt-Disable "PowerShell ScriptBlockLogging" {
  Remove-Item -Path $sbLogPath -Recurse -Force -ErrorAction SilentlyContinue
}

# 4) ModuleLogging
Prompt-Disable "PowerShell ModuleLogging" {
  Remove-Item -Path $modLogPath -Recurse -Force -ErrorAction SilentlyContinue
}

# 5) Defender features
Prompt-Disable "Controlled Folder Access" {
  Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
}
Prompt-Disable "Network Protection" {
  Set-MpPreference -EnableNetworkProtection Disabled -ErrorAction SilentlyContinue
}

# 6) Sysmon uninstall
if (Test-Path $SysmonExe) {
  Prompt-Disable "Sysmon service" {
    & $SysmonExe -u -accepteula | Out-Null
  }
}

Write-Log "Interactive disable complete."
Write-Host ""
Write-Host "Detailed log available at $LogFile"
