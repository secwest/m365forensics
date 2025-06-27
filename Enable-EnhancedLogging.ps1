# Enable-EnhancedLogging.ps1

<#
.SYNOPSIS
  Installs or uninstalls enhanced logging and protections.
.DESCRIPTION
  Modes:
    Install   - Enable audit policies, PowerShell logging, Defender features, and prompt/install Sysmon.
    Uninstall - Prompt and disable each enabled setting, and optionally uninstall Sysmon.
#>
param(
    [ValidateSet("Install","Uninstall")]
    [string]$Mode = "Install",
    [switch]$IncludeSysmon                 # If set, Sysmon will be installed without prompt
)

# ------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------
$LogFile        = "C:\Temp\EnhancedLoggingSetup.log"
$ErrorActionPreference = "Continue"

# Paths for Sysmon
$BaseDir      = $PSScriptRoot
$SysmonDir    = Join-Path $BaseDir "Sysmon"
$SysmonZip    = Join-Path $SysmonDir "Sysmon.zip"
$SysmonExe    = Join-Path $SysmonDir "Sysmon.exe"
$SysmonConfig = Join-Path $SysmonDir "sysmon-config.xml"

# Ensure log directory and file
$logDir = Split-Path $LogFile
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
"`r`n=== Enhanced Logging Script started on $(Get-Date) Mode=$Mode ===`r`n" |
    Out-File -FilePath $LogFile -Encoding UTF8

function Write-Log {
    param([string]$Msg)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "$ts [$Mode] - $Msg"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

# Audit and logging settings
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

function Prompt-Disable {
    param(
        [string]$Description,
        [scriptblock]$Action
    )
    $resp = Read-Host "Disable $Description? (Y/N)"
    if ($resp -match '^[Yy]') {
        Write-Log "Disabling: $Description"
        & $Action
        Write-Log "Disabled: $Description"
    } else {
        Write-Log "Skipped disabling: $Description"
    }
}

function Install-Features {
    Write-Log 'Installing features...'
    # Audit policies
    foreach ($cat in $auditSettings.Keys) {
        $cmd = "auditpol /set /subcategory:`"$cat`" $($auditSettings[$cat])"
        Write-Log "Executing: $cmd"
        Invoke-Expression $cmd
        Write-Log "Audit $cat enabled."
    }
    # CommandLine inclusion
    $cmd = "New-ItemProperty -Path $regPath -Name $regName -Value 1 -PropertyType DWord -Force"
    Write-Log "Executing: $cmd"
    Invoke-Expression $cmd | Out-Null
    Write-Log 'CommandLine inclusion enabled.'
    # PowerShell logging
    foreach ($psPath in @($sbLogPath, $modLogPath)) {
        $cmd = "New-Item -Path $psPath -Force"
        Write-Log "Executing: $cmd"
        Invoke-Expression $cmd | Out-Null
    }
    $cmd = "New-ItemProperty -Path $sbLogPath -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force"
    Write-Log "Executing: $cmd"
    Invoke-Expression $cmd | Out-Null
    $cmd = "New-ItemProperty -Path $modLogPath -Name EnableModuleLogging -PropertyType DWord -Value 1 -Force"
    Write-Log "Executing: $cmd"
    Invoke-Expression $cmd | Out-Null
    $cmd = "New-ItemProperty -Path $modLogPath -Name ModuleNames -PropertyType MultiString -Value '*' -Force"
    Write-Log "Executing: $cmd"
    Invoke-Expression $cmd | Out-Null
    Write-Log 'PowerShell logging enabled.'
    # Defender features
    foreach ($dCmd in @(
        'Set-MpPreference -EnableControlledFolderAccess Enabled',
        'Set-MpPreference -EnableNetworkProtection Enabled'
    )) {
        Write-Log "Executing: $dCmd"
        Invoke-Expression $dCmd | Out-Null
        Write-Log "$dCmd successful."
    }
    # Sysmon install prompt
    $install = $IncludeSysmon -or (Read-Host 'Install Sysmon? (Y/N)' -match '^[Yy]')
    if ($install) {
        Write-Log 'Installing Sysmon...'
        if (-not (Test-Path $SysmonDir)) { New-Item -Path $SysmonDir -ItemType Directory -Force }
        $cmd = "Invoke-WebRequest -UseBasicParsing -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile `"$SysmonZip`""
        Write-Log "Executing: $cmd"
        Invoke-Expression $cmd
        $cmd = "Expand-Archive -LiteralPath `"$SysmonZip`" -DestinationPath `"$SysmonDir`" -Force"
        Write-Log "Executing: $cmd"
        Invoke-Expression $cmd
        @"
<Sysmon schemaversion=\"4.30\">
  <EventFiltering>
    <ProcessCreate onmatch=\"include\" />
    <NetworkConnect onmatch=\"include\" />
  </EventFiltering>
</Sysmon>
"@ | Out-File -FilePath $SysmonConfig -Encoding ASCII
        $cmd = "& `$SysmonExe -accepteula -i `$SysmonConfig"
        Write-Log "Executing: $cmd"
        & $SysmonExe -accepteula -i $SysmonConfig | Out-Null
        Write-Log 'Sysmon installed.'
    } else { Write-Log 'Sysmon install skipped.' }
    Write-Log 'Installation complete.'
    # Explicit disable commands summary
    Write-Host "`nCut-and-paste to disable specific features:`n"
    Write-Host "# Disable a specific audit:"; $auditSettings.Keys | ForEach-Object { Write-Host "auditpol /set /subcategory:'$_' /success:disable /failure:disable" }
    Write-Host "`n# Disable CommandLine inclusion:"; Write-Host "Remove-ItemProperty -Path $regPath -Name $regName"
    Write-Host "`n# Disable PowerShell logging:";
    Write-Host "Remove-Item -Path $sbLogPath -Recurse -Force";
    Write-Host "Remove-Item -Path $modLogPath -Recurse -Force"
    Write-Host "`n# Disable Defender features:";
    Write-Host "Set-MpPreference -EnableControlledFolderAccess Disabled";
    Write-Host "Set-MpPreference -EnableNetworkProtection Disabled"
    Write-Host "`n# Uninstall Sysmon:"; Write-Host "& $SysmonExe -u -accepteula"
    Write-Log 'Displayed explicit disable instructions.'
}

function Uninstall-Features {
    Write-Log 'Uninstalling features...'
    # Prompt and disable each section
    foreach ($cat in $auditSettings.Keys) {
        Prompt-Disable "audit $cat" { auditpol /set /subcategory:"$cat" /success:disable /failure:disable }
    }
    Prompt-Disable 'CommandLine inclusion' { Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue }
    Prompt-Disable 'ScriptBlockLogging' { Remove-Item -Path $sbLogPath -Recurse -Force }
    Prompt-Disable 'ModuleLogging' { Remove-Item -Path $modLogPath -Recurse -Force }
    Prompt-Disable 'ControlledFolderAccess' { Set-MpPreference -EnableControlledFolderAccess Disabled }
    Prompt-Disable 'NetworkProtection'     { Set-MpPreference -EnableNetworkProtection Disabled }
    if (Test-Path $SysmonExe) {
        Prompt-Disable 'Sysmon service' { & $SysmonExe -u -accepteula }
    }
    Write-Log 'Uninstallation complete.'
}

# Main
if ($Mode -eq 'Install') { Install-Features } else { Uninstall-Features }
Write-Host "`nLog written to: $LogFile`n"
