# Enable-EnhancedLogging.ps1

<##
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
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
"`r`n=== Enhanced Logging Script started on $(Get-Date) Mode=$Mode ===`r`n" |
    Out-File -FilePath $LogFile -Encoding UTF8

function Write-Log {
    param([string]$Msg,[string]$Color='White')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "$ts [$Mode] - $Msg"
    Write-Host $line -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $line
}

Write-Log "Starting $Mode mode..." 'Cyan'

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

function Install-Features {
    Write-Log 'Installing features...' 'Yellow'
    # Audit policies
    foreach ($cat in $auditSettings.Keys) {
        $cmd = "auditpol /set /subcategory:`"$cat`" $($auditSettings[$cat])"
        Write-Log "=> $cmd" 'DarkCyan'
        Invoke-Expression $cmd
        Write-Log "Audit '$cat' enabled" 'Green'
    }
    # CommandLine inclusion
    $cmd = "New-ItemProperty -Path $regPath -Name $regName -Value 1 -PropertyType DWord -Force"
    Write-Log "=> $cmd" 'DarkCyan'
    Invoke-Expression $cmd | Out-Null
    Write-Log 'CommandLine inclusion enabled' 'Green'
    # PowerShell logging
    foreach ($psPath in @($sbLogPath,$modLogPath)) {
        $cmd = "New-Item -Path $psPath -Force"
        Write-Log "=> $cmd" 'DarkCyan'
        Invoke-Expression $cmd | Out-Null
    }
    $cmds=@(
        "New-ItemProperty -Path $sbLogPath -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force",
        "New-ItemProperty -Path $modLogPath -Name EnableModuleLogging -PropertyType DWord -Value 1 -Force",
        "New-ItemProperty -Path $modLogPath -Name ModuleNames -PropertyType MultiString -Value '*' -Force"
    )
    foreach($c in $cmds){ Write-Log "=> $c" 'DarkCyan'; Invoke-Expression $c | Out-Null }
    Write-Log 'PowerShell logging enabled' 'Green'
    # Defender features
    foreach ($dCmd in @(
        'Set-MpPreference -EnableControlledFolderAccess Enabled',
        'Set-MpPreference -EnableNetworkProtection Enabled'
    )) {
        Write-Log "=> $dCmd" 'DarkCyan'
        Invoke-Expression $dCmd | Out-Null
        Write-Log "$dCmd successful" 'Green'
    }
    # Sysmon install prompt
    $install = $IncludeSysmon -or (Read-Host 'Install Sysmon? (Y/N)' -match '^[Yy]')
    if ($install) {
        Write-Log 'Installing Sysmon...' 'Yellow'
        if (-not (Test-Path $SysmonDir)) { New-Item -Path $SysmonDir -ItemType Directory -Force }
        $cmd = "Invoke-WebRequest -UseBasicParsing -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile `"$SysmonZip`""
        Write-Log "=> $cmd" 'DarkCyan'; Invoke-Expression $cmd
        $cmd = "Expand-Archive -LiteralPath `"$SysmonZip`" -DestinationPath `"$SysmonDir`" -Force"
        Write-Log "=> $cmd" 'DarkCyan'; Invoke-Expression $cmd
        @"
<Sysmon schemaversion=\"4.30\">
  <EventFiltering>
    <ProcessCreate onmatch=\"include\" />
    <NetworkConnect onmatch=\"include\" />
  </EventFiltering>
</Sysmon>
"@ | Out-File -FilePath $SysmonConfig -Encoding ASCII
        Write-Log "=> & $SysmonExe -accepteula -i $SysmonConfig" 'DarkCyan'
        & $SysmonExe -accepteula -i $SysmonConfig | Out-Null
        Write-Log 'Sysmon installed' 'Green'
    } else { Write-Log 'Sysmon install skipped' 'Yellow' }
    Write-Log 'Installation complete' 'Cyan'
    # Explicit disable commands summary
    Write-Host "`nCut-and-paste to disable features:`n" -ForegroundColor Magenta
    Write-Host "# Disable audit category:" -ForegroundColor Magenta
    $auditSettings.Keys | ForEach-Object { Write-Host "  auditpol /set /subcategory:'$_' /success:disable /failure:disable" -ForegroundColor White }
    Write-Host "`n# Disable CommandLine inclusion:" -ForegroundColor Magenta
    Write-Host "  Remove-ItemProperty -Path $regPath -Name $regName" -ForegroundColor White
    Write-Host "`n# Disable PowerShell logging:" -ForegroundColor Magenta
    Write-Host "  Remove-Item -Path $sbLogPath -Recurse -Force" -ForegroundColor White
    Write-Host "  Remove-Item -Path $modLogPath -Recurse -Force" -ForegroundColor White
    Write-Host "`n# Disable Defender features:" -ForegroundColor Magenta
    Write-Host "  Set-MpPreference -EnableControlledFolderAccess Disabled" -ForegroundColor White
    Write-Host "  Set-MpPreference -EnableNetworkProtection Disabled" -ForegroundColor White
    Write-Host "`n# Uninstall Sysmon:" -ForegroundColor Magenta
    Write-Host "  & $SysmonExe -u -accepteula" -ForegroundColor White
    Write-Log 'Displayed explicit disable instructions' 'Cyan'
}

function Uninstall-Features {
    Write-Log 'Uninstalling features...' 'Yellow'
    foreach ($cat in $auditSettings.Keys) {
        Prompt-Disable "audit category '$cat'" { Invoke-Expression "auditpol /set /subcategory:'$cat' /success:disable /failure:disable" }
    }
    Prompt-Disable 'CommandLine inclusion' { Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue }
    Prompt-Disable 'ScriptBlockLogging'     { Remove-Item -Path $sbLogPath -Recurse -Force }
    Prompt-Disable 'ModuleLogging'          { Remove-Item -Path $modLogPath -Recurse -Force }
    Prompt-Disable 'ControlledFolderAccess'  { Set-MpPreference -EnableControlledFolderAccess Disabled }
    Prompt-Disable 'NetworkProtection'      { Set-MpPreference -EnableNetworkProtection Disabled }
    if (Test-Path $SysmonExe) {
        Prompt-Disable 'Sysmon service'       { & $SysmonExe -u -accepteula }
    }
    Write-Log 'Uninstallation complete' 'Cyan'
}

# Main
if ($Mode -eq 'Install') { Install-Features } else { Uninstall-Features }
Write-Host "`nLog written to: $LogFile`n" -ForegroundColor Green
