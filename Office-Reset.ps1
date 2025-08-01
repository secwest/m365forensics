# Comprehensive OneDrive and Teams Reset Script
# Run as Administrator for best results

param(
    [switch]$IncludeOfficeActivation,
    [switch]$Force
)

# Function to stop processes safely
function Stop-AppProcess {
    param([string[]]$ProcessNames)
    
    foreach ($proc in $ProcessNames) {
        $processes = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($processes) {
            Write-Host "Stopping $proc..." -ForegroundColor Yellow
            Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
    }
}

# Function to clear Teams cache
function Clear-TeamsCache {
    Write-Host "`nClearing Microsoft Teams cache..." -ForegroundColor Cyan
    
    # Teams cache locations
    $teamsPaths = @(
        "$env:APPDATA\Microsoft\Teams\Application Cache\Cache",
        "$env:APPDATA\Microsoft\Teams\blob_storage",
        "$env:APPDATA\Microsoft\Teams\Cache",
        "$env:APPDATA\Microsoft\Teams\databases",
        "$env:APPDATA\Microsoft\Teams\GPUCache",
        "$env:APPDATA\Microsoft\Teams\IndexedDB",
        "$env:APPDATA\Microsoft\Teams\Local Storage",
        "$env:APPDATA\Microsoft\Teams\tmp",
        "$env:APPDATA\Microsoft\Teams\Service Worker\CacheStorage",
        "$env:APPDATA\Microsoft\Teams\Service Worker\ScriptCache",
        "$env:APPDATA\Microsoft Teams"  # Classic Teams
    )
    
    foreach ($path in $teamsPaths) {
        if (Test-Path $path) {
            Write-Host "Removing: $path" -ForegroundColor Gray
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Clear Teams registry keys
    $teamsRegKeys = @(
        "HKCU:\Software\Microsoft\Office\Teams",
        "HKCU:\Software\Microsoft\Teams"
    )
    
    foreach ($key in $teamsRegKeys) {
        if (Test-Path $key) {
            Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Function to clear OneDrive cache
function Clear-OneDriveCache {
    Write-Host "`nClearing OneDrive cache..." -ForegroundColor Cyan
    
    # OneDrive cache locations
    $onedrivePaths = @(
        "$env:LOCALAPPDATA\Microsoft\OneAuth",
        "$env:LOCALAPPDATA\Microsoft\IdentityCache",
        "$env:LOCALAPPDATA\Microsoft\OneDrive\logs",
        "$env:LOCALAPPDATA\Microsoft\OneDrive\settings"
    )
    
    foreach ($path in $onedrivePaths) {
        if (Test-Path $path) {
            Write-Host "Removing: $path" -ForegroundColor Gray
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Function to clear credentials
function Clear-Credentials {
    Write-Host "`nClearing stored credentials..." -ForegroundColor Cyan
    
    $credentialPatterns = @(
        "MicrosoftOffice16_Data:*",
        "OneDrive*",
        "office*",
        "teams*",
        "msteams*",
        "Microsoft_Teams*"
    )
    
    $clearedCount = 0
    foreach ($pattern in $credentialPatterns) {
        cmdkey /list | Select-String $pattern | ForEach-Object {
            if ($_ -match "Target:\s*(.+)") {
                $target = $matches[1].Trim()
                Write-Host "Removing credential: $target" -ForegroundColor Gray
                cmdkey /delete:"$target" 2>$null
                $clearedCount++
            }
        }
    }
    Write-Host "Cleared $clearedCount credentials" -ForegroundColor Green
}

# Function to clear Office/Teams identity registry
function Clear-IdentityRegistry {
    Write-Host "`nClearing identity registry keys..." -ForegroundColor Cyan
    
    # Backup registry first
    $backupPath = "$env:USERPROFILE\Desktop\OfficeTeamsRegistry_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
    reg export "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office" $backupPath /y
    Write-Host "Registry backed up to: $backupPath" -ForegroundColor Green
    
    # Remove identity keys
    $identityKeys = @(
        "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Identity",
        "HKCU:\SOFTWARE\Microsoft\Office\Teams\Identity",
        "HKCU:\SOFTWARE\Microsoft\Office\16.0\Teams"
    )
    
    foreach ($key in $identityKeys) {
        if (Test-Path $key) {
            Write-Host "Removing: $key" -ForegroundColor Gray
            Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Handle HKEY_USERS identity (requires admin)
    try {
        $userSID = (New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $huPath = "Registry::HKEY_USERS\$userSID\SOFTWARE\Microsoft\Office\16.0\Common\Identity"
        if (Test-Path $huPath) {
            Remove-Item -Path $huPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "Could not clear HKEY_USERS identity (admin required)" -ForegroundColor Yellow
    }
}

# Function to reset Teams specifically
function Reset-TeamsApp {
    Write-Host "`nResetting Teams app..." -ForegroundColor Cyan
    
    # Get Teams package info
    $teamsPackage = Get-AppxPackage -Name "*Teams*" -ErrorAction SilentlyContinue
    
    if ($teamsPackage) {
        # Reset the Teams app
        foreach ($package in $teamsPackage) {
            Write-Host "Resetting package: $($package.Name)" -ForegroundColor Gray
            try {
                # Reset without removing
                Add-AppxPackage -DisableDevelopmentMode -Register "$($package.InstallLocation)\AppXManifest.xml"
            } catch {
                Write-Host "Could not reset $($package.Name): $_" -ForegroundColor Yellow
            }
        }
    }
}

# Main execution
Write-Host "OneDrive and Teams Reset Tool" -ForegroundColor Green
Write-Host "==============================" -ForegroundColor Green

if (-not $Force) {
    $confirm = Read-Host "`nThis will reset OneDrive and Teams. Continue? (Y/N)"
    if ($confirm -ne 'Y') {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit
    }
}

try {
    # Stop all related processes
    Write-Host "`nStopping applications..." -ForegroundColor Cyan
    Stop-AppProcess -ProcessNames @("OneDrive", "Teams", "ms-teams", "Teams.exe", "OneDriveSetup")
    
    # Clear all caches and settings
    Clear-IdentityRegistry
    Clear-OneDriveCache
    Clear-TeamsCache
    Clear-Credentials
    
    # Reset Teams app if it's installed as AppX
    Reset-TeamsApp
    
    # Additional cleanup for persistent issues
    if ($IncludeOfficeActivation) {
        Write-Host "`nClearing Office activation..." -ForegroundColor Cyan
        
        $officeKeys = @(
            "HKCU:\Software\Microsoft\Office\16.0\Common\Licensing",
            "HKCU:\Software\Microsoft\Office\16.0\Common\ServicesManagerCache",
            "HKCU:\Software\Microsoft\Office\16.0\Common\Experiment"
        )
        
        foreach ($key in $officeKeys) {
            if (Test-Path $key) {
                Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    # Clear IE/Edge cache (sometimes affects authentication)
    Write-Host "`nClearing browser caches..." -ForegroundColor Cyan
    RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 2
    
    Write-Host "`n✓ Reset completed successfully!" -ForegroundColor Green
    Write-Host "`nNext steps:" -ForegroundColor Yellow
    Write-Host "1. Restart your computer (recommended)" -ForegroundColor White
    Write-Host "2. Sign in to OneDrive first" -ForegroundColor White
    Write-Host "3. Then sign in to Teams" -ForegroundColor White
    
} catch {
    Write-Host "`n✗ Error occurred: $_" -ForegroundColor Red
    Write-Host "Try running as Administrator" -ForegroundColor Yellow
}
