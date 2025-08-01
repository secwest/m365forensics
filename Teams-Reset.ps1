# Teams-Only Reset Script
function Reset-MicrosoftTeams {
    param([switch]$KeepSettings)
    
    Write-Host "Microsoft Teams Reset Tool" -ForegroundColor Cyan
    
    # Stop Teams processes
    $teamsProcesses = @("Teams", "ms-teams", "Teams.exe", "TeamsPresentationHost", "TeamsUpdate")
    foreach ($proc in $teamsProcesses) {
        Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force
    }
    
    Start-Sleep -Seconds 3
    
    # Teams paths to clear
    $paths = @{
        "Cache" = @(
            "$env:APPDATA\Microsoft\Teams\Application Cache\Cache",
            "$env:APPDATA\Microsoft\Teams\blob_storage",
            "$env:APPDATA\Microsoft\Teams\Cache",
            "$env:APPDATA\Microsoft\Teams\databases",
            "$env:APPDATA\Microsoft\Teams\GPUCache",
            "$env:APPDATA\Microsoft\Teams\IndexedDB",
            "$env:APPDATA\Microsoft\Teams\Local Storage",
            "$env:APPDATA\Microsoft\Teams\tmp"
        )
        "Settings" = @(
            "$env:APPDATA\Microsoft\Teams\desktop-config.json",
            "$env:APPDATA\Microsoft\Teams\settings.json",
            "$env:APPDATA\Microsoft\Teams\storage.json"
        )
    }
    
    # Clear cache
    foreach ($path in $paths.Cache) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Cleared: $(Split-Path $path -Leaf)" -ForegroundColor Gray
        }
    }
    
    # Clear settings unless specified to keep
    if (-not $KeepSettings) {
        foreach ($path in $paths.Settings) {
            if (Test-Path $path) {
                Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    # Clear Teams credentials
    cmdkey /list | Select-String "teams|msteams" -SimpleMatch | ForEach-Object {
        if ($_ -match "Target:\s*(.+)") {
            cmdkey /delete:"$($matches[1].Trim())" 2>$null
        }
    }
    
    Write-Host "`nTeams reset complete!" -ForegroundColor Green
}

# Run the reset
Reset-MicrosoftTeams
