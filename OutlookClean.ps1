# Outlook Autodiscover Cache Cleanup Script
# Run as Administrator

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "Outlook Autodiscover Cache Cleanup Script" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

# Check for admin rights
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires administrator privileges." -ForegroundColor Red
    Write-Host "Please run PowerShell as administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Kill Outlook if running
Write-Host "Closing Outlook if running..." -ForegroundColor Yellow
Get-Process outlook -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

# Clear Registry autodiscover entries
Write-Host ""
Write-Host "Clearing Registry autodiscover entries..." -ForegroundColor Yellow

# Office versions to check
$officeVersions = @("16.0", "15.0", "14.0")

foreach ($version in $officeVersions) {
    $regPath = "HKCU:\Software\Microsoft\Office\$version\Outlook\AutoDiscover"
    if (Test-Path $regPath) {
        Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Cleared autodiscover registry for Office $version" -ForegroundColor Green
    }
}

# Clear cached credentials
Write-Host ""
Write-Host "Clearing cached credentials..." -ForegroundColor Yellow

$credentials = cmdkey /list | Select-String -Pattern "Target:" | ForEach-Object {
    $_.Line -replace ".*Target:\s*", ""
}

foreach ($cred in $credentials) {
    if ($cred -match "outlook|office|exchange|microsoft" -and $cred -notmatch "MicrosoftAccount") {
        Write-Host "Removing credential: $cred" -ForegroundColor Gray
        cmdkey /delete:$cred | Out-Null
    }
}

# Clear autodiscover XML cache files
Write-Host ""
Write-Host "Clearing autodiscover XML cache files..." -ForegroundColor Yellow

$cachePaths = @(
    "$env:LOCALAPPDATA\Microsoft\Outlook\16\AutoDiscover",
    "$env:LOCALAPPDATA\Microsoft\Outlook\15\AutoDiscover",
    "$env:LOCALAPPDATA\Microsoft\Outlook\14\AutoDiscover"
)

foreach ($path in $cachePaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Filter "*.xml" -ErrorAction SilentlyContinue | Remove-Item -Force
        Write-Host "Cleared XML files from: $path" -ForegroundColor Green
    }
}

# Clear SCP lookup cache from registry
Write-Host ""
Write-Host "Clearing SCP lookup cache..." -ForegroundColor Yellow
$scpPaths = Get-ChildItem "HKCU:\Software\Microsoft\Office\*\Outlook\AutoDiscover\SCP" -ErrorAction SilentlyContinue
foreach ($scp in $scpPaths) {
    Remove-Item $scp.PSPath -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "Cleanup completed!" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Start Outlook"
Write-Host "2. When prompted, enter your NEW domain credentials"
Write-Host "3. To test autodiscover:"
Write-Host "   - Hold Ctrl + right-click Outlook icon in system tray"
Write-Host "   - Select 'Test E-mail AutoConfiguration'"
Write-Host "   - Enter new email address and password"
Write-Host "   - Check only 'Use AutoDiscover'"
Write-Host "   - Click Test"
Write-Host ""
Write-Host "To run Outlook with clean autodiscover:" -ForegroundColor Cyan
Write-Host "outlook.exe /cleanautodiscoverdir"
Write-Host ""
Read-Host "Press Enter to exit"
