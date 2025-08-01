# PowerShell One-Liners for Clearing Autodiscover Cache (No Admin Required)

# Option 1: Complete cleanup and restart with clean autodiscover
Get-Process outlook -EA SilentlyContinue | Stop-Process -Force; Remove-Item "HKCU:\Software\Microsoft\Office\16.0\Outlook\AutoDiscover" -Recurse -Force -EA SilentlyContinue; Remove-Item "$env:LOCALAPPDATA\Microsoft\Outlook\16\AutoDiscover\*.xml" -Force -EA SilentlyContinue; Start-Process outlook.exe -ArgumentList "/cleanautodiscoverdir"

# Option 2: Just clear cache (don't start Outlook)
Get-Process outlook -EA SilentlyContinue | Stop-Process -Force; Remove-Item "HKCU:\Software\Microsoft\Office\16.0\Outlook\AutoDiscover" -Recurse -Force -EA SilentlyContinue; Remove-Item "$env:LOCALAPPDATA\Microsoft\Outlook\16\AutoDiscover\*.xml" -Force -EA SilentlyContinue

# Option 3: Clear and show what was removed
Get-Process outlook -EA SilentlyContinue | Stop-Process -Force; Write-Host "Registry entries removed:" -ForegroundColor Yellow; Remove-Item "HKCU:\Software\Microsoft\Office\16.0\Outlook\AutoDiscover" -Recurse -Force -Verbose -EA SilentlyContinue; Write-Host "`nXML files removed:" -ForegroundColor Yellow; Remove-Item "$env:LOCALAPPDATA\Microsoft\Outlook\16\AutoDiscover\*.xml" -Force -Verbose -EA SilentlyContinue

# Option 4: Interactive script
$outlook = Get-Process outlook -EA SilentlyContinue; if($outlook){Write-Host "Closing Outlook..." -ForegroundColor Yellow; $outlook | Stop-Process -Force}; Write-Host "Clearing autodiscover cache..." -ForegroundColor Yellow; Remove-Item "HKCU:\Software\Microsoft\Office\16.0\Outlook\AutoDiscover" -Recurse -Force -EA SilentlyContinue; Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Outlook" -Recurse -Filter "*.xml" | Where-Object {$_.DirectoryName -like "*AutoDiscover*"} | Remove-Item -Force; Write-Host "Cache cleared! Start Outlook with: outlook.exe /cleanautodiscoverdir" -ForegroundColor Green

# Option 5: Check what will be deleted first
Write-Host "Registry keys found:" -Foreground
