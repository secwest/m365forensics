Remove-Item "$env:LOCALAPPDATA\Microsoft\Outlook\*.xml" -Force
reg delete HKCU\Software\Microsoft\Office\16.0\Outlook\AutoDiscover /f
reg delete HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles /f
reg delete "HKCU\Software\Microsoft\OneDrive\Accounts" /f
reg delete "HKCU\Software\Microsoft\OneDrive\Tenants" /f
reg delete "HKCU\Software\Microsoft\OneDrive\IdentityCache" /f
reg delete "HKCU\Software\Microsoft\OneDrive\Business1" /f
"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE" /signout
"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE" /resetnavpane /resetfolders
"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE" /profiles

# Repair Office installation
"C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeClickToRun.exe" scenario=Repair platform=x64 culture=en-us RepairType=QuickRepair

echo Resetting all Office/Outlook authentication...

:: Step 1: Kill everything
taskkill /F /IM outlook.exe 2>nul
taskkill /F /IM HxOutlook.exe 2>nul
taskkill /F /IM HxTsr.exe 2>nul
taskkill /F /IM OfficeClickToRun.exe 2>nul
timeout /t 2

:: Step 2: Clear system-wide auth
echo Y | powershell -Command "Get-ChildItem 'HKCU:\Software\Microsoft\Office\16.0\Common\Identity\Identities' | Remove-Item -Recurse -Force"
echo Y | powershell -Command "Remove-Item -Path '$env:LOCALAPPDATA\Microsoft\Office\16.0\Licensing' -Recurse -Force -ErrorAction SilentlyContinue"
echo Y | powershell -Command "Remove-Item -Path '$env:LOCALAPPDATA\Microsoft\Office\Licenses' -Recurse -Force -ErrorAction SilentlyContinue"

:: Step 3: Clear stored passwords from Windows
rundll32.exe keymgr.dll,KRShowKeyMgr
echo Please manually delete any Microsoft/Office entries, then press any key
pause

:: Step 4: Reset Office activation
cscript //NoLogo "C:\Program Files\Microsoft Office\Office16\ospp.vbs" /dstatus
cscript //NoLogo "C:\Program Files\Microsoft Office\Office16\ospp.vbs" /unpkey:all

:: Step 5: Start fresh
start outlook.exe /safe /nocustomize



********
# PowerShell script to reset without uninstalling
Stop-Process -Name outlook -Force -ErrorAction SilentlyContinue
Remove-Item "HKCU:\Software\Microsoft\Office\16.0\Outlook" -Recurse -Force
Remove-Item "$env:LOCALAPPDATA\Microsoft\Outlook\*" -Recurse -Force
Remove-Item "$env:APPDATA\Microsoft\Outlook\*.srs" -Force
