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
