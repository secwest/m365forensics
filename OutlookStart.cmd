Remove-Item "$env:LOCALAPPDATA\Microsoft\Outlook\*.xml" -Force
reg delete HKCU\Software\Microsoft\Office\16.0\Outlook\AutoDiscover /f
reg delete HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles /f
reg delete "HKCU\Software\Microsoft\OneDrive\Accounts" /f
"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE" /profiles
