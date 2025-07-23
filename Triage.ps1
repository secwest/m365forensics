# INCIDENT RESPONSE TRIAGE SCRIPT - Active Attacker Collection
# Run as Administrator for full access

# Initialize incident response
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$incidentPath = "C:\incident_$timestamp"
New-Item -ItemType Directory -Path $incidentPath -Force | Out-Null
Start-Transcript -Path "$incidentPath\collection_log.txt"

Write-Host "=== INCIDENT RESPONSE COLLECTION STARTED: $timestamp ===" -ForegroundColor Yellow

# SECTION 1: ACTIVE NETWORK CONNECTIONS & REMOTE ACCESS
Write-Host "`n[1] COLLECTING NETWORK CONNECTIONS & REMOTE ACCESS DATA" -ForegroundColor Cyan

# Enhanced network connections with DNS resolution and process details
Get-NetTCPConnection | Where-Object {$_.State -eq "Established" -or $_.State -eq "Listen"} | 
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        $dns = try { [System.Net.Dns]::GetHostEntry($_.RemoteAddress).HostName } catch { $_.RemoteAddress }
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemoteDNS = $dns
            RemotePort = $_.RemotePort
            State = $_.State
            ProcessName = $proc.ProcessName
            ProcessId = $_.OwningProcess
            ProcessPath = $proc.Path
            ProcessStart = $proc.StartTime
            ProcessCmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.OwningProcess)").CommandLine
        }
    } | Export-Csv "$incidentPath\network_connections_enhanced.csv" -NoTypeInformation

# Comprehensive netstat output
netstat -anob > "$incidentPath\netstat_full.txt"
netstat -rn > "$incidentPath\routing_table.txt"

# Active sessions and logged-in users
@"
=== RDP SESSIONS ===
$(qwinsta)

=== LOGGED IN USERS ===
$(quser)

=== NET SESSIONS ===
$(net session 2>$null)

=== POWERSHELL REMOTING CONFIG ===
$(Get-WSManInstance -ResourceURI winrm/config/service -ErrorAction SilentlyContinue | Out-String)
$(Get-PSSessionConfiguration | Out-String)
"@ | Out-File "$incidentPath\active_sessions.txt"

# Check for remote access tools and suspicious services
$remoteTools = "TeamViewer|AnyDesk|Chrome Remote|LogMeIn|VNC|RDP|WinRM|SSH|ScreenConnect|Splashtop|GoToMyPC|Radmin|DameWare|pcAnywhere|Ammyy|UltraVNC|TightVNC|RealVNC"
Get-Service | Where-Object {$_.Name -match $remoteTools -or $_.DisplayName -match $remoteTools} | 
    Select-Object Name, DisplayName, Status, StartType, 
    @{Name="Path";Expression={(Get-WmiObject Win32_Service -Filter "Name='$($_.Name)'").PathName}} |
    Export-Csv "$incidentPath\remote_access_services.csv" -NoTypeInformation

# SECTION 2: PROCESS ANALYSIS
Write-Host "`n[2] COLLECTING PROCESS INFORMATION" -ForegroundColor Cyan

# All processes with enhanced details
Get-WmiObject Win32_Process | Select-Object Name, ProcessId, ParentProcessId, 
    @{Name="ParentName";Expression={
        $parent = Get-WmiObject Win32_Process -Filter "ProcessId=$($_.ParentProcessId)" -ErrorAction SilentlyContinue
        if($parent) { $parent.Name } else { "N/A" }
    }},
    CommandLine, CreationDate, ExecutablePath,
    @{Name="Owner";Expression={$_.GetOwner().User}},
    @{Name="OwnerDomain";Expression={$_.GetOwner().Domain}} |
    Export-Csv "$incidentPath\all_processes_detailed.csv" -NoTypeInformation

# Processes with network connections
$netProcs = (Get-NetTCPConnection).OwningProcess | Select-Object -Unique
Get-Process | Where-Object {$_.Id -in $netProcs} | 
    Select-Object ProcessName, Id, StartTime, Path, Company, Description,
    @{Name="Connections";Expression={
        (Get-NetTCPConnection -OwningProcess $_.Id | Measure-Object).Count
    }} | Export-Csv "$incidentPath\network_processes.csv" -NoTypeInformation

# Recently started processes (last 2 hours)
Get-Process | Where-Object {$_.StartTime -gt (Get-Date).AddHours(-2)} | 
    Select-Object ProcessName, Id, StartTime, Path, Company |
    Export-Csv "$incidentPath\recent_processes.csv" -NoTypeInformation

# Suspicious process indicators
$suspiciousProcs = Get-Process | Where-Object {
    $_.Path -match "\\AppData\\|\\Temp\\|\\Users\\Public\\" -or
    $_.ProcessName -match "^[a-z]{8}$|^[0-9]{4,}$" -or
    ($_.ProcessName -eq "svchost" -and $_.Path -notmatch "\\System32\\")
}
$suspiciousProcs | Select-Object ProcessName, Id, Path, StartTime | 
    Export-Csv "$incidentPath\suspicious_processes.csv" -NoTypeInformation

# SECTION 3: PERSISTENCE MECHANISMS
Write-Host "`n[3] CHECKING PERSISTENCE MECHANISMS" -ForegroundColor Cyan

# Scheduled tasks with details
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | 
    ForEach-Object {
        $task = $_
        $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            TaskName = $task.TaskName
            TaskPath = $task.TaskPath
            State = $task.State
            Author = $task.Author
            Description = $task.Description
            LastRunTime = $info.LastRunTime
            NextRunTime = $info.NextRunTime
            Actions = ($task.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "
        }
    } | Export-Csv "$incidentPath\scheduled_tasks_detailed.csv" -NoTypeInformation

# Registry persistence locations
$regPersistence = @{
    "HKLM_Run" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    "HKLM_RunOnce" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    "HKLM_RunServices" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices"
    "HKLM_RunServicesOnce" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    "HKCU_Run" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    "HKCU_RunOnce" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    "HKLM_Winlogon" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    "HKCU_Winlogon" = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    "HKLM_RunOnceEx" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
    "HKCU_RunOnceEx" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
}

$regResults = @()
foreach ($key in $regPersistence.GetEnumerator()) {
    $values = Get-ItemProperty $key.Value -ErrorAction SilentlyContinue
    if ($values) {
        $values.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            $regResults += [PSCustomObject]@{
                Location = $key.Name
                Name = $_.Name
                Value = $_.Value
            }
        }
    }
}
$regResults | Export-Csv "$incidentPath\registry_persistence.csv" -NoTypeInformation

# WMI persistence
Get-WmiObject -Namespace root\subscription -Class __EventFilter | 
    Export-Csv "$incidentPath\wmi_event_filters.csv" -NoTypeInformation
Get-WmiObject -Namespace root\subscription -Class __EventConsumer | 
    Export-Csv "$incidentPath\wmi_event_consumers.csv" -NoTypeInformation
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | 
    Export-Csv "$incidentPath\wmi_bindings.csv" -NoTypeInformation

# Startup folders
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -ErrorAction SilentlyContinue |
    Export-Csv "$incidentPath\all_users_startup.csv" -NoTypeInformation
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue |
    Export-Csv "$incidentPath\current_user_startup.csv" -NoTypeInformation

# SECTION 4: EVENT LOG ANALYSIS
Write-Host "`n[4] EXTRACTING EVENT LOGS" -ForegroundColor Cyan

# Security events - expanded ID list
$securityEvents = @{
    LogName = 'Security'
    ID = 1102,4624,4625,4634,4647,4648,4672,4688,4697,4698,4699,4700,4701,4702,4719,4720,4732,4738,4776,4778,4779,5140,5145,7045
    StartTime = (Get-Date).AddDays(-7)
}
Get-WinEvent -FilterHashtable $securityEvents -ErrorAction SilentlyContinue | 
    Select-Object TimeCreated, Id, Message, UserId |
    Export-Csv "$incidentPath\security_events_week.csv" -NoTypeInformation

# PowerShell logs - both classic and operational
Get-WinEvent -LogName "Windows PowerShell" -MaxEvents 1000 -ErrorAction SilentlyContinue |
    Export-Csv "$incidentPath\powershell_classic_logs.csv" -NoTypeInformation
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 1000 -ErrorAction SilentlyContinue |
    Export-Csv "$incidentPath\powershell_operational_logs.csv" -NoTypeInformation

# RDP and Terminal Services logs
$rdpLogs = @(
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
)
foreach ($log in $rdpLogs) {
    Get-WinEvent -LogName $log -MaxEvents 500 -ErrorAction SilentlyContinue |
        Export-Csv "$incidentPath\rdp_$($log.Replace('/','-')).csv" -NoTypeInformation
}

# Export full event logs
wevtutil epl Security "$incidentPath\Security.evtx"
wevtutil epl Application "$incidentPath\Application.evtx"
wevtutil epl System "$incidentPath\System.evtx"
wevtutil epl "Microsoft-Windows-PowerShell/Operational" "$incidentPath\PowerShell-Operational.evtx" 2>$null
wevtutil epl "Microsoft-Windows-Sysmon/Operational" "$incidentPath\Sysmon-Operational.evtx" 2>$null

# SECTION 5: SYSTEM STATE & ADDITIONAL CHECKS
Write-Host "`n[5] COLLECTING SYSTEM STATE INFORMATION" -ForegroundColor Cyan

# System information
systeminfo > "$incidentPath\systeminfo.txt"
Get-ComputerInfo | Export-Csv "$incidentPath\computer_info.csv" -NoTypeInformation

# Active ports and firewall rules
Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true -and $_.Direction -eq "Inbound"} |
    Select-Object DisplayName, Profile, Action, Protocol, LocalPort |
    Export-Csv "$incidentPath\firewall_rules_inbound.csv" -NoTypeInformation

# DNS cache (might show attacker domains)
Get-DnsClientCache | Export-Csv "$incidentPath\dns_cache.csv" -NoTypeInformation

# ARP cache
arp -a > "$incidentPath\arp_cache.txt"

# Currently loaded drivers (rootkit detection)
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, DriverDate, IsSigned |
    Export-Csv "$incidentPath\loaded_drivers.csv" -NoTypeInformation

# Shadow copies (in case attacker deleted them)
vssadmin list shadows > "$incidentPath\shadow_copies.txt" 2>&1

# SECTION 6: QUICK ANALYSIS SUMMARY
Write-Host "`n[6] GENERATING QUICK ANALYSIS SUMMARY" -ForegroundColor Cyan

$summary = @"
INCIDENT RESPONSE QUICK SUMMARY
Generated: $(Get-Date)

SUSPICIOUS INDICATORS FOUND:
- Suspicious Processes: $($suspiciousProcs.Count)
- Active Network Connections: $((Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}).Count)
- Remote Access Services: $((Get-Service | Where-Object {$_.Name -match $remoteTools}).Count)
- Recent Logins: Check security_events_week.csv for details

RECOMMENDED IMMEDIATE ACTIONS:
1. Review network_connections_enhanced.csv for unknown external IPs
2. Check suspicious_processes.csv for potential malware
3. Examine scheduled_tasks_detailed.csv for persistence
4. Analyze security_events_week.csv for lateral movement

Files collected to: $incidentPath
"@

$summary | Out-File "$incidentPath\SUMMARY.txt"
Write-Host $summary -ForegroundColor Green

Stop-Transcript
Write-Host "`n=== COLLECTION COMPLETE ===" -ForegroundColor Yellow
Write-Host "Data saved to: $incidentPath" -ForegroundColor Green
Write-Host "Recommend immediate network isolation after reviewing active connections!" -ForegroundColor Red
