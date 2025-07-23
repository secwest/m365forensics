# INCIDENT RESPONSE TRIAGE SCRIPT - ROBUST VERSION
# Run as Administrator: powershell -ExecutionPolicy Bypass -File .\Triage.ps1

param(
    [switch]$SkipDNS = $true,  # Skip DNS resolution by default for speed
    [switch]$Quick = $false,    # Quick mode - essential data only
    [int]$TimeoutSeconds = 30   # Timeout for long operations
)

# Initialize
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$incidentPath = "C:\incident_$timestamp"

# Create incident folder
try {
    New-Item -ItemType Directory -Path $incidentPath -Force | Out-Null
    Start-Transcript -Path "$incidentPath\collection_log.txt" -Force
} catch {
    Write-Host "ERROR: Cannot create incident folder. Exiting." -ForegroundColor Red
    exit 1
}

Write-Host "=== INCIDENT RESPONSE COLLECTION STARTED: $timestamp ===" -ForegroundColor Yellow
Write-Host "Output directory: $incidentPath" -ForegroundColor Cyan
if ($Quick) { Write-Host "Running in QUICK mode" -ForegroundColor Yellow }

# Progress tracking function
function Show-Progress {
    param($Activity, $Status)
    Write-Host "[$([DateTime]::Now.ToString('HH:mm:ss'))] $Activity - $Status" -ForegroundColor Green
}

# SECTION 1: CRITICAL - ACTIVE CONNECTIONS & SUSPICIOUS PROCESSES
Show-Progress "SECTION 1" "Collecting active network connections"

try {
    # Fast network collection without DNS
    $connections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established" -or $_.State -eq "Listen"}
    $connections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
        Export-Csv "$incidentPath\network_connections_fast.csv" -NoTypeInformation
    
    Write-Host "  - Found $($connections.Count) active connections" -ForegroundColor Gray
    
    # Get process details for network connections
    $netPids = $connections.OwningProcess | Select-Object -Unique
    $networkProcesses = @()
    
    foreach ($pid in $netPids) {
        $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
        if ($proc) {
            $wmiProc = Get-WmiObject Win32_Process -Filter "ProcessId=$pid" -ErrorAction SilentlyContinue
            $networkProcesses += [PSCustomObject]@{
                ProcessName = $proc.ProcessName
                ProcessId = $pid
                Path = $proc.Path
                StartTime = $proc.StartTime
                CommandLine = $wmiProc.CommandLine
                ParentProcessId = $wmiProc.ParentProcessId
                ConnectionCount = ($connections | Where-Object {$_.OwningProcess -eq $pid}).Count
            }
        }
    }
    
    $networkProcesses | Export-Csv "$incidentPath\network_processes.csv" -NoTypeInformation
    Write-Host "  - Identified $($networkProcesses.Count) processes with network activity" -ForegroundColor Gray
    
    # Check specific suspicious PIDs if provided in earlier analysis
    $suspiciousPids = @(6640, 11492, 2072, 5300)  # From your netstat
    Show-Progress "SECTION 1" "Checking known suspicious PIDs"
    
    $suspiciousDetails = @()
    foreach ($pid in $suspiciousPids) {
        $proc = Get-WmiObject Win32_Process -Filter "ProcessId=$pid" -ErrorAction SilentlyContinue
        if ($proc) {
            $suspiciousDetails += $proc | Select-Object ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId, @{N='CreationDate';E={$_.ConvertToDateTime($_.CreationDate)}}
            Write-Host "  - Found suspicious PID $pid : $($proc.Name)" -ForegroundColor Yellow
        }
    }
    if ($suspiciousDetails) {
        $suspiciousDetails | Export-Csv "$incidentPath\suspicious_pids_detailed.csv" -NoTypeInformation
    }
    
} catch {
    Write-Host "ERROR in network collection: $_" -ForegroundColor Red
}

# Quick netstat for established connections
Show-Progress "SECTION 1" "Running netstat for established connections"
try {
    $netstatJob = Start-Job -ScriptBlock { netstat -ano | Select-String "ESTABLISHED|LISTEN" }
    $result = Wait-Job $netstatJob -Timeout $TimeoutSeconds
    if ($result) {
        Receive-Job $netstatJob | Out-File "$incidentPath\netstat_established.txt"
    } else {
        Stop-Job $netstatJob -Force
        "Netstat timed out after $TimeoutSeconds seconds" | Out-File "$incidentPath\netstat_established.txt"
    }
    Remove-Job $netstatJob -Force
} catch {
    Write-Host "WARNING: Netstat failed" -ForegroundColor Yellow
}

# SECTION 2: REMOTE ACCESS & SESSIONS
Show-Progress "SECTION 2" "Checking remote access and sessions"

try {
    $sessionInfo = @"
=== COLLECTION TIME: $(Get-Date) ===

=== RDP SESSIONS (qwinsta) ===
$(qwinsta 2>&1)

=== LOGGED IN USERS (quser) ===
$(quser 2>&1)

=== NETWORK SESSIONS (net session) ===
$(net session 2>&1)

=== NETWORK SHARES (net share) ===
$(net share 2>&1)

=== REMOTE CONNECTIONS (net use) ===
$(net use 2>&1)
"@
    $sessionInfo | Out-File "$incidentPath\remote_sessions.txt"
    
    # Check for remote access tools
    Show-Progress "SECTION 2" "Scanning for remote access tools"
    $remoteTools = "TeamViewer|AnyDesk|Chrome.*Remote|LogMeIn|VNC|WinRM|SSH|ScreenConnect|Splashtop|GoToMyPC|Radmin|DameWare|pcAnywhere|Ammyy|UltraVNC|TightVNC|RealVNC|RemotePC|Zoho|Supremo|ISL|ShowMyPC|BeAnywhere|Mikogo|Bomgar|ConnectWise|N-able|Datto|Kaseya|AutoTask|Mesh.*Central|TakeControl|GoToAssist|WebEx|Join\.me|RemoteUtilities|NoMachine|AeroAdmin|Iperius|Thinfinity|TSplus|2X|Parallels|Citrix|VMware.*Horizon"
    
    $remoteServices = Get-Service | Where-Object {$_.Name -match $remoteTools -or $_.DisplayName -match $remoteTools}
    if ($remoteServices) {
        $remoteServices | Select-Object Name, DisplayName, Status, StartType | 
            Export-Csv "$incidentPath\remote_access_services.csv" -NoTypeInformation
        Write-Host "  - Found $($remoteServices.Count) remote access services" -ForegroundColor Yellow
    }
    
    $remoteProcs = Get-Process | Where-Object {$_.ProcessName -match $remoteTools -or $_.Description -match $remoteTools}
    if ($remoteProcs) {
        $remoteProcs | Select-Object ProcessName, Id, Path, Description |
            Export-Csv "$incidentPath\remote_access_processes.csv" -NoTypeInformation
        Write-Host "  - Found $($remoteProcs.Count) remote access processes" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "WARNING: Session collection incomplete: $_" -ForegroundColor Yellow
}

# SECTION 3: PROCESS ANALYSIS
if (!$Quick) {
    Show-Progress "SECTION 3" "Analyzing all processes"
    
    try {
        # All processes with details
        $allProcesses = Get-WmiObject Win32_Process | Select-Object Name, ProcessId, ParentProcessId, 
            CommandLine, ExecutablePath,
            @{N='CreationDate';E={if($_.CreationDate){$_.ConvertToDateTime($_.CreationDate)}else{'Unknown'}}},
            @{N='Owner';E={$_.GetOwner().User}},
            @{N='Domain';E={$_.GetOwner().Domain}}
        
        $allProcesses | Export-Csv "$incidentPath\all_processes.csv" -NoTypeInformation
        Write-Host "  - Collected $($allProcesses.Count) total processes" -ForegroundColor Gray
        
        # Recent processes (last 2 hours)
        $recentTime = (Get-Date).AddHours(-2)
        $recentProcs = Get-Process | Where-Object {$_.StartTime -gt $recentTime}
        if ($recentProcs) {
            $recentProcs | Select-Object ProcessName, Id, StartTime, Path, Company |
                Export-Csv "$incidentPath\recent_processes_2hr.csv" -NoTypeInformation
            Write-Host "  - Found $($recentProcs.Count) processes started in last 2 hours" -ForegroundColor Gray
        }
        
        # Suspicious locations
        Show-Progress "SECTION 3" "Checking suspicious process locations"
        $suspiciousLocs = Get-Process | Where-Object {
            $_.Path -match "\\AppData\\|\\Temp\\|\\Users\\Public\\|\\ProgramData\\|\\Windows\\Temp\\|\\Recycle|\\Users\\[^\\]+\\[^\\]+$" -and
            $_.Path -notmatch "\\AppData\\Local\\Microsoft\\|\\AppData\\Local\\Google\\|\\AppData\\Roaming\\Microsoft\\"
        }
        if ($suspiciousLocs) {
            $suspiciousLocs | Select-Object ProcessName, Id, Path, StartTime |
                Export-Csv "$incidentPath\suspicious_locations.csv" -NoTypeInformation
            Write-Host "  - Found $($suspiciousLocs.Count) processes in suspicious locations" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "WARNING: Process analysis incomplete: $_" -ForegroundColor Yellow
    }
}

# SECTION 4: PERSISTENCE MECHANISMS
Show-Progress "SECTION 4" "Checking persistence mechanisms"

try {
    # Scheduled tasks
    $tasks = Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}
    $taskDetails = @()
    
    foreach ($task in $tasks) {
        try {
            $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            $taskDetails += [PSCustomObject]@{
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                State = $task.State
                Author = $task.Author
                LastRunTime = $info.LastRunTime
                NextRunTime = $info.NextRunTime
                Actions = ($task.Actions.Execute -join "; ")
                Arguments = ($task.Actions.Arguments -join "; ")
            }
        } catch { }
    }
    
    $taskDetails | Export-Csv "$incidentPath\scheduled_tasks.csv" -NoTypeInformation
    Write-Host "  - Found $($taskDetails.Count) active scheduled tasks" -ForegroundColor Gray
    
    # Registry persistence - simplified
    Show-Progress "SECTION 4" "Checking registry persistence"
    $regResults = @()
    $regKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($key in $regKeys) {
        try {
            $values = Get-ItemProperty $key -ErrorAction SilentlyContinue
            if ($values) {
                $values.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                    $regResults += "$key\$($_.Name) = $($_.Value)"
                }
            }
        } catch { }
    }
    
    $regResults | Out-File "$incidentPath\registry_autoruns.txt"
    Write-Host "  - Found $($regResults.Count) registry autorun entries" -ForegroundColor Gray
    
    # WMI Persistence check
    try {
        $wmiFilters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
        if ($wmiFilters) {
            $wmiFilters | Export-Csv "$incidentPath\wmi_persistence.csv" -NoTypeInformation
            Write-Host "  - Found $($wmiFilters.Count) WMI event filters" -ForegroundColor Yellow
        }
    } catch { }
    
} catch {
    Write-Host "WARNING: Persistence check incomplete: $_" -ForegroundColor Yellow
}

# SECTION 5: EVENT LOGS
if (!$Quick) {
    Show-Progress "SECTION 5" "Collecting event logs"
    
    try {
        # Key security events
        $secEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4624,4625,4648,4672,4688,4720,4732,4776,7045
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 1000 -ErrorAction SilentlyContinue
        
        if ($secEvents) {
            $secEvents | Select-Object TimeCreated, Id, Message |
                Export-Csv "$incidentPath\security_events_24hr.csv" -NoTypeInformation
            Write-Host "  - Collected $($secEvents.Count) security events" -ForegroundColor Gray
        }
        
        # Export full logs
        Show-Progress "SECTION 5" "Exporting full event logs"
        $logs = @("Security", "System", "Application")
        foreach ($log in $logs) {
            $exportJob = Start-Job -ScriptBlock {
                param($log, $path)
                wevtutil epl $log "$path\$log.evtx" 2>$null
            } -ArgumentList $log, $incidentPath
            
            $result = Wait-Job $exportJob -Timeout 30
            if (!$result) {
                Stop-Job $exportJob -Force
                Write-Host "  - WARNING: $log log export timed out" -ForegroundColor Yellow
            }
            Remove-Job $exportJob -Force
        }
        
    } catch {
        Write-Host "WARNING: Event log collection incomplete: $_" -ForegroundColor Yellow
    }
}

# SECTION 6: SYSTEM STATE
Show-Progress "SECTION 6" "Collecting system state"

try {
    # Basic system info
    systeminfo | Select-Object -First 50 | Out-File "$incidentPath\systeminfo.txt"
    
    # Network configuration
    ipconfig /all > "$incidentPath\ipconfig.txt" 2>&1
    route print > "$incidentPath\routes.txt" 2>&1
    arp -a > "$incidentPath\arp_cache.txt" 2>&1
    
    # DNS cache
    Get-DnsClientCache | Export-Csv "$incidentPath\dns_cache.csv" -NoTypeInformation
    
    # Firewall rules
    Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true -and $_.Direction -eq "Inbound"} |
        Select-Object DisplayName, Action, Protocol, 
        @{N='LocalPort';E={($_ | Get-NetFirewallPortFilter).LocalPort}} |
        Export-Csv "$incidentPath\firewall_rules.csv" -NoTypeInformation
    
    # Currently open files/handles (useful for ransomware detection)
    try {
        handle.exe -a -nobanner 2>$null | Out-File "$incidentPath\open_handles.txt"
    } catch {
        openfiles /query /fo csv 2>$null | Out-File "$incidentPath\open_files.csv"
    }
    
} catch {
    Write-Host "WARNING: System state collection incomplete: $_" -ForegroundColor Yellow
}

# SECTION 7: QUICK ANALYSIS & SUMMARY
Show-Progress "ANALYSIS" "Generating summary"

try {
    # Analyze collected data
    $establishedConns = Import-Csv "$incidentPath\network_connections_fast.csv" -ErrorAction SilentlyContinue | 
        Where-Object {$_.State -eq "Established"}
    $suspiciousLocs = Import-Csv "$incidentPath\suspicious_locations.csv" -ErrorAction SilentlyContinue
    $remoteTools = Import-Csv "$incidentPath\remote_access_services.csv" -ErrorAction SilentlyContinue
    
    # Look for IOCs
    $iocFindings = @()
    
    # Check for common backdoor ports
    $backdoorPorts = @(4444,4445,5555,6666,7777,8888,9999,31337,12345,54321)
    $suspiciousPorts = $establishedConns | Where-Object {$_.LocalPort -in $backdoorPorts -or $_.RemotePort -in $backdoorPorts}
    if ($suspiciousPorts) {
        $iocFindings += "CRITICAL: Found connections on known backdoor ports"
        $suspiciousPorts | Export-Csv "$incidentPath\ALERT_backdoor_ports.csv" -NoTypeInformation
    }
    
    # Check for PowerShell listeners
    $psListeners = $networkProcesses | Where-Object {$_.ProcessName -eq "powershell" -or $_.ProcessName -eq "pwsh"}
    if ($psListeners) {
        $iocFindings += "WARNING: PowerShell processes with network connections"
        $psListeners | Export-Csv "$incidentPath\ALERT_powershell_network.csv" -NoTypeInformation
    }
    
    # Generate summary
    $summary = @"
INCIDENT RESPONSE SUMMARY
=========================
Generated: $(Get-Date)
Hostname: $env:COMPUTERNAME
User: $env:USERDOMAIN\$env:USERNAME

QUICK STATISTICS:
- Active Network Connections: $(if($establishedConns){$establishedConns.Count}else{0})
- Total Processes: $(if($allProcesses){$allProcesses.Count}else{'Not collected'})
- Processes in Suspicious Locations: $(if($suspiciousLocs){$suspiciousLocs.Count}else{0})
- Remote Access Tools Found: $(if($remoteTools){$remoteTools.Count}else{0})
- Active Scheduled Tasks: $(if($taskDetails){$taskDetails.Count}else{0})

SUSPECTED MALICIOUS PIDs INVESTIGATED:
$(if($suspiciousDetails){
    $suspiciousDetails | ForEach-Object {
        "- PID $($_.ProcessId): $($_.Name) [$($_.ExecutablePath)]"
    } | Out-String
}else{"- None found from list: 6640, 11492, 2072, 5300"})

IOC FINDINGS:
$(if($iocFindings){$iocFindings -join "`n"}else{"- No automatic IOCs detected"})

RECOMMENDED ACTIONS:
1. Review network_connections_fast.csv for unknown IPs
2. Investigate any processes in suspicious_locations.csv
3. Check scheduled_tasks.csv for recent additions
4. Examine remote_access_* files for unauthorized tools
5. Review ALERT_* files for critical findings

All data saved to: $incidentPath
"@
    
    $summary | Out-File "$incidentPath\SUMMARY.txt"
    Write-Host "`n$summary" -ForegroundColor Cyan
    
} catch {
    Write-Host "WARNING: Summary generation incomplete" -ForegroundColor Yellow
}

# Cleanup
Stop-Transcript
Write-Host "`n=== COLLECTION COMPLETE ===" -ForegroundColor Green
Write-Host "Data location: $incidentPath" -ForegroundColor Green
Write-Host "`nRECOMMENDATION: If remote access confirmed, disconnect network immediately!" -ForegroundColor Red

# Create a quick ZIP if possible
try {
    Compress-Archive -Path "$incidentPath\*" -DestinationPath "$incidentPath.zip" -Force
    Write-Host "Archive created: $incidentPath.zip" -ForegroundColor Green
} catch {
    Write-Host "Could not create ZIP archive" -ForegroundColor Yellow
}
