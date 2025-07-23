# GENERIC INCIDENT RESPONSE TRIAGE SCRIPT v3.2
# Run as Administrator: powershell -ExecutionPolicy Bypass -File .\Triage.ps1

param(
    [switch]$Quick = $false,
    [switch]$Deep = $false,
    [int]$TimeoutSeconds = 30,
    [int]$DaysBack = 7,
    [array]$TargetPIDs = @(),  # Optional: -TargetPIDs 6640,11492,2072,5300
    [switch]$SkipMemory = $false,
    [switch]$SkipFileSystem = $false
)

# Initialize
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"  # Disable progress bars for speed
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$incidentPath = "C:\incident_$timestamp"
$global:alertCount = 0
$global:findings = @()

# Color output helper
function Write-ColorOutput {
    param($Message, $Type = "Info", $LogOnly = $false)
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    
    if (!$LogOnly) {
        switch ($Type) {
            "Success" { Write-Host $logMessage -ForegroundColor Green }
            "Error" { Write-Host $logMessage -ForegroundColor Red }
            "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
            "Alert" { Write-Host $logMessage -ForegroundColor Red -BackgroundColor Yellow }
            "Info" { Write-Host $logMessage -ForegroundColor Cyan }
            "Progress" { Write-Host $logMessage -ForegroundColor Gray }
            default { Write-Host $logMessage }
        }
    }
    
    # Always log to file
    $logMessage | Out-File "$incidentPath\console_output.log" -Append -Force
}

# Create folder structure
try {
    $folders = @("$incidentPath", "$incidentPath\Network", "$incidentPath\Processes", 
                 "$incidentPath\Persistence", "$incidentPath\Logs", "$incidentPath\System", 
                 "$incidentPath\ALERTS", "$incidentPath\Memory", "$incidentPath\FileSystem")
    $folders | ForEach-Object { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
    Start-Transcript -Path "$incidentPath\collection_transcript.txt" -Force | Out-Null
} catch {
    Write-Host "ERROR: Cannot create incident folder. Exiting." -ForegroundColor Red
    exit 1
}

Write-ColorOutput "=== INCIDENT RESPONSE COLLECTION STARTED ===" "Success"
Write-ColorOutput "Output directory: $incidentPath" "Info"
Write-ColorOutput "Mode: $(if($Quick){'Quick'}elseif($Deep){'Deep'}else{'Standard'})" "Info"
if ($TargetPIDs) { Write-ColorOutput "Target PIDs to investigate: $($TargetPIDs -join ', ')" "Info" }

# SECTION 1: FAST NETWORK ANALYSIS
Write-ColorOutput "`n[NETWORK ANALYSIS]" "Progress"

try {
    # Get connections without hanging
    Write-ColorOutput "Collecting network connections..." "Progress"
    $connections = Get-NetTCPConnection
    $established = @($connections | Where-Object {$_.State -eq "Established"})
    $listening = @($connections | Where-Object {$_.State -eq "Listen"})
    
    Write-ColorOutput "Active connections: Total=$($connections.Count), Established=$($established.Count), Listening=$($listening.Count)" "Info"
    
    # Export basic connections first
    $connections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
        Export-Csv "$incidentPath\Network\connections_basic.csv" -NoTypeInformation
    
    # Check for suspicious ports
    $suspiciousPorts = @{
        "4444"="Metasploit"; "4445"="Backdoor"; "5555"="Backdoor"; 
        "6666"="Backdoor"; "7777"="Backdoor"; "8888"="Backdoor";
        "9999"="Backdoor"; "31337"="BackOrifice"; "12345"="NetBus"
    }
    
    $alerts = @()
    foreach ($conn in $established) {
        foreach ($port in $suspiciousPorts.Keys) {
            if ($conn.LocalPort -eq $port -or $conn.RemotePort -eq $port) {
                $alert = "SUSPICIOUS PORT: $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) [$($suspiciousPorts[$port])]"
                Write-ColorOutput $alert "Alert"
                $alerts += $alert
                $global:alertCount++
            }
        }
    }
    
    # Quick process mapping for network connections
    Write-ColorOutput "Mapping network processes..." "Progress"
    $netProcesses = @{}
    $established | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object {
        if ($_ -gt 0) {
            $proc = Get-Process -Id $_ -ErrorAction SilentlyContinue
            if ($proc) {
                $netProcesses[$_] = @{
                    Name = $proc.ProcessName
                    Path = $proc.Path
                    Company = $proc.Company
                }
            }
        }
    }
    
    # Show top talkers
    $topTalkers = $established | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 5
    Write-ColorOutput "Top network processes:" "Info"
    $topTalkers | ForEach-Object {
        $procInfo = $netProcesses[$_.Name]
        if ($procInfo) {
            Write-ColorOutput "  - $($procInfo.Name) (PID: $($_.Name)): $($_.Count) connections" "Info"
        }
    }
    
    # External IPs
    $externalIPs = $established | Where-Object {
        $_.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fe80:)"
    } | Select-Object -ExpandProperty RemoteAddress -Unique
    
    if ($externalIPs) {
        Write-ColorOutput "External IPs connected: $($externalIPs.Count)" "Warning"
        $externalIPs | Select-Object -First 10 | ForEach-Object {
            Write-ColorOutput "  - $_" "Info"
        }
        $externalIPs | Out-File "$incidentPath\Network\external_ips.txt"
    }
    
    # Run netstat in background
    Start-Job -Name "Netstat" -ScriptBlock {
        param($path)
        netstat -anob > "$path\Network\netstat_full.txt" 2>&1
    } -ArgumentList $incidentPath | Out-Null
    
} catch {
    Write-ColorOutput "Error in network analysis: $_" "Error"
}

# SECTION 2: PROCESS ANALYSIS (OPTIMIZED)
Write-ColorOutput "`n[PROCESS ANALYSIS]" "Progress"

try {
    Write-ColorOutput "Getting process list..." "Progress"
    
    # Get basic process info first (fast)
    $processes = Get-Process | Select-Object Id, ProcessName, Path, Company, StartTime, CPU, WS
    Write-ColorOutput "Total processes: $($processes.Count)" "Info"
    
    # Quick suspicious checks
    $suspiciousLocs = $processes | Where-Object {
        $_.Path -match "\\Temp\\|\\AppData\\Local\\Temp\\|\\Users\\Public\\|\\ProgramData\\" -and
        $_.Path -notmatch "Microsoft|Windows|Google|Mozilla"
    }
    
    if ($suspiciousLocs) {
        Write-ColorOutput "Processes in suspicious locations: $($suspiciousLocs.Count)" "Alert"
        $suspiciousLocs | Select-Object -First 5 | ForEach-Object {
            Write-ColorOutput "  - $($_.ProcessName) from $($_.Path)" "Warning"
        }
        $suspiciousLocs | Export-Csv "$incidentPath\ALERTS\suspicious_process_locations.csv" -NoTypeInformation
        $global:alertCount += $suspiciousLocs.Count
    }
    
    # Check for specific PIDs if provided
    if ($TargetPIDs) {
        Write-ColorOutput "Checking target PIDs: $($TargetPIDs -join ', ')" "Progress"
        foreach ($targetPid in $TargetPIDs) {
            $proc = $processes | Where-Object {$_.Id -eq $targetPid}
            if ($proc) {
                Write-ColorOutput ("  - Found PID " + $targetPid + ": " + $proc.ProcessName + " [" + $proc.Path + "]") "Alert"
                $global:alertCount++
                
                # Get detailed info for target PIDs
                $wmiProc = Get-WmiObject Win32_Process -Filter "ProcessId=$targetPid" -ErrorAction SilentlyContinue
                if ($wmiProc) {
                    $wmiProc | Select-Object ProcessId, Name, CommandLine, ParentProcessId, CreationDate |
                        Export-Csv "$incidentPath\ALERTS\target_pid_$targetPid.csv" -NoTypeInformation
                }
            } else {
                Write-ColorOutput ("  - PID " + $targetPid + " not found") "Info"
            }
        }
    }
    
    # Export process list
    $processes | Export-Csv "$incidentPath\Processes\process_list_basic.csv" -NoTypeInformation
    
    # Check for PowerShell/CMD with network
    $shells = $processes | Where-Object {
        $_.ProcessName -match "powershell|cmd|wscript|cscript" -and
        $_.Id -in $established.OwningProcess
    }
    
    if ($shells) {
        Write-ColorOutput "Command shells with network connections: $($shells.Count)" "Alert"
        $shells | ForEach-Object {
            Write-ColorOutput "  - $($_.ProcessName) (PID: $($_.Id))" "Warning"
        }
        $shells | Export-Csv "$incidentPath\ALERTS\shells_with_network.csv" -NoTypeInformation
        $global:alertCount += $shells.Count
    }
    
    # Check for suspicious process names
    $suspiciousNames = $processes | Where-Object {
        $_.ProcessName -match "^[a-z]{8}$|^[0-9]{4,}$" -or
        ($_.ProcessName -eq "svchost" -and $_.Path -and $_.Path -notmatch "\\System32\\|\\SysWOW64\\")
    }
    
    if ($suspiciousNames) {
        Write-ColorOutput "Suspicious process names: $($suspiciousNames.Count)" "Alert"
        $suspiciousNames | Select-Object -First 3 | ForEach-Object {
            Write-ColorOutput "  - $($_.ProcessName) (PID: $($_.Id))" "Warning"
        }
        $suspiciousNames | Export-Csv "$incidentPath\ALERTS\suspicious_process_names.csv" -NoTypeInformation
        $global:alertCount += $suspiciousNames.Count
    }
    
} catch {
    Write-ColorOutput "Error in process analysis: $_" "Error"
}

# SECTION 3: REMOTE ACCESS DETECTION
Write-ColorOutput "`n[REMOTE ACCESS DETECTION]" "Progress"

try {
    # Quick check for common remote tools
    $remoteTools = "TeamViewer|AnyDesk|Chrome.*Remote|LogMeIn|VNC|ScreenConnect|Ammyy|Splashtop|GoToMyPC|RemotePC|Radmin|DameWare|UltraViewer"
    
    $remoteProcs = $processes | Where-Object {$_.ProcessName -match $remoteTools}
    $remoteSvcs = Get-Service | Where-Object {$_.Name -match $remoteTools -or $_.DisplayName -match $remoteTools}
    
    if ($remoteProcs -or $remoteSvcs) {
        Write-ColorOutput "Remote access tools detected!" "Alert"
        if ($remoteProcs) {
            $remoteProcs | ForEach-Object {
                Write-ColorOutput "  - Process: $($_.ProcessName)" "Warning"
            }
            $remoteProcs | Export-Csv "$incidentPath\ALERTS\remote_access_processes.csv" -NoTypeInformation
        }
        if ($remoteSvcs) {
            $remoteSvcs | Where-Object {$_.Status -eq "Running"} | ForEach-Object {
                Write-ColorOutput "  - Service: $($_.DisplayName) [$($_.Status)]" "Warning"
            }
            $remoteSvcs | Export-Csv "$incidentPath\ALERTS\remote_access_services.csv" -NoTypeInformation
        }
        $global:alertCount++
    }
    
    # Check active sessions
    Write-ColorOutput "Checking active sessions..." "Progress"
    $sessions = qwinsta 2>&1
    $activeUsers = ($sessions | Select-String "Active" | Measure-Object).Count
    Write-ColorOutput "Active sessions: $activeUsers" "Info"
    
    if ($activeUsers -gt 1) {
        Write-ColorOutput "Multiple active sessions detected!" "Warning"
        $global:alertCount++
    }
    
    $sessions | Out-File "$incidentPath\Network\active_sessions.txt"
    quser 2>&1 | Out-File "$incidentPath\Network\logged_users.txt"
    
    # Check RDP status
    $rdpStatus = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue
    if ($rdpStatus -and $rdpStatus.fDenyTSConnections -eq 0) {
        Write-ColorOutput "RDP is ENABLED" "Warning"
        $global:findings += "RDP_ENABLED"
        "RDP is enabled (fDenyTSConnections = 0)" | Out-File "$incidentPath\ALERTS\rdp_enabled.txt"
    }
    
} catch {
    Write-ColorOutput "Error in remote access detection: $_" "Error"
}

# SECTION 4: PERSISTENCE QUICK CHECK
Write-ColorOutput "`n[PERSISTENCE MECHANISMS]" "Progress"

try {
    # Registry Run keys (fast check)
    Write-ColorOutput "Checking common persistence locations..." "Progress"
    $runKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    $autorunEntries = @()
    $autorunCount = 0
    
    foreach ($key in $runKeys) {
        $values = Get-ItemProperty $key -ErrorAction SilentlyContinue
        if ($values) {
            $props = $values.PSObject.Properties | Where-Object {$_.Name -notmatch "^PS"}
            $autorunCount += $props.Count
            
            $props | ForEach-Object {
                $autorunEntries += [PSCustomObject]@{
                    Location = $key
                    Name = $_.Name
                    Value = $_.Value
                }
                
                # Show first few in console
                if ($autorunEntries.Count -le 5) {
                    $displayValue = if ($_.Value.Length -gt 50) { $_.Value.Substring(0, 50) + "..." } else { $_.Value }
                    Write-ColorOutput "  - $($_.Name): $displayValue" "Info"
                }
            }
        }
    }
    
    Write-ColorOutput "Registry autoruns found: $autorunCount" "Info"
    if ($autorunEntries) {
        $autorunEntries | Export-Csv "$incidentPath\Persistence\registry_autoruns.csv" -NoTypeInformation
    }
    
    # Recent scheduled tasks
    Write-ColorOutput "Checking scheduled tasks..." "Progress"
    $recentTasks = @()
    $allTasks = Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}
    
    foreach ($task in $allTasks) {
        if ($task.Date -and ([DateTime]$task.Date -gt (Get-Date).AddDays(-30))) {
            $recentTasks += $task
        }
    }
    
    if ($recentTasks) {
        Write-ColorOutput "Recently created tasks (30 days): $($recentTasks.Count)" "Warning"
        $recentTasks | Select-Object -First 3 | ForEach-Object {
            Write-ColorOutput "  - $($_.TaskName) [$($_.TaskPath)]" "Info"
        }
        $recentTasks | Select-Object TaskName, TaskPath, State, Author, Date |
            Export-Csv "$incidentPath\ALERTS\recent_scheduled_tasks.csv" -NoTypeInformation
        $global:alertCount++
    }
    
    # Quick service check
    Write-ColorOutput "Checking for suspicious services..." "Progress"
    $suspiciousSvc = Get-WmiObject Win32_Service | Where-Object {
        $_.PathName -match "powershell|cmd\.exe|wscript|cscript|rundll32.*\.txt|rundll32.*\.dat" -or
        $_.PathName -match "\\Users\\|\\Temp\\|\\AppData\\" -or
        $_.StartName -notmatch "LocalSystem|LocalService|NetworkService|NT AUTHORITY"
    }
    
    if ($suspiciousSvc) {
        Write-ColorOutput "Suspicious services: $($suspiciousSvc.Count)" "Alert"
        $suspiciousSvc | Select-Object -First 3 | ForEach-Object {
            Write-ColorOutput "  - $($_.Name): $($_.PathName)" "Warning"
        }
        $suspiciousSvc | Select-Object Name, DisplayName, PathName, StartMode, State, StartName |
            Export-Csv "$incidentPath\ALERTS\suspicious_services.csv" -NoTypeInformation
        $global:alertCount += $suspiciousSvc.Count
    }
    
} catch {
    Write-ColorOutput "Error in persistence check: $_" "Error"
}

# SECTION 5: EVENT LOG QUICK ANALYSIS
if (!$Quick) {
    Write-ColorOutput "`n[EVENT LOG ANALYSIS]" "Progress"
    
    try {
        # Last 24h key events
        Write-ColorOutput "Checking recent security events..." "Progress"
        $secEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4624,4625,4720,4732,7045,1102,4688
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 200 -ErrorAction SilentlyContinue
        
        if ($secEvents) {
            $logonEvents = @($secEvents | Where-Object {$_.Id -eq 4624})
            $failedLogons = @($secEvents | Where-Object {$_.Id -eq 4625})
            $newServices = @($secEvents | Where-Object {$_.Id -eq 7045})
            $processCreation = @($secEvents | Where-Object {$_.Id -eq 4688})
            
            Write-ColorOutput "Last 24h events: Logons=$($logonEvents.Count), Failed=$($failedLogons.Count), New Services=$($newServices.Count), Processes=$($processCreation.Count)" "Info"
            
            if ($failedLogons.Count -gt 10) {
                Write-ColorOutput "High number of failed logons!" "Alert"
                $global:alertCount++
                
                # Group by account
                $failedAccounts = $failedLogons | Group-Object {$_.Properties[5].Value} | 
                    Sort-Object Count -Descending | Select-Object -First 5
                Write-ColorOutput "  Top failed accounts:" "Warning"
                $failedAccounts | ForEach-Object {
                    Write-ColorOutput "    - $($_.Name): $($_.Count) attempts" "Info"
                }
            }
            
            if ($newServices) {
                Write-ColorOutput "New services installed:" "Warning"
                $newServices | Select-Object -First 3 | ForEach-Object {
                    Write-ColorOutput "  - $($_.TimeCreated): Service installed" "Info"
                }
                $global:alertCount++
            }
        }
        
        # PowerShell logs
        $psLogs = Get-WinEvent -LogName "Windows PowerShell" -MaxEvents 50 -ErrorAction SilentlyContinue |
            Where-Object {$_.Message -match "DownloadString|IEX|Invoke-Expression|EncodedCommand"}
        
        if ($psLogs) {
            Write-ColorOutput "Suspicious PowerShell activity detected!" "Alert"
            $psLogs | Select-Object -First 3 | ForEach-Object {
                Write-ColorOutput "  - $($_.TimeCreated): Suspicious command" "Warning"
            }
            $global:alertCount++
        }
        
        # Export logs in background
        Start-Job -Name "EventLogs" -ScriptBlock {
            param($path)
            wevtutil epl Security "$path\Logs\Security.evtx" 2>$null
            wevtutil epl System "$path\Logs\System.evtx" 2>$null
            wevtutil epl Application "$path\Logs\Application.evtx" 2>$null
            wevtutil epl "Windows PowerShell" "$path\Logs\PowerShell.evtx" 2>$null
        } -ArgumentList $incidentPath | Out-Null
        
    } catch {
        Write-ColorOutput "Error in event log analysis: $_" "Error"
    }
}

# SECTION 6: SYSTEM INFO COLLECTION
Write-ColorOutput "`n[SYSTEM INFORMATION]" "Progress"

try {
    # Basic system info
    $os = Get-WmiObject Win32_OperatingSystem
    $cs = Get-WmiObject Win32_ComputerSystem
    
    $bootTime = $os.ConvertToDateTime($os.LastBootUpTime)
    $uptime = (Get-Date) - $bootTime
    
    Write-ColorOutput "System: $($cs.Name) - $($os.Caption)" "Info"
    Write-ColorOutput "Last Boot: $bootTime (Uptime: $($uptime.Days)d $($uptime.Hours)h)" "Info"
    
    # System info to file
    @"
Computer Name: $($cs.Name)
Domain: $($cs.Domain)
OS: $($os.Caption) $($os.OSArchitecture)
Version: $($os.Version)
Install Date: $($os.ConvertToDateTime($os.InstallDate))
Last Boot: $bootTime
Uptime: $($uptime.Days) days, $($uptime.Hours) hours
"@ | Out-File "$incidentPath\System\basic_info.txt"
    
    # AV Status
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defender) {
        if (!$defender.RealTimeProtectionEnabled) {
            Write-ColorOutput "Windows Defender Real-Time Protection is DISABLED!" "Alert"
            $global:alertCount++
            "Defender Real-Time Protection: DISABLED" | Out-File "$incidentPath\ALERTS\defender_disabled.txt"
        } else {
            Write-ColorOutput "Windows Defender is active (Last update: $($defender.AntivirusSignatureLastUpdated))" "Success"
        }
        
        $defender | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, 
            AntivirusSignatureLastUpdated, BehaviorMonitorEnabled |
            Export-Csv "$incidentPath\System\defender_status.csv" -NoTypeInformation
    }
    
    # Network config
    Write-ColorOutput "Collecting network configuration..." "Progress"
    ipconfig /all > "$incidentPath\Network\ipconfig.txt" 2>&1
    route print > "$incidentPath\Network\routes.txt" 2>&1
    arp -a > "$incidentPath\Network\arp.txt" 2>&1
    
    # DNS Cache
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    if ($dnsCache) {
        $dnsCache | Export-Csv "$incidentPath\Network\dns_cache.csv" -NoTypeInformation
        $suspiciousDns = $dnsCache | Where-Object {
            $_.Entry -match "\.tk$|\.ml$|\.ga$|\.cf$" -or
            $_.Entry -match "\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}"
        }
        if ($suspiciousDns) {
            Write-ColorOutput "Suspicious DNS entries found!" "Warning"
            $suspiciousDns | Select-Object -First 3 | ForEach-Object {
                Write-ColorOutput "  - $($_.Entry)" "Info"
            }
        }
    }
    
    # Firewall
    $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    if ($fwProfiles) {
        $fwDisabled = @($fwProfiles | Where-Object {!$_.Enabled})
        if ($fwDisabled) {
            Write-ColorOutput "Firewall profiles disabled: $($fwDisabled.Name -join ', ')" "Warning"
            $global:alertCount++
        }
        $fwProfiles | Select-Object Name, Enabled | Export-Csv "$incidentPath\System\firewall_status.csv" -NoTypeInformation
    }
    
} catch {
    Write-ColorOutput "Error in system info collection: $_" "Error"
}

# SECTION 7: QUICK IOC EXTRACTION
Write-ColorOutput "`n[IOC EXTRACTION]" "Progress"

try {
    $iocs = @{
        SuspiciousIPs = @()
        SuspiciousProcesses = @()
        SuspiciousFiles = @()
        PersistenceLocations = @()
    }
    
    # Collect external IPs
    if (Test-Path "$incidentPath\Network\external_ips.txt") {
        $iocs.SuspiciousIPs = Get-Content "$incidentPath\Network\external_ips.txt"
    }
    
    # Collect suspicious process names
    if ($suspiciousLocs) {
        $iocs.SuspiciousProcesses = $suspiciousLocs | Select-Object -ExpandProperty ProcessName -Unique
    }
    
    # Collect persistence
    if ($autorunEntries) {
        $iocs.PersistenceLocations = $autorunEntries | Select-Object -First 10
    }
    
    $iocs | ConvertTo-Json -Depth 3 | Out-File "$incidentPath\ALERTS\quick_iocs.json"
    Write-ColorOutput "IOCs extracted to quick_iocs.json" "Info"
    
} catch {
    Write-ColorOutput "Error extracting IOCs: $_" "Error"
}

# SECTION 8: SUMMARY AND ARCHIVE
Write-ColorOutput "`n[GENERATING SUMMARY]" "Progress"

# Wait for background jobs (with timeout)
$jobs = Get-Job
if ($jobs) {
    Write-ColorOutput "Waiting for background tasks..." "Progress"
    $jobs | ForEach-Object {
        $_ | Wait-Job -Timeout 20 | Out-Null
        if ($_.State -eq "Running") {
            $_ | Stop-Job
            Write-ColorOutput "  - Stopped long-running job: $($_.Name)" "Warning"
        }
    }
    $jobs | Remove-Job -Force
}

# Count alerts
$alertFiles = Get-ChildItem "$incidentPath\ALERTS" -Filter "*.*" -ErrorAction SilentlyContinue
$totalAlerts = $global:alertCount + $alertFiles.Count

# Generate summary
$summary = @"
================================================
       INCIDENT RESPONSE SUMMARY
================================================
Collection Time: $(Get-Date)
Hostname: $env:COMPUTERNAME
Domain: $env:USERDOMAIN
Username: $env:USERNAME
------------------------------------------------

THREAT LEVEL: $(if($totalAlerts -gt 10){"CRITICAL"}elseif($totalAlerts -gt 5){"HIGH"}elseif($totalAlerts -gt 0){"MEDIUM"}else{"LOW"})
TOTAL ALERTS: $totalAlerts

KEY FINDINGS:
$(if($established){"> Network Connections: $($established.Count) established, $($listening.Count) listening"})
$(if($suspiciousLocs){"> Suspicious Process Locations: $($suspiciousLocs.Count)"})
$(if($suspiciousNames){"> Suspicious Process Names: $($suspiciousNames.Count)"})
$(if($shells){"> Shells with Network: $($shells.Count)"})
$(if($remoteProcs -or $remoteSvcs){"> Remote Access Tools: DETECTED"})
$(if($recentTasks){"> Recent Scheduled Tasks: $($recentTasks.Count)"})
$(if($suspiciousSvc){"> Suspicious Services: $($suspiciousSvc.Count)"})
$(if($failedLogons -and $failedLogons.Count -gt 10){"> Failed Logons (24h): $($failedLogons.Count)"})
$(if($rdpStatus -and $rdpStatus.fDenyTSConnections -eq 0){"> RDP: ENABLED"})
$(if($defender -and !$defender.RealTimeProtectionEnabled){"> Windows Defender: DISABLED"})

EVIDENCE LOCATION: $incidentPath

$(if($totalAlerts -gt 10){
"================================================
!!! CRITICAL SEVERITY - IMMEDIATE ACTION !!!
================================================
1. ISOLATE THIS SYSTEM FROM NETWORK NOW
2. DO NOT REBOOT OR SHUTDOWN
3. PRESERVE MEMORY DUMP
4. CONTACT INCIDENT RESPONSE TEAM
================================================"
}elseif($totalAlerts -gt 5){
"------------------------------------------------
** HIGH SEVERITY - INVESTIGATE IMMEDIATELY **
------------------------------------------------
1. Review all files in ALERTS folder
2. Consider network isolation
3. Check external IP connections
4. Review persistence mechanisms
------------------------------------------------"
}elseif($totalAlerts -gt 0){
"------------------------------------------------
* MEDIUM SEVERITY - FURTHER ANALYSIS NEEDED *
------------------------------------------------
1. Review findings in detail
2. Monitor system closely
3. Check for additional IOCs
------------------------------------------------"
}else{
"------------------------------------------------
* LOW SEVERITY - ROUTINE CHECK COMPLETE *
------------------------------------------------
No immediate threats detected.
Continue standard monitoring.
------------------------------------------------"
})
"@

Write-ColorOutput "`n$summary" "Success"
$summary | Out-File "$incidentPath\SUMMARY.txt"

Stop-Transcript

# Create evidence ZIP
Write-ColorOutput "`nCreating evidence archive..." "Progress"
try {
    $zipPath = "$incidentPath.zip"
    Compress-Archive -Path "$incidentPath\*" -DestinationPath $zipPath -Force
    $zipInfo = Get-Item $zipPath
    Write-ColorOutput "Evidence archive created: $zipPath" "Success"
    Write-ColorOutput "Archive size: $([math]::Round($zipInfo.Length/1MB, 2)) MB" "Info"
} catch {
    Write-ColorOutput "Failed to create ZIP: $_" "Error"
}

Write-ColorOutput "`n=== COLLECTION COMPLETE ===" "Success"
Write-ColorOutput "All evidence saved to: $incidentPath" "Info"

# Final alert
if ($totalAlerts -gt 0) {
    Write-ColorOutput "`n!!! $totalAlerts ALERTS REQUIRE INVESTIGATION !!!" "Alert"
    if ($totalAlerts -gt 5) {
        [console]::beep(1000,300)
        [console]::beep(1000,300)
        [console]::beep(1000,300)
    }
}

# Show how to access results
Write-ColorOutput "`nNext steps:" "Info"
Write-ColorOutput "1. Review: $incidentPath\SUMMARY.txt" "Info"
Write-ColorOutput "2. Check alerts: $incidentPath\ALERTS\" "Info"
Write-ColorOutput "3. Analyze evidence: $incidentPath.zip" "Info"
