# COMPREHENSIVE INCIDENT RESPONSE TRIAGE SCRIPT v2 - FIXED
# Run as Administrator: powershell -ExecutionPolicy Bypass -File .\Triage.ps1

param(
    [switch]$SkipDNS = $true,
    [switch]$Quick = $false,
    [switch]$Deep = $false,      # Deep analysis mode
    [int]$TimeoutSeconds = 30,
    [int]$DaysBack = 7           # How many days back to check logs
)

# Initialize
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$startTime = Get-Date  # Store actual DateTime for duration calculation
$incidentPath = "C:\incident_$timestamp"

# Create incident folder structure
try {
    $folders = @(
        $incidentPath,
        "$incidentPath\Network",
        "$incidentPath\Processes",
        "$incidentPath\Persistence",
        "$incidentPath\Logs",
        "$incidentPath\System",
        "$incidentPath\ALERTS",
        "$incidentPath\Memory",
        "$incidentPath\FileSystem"
    )
    $folders | ForEach-Object { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
    Start-Transcript -Path "$incidentPath\collection_log.txt" -Force
} catch {
    Write-Host "ERROR: Cannot create incident folder. Exiting." -ForegroundColor Red
    exit 1
}

Write-Host "=== COMPREHENSIVE INCIDENT RESPONSE COLLECTION STARTED: $timestamp ===" -ForegroundColor Yellow
Write-Host "Output directory: $incidentPath" -ForegroundColor Cyan
if ($Quick) { Write-Host "Running in QUICK mode" -ForegroundColor Yellow }
if ($Deep) { Write-Host "Running in DEEP analysis mode" -ForegroundColor Yellow }

# Helper Functions
function Show-Progress {
    param($Activity, $Status)
    Write-Host "[$([DateTime]::Now.ToString('HH:mm:ss'))] $Activity - $Status" -ForegroundColor Green
}

function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Warn if not admin
if (!(Test-Administrator)) {
    Write-Host "WARNING: Not running as Administrator. Some data collection will be limited." -ForegroundColor Yellow
}

# SECTION 1: NETWORK ANALYSIS (ENHANCED)
Show-Progress "NETWORK ANALYSIS" "Collecting comprehensive network data"

try {
    # Get all network connections with enhanced details
    $connections = Get-NetTCPConnection
    $establishedConns = $connections | Where-Object {$_.State -eq "Established"}
    $listeningPorts = $connections | Where-Object {$_.State -eq "Listen"}
    
    # Export raw connections
    $connections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, CreationTime |
        Export-Csv "$incidentPath\Network\all_connections.csv" -NoTypeInformation
    
    Write-Host "  - Total connections: $($connections.Count) (Established: $($establishedConns.Count), Listening: $($listeningPorts.Count))" -ForegroundColor Gray
    
    # Process network connections with enhanced details
    Show-Progress "NETWORK ANALYSIS" "Analyzing network processes"
    $networkProcesses = @()
    $uniquePids = $connections.OwningProcess | Select-Object -Unique
    
    foreach ($procId in $uniquePids) {
        if ($procId -eq 0 -or $procId -eq 4) { continue }  # Skip System processes
        
        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        $wmiProc = Get-WmiObject Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue
        
        if ($proc -or $wmiProc) {
            $conns = $connections | Where-Object {$_.OwningProcess -eq $procId}
            $established = ($conns | Where-Object {$_.State -eq "Established"}).Count
            $listening = ($conns | Where-Object {$_.State -eq "Listen"}).Count
            
            # Get digital signature info
            $signature = if ($proc.Path) {
                Get-AuthenticodeSignature -FilePath $proc.Path -ErrorAction SilentlyContinue
            } else { $null }
            
            $networkProcesses += [PSCustomObject]@{
                ProcessName = if($proc) {$proc.ProcessName} else {$wmiProc.Name}
                ProcessId = $procId
                Path = if($proc) {$proc.Path} else {$wmiProc.ExecutablePath}
                CommandLine = $wmiProc.CommandLine
                ParentProcessId = $wmiProc.ParentProcessId
                StartTime = if($proc) {$proc.StartTime} else {'Unknown'}
                TotalConnections = $conns.Count
                EstablishedCount = $established
                ListeningCount = $listening
                Signed = if($signature) {$signature.Status -eq "Valid"} else {'Unknown'}
                SignerCertificate = if($signature -and $signature.SignerCertificate) {$signature.SignerCertificate.Subject} else {'None'}
                MD5Hash = if($proc.Path -and (Test-Path $proc.Path)) {
                    (Get-FileHash -Path $proc.Path -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
                } else {'N/A'}
            }
        }
    }
    
    $networkProcesses | Export-Csv "$incidentPath\Network\network_processes_detailed.csv" -NoTypeInformation
    
    # Check for suspicious network patterns
    Show-Progress "NETWORK ANALYSIS" "Checking for suspicious network patterns"
    
    # Known malicious ports
    $maliciousPorts = @{
        "4444" = "Metasploit default"
        "4445" = "Backdoor common"
        "5555" = "Android ADB/Backdoor"
        "6666" = "Backdoor common"
        "6667" = "IRC backdoor"
        "7777" = "Backdoor common"
        "8888" = "Backdoor common"
        "9999" = "Backdoor common"
        "12345" = "NetBus"
        "31337" = "Back Orifice"
        "54321" = "BackDoor"
        "65535" = "RC/NetCat"
    }
    
    $suspiciousConns = @()
    foreach ($conn in $establishedConns) {
        $suspicious = $false
        $reason = @()
        
        # Check for known bad ports
        if ($maliciousPorts.ContainsKey($conn.LocalPort.ToString())) {
            $suspicious = $true
            $reason += "Local port $($conn.LocalPort) - $($maliciousPorts[$conn.LocalPort.ToString()])"
        }
        if ($maliciousPorts.ContainsKey($conn.RemotePort.ToString())) {
            $suspicious = $true
            $reason += "Remote port $($conn.RemotePort) - $($maliciousPorts[$conn.RemotePort.ToString()])"
        }
        
        # Check for suspicious IPs (private to public unusual ports)
        if ($conn.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fe80:)" -and
            $conn.LocalPort -gt 30000) {
            $suspicious = $true
            $reason += "High local port to external IP"
        }
        
        if ($suspicious) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $suspiciousConns += [PSCustomObject]@{
                LocalAddress = $conn.LocalAddress
                LocalPort = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                ProcessId = $conn.OwningProcess
                ProcessName = if($proc) {$proc.ProcessName} else {'Unknown'}
                ProcessPath = if($proc) {$proc.Path} else {'Unknown'}
                Reason = $reason -join "; "
            }
        }
    }
    
    if ($suspiciousConns) {
        $suspiciousConns | Export-Csv "$incidentPath\ALERTS\suspicious_network_connections.csv" -NoTypeInformation
        Write-Host "  - ALERT: Found $($suspiciousConns.Count) suspicious connections!" -ForegroundColor Red
    }
    
    # Netstat with different parameters for comparison
    Show-Progress "NETWORK ANALYSIS" "Running comprehensive netstat"
    netstat -anob > "$incidentPath\Network\netstat_anob.txt" 2>&1
    netstat -anp tcp > "$incidentPath\Network\netstat_tcp.txt" 2>&1
    netstat -anp udp > "$incidentPath\Network\netstat_udp.txt" 2>&1
    netstat -rn > "$incidentPath\Network\routing_table.txt" 2>&1
    
    # Network configuration
    ipconfig /all > "$incidentPath\Network\ipconfig_all.txt" 2>&1
    ipconfig /displaydns > "$incidentPath\Network\dns_cache_full.txt" 2>&1
    nbtstat -c > "$incidentPath\Network\netbios_cache.txt" 2>&1
    
} catch {
    Write-Host "ERROR in network collection: $_" -ForegroundColor Red
}

# SECTION 2: PROCESS DEEP ANALYSIS
Show-Progress "PROCESS ANALYSIS" "Performing deep process analysis"

try {
    # Get all processes with complete details
    $allProcesses = Get-WmiObject Win32_Process | ForEach-Object {
        $proc = $_
        
        # Try to get owner, but handle failures gracefully
        $owner = try {
            $ownerInfo = $proc.GetOwner()
            if ($ownerInfo.ReturnValue -eq 0) {
                "$($ownerInfo.Domain)\$($ownerInfo.User)"
            } else {
                "SYSTEM"
            }
        } catch {
            "SYSTEM"
        }
        
        $procObj = Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
        
        # Check if running from suspicious location
        $suspiciousPath = $false
        $pathReason = ""
        if ($proc.ExecutablePath) {
            if ($proc.ExecutablePath -match "\\Users\\[^\\]+\\AppData\\Local\\Temp\\") {
                $suspiciousPath = $true; $pathReason = "Running from user temp"
            } elseif ($proc.ExecutablePath -match "\\Windows\\Temp\\") {
                $suspiciousPath = $true; $pathReason = "Running from Windows temp"
            } elseif ($proc.ExecutablePath -match "\\ProgramData\\" -and $proc.ExecutablePath -notmatch "Microsoft|Windows") {
                $suspiciousPath = $true; $pathReason = "Running from ProgramData"
            } elseif ($proc.ExecutablePath -match "\\Users\\Public\\") {
                $suspiciousPath = $true; $pathReason = "Running from Public folder"
            } elseif ($proc.ExecutablePath -match "\\AppData\\Roaming\\" -and $proc.ExecutablePath -notmatch "Microsoft|Mozilla|Google") {
                $suspiciousPath = $true; $pathReason = "Running from Roaming"
            }
        }
        
        [PSCustomObject]@{
            Name = $proc.Name
            ProcessId = $proc.ProcessId
            ParentProcessId = $proc.ParentProcessId
            ParentName = (Get-WmiObject Win32_Process -Filter "ProcessId=$($proc.ParentProcessId)" -ErrorAction SilentlyContinue).Name
            Path = $proc.ExecutablePath
            CommandLine = $proc.CommandLine
            CreationDate = if($proc.CreationDate) {$proc.ConvertToDateTime($proc.CreationDate)} else {'Unknown'}
            Owner = $owner
            ThreadCount = $proc.ThreadCount
            HandleCount = $proc.HandleCount
            WorkingSetSizeMB = [math]::Round($proc.WorkingSetSize / 1MB, 2)
            VirtualSizeMB = [math]::Round($proc.VirtualSize / 1MB, 2)
            SessionId = $proc.SessionId
            SuspiciousPath = $suspiciousPath
            PathReason = $pathReason
            CPUTime = if($procObj) {$procObj.TotalProcessorTime} else {'N/A'}
        }
    }
    
    $allProcesses | Export-Csv "$incidentPath\Processes\all_processes_detailed.csv" -NoTypeInformation
    Write-Host "  - Analyzed $($allProcesses.Count) processes" -ForegroundColor Gray
    
    # Suspicious processes
    $suspiciousProcs = $allProcesses | Where-Object {$_.SuspiciousPath -eq $true}
    if ($suspiciousProcs) {
        $suspiciousProcs | Export-Csv "$incidentPath\ALERTS\suspicious_process_locations.csv" -NoTypeInformation
        Write-Host "  - ALERT: Found $($suspiciousProcs.Count) processes in suspicious locations!" -ForegroundColor Red
    }
    
    # Check for specific suspicious patterns
    Show-Progress "PROCESS ANALYSIS" "Checking for malware patterns"
    
    # PowerShell with encoded commands
    $encodedPS = $allProcesses | Where-Object {
        $_.Name -match "powershell|pwsh" -and 
        $_.CommandLine -match "-e[nc]|encodedcommand|base64"
    }
    if ($encodedPS) {
        $encodedPS | Export-Csv "$incidentPath\ALERTS\encoded_powershell.csv" -NoTypeInformation
        Write-Host "  - ALERT: Found encoded PowerShell commands!" -ForegroundColor Red
    }
    
    # Suspicious process names (common malware patterns)
    $suspiciousNames = $allProcesses | Where-Object {
        $_.Name -match "^[a-z]{8}\.exe$|^[0-9]{4,}\.exe$|^[a-f0-9]{32}\.exe$" -or
        ($_.Name -eq "svchost.exe" -and $_.Path -notmatch "\\System32\\|\\SysWOW64\\") -or
        ($_.Name -match "csrss|winlogon|services|lsass|smss" -and $_.Path -notmatch "\\System32\\|\\SysWOW64\\")
    }
    if ($suspiciousNames) {
        $suspiciousNames | Export-Csv "$incidentPath\ALERTS\suspicious_process_names.csv" -NoTypeInformation
        Write-Host "  - ALERT: Found processes with suspicious names!" -ForegroundColor Red
    }
    
    # Process tree for suspicious PIDs
    $targetPids = @(6640, 11492, 2072, 5300)  # Your suspicious PIDs
    Show-Progress "PROCESS ANALYSIS" "Investigating specific PIDs: $($targetPids -join ', ')"
    
    $pidInvestigation = @()
    foreach ($targetPid in $targetPids) {
        $targetProc = $allProcesses | Where-Object {$_.ProcessId -eq $targetPid}
        if ($targetProc) {
            # Get process tree
            $children = $allProcesses | Where-Object {$_.ParentProcessId -eq $targetPid}
            $parent = $allProcesses | Where-Object {$_.ProcessId -eq $targetProc.ParentProcessId}
            
            $pidInvestigation += [PSCustomObject]@{
                TargetPID = $targetPid
                ProcessName = $targetProc.Name
                Path = $targetProc.Path
                CommandLine = $targetProc.CommandLine
                Parent = "$($parent.ProcessId) - $($parent.Name)"
                Children = ($children | ForEach-Object {"$($_.ProcessId) - $($_.Name)"}) -join "; "
                Owner = $targetProc.Owner
                CreationDate = $targetProc.CreationDate
            }
            Write-Host "  - Found suspicious PID $targetPid : $($targetProc.Name)" -ForegroundColor Yellow
        }
    }
    if ($pidInvestigation) {
        $pidInvestigation | Export-Csv "$incidentPath\ALERTS\target_pid_investigation.csv" -NoTypeInformation
    }
    
} catch {
    Write-Host "ERROR in process analysis: $_" -ForegroundColor Red
}

# SECTION 3: ENHANCED PERSISTENCE CHECKS
Show-Progress "PERSISTENCE" "Checking comprehensive persistence mechanisms"

try {
    # Registry persistence - expanded locations
    $regLocations = @{
        # Standard Run keys
        "HKLM_Run" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        "HKLM_RunOnce" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        "HKLM_RunServices" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices"
        "HKLM_RunServicesOnce" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
        "HKCU_Run" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        "HKCU_RunOnce" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        
        # Winlogon
        "HKLM_Winlogon" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        "HKCU_Winlogon" = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        
        # Explorer
        "HKLM_Explorer_Run" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        "HKCU_Explorer_Run" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        
        # Services
        "HKLM_Services" = "HKLM:\System\CurrentControlSet\Services"
        
        # Browser Helper Objects
        "HKLM_BHO" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
        "HKLM_BHO_64" = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
        
        # Shell Extensions
        "HKLM_ShellExecuteHooks" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"
        
        # AppInit DLLs
        "HKLM_AppInit" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
        "HKLM_AppInit_64" = "HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
        
        # Image File Execution Options (Debugger)
        "HKLM_IFEO" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        
        # Print Monitors
        "HKLM_PrintMonitors" = "HKLM:\System\CurrentControlSet\Control\Print\Monitors"
        
        # LSA Providers
        "HKLM_LSA" = "HKLM:\System\CurrentControlSet\Control\Lsa"
        
        # Network Providers
        "HKLM_NetworkProvider" = "HKLM:\System\CurrentControlSet\Control\NetworkProvider\Order"
    }
    
    $regPersistence = @()
    foreach ($item in $regLocations.GetEnumerator()) {
        try {
            if ($item.Key -eq "HKLM_Services" -or $item.Key -eq "HKLM_IFEO") {
                # Special handling for services and IFEO
                Get-ChildItem $item.Value -ErrorAction SilentlyContinue | ForEach-Object {
                    $subkey = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    if ($item.Key -eq "HKLM_Services" -and $subkey.ImagePath) {
                        $regPersistence += [PSCustomObject]@{
                            Location = "$($item.Key)\$($_.PSChildName)"
                            Type = "Service"
                            Value = $subkey.ImagePath
                            Start = $subkey.Start
                        }
                    } elseif ($item.Key -eq "HKLM_IFEO" -and $subkey.Debugger) {
                        $regPersistence += [PSCustomObject]@{
                            Location = "$($item.Key)\$($_.PSChildName)"
                            Type = "IFEO Debugger"
                            Value = $subkey.Debugger
                            Start = "N/A"
                        }
                    }
                }
            } else {
                $values = Get-ItemProperty $item.Value -ErrorAction SilentlyContinue
                if ($values) {
                    $values.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                        $regPersistence += [PSCustomObject]@{
                            Location = $item.Key
                            Type = "Autorun"
                            Name = $_.Name
                            Value = $_.Value
                        }
                    }
                }
            }
        } catch { }
    }
    
    $regPersistence | Export-Csv "$incidentPath\Persistence\registry_persistence_comprehensive.csv" -NoTypeInformation
    Write-Host "  - Found $($regPersistence.Count) registry persistence entries" -ForegroundColor Gray
    
    # Scheduled Tasks with more details
    Show-Progress "PERSISTENCE" "Analyzing scheduled tasks"
    $tasks = Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}
    $taskAnalysis = @()
    
    foreach ($task in $tasks) {
        try {
            $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            $principal = $task.Principal
            
            # Check if task was created recently
            $recentlyCreated = $false
            if ($task.Date -and ([DateTime]$task.Date -gt (Get-Date).AddDays(-$DaysBack))) {
                $recentlyCreated = $true
            }
            
            $taskAnalysis += [PSCustomObject]@{
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                State = $task.State
                Author = $task.Author
                Description = $task.Description
                CreatedDate = $task.Date
                RecentlyCreated = $recentlyCreated
                LastRunTime = $info.LastRunTime
                NextRunTime = $info.NextRunTime
                LastResult = $info.LastTaskResult
                RunAsUser = $principal.UserId
                RunLevel = $principal.RunLevel
                Actions = ($task.Actions | ForEach-Object {"$($_.Execute) $($_.Arguments)"}) -join "; "
                Triggers = ($task.Triggers | ForEach-Object {$_.CimClass.CimClassName}) -join "; "
            }
        } catch { }
    }
    
    $taskAnalysis | Export-Csv "$incidentPath\Persistence\scheduled_tasks_analysis.csv" -NoTypeInformation
    
    # Recently created tasks
    $recentTasks = $taskAnalysis | Where-Object {$_.RecentlyCreated -eq $true}
    if ($recentTasks) {
        $recentTasks | Export-Csv "$incidentPath\ALERTS\recent_scheduled_tasks.csv" -NoTypeInformation
        Write-Host "  - ALERT: Found $($recentTasks.Count) recently created scheduled tasks!" -ForegroundColor Yellow
    }
    
    # WMI Persistence
    Show-Progress "PERSISTENCE" "Checking WMI persistence"
    @('root\subscription', 'root\default') | ForEach-Object {
        $namespace = $_
        Get-WmiObject -Namespace $namespace -Class __EventFilter -ErrorAction SilentlyContinue | 
            Export-Csv "$incidentPath\Persistence\wmi_eventfilters_$($namespace.Replace('\','_')).csv" -NoTypeInformation
        Get-WmiObject -Namespace $namespace -Class __EventConsumer -ErrorAction SilentlyContinue | 
            Export-Csv "$incidentPath\Persistence\wmi_eventconsumers_$($namespace.Replace('\','_')).csv" -NoTypeInformation
        Get-WmiObject -Namespace $namespace -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | 
            Export-Csv "$incidentPath\Persistence\wmi_bindings_$($namespace.Replace('\','_')).csv" -NoTypeInformation
    }
    
    # Startup locations
    Show-Progress "PERSISTENCE" "Checking startup locations"
    $startupPaths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ALLUSERSPROFILE\Start Menu\Programs\StartUp",
        "$env:USERPROFILE\Start Menu\Programs\Startup"
    )
    
    $startupFiles = @()
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $startupFiles += [PSCustomObject]@{
                    Path = $_.FullName
                    Name = $_.Name
                    CreationTime = $_.CreationTime
                    LastWriteTime = $_.LastWriteTime
                    Size = $_.Length
                    Target = if($_.Extension -eq '.lnk') {
                        $sh = New-Object -ComObject WScript.Shell
                        $shortcut = $sh.CreateShortcut($_.FullName)
                        $shortcut.TargetPath
                    } else { 'N/A' }
                }
            }
        }
    }
    
    if ($startupFiles) {
        $startupFiles | Export-Csv "$incidentPath\Persistence\startup_files.csv" -NoTypeInformation
    }
    
    # Services analysis
    Show-Progress "PERSISTENCE" "Analyzing services"
    $services = Get-WmiObject Win32_Service | Select-Object Name, DisplayName, State, StartMode, 
        PathName, StartName, ProcessId, Description,
        @{N='AcceptStop';E={$_.AcceptStop}},
        @{N='ServiceType';E={$_.ServiceType}}
    
    # Check for suspicious services
    $suspiciousServices = $services | Where-Object {
        $_.PathName -match "\\Users\\|\\Temp\\|\\AppData\\" -or
        $_.PathName -match "^[a-z]:\\[^\\]+\.exe" -or
        $_.StartName -notmatch "LocalSystem|LocalService|NetworkService|NT AUTHORITY" -or
        ($_.State -eq "Running" -and $_.PathName -match "powershell|cmd\.exe|wscript|cscript|rundll32")
    }
    
    $services | Export-Csv "$incidentPath\System\all_services.csv" -NoTypeInformation
    if ($suspiciousServices) {
        $suspiciousServices | Export-Csv "$incidentPath\ALERTS\suspicious_services.csv" -NoTypeInformation
        Write-Host "  - ALERT: Found $($suspiciousServices.Count) suspicious services!" -ForegroundColor Red
    }
    
} catch {
    Write-Host "ERROR in persistence checks: $_" -ForegroundColor Red
}

# SECTION 4: REMOTE ACCESS DETECTION (ENHANCED)
Show-Progress "REMOTE ACCESS" "Comprehensive remote access detection"

try {
    # Current sessions
    @"
=== RDP SESSIONS (qwinsta) ===
$(qwinsta 2>&1)

=== LOGGED USERS (quser) ===
$(quser 2>&1)

=== NET SESSIONS ===
$(net session 2>&1)

=== NET USE ===
$(net use 2>&1)

=== NET SHARE ===
$(net share 2>&1)

=== OPENFILES ===
$(openfiles /query /fo table 2>&1)
"@ | Out-File "$incidentPath\Network\active_sessions_detailed.txt"
    
    # Remote access tools - comprehensive list
    $remoteToolPatterns = @(
        # Commercial RATs
        "TeamViewer", "AnyDesk", "Chrome.*Remote", "LogMeIn", "GoToMyPC", "Splashtop",
        "ScreenConnect", "ConnectWise", "RemotePC", "Zoho.*Assist", "ISL.*Online",
        "ShowMyPC", "BeAnywhere", "Mikogo", "Bomgar", "BeyondTrust", "DameWare",
        "pcAnywhere", "Radmin", "RemoteUtilities", "NoMachine", "AeroAdmin", "SupRemo",
        "UltraViewer", "Iperius", "TightVNC", "UltraVNC", "RealVNC", "TigerVNC",
        
        # System tools
        "VNC", "RDP", "WinRM", "SSH", "Telnet", "psexec", "wmic", "winrs",
        
        # Potential malicious
        "Ammyy", "CrossLoop", "LogMeIn123", "GoToAssist", "FastSupport",
        "QuickSupport", "Supremo", "AnyPlace", "Thinfinity", "TSplus", "2X",
        "Parallels.*Access", "Citrix", "VMware.*Horizon",
        
        # Backdoors/Trojans (common names)
        "njrat", "darkcomet", "cybergate", "xtreme", "poison.*ivy", "netwire",
        "nanocore", "remcos", "quasar", "asyncrat", "venom.*rat", "blackshades",
        "pandora", "plasma.*rat", "orcus", "imminent.*monitor", "luminosity",
        "comet.*rat", "mega.*rat", "paradox.*rat"
    )
    
    $pattern = $remoteToolPatterns -join '|'
    
    # Check running processes
    $remoteProcesses = Get-Process | Where-Object {
        $_.ProcessName -match $pattern -or 
        $_.Description -match $pattern -or
        $_.MainWindowTitle -match $pattern
    }
    
    # Check services
    $remoteServices = Get-Service | Where-Object {
        $_.Name -match $pattern -or 
        $_.DisplayName -match $pattern
    }
    
    # Check installed programs
    $installedRATs = @()
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($path in $uninstallPaths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object {
            $_.DisplayName -match $pattern -or $_.Publisher -match $pattern
        } | ForEach-Object {
            $installedRATs += [PSCustomObject]@{
                Name = $_.DisplayName
                Publisher = $_.Publisher
                InstallDate = $_.InstallDate
                InstallLocation = $_.InstallLocation
                UninstallString = $_.UninstallString
            }
        }
    }
    
    # Export findings
    if ($remoteProcesses) {
        $remoteProcesses | Select-Object ProcessName, Id, Path, Description, StartTime |
            Export-Csv "$incidentPath\ALERTS\remote_access_processes.csv" -NoTypeInformation
        Write-Host "  - ALERT: Found $($remoteProcesses.Count) remote access processes!" -ForegroundColor Red
    }
    
    if ($remoteServices) {
        $remoteServices | Select-Object Name, DisplayName, Status, StartType |
            Export-Csv "$incidentPath\ALERTS\remote_access_services.csv" -NoTypeInformation
        Write-Host "  - ALERT: Found $($remoteServices.Count) remote access services!" -ForegroundColor Red
    }
    
    if ($installedRATs) {
        $installedRATs | Export-Csv "$incidentPath\ALERTS\installed_remote_tools.csv" -NoTypeInformation
        Write-Host "  - ALERT: Found $($installedRATs.Count) installed remote access tools!" -ForegroundColor Red
    }
    
    # Check for SSH server
    $sshService = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($sshService -and $sshService.Status -eq "Running") {
        "SSH Server is running!" | Out-File "$incidentPath\ALERTS\ssh_server_active.txt"
        Write-Host "  - ALERT: SSH server is running!" -ForegroundColor Red
    }
    
    # Check RDP settings
    $rdpReg = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue
    if ($rdpReg.fDenyTSConnections -eq 0) {
        "RDP is ENABLED! fDenyTSConnections = 0" | Out-File "$incidentPath\ALERTS\rdp_enabled.txt"
        Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue |
            Out-File "$incidentPath\ALERTS\rdp_settings.txt" -Append
    }
    
} catch {
    Write-Host "ERROR in remote access detection: $_" -ForegroundColor Red
}

# SECTION 5: MEMORY AND HANDLES
if (!$Quick) {
    Show-Progress "MEMORY ANALYSIS" "Collecting memory artifacts"
    
    try {
        # Process memory stats
        Get-Process | Select-Object ProcessName, Id, 
            @{N='WorkingSetMB';E={[math]::Round($_.WorkingSet64/1MB,2)}},
            @{N='PrivateMemoryMB';E={[math]::Round($_.PrivateMemorySize64/1MB,2)}},
            @{N='VirtualMemoryMB';E={[math]::Round($_.VirtualMemorySize64/1MB,2)}},
            Handles, NPM, PM, CPU |
            Sort-Object WorkingSetMB -Descending |
            Export-Csv "$incidentPath\Memory\process_memory_usage.csv" -NoTypeInformation
        
        # Look for process injection indicators
        $injectionSuspects = Get-Process | Where-Object {
            $_.ProcessName -match "svchost|explorer|winlogon|csrss|services|lsass" -and
            $_.Modules.Count -gt 100
        }
        
        if ($injectionSuspects) {
            $injectionSuspects | Select-Object ProcessName, Id, 
                @{N='ModuleCount';E={$_.Modules.Count}},
                @{N='SuspiciousModules';E={
                    ($_.Modules | Where-Object {
                        $_.FileName -notmatch "Windows|System32|SysWOW64|Microsoft"
                    }).FileName -join "; "
                }} | Export-Csv "$incidentPath\ALERTS\possible_process_injection.csv" -NoTypeInformation
        }
        
        # Handles and DLLs for suspicious processes
        if ($targetPids) {
            foreach ($suspPid in $targetPids) {
                try {
                    # Get loaded modules
                    $modules = Get-Process -Id $suspPid -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Modules
                    $modules | Select-Object ModuleName, FileName, FileVersion, Size |
                        Export-Csv "$incidentPath\Memory\pid_${suspPid}_modules.csv" -NoTypeInformation
                    
                    # Try to get handles (requires handle.exe)
                    if (Get-Command handle.exe -ErrorAction SilentlyContinue) {
                        handle.exe -p $suspPid -nobanner 2>$null | 
                            Out-File "$incidentPath\Memory\pid_${suspPid}_handles.txt"
                    }
                } catch { }
            }
        }
        
    } catch {
        Write-Host "WARNING: Memory analysis incomplete: $_" -ForegroundColor Yellow
    }
}

# SECTION 6: FILE SYSTEM ANALYSIS
if (!$Quick) {
    Show-Progress "FILE SYSTEM" "Analyzing recent file system changes"
    
    try {
        # Recent file modifications in key directories
        $recentDate = (Get-Date).AddDays(-$DaysBack)
        $keyPaths = @(
            "$env:TEMP",
            "$env:APPDATA",
            "$env:LOCALAPPDATA\Temp",
            "$env:PUBLIC",
            "C:\ProgramData"
        )
        
        $recentFiles = @()
        foreach ($path in $keyPaths) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object {$_.LastWriteTime -gt $recentDate -or $_.CreationTime -gt $recentDate} |
                    Select-Object FullName, CreationTime, LastWriteTime, Length,
                        @{N='Extension';E={$_.Extension}},
                        @{N='Hidden';E={$_.Attributes -band [System.IO.FileAttributes]::Hidden}} |
                    ForEach-Object { $recentFiles += $_ }
            }
        }
        
        if ($recentFiles) {
            $recentFiles | Sort-Object CreationTime -Descending |
                Select-Object -First 500 |
                Export-Csv "$incidentPath\FileSystem\recent_files_key_locations.csv" -NoTypeInformation
            
            # Suspicious executables
            $suspExes = $recentFiles | Where-Object {
                $_.Extension -match "\.exe$|\.dll$|\.bat$|\.cmd$|\.ps1$|\.vbs$|\.js$|\.jar$|\.scr$"
            }
            if ($suspExes) {
                $suspExes | Export-Csv "$incidentPath\ALERTS\recent_executables.csv" -NoTypeInformation
                Write-Host "  - Found $($suspExes.Count) recent executable files" -ForegroundColor Yellow
            }
        }
        
        # Check for ransomware indicators
        $ransomwareExts = "\.encrypted$|\.locked$|\.crypto$|\.enc$|\.[a-z0-9]{5,8}$"
        $encryptedFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {$_.Extension -match $ransomwareExts} |
            Select-Object -First 20
        
        if ($encryptedFiles) {
            $encryptedFiles | Select-Object FullName, Extension, Length, LastWriteTime |
                Export-Csv "$incidentPath\ALERTS\possible_ransomware_files.csv" -NoTypeInformation
            Write-Host "  - ALERT: Possible ransomware activity detected!" -ForegroundColor Red
        }
        
        # Shadow copies
        vssadmin list shadows 2>&1 | Out-File "$incidentPath\FileSystem\shadow_copies.txt"
        
        # Recently accessed documents
        $recentDocs = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 50
        $recentDocs | Select-Object Name, LastWriteTime, Target |
            Export-Csv "$incidentPath\FileSystem\recent_documents.csv" -NoTypeInformation
        
    } catch {
        Write-Host "WARNING: File system analysis incomplete: $_" -ForegroundColor Yellow
    }
}

# SECTION 7: ENHANCED EVENT LOG COLLECTION
Show-Progress "EVENT LOGS" "Collecting and analyzing event logs"

try {
    # Critical security events
    $securityEvents = @{
        # Authentication
        "4624" = "Successful logon"
        "4625" = "Failed logon"
        "4634" = "Logoff"
        "4647" = "User initiated logoff"
        "4648" = "Logon using explicit credentials"
        "4672" = "Special privileges assigned"
        "4776" = "NTLM authentication"
        
        # Account changes
        "4720" = "User account created"
        "4722" = "User account enabled"
        "4723" = "Password change attempt"
        "4724" = "Password reset attempt"
        "4725" = "User account disabled"
        "4726" = "User account deleted"
        "4738" = "User account changed"
        "4740" = "User account locked"
        
        # Group changes
        "4728" = "Member added to security group"
        "4732" = "Member added to security group"
        "4756" = "Member added to universal group"
        
        # Process/Service
        "4688" = "Process creation"
        "4689" = "Process termination"
        "7034" = "Service crashed unexpectedly"
        "7035" = "Service sent start/stop control"
        "7036" = "Service started or stopped"
        "7040" = "Service start type changed"
        "7045" = "Service was installed"
        
        # System
        "1102" = "Audit log cleared"
        "4719" = "System audit policy changed"
        
        # Network shares
        "5140" = "Network share accessed"
        "5142" = "Network share added"
        "5144" = "Network share deleted"
        
        # Scheduled tasks
        "4698" = "Scheduled task created"
        "4699" = "Scheduled task deleted"
        "4700" = "Scheduled task enabled"
        "4701" = "Scheduled task disabled"
        "4702" = "Scheduled task updated"
    }
    
    # Get security events
    $secIds = $securityEvents.Keys | ForEach-Object {[int]$_}
    $securityFilter = @{
        LogName = 'Security'
        ID = $secIds
        StartTime = (Get-Date).AddDays(-$DaysBack)
    }
    
    Show-Progress "EVENT LOGS" "Extracting security events"
    $secEvents = Get-WinEvent -FilterHashtable $securityFilter -MaxEvents 5000 -ErrorAction SilentlyContinue
    
    if ($secEvents) {
        $secEvents | Select-Object TimeCreated, Id,
            @{N='EventType';E={$securityEvents[$_.Id.ToString()]}},
            @{N='User';E={$_.Properties[1].Value}},
            @{N='Computer';E={$_.MachineName}},
            Message | Export-Csv "$incidentPath\Logs\security_events_analyzed.csv" -NoTypeInformation
        
        # Analyze logon patterns
        $logonEvents = $secEvents | Where-Object {$_.Id -in @(4624,4625)}
        $failedLogons = $logonEvents | Where-Object {$_.Id -eq 4625} | Group-Object {$_.Properties[5].Value} |
            Where-Object {$_.Count -gt 5} | Select-Object Name, Count
        
        if ($failedLogons) {
            $failedLogons | Export-Csv "$incidentPath\ALERTS\bruteforce_attempts.csv" -NoTypeInformation
            Write-Host "  - ALERT: Possible brute force attempts detected!" -ForegroundColor Red
        }
    }
    
    # PowerShell logs
    Show-Progress "EVENT LOGS" "Analyzing PowerShell activity"
    @('Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational') | ForEach-Object {
        $psEvents = Get-WinEvent -LogName $_ -MaxEvents 1000 -ErrorAction SilentlyContinue |
            Where-Object {$_.TimeCreated -gt (Get-Date).AddDays(-$DaysBack)}
        
        if ($psEvents) {
            # Look for suspicious commands
            $suspiciousPS = $psEvents | Where-Object {
                $_.Message -match "DownloadString|DownloadFile|Invoke-Expression|IEX|EncodedCommand|bypass|hidden|nop|noni|enc|base64"
            }
            
            if ($suspiciousPS) {
                $suspiciousPS | Select-Object TimeCreated, Id, Message |
                    Export-Csv "$incidentPath\ALERTS\suspicious_powershell.csv" -NoTypeInformation
                Write-Host "  - ALERT: Suspicious PowerShell activity detected!" -ForegroundColor Red
            }
        }
    }
    
    # System log for service installations
    $sysEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045; StartTime=(Get-Date).AddDays(-$DaysBack)} -ErrorAction SilentlyContinue
    if ($sysEvents) {
        $sysEvents | Select-Object TimeCreated,
            @{N='ServiceName';E={$_.Properties[0].Value}},
            @{N='ServiceFile';E={$_.Properties[1].Value}},
            @{N='ServiceType';E={$_.Properties[2].Value}},
            @{N='ServiceStart';E={$_.Properties[3].Value}},
            @{N='ServiceAccount';E={$_.Properties[4].Value}} |
            Export-Csv "$incidentPath\Logs\new_services_installed.csv" -NoTypeInformation
    }
    
    # Export full logs
    Show-Progress "EVENT LOGS" "Exporting full event logs"
    $exportLogs = @(
        "Security",
        "System", 
        "Application",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
        "Microsoft-Windows-Bits-Client/Operational",
        "Microsoft-Windows-WinRM/Operational"
    )
    
    foreach ($log in $exportLogs) {
        $logFile = $log.Replace('/', '-').Replace('\', '-')
        wevtutil epl $log "$incidentPath\Logs\$logFile.evtx" 2>$null
    }
    
} catch {
    Write-Host "WARNING: Event log analysis incomplete: $_" -ForegroundColor Yellow
}

# SECTION 8: BROWSER AND DOWNLOAD ANALYSIS
if ($Deep) {
    Show-Progress "BROWSER ANALYSIS" "Checking browser artifacts"
    
    try {
        # Chrome downloads
        $chromeHistory = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
        if (Test-Path $chromeHistory) {
            Copy-Item $chromeHistory "$incidentPath\browser_chrome_history.db" -Force
        }
        
        # Edge downloads
        $edgeHistory = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
        if (Test-Path $edgeHistory) {
            Copy-Item $edgeHistory "$incidentPath\browser_edge_history.db" -Force
        }
        
        # Recent downloads folder
        $downloads = Get-ChildItem "$env:USERPROFILE\Downloads" -ErrorAction SilentlyContinue |
            Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-$DaysBack)} |
            Select-Object Name, Length, CreationTime, LastWriteTime,
                @{N='Zone';E={
                    try {
                        $ads = Get-Item $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue
                        if ($ads) { (Get-Content $_.FullName:Zone.Identifier)[1].Replace('ZoneId=','') }
                        else { 'Local' }
                    } catch { 'Unknown' }
                }}
        
        if ($downloads) {
            $downloads | Export-Csv "$incidentPath\FileSystem\recent_downloads.csv" -NoTypeInformation
            
            # Files from Internet (Zone 3)
            $internetFiles = $downloads | Where-Object {$_.Zone -eq '3'}
            if ($internetFiles) {
                Write-Host "  - Found $($internetFiles.Count) recently downloaded files from Internet" -ForegroundColor Yellow
            }
        }
        
    } catch {
        Write-Host "WARNING: Browser analysis incomplete: $_" -ForegroundColor Yellow
    }
}

# SECTION 9: SECURITY SOFTWARE STATUS
Show-Progress "SECURITY" "Checking security software status"

try {
    # Windows Defender status
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defenderStatus) {
        $defenderStatus | Select-Object AntivirusEnabled, AntispywareEnabled, 
            RealTimeProtectionEnabled, BehaviorMonitorEnabled,
            AntivirusSignatureLastUpdated, AntispywareSignatureLastUpdated,
            NISEnabled, OnAccessProtectionEnabled |
            Export-Csv "$incidentPath\System\defender_status.csv" -NoTypeInformation
        
        if (!$defenderStatus.RealTimeProtectionEnabled) {
            "WARNING: Windows Defender Real-Time Protection is DISABLED!" | 
                Out-File "$incidentPath\ALERTS\defender_disabled.txt"
            Write-Host "  - ALERT: Windows Defender Real-Time Protection is disabled!" -ForegroundColor Red
        }
    }
    
    # Get all AV products
    Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
        Select-Object displayName, productState, pathToSignedProductExe |
        Export-Csv "$incidentPath\System\antivirus_products.csv" -NoTypeInformation
    
    # Firewall status
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
        Export-Csv "$incidentPath\System\firewall_profiles.csv" -NoTypeInformation
    
} catch {
    Write-Host "WARNING: Security software check incomplete: $_" -ForegroundColor Yellow
}

# SECTION 10: COMPREHENSIVE SUMMARY AND IOC GENERATION
Show-Progress "ANALYSIS" "Generating comprehensive incident summary"

try {
    # Collect all alerts
    $alertFiles = Get-ChildItem "$incidentPath\ALERTS" -Filter "*.csv" -ErrorAction SilentlyContinue
    $alertCount = $alertFiles.Count
    
    # Generate IoCs
    $iocs = @{
        IPs = @()
        Domains = @()
        Hashes = @()
        ProcessNames = @()
        ServiceNames = @()
        FileNames = @()
        RegistryKeys = @()
    }
    
    # Extract suspicious IPs from connections
    if (Test-Path "$incidentPath\Network\all_connections.csv") {
        $connections = Import-Csv "$incidentPath\Network\all_connections.csv"
        $externalIPs = $connections | Where-Object {
            $_.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fe80:)" -and
            $_.RemoteAddress -ne "0.0.0.0"
        } | Select-Object -ExpandProperty RemoteAddress -Unique
        $iocs.IPs = $externalIPs
    }
    
    # Extract suspicious process names
    if (Test-Path "$incidentPath\ALERTS\suspicious_process_names.csv") {
        $suspProcs = Import-Csv "$incidentPath\ALERTS\suspicious_process_names.csv"
        $iocs.ProcessNames = $suspProcs.Name | Select-Object -Unique
    }
    
    # Extract file hashes from network processes
    if (Test-Path "$incidentPath\Network\network_processes_detailed.csv") {
        $netProcs = Import-Csv "$incidentPath\Network\network_processes_detailed.csv"
        $iocs.Hashes = $netProcs | Where-Object {$_.MD5Hash -ne 'N/A'} | 
            Select-Object -ExpandProperty MD5Hash -Unique
    }
    
    # Save IOCs
    $iocs | ConvertTo-Json -Depth 3 | Out-File "$incidentPath\ALERTS\extracted_iocs.json"
    
    # Calculate collection duration
    $collectionDuration = (Get-Date) - $startTime
    
    # Generate final summary
    $summary = @"
========================================
COMPREHENSIVE INCIDENT RESPONSE SUMMARY
========================================
Generated: $(Get-Date)
Hostname: $env:COMPUTERNAME
Domain: $env:USERDOMAIN
Current User: $env:USERNAME
System: $(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Caption)

COLLECTION PARAMETERS:
- Mode: $(if($Quick){"Quick"}elseif($Deep){"Deep"}else{"Standard"})
- Days Back: $DaysBack
- Collection Time: $($collectionDuration.ToString())

CRITICAL ALERTS FOUND: $alertCount
$(if($alertFiles){
    $alertFiles | ForEach-Object {
        $count = (Import-Csv $_.FullName | Measure-Object).Count
        "- $($_.BaseName): $count items"
    } | Out-String
})

NETWORK SUMMARY:
- Total Connections: $(if($connections){$connections.Count}else{0})
- Established: $(if($establishedConns){$establishedConns.Count}else{0})
- Listening Ports: $(if($listeningPorts){$listeningPorts.Count}else{0})
- External IPs Connected: $(if($iocs.IPs){$iocs.IPs.Count}else{0})

SUSPICIOUS FINDINGS:
- Processes in suspicious locations: $(if($suspiciousProcs){$suspiciousProcs.Count}else{0})
- Remote access tools: $(if($remoteTools -or $remoteProcesses -or $remoteServices){($remoteTools.Count + $remoteProcesses.Count + $remoteServices.Count)}else{0})
- PowerShell with encoded commands: $(if($encodedPS){$encodedPS.Count}else{0})
- Recently created scheduled tasks: $(if($recentTasks){$recentTasks.Count}else{0})

TARGET PIDs INVESTIGATION (6640, 11492, 2072, 5300):
$(if($pidInvestigation){
    $pidInvestigation | ForEach-Object {
        "- PID $($_.TargetPID): $($_.ProcessName)"
        "  Path: $($_.Path)"
        "  Command: $($_.CommandLine)"
        "  Parent: $($_.Parent)"
    } | Out-String
}else{
    "- None of the target PIDs were found running"
})

IMMEDIATE RECOMMENDED ACTIONS:
1. Review all files in $incidentPath\ALERTS\ folder
2. Investigate external IPs in extracted_iocs.json
3. Check suspicious_network_connections.csv for backdoors
4. Review remote_access_* files for unauthorized tools
5. Examine scheduled_tasks_analysis.csv for persistence
6. Check security_events_analyzed.csv for authentication anomalies

EVIDENCE PACKAGE:
- Total Size: $([math]::Round((Get-ChildItem $incidentPath -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB, 2)) MB
- Location: $incidentPath
- ZIP Archive: $(if(Test-Path "$incidentPath.zip"){"$incidentPath.zip"}else{"Not created"})

NEXT STEPS:
$(if($alertCount -gt 5){
"*** HIGH PRIORITY INCIDENT ***
1. IMMEDIATELY isolate this system from network
2. Preserve system memory with WinPMEM or similar
3. Create forensic image of disk
4. Do not reboot or shutdown the system
5. Engage incident response team"
}elseif($alertCount -gt 0){
"** SUSPICIOUS ACTIVITY DETECTED **
1. Monitor system closely
2. Review all alerts thoroughly  
3. Consider network isolation
4. Prepare for full forensic collection"
}else{
"* ROUTINE COLLECTION COMPLETE *
1. Review collected data
2. No immediate threats detected
3. Archive data for baseline"
})

========================================
"@
    
    $summary | Out-File "$incidentPath\INCIDENT_SUMMARY.txt"
    Write-Host $summary -ForegroundColor Cyan
    
    # Create HTML report if deep mode
    if ($Deep) {
        $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Incident Response Report - $env:COMPUTERNAME</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .alert { background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; margin: 10px 0; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeeba; padding: 10px; margin: 10px 0; }
        .info { background-color: #d1ecf1; border: 1px solid #bee5eb; padding: 10px; margin: 10px 0; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Incident Response Report</h1>
    <div class="info">
        <strong>System:</strong> $env:COMPUTERNAME<br>
        <strong>Generated:</strong> $(Get-Date)<br>
        <strong>Alerts Found:</strong> $alertCount
    </div>
    
    <h2>Critical Alerts</h2>
    $(if($alertFiles){
        $alertFiles | ForEach-Object {
            $data = Import-Csv $_.FullName | Select-Object -First 10
            "<h3>$($_.BaseName)</h3>"
            if($data){
                "<table>"
                "<tr>"
                $data[0].PSObject.Properties.Name | ForEach-Object { "<th>$_</th>" }
                "</tr>"
                $data | ForEach-Object {
                    "<tr>"
                    $_.PSObject.Properties.Value | ForEach-Object { "<td>$_</td>" }
                    "</tr>"
                }
                "</table>"
            }
        } | Out-String
    })
    
    <h2>Network Connections Summary</h2>
    <p>Review the full network analysis in the Network folder.</p>
    
    <h2>Recommended Actions</h2>
    <div class="alert">
        <ol>
            <li>Isolate system if critical alerts found</li>
            <li>Review all CSV files in ALERTS folder</li>
            <li>Check IOCs against threat intelligence</li>
            <li>Preserve evidence before remediation</li>
        </ol>
    </div>
</body>
</html>
"@
        $htmlReport | Out-File "$incidentPath\INCIDENT_REPORT.html"
    }
    
} catch {
    Write-Host "ERROR generating summary: $_" -ForegroundColor Red
}

# Cleanup and final steps
Stop-Transcript

# Create ZIP archive
try {
    Show-Progress "FINALIZE" "Creating evidence archive"
    Compress-Archive -Path "$incidentPath\*" -DestinationPath "$incidentPath.zip" -CompressionLevel Optimal -Force
    Write-Host "`n=== EVIDENCE ARCHIVE CREATED: $incidentPath.zip ===" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Could not create ZIP archive: $_" -ForegroundColor Yellow
}

Write-Host "`n=== INCIDENT RESPONSE COLLECTION COMPLETE ===" -ForegroundColor Green
Write-Host "Evidence location: $incidentPath" -ForegroundColor Cyan
Write-Host "`nIMPORTANT: Review $incidentPath\INCIDENT_SUMMARY.txt for findings and recommendations" -ForegroundColor Yellow

# If critical alerts, sound system beep
if ($alertCount -gt 5) {
    [console]::beep(1000,500)
    [console]::beep(1000,500)
    Write-Host "`n!!! CRITICAL ALERTS DETECTED - IMMEDIATE ACTION REQUIRED !!!" -ForegroundColor Red -BackgroundColor Yellow
}
