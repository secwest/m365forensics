# ULTIMATE INCIDENT RESPONSE TRIAGE SCRIPT v4.3 - WITH ENHANCED PROGRESS
# Run as Administrator: powershell -ExecutionPolicy Bypass -File .\Triage.ps1

param(
    [switch]$Quick = $false,
    [switch]$Deep = $false,
    [switch]$UltraDeep = $false,
    [int]$TimeoutSeconds = 30,
    [int]$DaysBack = 7,
    [array]$TargetPIDs = @(),
    [array]$TargetIPs = @(),
    [switch]$SkipMemory = $false,
    [switch]$SkipFileSystem = $false,
    [switch]$SkipBrowser = $false,
    [switch]$SkipNetwork = $false,
    [switch]$SkipDNS = $false,
    [switch]$LiveResponse = $false
)

# Initialize
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "Continue"  # Changed from SilentlyContinue to show progress bars
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$incidentPath = "C:\incident_$timestamp"
$global:alertCount = 0
$global:criticalAlerts = @()
$global:findings = @()
$global:networkConnected = $false
$global:iocs = @{
    IPs = @()
    Domains = @()
    Hashes = @()
    ProcessNames = @()
    ServiceNames = @()
    FileNames = @()
    RegistryKeys = @()
    Users = @()
    Mutexes = @()
}

# Progress tracking variables
$script:mainProgressId = 0
$script:subProgressId = 1

# Enhanced color output with logging - NO UNICODE
function Write-ColorOutput {
    param($Message, $Type = "Info", $LogOnly = $false, $Critical = $false)
    
    $timestamp = Get-Date -Format "HH:mm:ss.fff"
    $logMessage = "[$timestamp] [$Type] $Message"
    
    if (!$LogOnly) {
        switch ($Type) {
            "Success" { Write-Host $logMessage -ForegroundColor Green }
            "Error" { Write-Host $logMessage -ForegroundColor Red }
            "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
            "Alert" { 
                if ($Critical) {
                    Write-Host $logMessage -ForegroundColor White -BackgroundColor Red
                    $global:criticalAlerts += $Message
                } else {
                    Write-Host $logMessage -ForegroundColor Red -BackgroundColor Yellow
                }
            }
            "Info" { Write-Host $logMessage -ForegroundColor Cyan }
            "Progress" { Write-Host $logMessage -ForegroundColor Gray }
            "Finding" { Write-Host $logMessage -ForegroundColor Magenta }
            default { Write-Host $logMessage }
        }
    }
    
    # Always log - with error handling
    try {
        if (Test-Path "$incidentPath\console_output.log") {
            $logMessage | Out-File "$incidentPath\console_output.log" -Append -Force
        }
        
        if ($Type -eq "Alert" -and (Test-Path "$incidentPath\ALERTS")) {
            $logMessage | Out-File "$incidentPath\ALERTS\alert_log.txt" -Append -Force
        }
    } catch {
        # Silent fail on logging errors
    }
}

# Test network connectivity
function Test-NetworkConnection {
    param([int]$TimeoutMs = 2000)
    
    try {
        # Quick ping test to common DNS servers
        $ping = New-Object System.Net.NetworkInformation.Ping
        $dnsServers = @("8.8.8.8", "1.1.1.1", "208.67.222.222")
        
        foreach ($dns in $dnsServers) {
            try {
                $reply = $ping.Send($dns, $TimeoutMs)
                if ($reply.Status -eq "Success") {
                    return $true
                }
            } catch {
                continue
            }
        }
        
        # Also check if we have any active network adapters
        $activeAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq "Up"}
        if ($activeAdapters) {
            return $true
        }
        
        return $false
    } catch {
        return $false
    } finally {
        if ($ping) {
            $ping.Dispose()
        }
    }
}

# DNS Resolution with timeout and network check
function Resolve-DNSWithTimeout {
    param(
        [string]$IPAddress,
        [int]$TimeoutSeconds = 2
    )
    
    # Quick checks
    if ($Quick -or $SkipDNS) {
        return "DNS-SKIPPED"
    }
    
    if (!$global:networkConnected) {
        return "OFFLINE"
    }
    
    # Validate IP address
    try {
        $null = [System.Net.IPAddress]::Parse($IPAddress)
    } catch {
        return "INVALID-IP"
    }
    
    # Check cache first
    if ($script:dnsCache.ContainsKey($IPAddress)) {
        return $script:dnsCache[$IPAddress]
    }
    
    # Create a runspace for true timeout control
    $runspace = $null
    $powershell = $null
    
    try {
        $runspace = [runspacefactory]::CreateRunspace()
        $runspace.Open()
        
        $powershell = [powershell]::Create()
        $powershell.Runspace = $runspace
        
        $script = {
            param($ip)
            try {
                $result = [System.Net.Dns]::GetHostEntry($ip)
                return $result.HostName
            } catch {
                return "NO-PTR"
            }
        }
        
        $null = $powershell.AddScript($script).AddArgument($IPAddress)
        $handle = $powershell.BeginInvoke()
        
        # Wait for completion with timeout
        $completed = $handle.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000)
        
        if ($completed) {
            $result = $powershell.EndInvoke($handle)
            $dnsResult = if ($result -and $result.Count -gt 0) { $result[0] } else { "NO-PTR" }
        } else {
            # Timeout occurred
            $powershell.Stop()
            $dnsResult = "TIMEOUT"
        }
    } catch {
        $dnsResult = "ERROR"
    } finally {
        if ($powershell) {
            $powershell.Dispose()
        }
        if ($runspace) {
            $runspace.Close()
            $runspace.Dispose()
        }
    }
    
    # Cache the result
    $script:dnsCache[$IPAddress] = $dnsResult
    
    return $dnsResult
}

# Global DNS cache
$script:dnsCache = @{}

# Main progress phases
$script:phases = @(
    "Initialization",
    "Rapid Triage",
    "Network Forensics",
    "Process Forensics",
    "Persistence Analysis",
    "Memory Forensics",
    "File System Forensics",
    "Browser Forensics",
    "Event Log Forensics",
    "Security Assessment",
    "Remote Access Investigation",
    "IOC Extraction",
    "Final Analysis"
)

# Initialize main progress
Write-Progress -Id $script:mainProgressId -Activity "Incident Response Collection" -Status "Starting..." -PercentComplete 0

# Check network connectivity at start
Write-Host "Checking network connectivity..." -ForegroundColor Gray
$global:networkConnected = Test-NetworkConnection
if ($global:networkConnected) {
    Write-Host "Network: CONNECTED" -ForegroundColor Green
} else {
    Write-Host "Network: OFFLINE (DNS lookups will be skipped)" -ForegroundColor Yellow
    $SkipDNS = $true
}

# Create comprehensive folder structure with error handling
Write-Progress -Id $script:mainProgressId -Activity "Incident Response Collection" -Status "Phase 1/13: Initialization" -PercentComplete 5
try {
    $folders = @(
        "$incidentPath",
        "$incidentPath\Network",
        "$incidentPath\Network\Connections",
        "$incidentPath\Network\Captures",
        "$incidentPath\Processes",
        "$incidentPath\Processes\Dumps",
        "$incidentPath\Persistence",
        "$incidentPath\Persistence\Registry",
        "$incidentPath\Persistence\WMI",
        "$incidentPath\Persistence\Tasks",
        "$incidentPath\Logs",
        "$incidentPath\Logs\Windows",
        "$incidentPath\Logs\Applications",
        "$incidentPath\System",
        "$incidentPath\System\Drivers",
        "$incidentPath\System\Security",
        "$incidentPath\ALERTS",
        "$incidentPath\Memory",
        "$incidentPath\FileSystem",
        "$incidentPath\FileSystem\Timeline",
        "$incidentPath\Browser",
        "$incidentPath\IOCs",
        "$incidentPath\Artifacts",
        "$incidentPath\Timeline"
    )
    
    foreach ($folder in $folders) {
        try {
            $null = New-Item -ItemType Directory -Path $folder -Force -ErrorAction SilentlyContinue
        } catch {
            # Continue even if some folders fail
        }
    }
    
    # Test write access
    try {
        "Test" | Out-File "$incidentPath\test.txt" -Force
        Remove-Item "$incidentPath\test.txt" -Force
    } catch {
        Write-Host "ERROR: Cannot write to incident folder. Check permissions." -ForegroundColor Red
        exit 1
    }
    
    Start-Transcript -Path "$incidentPath\collection_transcript.txt" -Force -ErrorAction SilentlyContinue | Out-Null
} catch {
    Write-Host "ERROR: Cannot create incident folder at $incidentPath. Exiting." -ForegroundColor Red
    exit 1
}

# Display banner - NO UNICODE
$banner = @"
================================================================================
    ULTIMATE INCIDENT RESPONSE COLLECTION v4.3 - WITH PROGRESS TRACKING
================================================================================
    Time: $(Get-Date)
    Mode: $(if($UltraDeep){"ULTRA-DEEP"}elseif($Deep){"DEEP"}elseif($Quick){"QUICK"}else{"STANDARD"})
    Output: $incidentPath
    Network: $(if($global:networkConnected){"CONNECTED"}else{"OFFLINE"})
    DNS: $(if($SkipDNS -or !$global:networkConnected){"DISABLED"}else{"ENABLED (2s timeout)"})
================================================================================
"@
Write-Host $banner -ForegroundColor Yellow

# Check privileges
$isAdmin = $false
try {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $isAdmin = $false
}

if (!$isAdmin) {
    Write-ColorOutput "WARNING: Not running as Administrator. Collection will be limited!" "Warning"
}

# SECTION 1: ULTRA-FAST TRIAGE (Always run first)
Write-Progress -Id $script:mainProgressId -Activity "Incident Response Collection" -Status "Phase 2/13: Rapid Triage" -PercentComplete 10
Write-ColorOutput "`n[PHASE 1: RAPID TRIAGE]" "Progress"

try {
    # Get critical system state with error handling
    $osInfo = $null
    $csInfo = $null
    
    try {
        $osInfo = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
        $csInfo = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
    } catch {
        Write-ColorOutput "Warning: Could not retrieve system info via WMI" "Warning"
        # Try alternative methods
        try {
            $osInfo = Get-CimInstance Win32_OperatingSystem
            $csInfo = Get-CimInstance Win32_ComputerSystem
        } catch {
            Write-ColorOutput "Error: Cannot retrieve basic system information" "Error"
        }
    }
    
    if ($osInfo -and $csInfo) {
        $bootTime = try { $osInfo.ConvertToDateTime($osInfo.LastBootUpTime) } catch { "Unknown" }
        $uptime = if ($bootTime -ne "Unknown") { (Get-Date) - $bootTime } else { "Unknown" }
        
        Write-ColorOutput "System: $($csInfo.Name) | OS: $($osInfo.Caption) | Boot: $bootTime" "Info"
        if ($uptime -ne "Unknown") {
            Write-ColorOutput "Domain: $($csInfo.Domain) | User: $env:USERNAME | Uptime: $($uptime.Days)d $($uptime.Hours)h" "Info"
        }
    }
    
    # Quick threat assessment with error handling
    $quickChecks = @{
        "Active_Connections" = 0
        "Listening_Ports" = 0
        "Running_Processes" = 0
        "Services" = 0
        "Logged_Users" = 0
    }
    
    try {
        $tcpConns = Get-NetTCPConnection -ErrorAction SilentlyContinue
        if ($tcpConns) {
            $quickChecks.Active_Connections = ($tcpConns | Where-Object {$_.State -eq "Established"}).Count
            $quickChecks.Listening_Ports = ($tcpConns | Where-Object {$_.State -eq "Listen"}).Count
        }
    } catch {
        Write-ColorOutput "Warning: Could not enumerate network connections" "Warning"
    }
    
    try {
        $quickChecks.Running_Processes = (Get-Process -ErrorAction SilentlyContinue).Count
        $quickChecks.Services = (Get-Service -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq "Running"}).Count
    } catch { }
    
    try {
        $quickChecks.Logged_Users = (quser 2>&1 | Select-String "Active" -ErrorAction SilentlyContinue).Count
    } catch { }
    
    Write-ColorOutput "Quick Stats: Connections=$($quickChecks.Active_Connections), Listeners=$($quickChecks.Listening_Ports), Processes=$($quickChecks.Running_Processes)" "Info"
    
    # Immediate threat indicators
    try {
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defender -and !$defender.RealTimeProtectionEnabled) {
            Write-ColorOutput "DEFENDER DISABLED - System is unprotected!" "Alert" -Critical $true
            $global:alertCount += 5
        }
    } catch {
        Write-ColorOutput "Warning: Could not check Windows Defender status" "Warning"
    }
    
    # Check for obvious compromise indicators
    try {
        $obviousThreats = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.ProcessName -match "^[a-z]{8}$|^[0-9]{6,}$|mimikatz|lazagne|procdump|pwdump|gsecdump"
        }
        if ($obviousThreats) {
            Write-ColorOutput "KNOWN MALICIOUS TOOLS DETECTED!" "Alert" -Critical $true
            $obviousThreats | ForEach-Object {
                Write-ColorOutput "  - $($_.ProcessName) [PID: $($_.Id)]" "Alert"
            }
            $global:alertCount += 10
        }
    } catch {
        Write-ColorOutput "Warning: Could not check for malicious processes" "Warning"
    }
    
} catch {
    Write-ColorOutput "Error in rapid triage: $_" "Error"
}

# SECTION 2: NETWORK ANALYSIS (ENHANCED WITH FIXES)
if (!$SkipNetwork) {
    Write-Progress -Id $script:mainProgressId -Activity "Incident Response Collection" -Status "Phase 3/13: Network Forensics" -PercentComplete 20
    Write-ColorOutput "`n[PHASE 2: NETWORK FORENSICS]" "Progress"
    
    try {
        Write-ColorOutput "Capturing network state..." "Progress"
        
        # Get all connections with error handling
        $allConnections = @()
        $udpEndpoints = @()
        $established = @()
        $listening = @()
        
        try {
            $allConnections = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
            if (!$allConnections) {
                # Fallback to netstat if Get-NetTCPConnection fails
                Write-ColorOutput "Using netstat fallback for connections..." "Warning"
                # We'll use netstat output later
            }
        } catch {
            Write-ColorOutput "Warning: Could not enumerate TCP connections" "Warning"
        }
        
        try {
            $udpEndpoints = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)
        } catch {
            Write-ColorOutput "Warning: Could not enumerate UDP endpoints" "Warning"
        }
        
        if ($allConnections) {
            $established = @($allConnections | Where-Object {$_.State -eq "Established"})
            $listening = @($allConnections | Where-Object {$_.State -eq "Listen"})
        }
        
        Write-ColorOutput "Found $($allConnections.Count) TCP connections, processing..." "Progress"
        
        # Enhanced connection analysis with error handling
        $connectionDetails = @()
        $totalConns = $allConnections.Count
        $processed = 0
        $startTime = Get-Date
        
        # Process connections with progress bar
        foreach ($conn in $allConnections) {
            $processed++
            
            # Update progress bar
            $percentComplete = [math]::Round(($processed / $totalConns) * 100)
            Write-Progress -Id $script:subProgressId -ParentId $script:mainProgressId `
                -Activity "Processing Network Connections" `
                -Status "Connection $processed of $totalConns" `
                -PercentComplete $percentComplete
            
            # Skip detailed analysis in Quick mode
            if ($Quick -and $conn.State -ne "Established") {
                continue
            }
            
            # Get process info with error handling
            $proc = $null
            try {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            } catch { }
            
            # DNS resolution with timeout (skip for internal IPs)
            $remoteDNS = "N/A"
            if ($conn.RemoteAddress -and $conn.RemoteAddress -notmatch "^(10\.|172\.|192\.168\.|127\.|::1|0\.0\.0\.0)") {
                $remoteDNS = Resolve-DNSWithTimeout -IPAddress $conn.RemoteAddress
            }
            
            # Get WMI info only for suspicious connections in standard mode
            $wmiInfo = $null
            if (!$Quick -and $conn.RemoteAddress -and ($conn.RemoteAddress -notmatch "^(10\.|172\.|192\.168\.|127\.)")) {
                try {
                    $wmiInfo = Get-WmiObject Win32_Process -Filter "ProcessId=$($conn.OwningProcess)" -ErrorAction SilentlyContinue
                } catch { }
            }
            
            $connectionDetails += [PSCustomObject]@{
                LocalAddress = if($conn.LocalAddress) {$conn.LocalAddress} else {"Unknown"}
                LocalPort = if($conn.LocalPort) {$conn.LocalPort} else {0}
                RemoteAddress = if($conn.RemoteAddress) {$conn.RemoteAddress} else {"Unknown"}
                RemoteDNS = $remoteDNS
                RemotePort = if($conn.RemotePort) {$conn.RemotePort} else {0}
                State = if($conn.State) {$conn.State} else {"Unknown"}
                ProcessId = if($conn.OwningProcess) {$conn.OwningProcess} else {0}
                ProcessName = if($proc) {$proc.ProcessName} else {"Unknown"}
                ProcessPath = if($proc) {$proc.Path} else {if($wmiInfo) {$wmiInfo.ExecutablePath} else {"N/A"}}
                CommandLine = if($wmiInfo -and !$Quick) {$wmiInfo.CommandLine} else {"N/A"}
                CreationTime = if($conn.CreationTime) {$conn.CreationTime} else {"Unknown"}
                GeoLocation = "Unknown"
            }
        }
        
        # Complete sub-progress
        Write-Progress -Id $script:subProgressId -Completed
        
        # Export connections with error handling
        if ($connectionDetails) {
            try {
                $connectionDetails | Export-Csv "$incidentPath\Network\Connections\all_connections_detailed.csv" -NoTypeInformation
            } catch {
                Write-ColorOutput "Warning: Could not export connection details" "Warning"
            }
        }
        
        Write-ColorOutput "Network capture completed in $([math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)) seconds" "Success"
        
        # Suspicious connection detection
        Write-ColorOutput "Analyzing connections for threats..." "Progress"
        
        $suspiciousConnections = @()
        $knownC2Ports = @(443, 4444, 4445, 5555, 6666, 7777, 8080, 8443, 8888, 9999, 12345, 31337, 54321)
        
        foreach ($conn in $established) {
            $reasons = @()
            $severity = 0
            
            # Check various suspicious patterns
            if ($conn.RemotePort -in $knownC2Ports) {
                $reasons += "Known C2 port: $($conn.RemotePort)"
                $severity += 3
            }
            
            if ($conn.LocalPort -gt 49152 -and $conn.RemoteAddress -notmatch "^(10\.|172\.|192\.168\.)") {
                $reasons += "High ephemeral port to external IP"
                $severity += 2
            }
            
            # PowerShell/CMD with network
            try {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                if ($proc -and $proc.ProcessName -match "powershell|cmd|wscript|cscript|mshta|rundll32") {
                    $reasons += "Scripting process with network: $($proc.ProcessName)"
                    $severity += 4
                }
            } catch { }
            
            # Check against target IPs if specified
            if ($TargetIPs -and $conn.RemoteAddress -in $TargetIPs) {
                $reasons += "Matches target IP investigation"
                $severity += 5
            }
            
            if ($reasons.Count -gt 0) {
                $suspiciousConnections += [PSCustomObject]@{
                    Severity = $severity
                    LocalEndpoint = "$($conn.LocalAddress):$($conn.LocalPort)"
                    RemoteEndpoint = "$($conn.RemoteAddress):$($conn.RemotePort)"
                    Process = if($proc) {"$($proc.ProcessName) [$($conn.OwningProcess)]"} else {"Unknown [$($conn.OwningProcess)]"}
                    Reasons = $reasons -join "; "
                    Timestamp = Get-Date
                }
            }
        }
        
        if ($suspiciousConnections) {
            try {
                $suspiciousConnections | Sort-Object Severity -Descending | 
                    Export-Csv "$incidentPath\ALERTS\suspicious_connections_prioritized.csv" -NoTypeInformation
            } catch { }
            
            Write-ColorOutput "Found $($suspiciousConnections.Count) suspicious connections!" "Alert"
            $global:alertCount += $suspiciousConnections.Count
            
            # Show top threats
            $suspiciousConnections | Sort-Object Severity -Descending | Select-Object -First 3 | ForEach-Object {
                Write-ColorOutput "  - SEVERITY $($_.Severity): $($_.RemoteEndpoint) | $($_.Reasons)" "Alert"
            }
        }
        
        # Network statistics
        Write-ColorOutput "Calculating network statistics..." "Progress"
        
        try {
            $netStats = @{
                TotalConnections = $allConnections.Count
                Established = $established.Count
                Listening = $listening.Count
                ExternalConnections = ($established | Where-Object {
                    $_.RemoteAddress -notmatch "^(10\.|172\.|192\.168\.|127\.|::1)"
                }).Count
                UniqueRemoteIPs = ($established.RemoteAddress | Select-Object -Unique).Count
                UniqueRemotePorts = ($established.RemotePort | Select-Object -Unique).Count
                TopTalkers = $established | Group-Object RemoteAddress | 
                    Sort-Object Count -Descending | Select-Object -First 10
            }
            
            $netStats | ConvertTo-Json -Depth 3 | Out-File "$incidentPath\Network\network_statistics.json"
        } catch {
            Write-ColorOutput "Warning: Could not calculate network statistics" "Warning"
        }
        
        # Netstat in background (skip in Quick mode)
        if (!$Quick) {
            Write-ColorOutput "Running netstat in background..." "Progress"
            try {
                Start-Job -Name "Netstat" -ScriptBlock {
                    param($path)
                    try {
                        netstat -anob > "$path\Network\netstat_anob.txt" 2>&1
                        netstat -s > "$path\Network\netstat_statistics.txt" 2>&1
                    } catch { }
                } -ArgumentList $incidentPath | Out-Null
            } catch { }
        }
        
        # Network configuration capture with error handling
        Write-ColorOutput "Capturing network configuration..." "Progress"
        
        try { ipconfig /all > "$incidentPath\Network\ipconfig_all.txt" 2>&1 } catch { }
        try { arp -a > "$incidentPath\Network\arp_cache.txt" 2>&1 } catch { }
        try { route print > "$incidentPath\Network\routing_table.txt" 2>&1 } catch { }
        
        if (!$Quick) {
            try { ipconfig /displaydns > "$incidentPath\Network\dns_cache.txt" 2>&1 } catch { }
            try { nbtstat -c > "$incidentPath\Network\netbios_cache.txt" 2>&1 } catch { }
            try { netsh wlan show profiles > "$incidentPath\Network\wifi_profiles.txt" 2>&1 } catch { }
        }
        
        # DNS cache analysis with error handling
        try {
            $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
            if ($dnsCache) {
                $suspiciousDomains = $dnsCache | Where-Object {
                    $_.Entry -match "\.tk$|\.ml$|\.ga$|\.cf$|\.bit$|\.onion$" -or
                    $_.Entry -match "^[a-f0-9]{32}\." -or
                    $_.Entry -match "\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}" -or
                    $_.Entry.Length -gt 50
                }
                
                if ($suspiciousDomains) {
                    Write-ColorOutput "Suspicious DNS entries detected!" "Alert"
                    try {
                        $suspiciousDomains | Export-Csv "$incidentPath\ALERTS\suspicious_dns.csv" -NoTypeInformation
                    } catch { }
                    $global:alertCount++
                }
                
                try {
                    $dnsCache | Export-Csv "$incidentPath\Network\dns_cache_full.csv" -NoTypeInformation
                } catch { }
            }
        } catch {
            Write-ColorOutput "Warning: Could not analyze DNS cache" "Warning"
        }
        
    } catch {
        Write-ColorOutput "Error in network forensics: $_" "Error"
    }
} else {
    Write-ColorOutput "`n[PHASE 2: NETWORK FORENSICS - SKIPPED]" "Warning"
}

# SECTION 3: PROCESS FORENSICS
Write-Progress -Id $script:mainProgressId -Activity "Incident Response Collection" -Status "Phase 4/13: Process Forensics" -PercentComplete 30
Write-ColorOutput "`n[PHASE 3: PROCESS FORENSICS]" "Progress"

try {
    Write-ColorOutput "Enumerating all processes..." "Progress"
    
    # Get comprehensive process information with error handling
    $allProcesses = @()
    $wmiProcesses = @()
    
    try {
        $wmiProcesses = @(Get-WmiObject Win32_Process -ErrorAction SilentlyContinue)
        if (!$wmiProcesses) {
            # Fallback to Get-Process
            Write-ColorOutput "Using Get-Process fallback..." "Warning"
            $processes = Get-Process -ErrorAction SilentlyContinue
            foreach ($proc in $processes) {
                $allProcesses += [PSCustomObject]@{
                    Name = $proc.ProcessName
                    ProcessId = $proc.Id
                    Path = $proc.Path
                    WorkingSetMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
                    HasNetwork = $false
                    TrustScore = 50
                    SuspicionReasons = ""
                }
            }
        }
    } catch {
        Write-ColorOutput "Error: Could not enumerate processes" "Error"
    }
    
    if ($wmiProcesses) {
        $totalProcs = $wmiProcesses.Count
        $procCount = 0
        
        foreach ($wmiProc in $wmiProcesses) {
            $procCount++
            
            # Update progress bar
            $percentComplete = [math]::Round(($procCount / $totalProcs) * 100)
            Write-Progress -Id $script:subProgressId -ParentId $script:mainProgressId `
                -Activity "Analyzing Processes" `
                -Status "Process $procCount of $totalProcs: $($wmiProc.Name)" `
                -PercentComplete $percentComplete
            
            try {
                $proc = Get-Process -Id $wmiProc.ProcessId -ErrorAction SilentlyContinue
                $owner = @{Domain="Unknown"; User="Unknown"}
                try {
                    $ownerInfo = $wmiProc.GetOwner()
                    if ($ownerInfo.ReturnValue -eq 0) {
                        $owner = @{Domain=$ownerInfo.Domain; User=$ownerInfo.User}
                    }
                } catch {
                    # Silent fail - many system processes have no owner
                }
                
                # Get parent process details
                $parentProc = $wmiProcesses | Where-Object {$_.ProcessId -eq $wmiProc.ParentProcessId}
                
                # Check digital signature (skip in Quick mode)
                $signature = $null
                $signed = "Unknown"
                if (!$Quick -and $wmiProc.ExecutablePath -and (Test-Path $wmiProc.ExecutablePath -ErrorAction SilentlyContinue)) {
                    try {
                        $signature = Get-AuthenticodeSignature -FilePath $wmiProc.ExecutablePath -ErrorAction SilentlyContinue
                        $signed = if($signature) {$signature.Status} else {"Error"}
                    } catch { }
                }
                
                # Calculate process integrity/trust score
                $trustScore = 100
                $suspicionReasons = @()
                
                # Deduct points for various suspicious indicators
                if ($wmiProc.ExecutablePath) {
                    if ($wmiProc.ExecutablePath -match "\\Temp\\|\\AppData\\Local\\Temp\\") {
                        $trustScore -= 30
                        $suspicionReasons += "Running from Temp"
                    }
                    if ($wmiProc.ExecutablePath -match "\\Users\\Public\\") {
                        $trustScore -= 25
                        $suspicionReasons += "Running from Public"
                    }
                    if ($wmiProc.ExecutablePath -match "\\ProgramData\\" -and 
                        $wmiProc.ExecutablePath -notmatch "Microsoft|Windows") {
                        $trustScore -= 20
                        $suspicionReasons += "Running from ProgramData"
                    }
                    if ($signed -ne "Valid") {
                        $trustScore -= 15
                        $suspicionReasons += "Unsigned or invalid signature"
                    }
                }
                
                if ($wmiProc.Name -match "^[a-z]{8}\.exe$|^[0-9]{4,}\.exe$") {
                    $trustScore -= 40
                    $suspicionReasons += "Suspicious name pattern"
                }
                
                if ($wmiProc.CommandLine -match "-enc|-e[nc]|base64|bypass|hidden") {
                    $trustScore -= 35
                    $suspicionReasons += "Suspicious command line"
                }
                
                # Check if process has network connections
                $hasNetwork = if($established) { $established.OwningProcess -contains $wmiProc.ProcessId } else { $false }
                
                # Calculate hashes (skip in Quick mode for performance)
                $md5Hash = "N/A"
                $sha256Hash = "N/A"
                if (!$Quick -and $wmiProc.ExecutablePath -and (Test-Path $wmiProc.ExecutablePath -ErrorAction SilentlyContinue)) {
                    try {
                        $fileSize = (Get-Item $wmiProc.ExecutablePath -ErrorAction SilentlyContinue).Length
                        if ($fileSize -and $fileSize -lt 50MB) {
                            $md5Hash = (Get-FileHash -Path $wmiProc.ExecutablePath -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
                            if (!$Quick -and $fileSize -lt 20MB) {
                                $sha256Hash = (Get-FileHash -Path $wmiProc.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                            }
                        }
                    } catch { }
                }
                
                # Build comprehensive process object
                $processInfo = [PSCustomObject]@{
                    Name = $wmiProc.Name
                    ProcessId = $wmiProc.ProcessId
                    ParentProcessId = $wmiProc.ParentProcessId
                    ParentName = if($parentProc) {$parentProc.Name} else {"Unknown"}
                    Path = $wmiProc.ExecutablePath
                    CommandLine = $wmiProc.CommandLine
                    CreationDate = if($wmiProc.CreationDate) {
                        try { $wmiProc.ConvertToDateTime($wmiProc.CreationDate) } catch { "Unknown" }
                    } else {"Unknown"}
                    Owner = "$($owner.Domain)\$($owner.User)"
                    SessionId = $wmiProc.SessionId
                    ThreadCount = $wmiProc.ThreadCount
                    HandleCount = $wmiProc.HandleCount
                    WorkingSetMB = [math]::Round($wmiProc.WorkingSetSize / 1MB, 2)
                    VirtualSizeMB = [math]::Round($wmiProc.VirtualSize / 1MB, 2)
                    CPUTime = if($proc) {$proc.TotalProcessorTime} else {"N/A"}
                    Priority = $wmiProc.Priority
                    Signed = $signed
                    HasNetwork = $hasNetwork
                    TrustScore = $trustScore
                    SuspicionReasons = $suspicionReasons -join "; "
                    MD5 = $md5Hash
                    SHA256 = $sha256Hash
                }
                
                $allProcesses += $processInfo
                
                # Alert on highly suspicious processes
                if ($trustScore -lt 50) {
                    Write-ColorOutput "SUSPICIOUS: $($wmiProc.Name) [PID: $($wmiProc.ProcessId)] Score: $trustScore" "Alert"
                    $global:alertCount++
                }
            } catch {
                # Skip process if error
                continue
            }
        }
        
        # Complete sub-progress
        Write-Progress -Id $script:subProgressId -Completed
    }
    
    # Export all processes
    if ($allProcesses) {
        try {
            $allProcesses | Export-Csv "$incidentPath\Processes\all_processes_forensic.csv" -NoTypeInformation
        } catch {
            Write-ColorOutput "Warning: Could not export process analysis" "Warning"
        }
    }
    
    Write-ColorOutput "Analyzed $($allProcesses.Count) processes" "Info"
    
    # Categorize processes by trust level
    $criticalProcesses = @($allProcesses | Where-Object {$_.TrustScore -lt 40})
    $suspiciousProcesses = @($allProcesses | Where-Object {$_.TrustScore -ge 40 -and $_.TrustScore -lt 70})
    
    if ($criticalProcesses) {
        try {
            $criticalProcesses | Export-Csv "$incidentPath\ALERTS\critical_processes.csv" -NoTypeInformation
        } catch { }
        Write-ColorOutput "CRITICAL: $($criticalProcesses.Count) highly suspicious processes!" "Alert" -Critical $true
    }
    
    if ($suspiciousProcesses) {
        try {
            $suspiciousProcesses | Export-Csv "$incidentPath\ALERTS\suspicious_processes.csv" -NoTypeInformation
        } catch { }
    }
    
    # Check for specific malware indicators (skip detailed checks in Quick mode)
    if (!$Quick) {
        Write-ColorOutput "Checking for malware indicators..." "Progress"
        
        $malwarePatterns = @{
            "Mimikatz" = "mimikatz|mimi|katz|kitten|mimidrv"
            "Cobalt Strike" = "beacon|artifact\.exe|cobaltstrike"
            "Metasploit" = "meterpreter|metasploit|msf"
            "PowerShell Empire" = "empire|invoke-empire"
            "BloodHound" = "bloodhound|sharphound|azurehound"
            "Ransomware" = "encrypt|crypto|locker|wanna|ryuk|conti|lockbit"
            "RATs" = "njrat|darkcomet|netwire|nanocore|remcos|asyncrat|quasar"
        }
        
        $detectedMalware = @()
        foreach ($pattern in $malwarePatterns.GetEnumerator()) {
            try {
                $matches = $allProcesses | Where-Object {
                    $_.Name -match $pattern.Value -or
                    $_.Path -match $pattern.Value -or
                    $_.CommandLine -match $pattern.Value
                }
                
                if ($matches) {
                    foreach ($match in $matches) {
                        $detectedMalware += [PSCustomObject]@{
                            MalwareFamily = $pattern.Key
                            ProcessName = $match.Name
                            ProcessId = $match.ProcessId
                            Path = $match.Path
                            CommandLine = $match.CommandLine
                            Detection = "Pattern match: $($pattern.Value)"
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        if ($detectedMalware) {
            Write-ColorOutput "MALWARE DETECTED!" "Alert" -Critical $true
            try {
                $detectedMalware | Export-Csv "$incidentPath\ALERTS\detected_malware.csv" -NoTypeInformation
            } catch { }
            $detectedMalware | ForEach-Object {
                Write-ColorOutput "  - $($_.MalwareFamily): $($_.ProcessName) [PID: $($_.ProcessId)]" "Alert"
            }
            $global:alertCount += 10
        }
    }
    
} catch {
    Write-ColorOutput "Error in process forensics: $_" "Error"
}

# SECTION 4: PERSISTENCE MECHANISMS (Reduced in Quick mode)
Write-Progress -Id $script:mainProgressId -Activity "Incident Response Collection" -Status "Phase 5/13: Persistence Analysis" -PercentComplete 40
Write-ColorOutput "`n[PHASE 4: PERSISTENCE ANALYSIS]" "Progress"

# Function to check registry keys
function CheckRegistryKey {
    param($KeyName, $KeyPath)
    
    try {
        if (Test-Path $KeyPath -ErrorAction SilentlyContinue) {
            $values = Get-ItemProperty $KeyPath -ErrorAction SilentlyContinue
            
            if ($values) {
                $values.PSObject.Properties | Where-Object {$_.Name -notmatch "^PS"} | ForEach-Object {
                    $suspicious = $false
                    $reason = ""
                    
                    # Check for suspicious patterns
                    if ($_.Value -match "powershell.*-e[nc]|cmd.*\/c|wscript|cscript|mshta|rundll32.*,") {
                        $suspicious = $true
                        $reason = "Suspicious command pattern"
                    }
                    
                    if ($_.Value -match "\\Temp\\|\\AppData\\Local\\Temp\\|\\Users\\Public\\") {
                        $suspicious = $true
                        $reason = "Executes from temporary location"
                    }
                    
                    $script:regPersistence += [PSCustomObject]@{
                        Location = $KeyName
                        KeyPath = $KeyPath
                        Name = $_.Name
                        Value = $_.Value
                        Suspicious = $suspicious
                        Reason = $reason
                        LastModified = try { (Get-Item $KeyPath -ErrorAction SilentlyContinue).LastWriteTime } catch { "Unknown" }
                    }
                    
                    if ($suspicious) {
                        Write-ColorOutput "SUSPICIOUS REGISTRY: $KeyName\$($_.Name)" "Alert"
                        $global:alertCount++
                    }
                }
            }
            
            # Check for IFEO debuggers
            if ($KeyPath -match "Image File Execution Options") {
                Get-ChildItem $KeyPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $debugger = Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue
                    if ($debugger -and $debugger.Debugger) {
                        $script:regPersistence += [PSCustomObject]@{
                            Location = "IFEO"
                            KeyPath = $_.PSPath
                            Name = $_.PSChildName
                            Value = $debugger.Debugger
                            Suspicious = $true
                            Reason = "IFEO Debugger hijack"
                            LastModified = $_.LastWriteTime
                        }
                        Write-ColorOutput "IFEO HIJACK: $($_.PSChildName) -> $($debugger.Debugger)" "Alert" -Critical $true
                        $global:alertCount += 5
                    }
                }
            }
        }
    } catch {
        # Silent fail for inaccessible keys
    }
}

try {
    # Registry persistence - basic check in Quick mode
    Write-ColorOutput "Checking registry persistence..." "Progress"
    
    $script:regPersistence = @()
    
    # Core registry keys to check (reduced set for Quick mode)
    $regKeys = @{
        "HKLM_Run" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        "HKLM_RunOnce" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        "HKCU_Run" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        "HKCU_RunOnce" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    
    # Add more keys if not in Quick mode
    if (!$Quick) {
        $regKeys += @{
            "HKLM_Run_Wow64" = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
            "HKLM_Winlogon" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
            "HKCU_Winlogon" = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
            "HKLM_BHO" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
            "HKLM_IFEO" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        }
    }
    
    $totalKeys = $regKeys.Count
    $currentKey = 0
    
    foreach ($keyInfo in $regKeys.GetEnumerator()) {
        $currentKey++
        $percentComplete = [math]::Round(($currentKey / $totalKeys) * 100)
        Write-Progress -Id $script:subProgressId -ParentId $script:mainProgressId `
            -Activity "Checking Registry Persistence" `
            -Status "Key $currentKey of $totalKeys: $($keyInfo.Key)" `
            -PercentComplete $percentComplete
        
        $keyName = $keyInfo.Key
        $keyPath = $keyInfo.Value
        
        # Special handling for wildcards
        if ($keyPath -match '\*') {
            $basePath = $keyPath -replace '\\\*.*', ''
            if (Test-Path $basePath -ErrorAction SilentlyContinue) {
                $subKeys = Get-ChildItem $basePath -Recurse -ErrorAction SilentlyContinue
                foreach ($subKey in $subKeys) {
                    CheckRegistryKey -KeyName "$keyName\$($subKey.PSChildName)" -KeyPath $subKey.PSPath
                }
            }
        } else {
            CheckRegistryKey -KeyName $keyName -KeyPath $keyPath
        }
    }
    
    Write-Progress -Id $script:subProgressId -Completed
    
    if ($script:regPersistence) {
        try {
            $script:regPersistence | Export-Csv "$incidentPath\Persistence\Registry\registry_persistence.csv" -NoTypeInformation
            $script:regPersistence | Where-Object {$_.Suspicious} | 
                Export-Csv "$incidentPath\ALERTS\suspicious_registry_persistence.csv" -NoTypeInformation
        } catch { }
    }
    
    Write-ColorOutput "Found $($script:regPersistence.Count) registry persistence entries" "Info"
    
    # Scheduled Tasks Analysis (simplified in Quick mode)
    Write-ColorOutput "Analyzing scheduled tasks..." "Progress"
    
    try {
        if ($Quick) {
            # Quick mode - just get basic info
            $allTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.State -eq "Ready"})
            $taskCount = $allTasks.Count
            Write-ColorOutput "Found $taskCount active scheduled tasks (detailed analysis skipped in Quick mode)" "Info"
            
            # Check for obvious suspicious tasks
            $suspiciousTasks = @($allTasks | Where-Object {
                $_.Actions.Execute -match "powershell|cmd|wscript|cscript|mshta" -and
                $_.Actions.Execute -match "\\Temp\\|\\AppData\\|\\Users\\Public\\"
            })
            
            if ($suspiciousTasks) {
                Write-ColorOutput "Found $($suspiciousTasks.Count) suspicious scheduled tasks!" "Alert"
                $global:alertCount += $suspiciousTasks.Count
            }
        } else {
            # Full analysis with progress
            $allTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)
            $taskAnalysis = @()
            $totalTasks = $allTasks.Count
            $currentTask = 0
            
            foreach ($task in $allTasks) {
                $currentTask++
                $percentComplete = [math]::Round(($currentTask / $totalTasks) * 100)
                Write-Progress -Id $script:subProgressId -ParentId $script:mainProgressId `
                    -Activity "Analyzing Scheduled Tasks" `
                    -Status "Task $currentTask of $totalTasks: $($task.TaskName)" `
                    -PercentComplete $percentComplete
                
                try {
                    $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                    $suspicious = $false
                    $suspicionReasons = @()
                    
                    # Check task properties
                    if ($task.Actions.Execute -match "powershell|cmd|wscript|cscript|mshta|rundll32") {
                        $suspicious = $true
                        $suspicionReasons += "Executes scripting engine"
                    }
                    
                    if ($task.Actions.Execute -match "\\Temp\\|\\AppData\\|\\Users\\Public\\") {
                        $suspicious = $true
                        $suspicionReasons += "Executes from suspicious location"
                    }
                    
                    $taskAnalysis += [PSCustomObject]@{
                        TaskName = $task.TaskName
                        TaskPath = $task.TaskPath
                        State = $task.State
                        Actions = ($task.Actions | ForEach-Object {"$($_.Execute) $($_.Arguments)"}) -join "; "
                        Triggers = ($task.Triggers | ForEach-Object {$_.CimClass.CimClassName}) -join "; "
                        Suspicious = $suspicious
                        SuspicionReasons = $suspicionReasons -join "; "
                    }
                    
                    if ($suspicious) {
                        Write-ColorOutput "SUSPICIOUS TASK: $($task.TaskName)" "Alert"
                        $global:alertCount++
                    }
                } catch {
                    continue
                }
            }
            
            Write-Progress -Id $script:subProgressId -Completed
            
            if ($taskAnalysis) {
                try {
                    $taskAnalysis | Export-Csv "$incidentPath\Persistence\Tasks\all_scheduled_tasks.csv" -NoTypeInformation
                    $taskAnalysis | Where-Object {$_.Suspicious} | 
                        Export-Csv "$incidentPath\ALERTS\suspicious_scheduled_tasks.csv" -NoTypeInformation
                } catch { }
            }
        }
    } catch {
        Write-ColorOutput "Warning: Could not analyze scheduled tasks" "Warning"
    }
    
    # Services Analysis (basic in Quick mode)
    Write-ColorOutput "Analyzing services..." "Progress"
    
    try {
        if ($Quick) {
            # Quick mode - just check for obvious issues
            $suspiciousServices = @(Get-Service -ErrorAction SilentlyContinue | Where-Object {
                $_.Status -eq "Running"
            } | ForEach-Object {
                try {
                    $svc = Get-WmiObject Win32_Service -Filter "Name='$($_.Name)'" -ErrorAction SilentlyContinue
                    if ($svc -and $svc.PathName -match "\\Temp\\|\\Users\\|cmd\.exe|powershell") {
                        $_
                    }
                } catch { }
            })
            
            if ($suspiciousServices) {
                Write-ColorOutput "Found $($suspiciousServices.Count) suspicious running services!" "Alert"
                $global:alertCount += $suspiciousServices.Count
            }
        } else {
            # Full service analysis with progress
            $services = @(Get-WmiObject Win32_Service -ErrorAction SilentlyContinue)
            $serviceAnalysis = @()
            $totalServices = $services.Count
            $currentService = 0
            
            foreach ($service in $services) {
                $currentService++
                $percentComplete = [math]::Round(($currentService / $totalServices) * 100)
                Write-Progress -Id $script:subProgressId -ParentId $script:mainProgressId `
                    -Activity "Analyzing Services" `
                    -Status "Service $currentService of $totalServices: $($service.Name)" `
                    -PercentComplete $percentComplete
                
                try {
                    $suspicious = $false
                    $suspicionReasons = @()
                    
                    # Check service executable
                    if ($service.PathName) {
                        if ($service.PathName -match "\\Users\\|\\Temp\\|\\AppData\\") {
                            $suspicious = $true
                            $suspicionReasons += "Service executable in user directory"
                        }
                        
                        if ($service.PathName -match "cmd\.exe|powershell|wscript|cscript|rundll32") {
                            $suspicious = $true
                            $suspicionReasons += "Service runs scripting engine"
                        }
                        
                        # Check for unquoted paths with spaces
                        if ($service.PathName -notmatch '^"' -and $service.PathName -match ' ') {
                            $suspicious = $true
                            $suspicionReasons += "Unquoted service path with spaces"
                        }
                    }
                    
                    $serviceAnalysis += [PSCustomObject]@{
                        Name = $service.Name
                        DisplayName = $service.DisplayName
                        State = $service.State
                        PathName = $service.PathName
                        StartName = $service.StartName
                        Suspicious = $suspicious
                        SuspicionReasons = $suspicionReasons -join "; "
                    }
                    
                    if ($suspicious -and $service.State -eq "Running") {
                        Write-ColorOutput "SUSPICIOUS SERVICE: $($service.Name)" "Alert"
                        $global:alertCount++
                    }
                } catch {
                    continue
                }
            }
            
            Write-Progress -Id $script:subProgressId -Completed
            
            if ($serviceAnalysis) {
                try {
                    $serviceAnalysis | Export-Csv "$incidentPath\System\all_services_analysis.csv" -NoTypeInformation
                    $serviceAnalysis | Where-Object {$_.Suspicious} | 
                        Export-Csv "$incidentPath\ALERTS\suspicious_services.csv" -NoTypeInformation
                } catch { }
            }
        }
    } catch {
        Write-ColorOutput "Warning: Could not analyze services" "Warning"
    }
    
} catch {
    Write-ColorOutput "Error in persistence analysis: $_" "Error"
}

# SECTION 5: MEMORY FORENSICS (Skip in Quick mode)
if (!$SkipMemory -and !$Quick) {
    Write-Progress -Id $script:mainProgressId -Activity "Incident Response Collection" -Status "Phase 6/13: Memory Forensics" -PercentComplete 50
    Write-ColorOutput "`n[PHASE 5: MEMORY FORENSICS]" "Progress"
    
    try {
        # Process memory statistics
        Write-ColorOutput "Analyzing process memory..." "Progress"
        
        $memoryAnalysis = @()
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            $totalProcesses = $processes.Count
            $currentProcess = 0
            
            foreach ($proc in $processes) {
                $currentProcess++
                $percentComplete = [math]::Round(($currentProcess / $totalProcesses) * 100)
                Write-Progress -Id $script:subProgressId -ParentId $script:mainProgressId `
                    -Activity "Analyzing Process Memory" `
                    -Status "Process $currentProcess of $totalProcesses: $($proc.ProcessName)" `
                    -PercentComplete $percentComplete
                
                try {
                    $memoryAnalysis += [PSCustomObject]@{
                        ProcessName = $proc.ProcessName
                        Id = $proc.Id
                        WorkingSetMB = [math]::Round($proc.WorkingSet64/1MB,2)
                        PrivateMemoryMB = [math]::Round($proc.PrivateMemorySize64/1MB,2)
                        VirtualMemoryMB = [math]::Round($proc.VirtualMemorySize64/1MB,2)
                        Handles = $proc.HandleCount
                        Threads = $proc.Threads.Count
                    }
                } catch {
                    # Skip process if we can't get memory info
                    continue
                }
            }
            
            Write-Progress -Id $script:subProgressId -Completed
            
            # Sort by working set
            $memoryAnalysis = $memoryAnalysis | Sort-Object WorkingSetMB -Descending
        } catch {
            Write-ColorOutput "Warning: Could not analyze process memory" "Warning"
        }
        
        if ($memoryAnalysis) {
            try {
                $memoryAnalysis | Export-Csv "$incidentPath\Memory\process_memory_analysis.csv" -NoTypeInformation
            } catch { }
            
            # Identify memory anomalies
            $memoryAnomalies = @($memoryAnalysis | Where-Object {
                $_.WorkingSetMB -gt 1000 -or
                $_.Handles -gt 10000 -or
                $_.Threads -gt 500
            })
            
            if ($memoryAnomalies) {
                Write-ColorOutput "Memory anomalies detected!" "Alert"
                try {
                    $memoryAnomalies | Export-Csv "$incidentPath\ALERTS\memory_anomalies.csv" -NoTypeInformation
                } catch { }
            }
        }
        
    } catch {
        Write-ColorOutput "Error in memory forensics: $_" "Error"
    }
} elseif ($Quick) {
    Write-ColorOutput "`n[PHASE 5: MEMORY FORENSICS - SKIPPED (Quick Mode)]" "Info"
} else {
    Write-ColorOutput "`n[PHASE 5: MEMORY FORENSICS - SKIPPED]" "Warning"
}

# SECTION 6: FILE SYSTEM FORENSICS (Limited in Quick mode)
if (!$SkipFileSystem) {
    Write-Progress -Id $script:mainProgressId -Activity "Incident Response Collection" -Status "Phase 7/13: File System Forensics" -PercentComplete 60
    Write-ColorOutput "`n[PHASE 6: FILE SYSTEM FORENSICS]" "Progress"
    
    try {
        # Recent file activity
        Write-ColorOutput "Analyzing recent file system activity..." "Progress"
        
        $recentDate = if($Quick) {(Get-Date).AddDays(-1)} else {(Get-Date).AddDays(-$DaysBack)}
        
        # Critical paths - reduced set for Quick mode
        $criticalPaths = if($Quick) {
            @(
                "$env:TEMP",
                "$env:LOCALAPPDATA\Temp",
                "$env:USERPROFILE\Downloads"
            )
        } else {
            @(
                "$env:TEMP",
                "$env:APPDATA",
                "$env:LOCALAPPDATA",
                "$env:LOCALAPPDATA\Temp",
                "$env:PUBLIC",
                "$env:ProgramData",
                "$env:USERPROFILE\Downloads",
                "$env:USERPROFILE\Documents",
                "$env:USERPROFILE\Desktop",
                "C:\Windows\Temp"
            )
        }
        
        $recentFiles = @()
        $suspiciousFiles = @()
        $fileCount = 0
        $totalPaths = $criticalPaths.Count
        $currentPath = 0
        
        foreach ($path in $criticalPaths) {
            $currentPath++
            if (Test-Path $path -ErrorAction SilentlyContinue) {
                $percentComplete = [math]::Round(($currentPath / $totalPaths) * 100)
                Write-Progress -Id $script:subProgressId -ParentId $script:mainProgressId `
                    -Activity "Scanning File System" `
                    -Status "Path $currentPath of $totalPaths: $path" `
                    -PercentComplete $percentComplete
                
                Write-ColorOutput "  Scanning: $path" "Progress"
                
                try {
                    # Limit depth in Quick mode
                    $scanParams = @{
                        Path = $path
                        File = $true
                        Force = $true
                        ErrorAction = 'SilentlyContinue'
                    }
                    
                    if (!$Quick) {
                        $scanParams['Recurse'] = $true
                    }
                    
                    $files = @(Get-ChildItem @scanParams |
                        Where-Object {
                            $_.CreationTime -gt $recentDate -or 
                            $_.LastWriteTime -gt $recentDate
                        })
                    
                    foreach ($file in $files) {
                        $fileCount++
                        if ($Quick -and $fileCount -gt 1000) {
                            Write-ColorOutput "  File limit reached in Quick mode" "Info"
                            break
                        }
                        
                        try {
                            $fileInfo = [PSCustomObject]@{
                                FullPath = $file.FullName
                                Directory = $file.DirectoryName
                                FileName = $file.Name
                                Extension = $file.Extension
                                Size = $file.Length
                                CreationTime = $file.CreationTime
                                LastWriteTime = $file.LastWriteTime
                                Hidden = ($file.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0
                                MD5 = ""
                                Suspicious = $false
                                SuspicionReason = ""
                            }
                            
                            # Check for suspicious patterns
                            if ($file.Extension -match "\.exe$|\.dll$|\.scr$|\.bat$|\.cmd$|\.ps1$|\.vbs$|\.js$") {
                                $fileInfo.Suspicious = $true
                                $fileInfo.SuspicionReason = "Executable file"
                                
                                # Calculate hash for small executables
                                if (!$Quick -and $file.Length -lt 10MB) {
                                    try {
                                        $fileInfo.MD5 = (Get-FileHash -Path $file.FullName -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
                                    } catch { }
                                }
                            }
                            
                            if ($file.Name -match "^[a-z]{8}\.(exe|dll)$|^[0-9]{6,}\.(exe|dll)$") {
                                $fileInfo.Suspicious = $true
                                $fileInfo.SuspicionReason += "; Random name pattern"
                            }
                            
                            $recentFiles += $fileInfo
                            
                            if ($fileInfo.Suspicious) {
                                $suspiciousFiles += $fileInfo
                            }
                        } catch {
                            continue
                        }
                    }
                } catch {
                    Write-ColorOutput "  Warning: Error scanning $path" "Warning"
                }
            }
        }
        
        Write-Progress -Id $script:subProgressId -Completed
        
        # Export results
        if ($recentFiles) {
            try {
                $recentFiles | Export-Csv "$incidentPath\FileSystem\recent_files.csv" -NoTypeInformation
            } catch { }
        }
        
        if ($suspiciousFiles) {
            Write-ColorOutput "Found $($suspiciousFiles.Count) suspicious files!" "Alert"
            try {
                $suspiciousFiles | Export-Csv "$incidentPath\ALERTS\suspicious_files.csv" -NoTypeInformation
            } catch { }
            $global:alertCount++
            
            # Show most suspicious
            $suspiciousFiles | Sort-Object CreationTime -Descending | Select-Object -First 5 | ForEach-Object {
                Write-ColorOutput "  - $($_.FileName): $($_.SuspicionReason)" "Alert"
            }
        }
        
        # Ransomware detection (skip in Quick mode)
        if (!$Quick) {
            Write-ColorOutput "Checking for ransomware indicators..." "Progress"
            
            $ransomwareIndicators = @{
                Extensions = @("\.encrypted$", "\.enc$", "\.locked$", "\.crypto$")
                NoteFiles = @("README.txt", "DECRYPT_INSTRUCTIONS.txt", "HOW_TO_DECRYPT.txt")
            }
            
            $ransomwareFiles = @()
            
            foreach ($ext in $ransomwareIndicators.Extensions) {
                $encrypted = @($recentFiles | Where-Object {$_.Extension -match $ext})
                if ($encrypted) {
                    $ransomwareFiles += $encrypted
                }
            }
            
            if ($ransomwareFiles) {
                Write-ColorOutput "RANSOMWARE INDICATORS DETECTED!" "Alert" -Critical $true
                try {
                    $ransomwareFiles | Export-Csv "$incidentPath\ALERTS\ransomware_files.csv" -NoTypeInformation
                } catch { }
                $global:alertCount += 10
            }
        }
        
    } catch {
        Write-ColorOutput "Error in file system forensics: $_" "Error"
    }
} else {
    Write-ColorOutput "`n[PHASE 6: FILE SYSTEM FORENSICS - SKIPPED]" "Warning"
}

# SECTION 7: BROWSER FORENSICS (Skip in Quick mode)
if (!$SkipBrowser -and !$Quick) {
    Write-Progress -Id $script:mainProgressId -Activity "Incident Response Collection" -Status "Phase 8/13: Browser Forensics" -PercentComplete 65
    Write-ColorOutput "`n[PHASE 7: BROWSER FORENSICS]" "Progress"
    
    try {
        # Browser paths
        $browsers = @{
            Chrome = @{
                Extensions = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
            }
            Edge = @{
                Extensions = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
            }
        }
        
        $totalBrowsers = $browsers.Count
        $currentBrowser = 0
        
        foreach ($browser in $browsers.GetEnumerator()) {
            $currentBrowser++
            $browserName = $browser.Key
            $paths = $browser.Value
            
            $percentComplete = [math]::Round(($currentBrowser / $totalBrowsers) * 100)
            Write-Progress -Id $script:subProgressId -ParentId $script:mainProgressId `
                -Activity "Analyzing Browser Data" `
                -Status "Browser $currentBrowser of $totalBrowsers: $browserName" `
                -PercentComplete $percentComplete
            
            Write-ColorOutput "Checking $browserName..." "Progress"
            
            foreach ($item in $paths.GetEnumerator()) {
                $itemName = $item.Key
                $itemPath = $item.Value
                
                if (Test-Path $itemPath -ErrorAction SilentlyContinue) {
                    $destPath = "$incidentPath\Browser\$browserName"
                    try {
                        $null = New-Item -ItemType Directory -Path $destPath -Force -ErrorAction SilentlyContinue
                    } catch { }
                    
                    # Check extensions
                    try {
                        if ($itemName -eq "Extensions") {
                            $extensions = @(Get-ChildItem $itemPath -Directory -ErrorAction SilentlyContinue)
                            $extensionList = @()
                            
                            foreach ($ext in $extensions) {
                                try {
                                    $manifestPath = Get-ChildItem "$($ext.FullName)\*\manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                                    if ($manifestPath) {
                                        $manifest = Get-Content $manifestPath.FullName -ErrorAction SilentlyContinue | ConvertFrom-Json
                                        
                                        if ($manifest) {
                                            $extensionList += [PSCustomObject]@{
                                                ID = $ext.Name
                                                Name = $manifest.name
                                                Version = $manifest.version
                                                Permissions = ($manifest.permissions -join "; ")
                                            }
                                        }
                                    }
                                } catch { }
                            }
                            
                            if ($extensionList) {
                                try {
                                    $extensionList | Export-Csv "$destPath\extensions.csv" -NoTypeInformation
                                } catch { }
                                
                                # Check for suspicious extensions
                                $suspiciousExt = @($extensionList | Where-Object {
                                    $_.Permissions -match "webRequest|tabs|cookies|all_urls"
                                })
                                
                                if ($suspiciousExt) {
                                    Write-ColorOutput "Suspicious browser extensions found!" "Alert"
                                    try {
                                        $suspiciousExt | Export-Csv "$incidentPath\ALERTS\suspicious_extensions.csv" -NoTypeInformation
                                    } catch { }
                                    $global:alertCount++
                                }
                            }
                        }
                    } catch { }
                }
            }
        }
        
        Write-Progress -Id $script:subProgressId -Completed
        
    } catch {
        Write-ColorOutput "Error in browser forensics: $_" "Error"
    }
} elseif ($Quick) {
    Write-ColorOutput "`n[PHASE 7: BROWSER FORENSICS - SKIPPED (Quick Mode)]" "Info"
} else {
    Write-ColorOutput "`n[PHASE 7: BROWSER FORENSICS - SKIPPED]" "Warning"
}

# SECTION 8: EVENT LOG FORENSICS (Limited in Quick mode)
Write-Progress -Id $script:mainProgressId -Activity "Incident Response Collection" -Status "Phase 9/13: Event Log Forensics" -PercentComplete 70
Write-ColorOutput "`n[PHASE 8: EVENT LOG FORENSICS]" "Progress"

try {
    # Define critical events to check
    $criticalEvents = @{
        "Security" = @{
            "4624" = "Successful logon"
            "4625" = "Failed logon"
            "4672" = "Special privileges assigned"
            "4688" = "Process creation"
            "4697" = "Service installed"
            "1102" = "Audit log cleared"
        }
        "System" = @{
            "7045" = "Service installed"
            "104" = "Event log cleared"
        }
    }
    
    # Add more events if not in Quick mode
    if (!$Quick) {
        $criticalEvents["Security"] += @{
            "4634" = "Logoff"
            "4698" = "Scheduled task created"
            "4720" = "User account created"
            "4732" = "Member added to security group"
            "5140" = "Network share accessed"
        }
    }
    
    $logAnalysis = @()
    $suspiciousEvents = @()
    
    # Limit time range in Quick mode
    $logTimeRange = if($Quick) {1} else {$DaysBack}
    
    $totalLogs = $criticalEvents.Keys.Count
    $currentLog = 0
    
    foreach ($logType in $criticalEvents.Keys) {
        $currentLog++
        $percentComplete = [math]::Round(($currentLog / $totalLogs) * 100)
        Write-Progress -Id $script:subProgressId -ParentId $script:mainProgressId `
            -Activity "Analyzing Event Logs" `
            -Status "Log $currentLog of $totalLogs: $logType" `
            -PercentComplete $percentComplete
        
        Write-ColorOutput "Analyzing $logType log..." "Progress"
        
        $eventIds = $criticalEvents[$logType].Keys | ForEach-Object {[int]$_}
        
        try {
            # Limit events in Quick mode
            $maxEvents = if($Quick) {1000} else {5000}
            
            $events = @(Get-WinEvent -FilterHashtable @{
                LogName = $logType
                ID = $eventIds
                StartTime = (Get-Date).AddDays(-$logTimeRange)
            } -MaxEvents $maxEvents -ErrorAction SilentlyContinue)
            
            if ($events) {
                foreach ($event in $events) {
                    try {
                        $eventInfo = [PSCustomObject]@{
                            TimeCreated = $event.TimeCreated
                            Log = $logType
                            EventID = $event.Id
                            EventType = $criticalEvents[$logType][$event.Id.ToString()]
                            Level = $event.LevelDisplayName
                            Computer = $event.MachineName
                            Message = if($event.Message) {$event.Message -replace "`r`n", " " -replace "\s+", " "} else {""}
                        }
                        
                        $logAnalysis += $eventInfo
                        
                        # Detect suspicious patterns
                        $suspicious = $false
                        $reason = ""
                        
                        # Failed logons
                        if ($event.Id -eq 4625) {
                            $suspicious = $true
                            $reason = "Failed logon attempt"
                        }
                        
                        # Log cleared
                        if ($event.Id -in @(1102, 104)) {
                            $suspicious = $true
                            $reason = "Event log cleared"
                        }
                        
                        # Service/task creation
                        if ($event.Id -in @(7045, 4697, 4698)) {
                            if ($event.Message -match "powershell|cmd|wscript|cscript|mshta|rundll32") {
                                $suspicious = $true
                                $reason = "Suspicious service/task created"
                            }
                        }
                        
                        if ($suspicious) {
                            $suspiciousEvents += [PSCustomObject]@{
                                Event = $eventInfo
                                Reason = $reason
                            }
                        }
                    } catch {
                        continue
                    }
                }
            }
        } catch {
            Write-ColorOutput "  Error reading $logType log: $_" "Error"
        }
    }
    
    Write-Progress -Id $script:subProgressId -Completed
    
    # Export results
    if ($logAnalysis) {
        try {
            $logAnalysis | Export-Csv "$incidentPath\Logs\Windows\event_log_analysis.csv" -NoTypeInformation
        } catch { }
    }
    
    if ($suspiciousEvents) {
        Write-ColorOutput "Found $($suspiciousEvents.Count) suspicious events!" "Alert"
        try {
            $suspiciousEvents | Select-Object -ExpandProperty Event | 
                Export-Csv "$incidentPath\ALERTS\suspicious_events.csv" -NoTypeInformation
        } catch { }
        $global:alertCount++
    }
    
    # Export full logs (skip in Quick mode)
    if (!$Quick) {
        Write-ColorOutput "Exporting full event logs..." "Progress"
        
        $exportLogs = @("Security", "System", "Application")
        
        foreach ($log in $exportLogs) {
            try {
                $logFile = $log -replace '/', '-'
                wevtutil epl $log "$incidentPath\Logs\$logFile.evtx" /ow:true 2>$null
            } catch { }
        }
    }
    
} catch {
    Write-ColorOutput "Error in event log forensics: $_" "Error"
}

# SECTION 9: SECURITY ASSESSMENT
Write-Progress -Id $script:mainProgressId -Activity "Incident Response Collection" -Status "Phase 10/13: Security Assessment" -PercentComplete 80
Write-ColorOutput "`n[PHASE 9: SECURITY ASSESSMENT]" "Progress"

try {
    $securityStatus = @{}
    
    # Windows Defender status
    Write-ColorOutput "Checking Windows Defender..." "Progress"
    try {
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        
        if ($defender) {
            $defenderStatus = [PSCustomObject]@{
                AntivirusEnabled = $defender.AntivirusEnabled
                RealTimeProtectionEnabled = $defender.RealTimeProtectionEnabled
                AntivirusSignatureLastUpdated = $defender.AntivirusSignatureLastUpdated
            }
            
            try {
                $defenderStatus | Export-Csv "$incidentPath\System\Security\defender_status.csv" -NoTypeInformation
            } catch { }
            
            if (!$defender.RealTimeProtectionEnabled) {
                Write-ColorOutput "Real-time protection is DISABLED!" "Alert" -Critical $true
                $securityStatus.DefenderDisabled = $true
                $global:alertCount += 5
            }
        }
    } catch {
        Write-ColorOutput "Warning: Could not check Windows Defender status" "Warning"
    }
    
    # Firewall status
    Write-ColorOutput "Checking Windows Firewall..." "Progress"
    try {
        $fwProfiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
        
        $fwDisabled = @($fwProfiles | Where-Object {!$_.Enabled})
        if ($fwDisabled) {
            Write-ColorOutput "Firewall disabled on profiles: $($fwDisabled.Name -join ', ')" "Alert"
            $global:alertCount++
        }
    } catch {
        Write-ColorOutput "Warning: Could not check firewall status" "Warning"
    }
    
} catch {
    Write-ColorOutput "Error in security assessment: $_" "Error"
}

# SECTION 10: REMOTE ACCESS INVESTIGATION (Basic in Quick mode)
Write-Progress -Id $script:mainProgressId -Activity "Incident Response Collection" -Status "Phase 11/13: Remote Access Investigation" -PercentComplete 85
Write-ColorOutput "`n[PHASE 10: REMOTE ACCESS INVESTIGATION]" "Progress"

try {
    $remoteAccessFindings = @{
        Tools = @()
        Services = @()
        Processes = @()
    }
    
    # Common remote tool patterns
    $remotePatterns = @(
        "TeamViewer", "AnyDesk", "Chrome.*Remote", "LogMeIn",
        "VNC", "RDP", "SSH", "Telnet",
        "ngrok", "netcat", "nc\.exe",
        "psexec", "paexec", "winexe"
    )
    
    # Check running processes
    Write-ColorOutput "Scanning for remote access processes..." "Progress"
    try {
        $remoteProcs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $procName = $_.ProcessName
            if ($_.Description) { $procName += " " + $_.Description }
            $matched = $false
            foreach ($pattern in $remotePatterns) {
                if ($procName -match $pattern) {
                    $matched = $true
                    break
                }
            }
            $matched
        })
        
        if ($remoteProcs) {
            foreach ($proc in $remoteProcs) {
                $remoteAccessFindings.Processes += [PSCustomObject]@{
                    Name = $proc.ProcessName
                    PID = $proc.Id
                    Path = $proc.Path
                }
                
                Write-ColorOutput "REMOTE TOOL: $($proc.ProcessName) [PID: $($proc.Id)]" "Alert"
                $global:alertCount++
            }
        }
    } catch {
        Write-ColorOutput "Warning: Could not scan for remote processes" "Warning"
    }
    
    # RDP sessions
    try {
        $rdpSessions = qwinsta 2>&1 | Select-String "Active|rdp-tcp#" -ErrorAction SilentlyContinue
        if ($rdpSessions) {
            Write-ColorOutput "Active RDP sessions detected!" "Alert"
            $global:alertCount++
        }
    } catch { }
    
    # Export findings
    if ($remoteAccessFindings.Processes) {
        try {
            $remoteAccessFindings.Processes | Export-Csv "$incidentPath\ALERTS\remote_access_processes.csv" -NoTypeInformation
        } catch { }
    }
    
} catch {
    Write-ColorOutput "Error in remote access investigation: $_" "Error"
}

# SECTION 11: IOC EXTRACTION
Write-Progress -Id $script:mainProgressId -Activity "Incident Response Collection" -Status "Phase 12/13: IOC Extraction" -PercentComplete 90
Write-ColorOutput "`n[PHASE 11: IOC EXTRACTION]" "Progress"

try {
    # Extract all IOCs from collected data
    Write-ColorOutput "Extracting Indicators of Compromise..." "Progress"
    
    # IPs
    if ($connectionDetails) {
        $global:iocs.IPs = @($connectionDetails | 
            Where-Object {$_.RemoteAddress -notmatch "^(10\.|172\.|192\.168\.|127\.|::1|0\.0\.0\.0)"} |
            Select-Object -ExpandProperty RemoteAddress -Unique)
    }
    
    # Domains
    if ($dnsCache) {
        $global:iocs.Domains = @($dnsCache | Select-Object -ExpandProperty Entry -Unique)
    }
    
    # File hashes
    if ($allProcesses) {
        $global:iocs.Hashes = @($allProcesses | 
            Where-Object {$_.MD5 -ne "N/A"} | 
            Select-Object -ExpandProperty MD5 -Unique)
    }
    
    # Process names
    if ($suspiciousProcesses) {
        $global:iocs.ProcessNames = @($suspiciousProcesses | 
            Select-Object -ExpandProperty Name -Unique)
    }
    
    # Create IOC report
    $iocReport = @{
        CollectionTime = Get-Date
        System = $env:COMPUTERNAME
        TotalIOCs = 0
        IOCs = $global:iocs
    }
    
    # Count total IOCs
    $global:iocs.PSObject.Properties | ForEach-Object {
        if ($_.Value) {
            $iocReport.TotalIOCs += $_.Value.Count
        }
    }
    
    # Export IOCs
    try {
        $iocReport | ConvertTo-Json -Depth 5 | Out-File "$incidentPath\IOCs\all_iocs.json"
    } catch { }
    
    # Create CSV for easy import
    $csvIOCs = @()
    
    foreach ($ip in $global:iocs.IPs | Select-Object -First 100) {
        $csvIOCs += [PSCustomObject]@{
            Type = "IP"
            Value = $ip
            Context = "Suspicious outbound connection"
        }
    }
    
    foreach ($domain in $global:iocs.Domains | Select-Object -First 100) {
        $csvIOCs += [PSCustomObject]@{
            Type = "Domain"
            Value = $domain
            Context = "DNS resolution"
        }
    }
    
    foreach ($hash in $global:iocs.Hashes | Select-Object -First 50) {
        $processName = ($allProcesses | Where-Object {$_.MD5 -eq $hash} | Select-Object -First 1).Name
        $csvIOCs += [PSCustomObject]@{
            Type = "MD5"
            Value = $hash
            Context = "Process: $processName"
        }
    }
    
    if ($csvIOCs) {
        try {
            $csvIOCs | Export-Csv "$incidentPath\IOCs\iocs_flat.csv" -NoTypeInformation
        } catch { }
    }
    
    Write-ColorOutput "Extracted $($iocReport.TotalIOCs) total IOCs" "Info"
    
} catch {
    Write-ColorOutput "Error extracting IOCs: $_" "Error"
}

# SECTION 12: FINAL ANALYSIS AND REPORTING
Write-Progress -Id $script:mainProgressId -Activity "Incident Response Collection" -Status "Phase 13/13: Final Analysis" -PercentComplete 95
Write-ColorOutput "`n[PHASE 12: FINAL ANALYSIS]" "Progress"

try {
    # Calculate threat score
    $threatScore = 0
    $threatFactors = @()
    
    # Factor in various indicators
    if ($global:alertCount -gt 0) {
        $threatScore += [Math]::Min($global:alertCount * 5, 50)
        $threatFactors += "Alerts: $($global:alertCount)"
    }
    
    if ($criticalProcesses -and $criticalProcesses.Count -gt 0) {
        $threatScore += $criticalProcesses.Count * 10
        $threatFactors += "Critical processes: $($criticalProcesses.Count)"
    }
    
    if ($detectedMalware -and $detectedMalware.Count -gt 0) {
        $threatScore += 50
        $threatFactors += "Malware detected: $($detectedMalware.Count)"
    }
    
    if ($ransomwareFiles -and $ransomwareFiles.Count -gt 0) {
        $threatScore += 80
        $threatFactors += "Ransomware indicators: Yes"
    }
    
    if ((!$defender -or !$defender.RealTimeProtectionEnabled) -or $fwDisabled) {
        $threatScore += 30
        $threatFactors += "Security disabled: Yes"
    }
    
    # Determine threat level
    $threatLevel = switch ($threatScore) {
        {$_ -ge 100} { "CRITICAL" }
        {$_ -ge 70} { "HIGH" }
        {$_ -ge 40} { "MEDIUM" }
        {$_ -ge 20} { "LOW" }
        default { "MINIMAL" }
    }
    
    # Generate executive summary - NO UNICODE
    $executiveSummary = @"
================================================================================
                    INCIDENT RESPONSE EXECUTIVE SUMMARY
================================================================================
System: $env:COMPUTERNAME
Date: $(Get-Date)
Collection Mode: $(if($Quick){"QUICK"}elseif($Deep){"DEEP"}else{"STANDARD"})
Collection ID: $timestamp

THREAT ASSESSMENT
=================
Threat Level: $threatLevel (Score: $threatScore/100)
Total Alerts: $($global:alertCount)

KEY FINDINGS
============
$(if ($global:criticalAlerts -and $global:criticalAlerts.Count -gt 0) {
"CRITICAL ALERTS:
$($global:criticalAlerts | ForEach-Object {"- $_"} | Out-String)"
})

Network Activity:
- Total Connections: $($allConnections.Count)
- Suspicious Connections: $(if($suspiciousConnections){$suspiciousConnections.Count}else{0})

Process Analysis:
- Total Processes: $($allProcesses.Count)
- Suspicious Processes: $(if($suspiciousProcesses){$suspiciousProcesses.Count}else{0})
- Critical Threats: $(if($criticalProcesses){$criticalProcesses.Count}else{0})

Security Status:
- Windows Defender: $(if($defender -and $defender.RealTimeProtectionEnabled){"Enabled"}else{"DISABLED"})
- Firewall: $(if($fwDisabled){"DISABLED on $($fwDisabled.Name -join ', ')"}else{"Enabled"})

RECOMMENDED ACTIONS
==================
$(switch ($threatLevel) {
    "CRITICAL" { "!!! IMMEDIATE ACTION REQUIRED !!!" }
    "HIGH" { "** HIGH PRIORITY RESPONSE **" }
    "MEDIUM" { "* ELEVATED MONITORING REQUIRED *" }
    "LOW" { "- REVIEW AND MONITOR -" }
    default { "- STANDARD MONITORING -" }
})

Evidence Location: $incidentPath
================================================================================
"@
    
    # Save executive summary
    try {
        $executiveSummary | Out-File "$incidentPath\EXECUTIVE_SUMMARY.txt"
    } catch { }
    
    Write-Host $executiveSummary -ForegroundColor Cyan
    
} catch {
    Write-ColorOutput "Error generating final report: $_" "Error"
}

# Wait for any background jobs
$remainingJobs = @(Get-Job -ErrorAction SilentlyContinue)
if ($remainingJobs) {
    Write-ColorOutput "Waiting for background tasks..." "Progress"
    $remainingJobs | ForEach-Object {
        try {
            $_ | Wait-Job -Timeout 10 | Out-Null
            if ($_.State -eq "Running") {
                $_ | Stop-Job
            }
            $_ | Remove-Job -Force
        } catch { }
    }
}

try {
    Stop-Transcript -ErrorAction SilentlyContinue
} catch { }

# Create ZIP archive
Write-Progress -Id $script:mainProgressId -Activity "Incident Response Collection" -Status "Creating evidence archive..." -PercentComplete 98
try {
    $zipPath = "C:\incident_${timestamp}_${env:COMPUTERNAME}.zip"
    Write-ColorOutput "Creating evidence archive..." "Progress"
    
    Compress-Archive -Path "$incidentPath\*" -DestinationPath $zipPath -CompressionLevel Optimal -Force
    
    $zipInfo = Get-Item $zipPath
    Write-ColorOutput "Evidence archive created: $zipPath" "Success"
    Write-ColorOutput "Archive size: $([math]::Round($zipInfo.Length/1MB, 2)) MB" "Info"
    
} catch {
    Write-ColorOutput "Failed to create archive: $_" "Error"
}

# Complete main progress
Write-Progress -Id $script:mainProgressId -Completed

# FINAL OUTPUT - NO UNICODE
Write-ColorOutput "`n================================================================================" "Success"
Write-ColorOutput "              INCIDENT RESPONSE COLLECTION COMPLETE" "Success"
Write-ColorOutput "================================================================================" "Success"
Write-ColorOutput "" "Info"
Write-ColorOutput "Threat Level: $threatLevel (Score: $threatScore/100)" $(if($threatScore -ge 70){"Alert"}else{"Info"})
Write-ColorOutput "Total Alerts: $($global:alertCount)" $(if($global:alertCount -gt 10){"Alert"}else{"Info"})
Write-ColorOutput "Evidence Location: $incidentPath" "Info"
if (Test-Path $zipPath) {
    Write-ColorOutput "Archive: $zipPath" "Info"
}
Write-ColorOutput "" "Info"

switch ($threatLevel) {
    "CRITICAL" {
        Write-ColorOutput "CRITICAL ACTIONS REQUIRED:" "Alert" -Critical $true
        Write-ColorOutput "1. ISOLATE SYSTEM IMMEDIATELY!" "Alert"
        Write-ColorOutput "2. PRESERVE EVIDENCE!" "Alert"
        Write-ColorOutput "3. CONTACT INCIDENT RESPONSE TEAM!" "Alert"
    }
    "HIGH" {
        Write-ColorOutput "HIGH PRIORITY ACTIONS:" "Warning"
        Write-ColorOutput "1. Isolate from sensitive networks" "Warning"
        Write-ColorOutput "2. Review all alerts" "Warning"
        Write-ColorOutput "3. Consider memory capture" "Warning"
    }
    default {
        Write-ColorOutput "Next Steps:" "Info"
        Write-ColorOutput "1. Review findings in $incidentPath\ALERTS\" "Info"
        Write-ColorOutput "2. Analyze IOCs in $incidentPath\IOCs\" "Info"
    }
}

Write-ColorOutput "`nCollection completed in $(if($Quick){'QUICK'}else{'STANDARD'}) mode" "Success"
Write-ColorOutput "================================================================================" "Success"

# Return summary object
return @{
    CollectionID = $timestamp
    ThreatLevel = $threatLevel
    ThreatScore = $threatScore
    AlertCount = $global:alertCount
    EvidencePath = $incidentPath
    ArchivePath = if(Test-Path $zipPath -ErrorAction SilentlyContinue) {$zipPath} else {""}
}
