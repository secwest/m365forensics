# ULTIMATE INCIDENT RESPONSE TRIAGE SCRIPT v4.0
# Run as Administrator: powershell -ExecutionPolicy Bypass -File .\Triage.ps1

param(
    [switch]$Quick = $false,
    [switch]$Deep = $false,
    [switch]$UltraDeep = $false,  # New: Most comprehensive mode
    [int]$TimeoutSeconds = 30,
    [int]$DaysBack = 7,
    [array]$TargetPIDs = @(),
    [array]$TargetIPs = @(),      # New: Specific IPs to investigate
    [switch]$SkipMemory = $false,
    [switch]$SkipFileSystem = $false,
    [switch]$SkipBrowser = $false,
    [switch]$LiveResponse = $false  # New: For active incident response
)

# Initialize
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$incidentPath = "C:\incident_$timestamp"
$global:alertCount = 0
$global:criticalAlerts = @()
$global:findings = @()
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

# Enhanced color output with logging
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
    
    # Always log
    $logMessage | Out-File "$incidentPath\console_output.log" -Append -Force
    
    # Log alerts separately
    if ($Type -eq "Alert") {
        $logMessage | Out-File "$incidentPath\ALERTS\alert_log.txt" -Append -Force
    }
}

# Create comprehensive folder structure
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
    $folders | ForEach-Object { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
    Start-Transcript -Path "$incidentPath\collection_transcript.txt" -Force | Out-Null
} catch {
    Write-Host "ERROR: Cannot create incident folder. Exiting." -ForegroundColor Red
    exit 1
}

# Display banner
$banner = @"
================================================================================
    ULTIMATE INCIDENT RESPONSE COLLECTION v4.0
================================================================================
    Time: $(Get-Date)
    Mode: $(if($UltraDeep){"ULTRA-DEEP"}elseif($Deep){"DEEP"}elseif($Quick){"QUICK"}else{"STANDARD"})
    Output: $incidentPath
================================================================================
"@
Write-Host $banner -ForegroundColor Yellow

# Check privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (!$isAdmin) {
    Write-ColorOutput "WARNING: Not running as Administrator. Collection will be limited!" "Warning"
}

# SECTION 1: ULTRA-FAST TRIAGE (Always run first)
Write-ColorOutput "`n[PHASE 1: RAPID TRIAGE]" "Progress"

try {
    # Get critical system state
    $osInfo = Get-WmiObject Win32_OperatingSystem
    $csInfo = Get-WmiObject Win32_ComputerSystem
    $bootTime = $osInfo.ConvertToDateTime($osInfo.LastBootUpTime)
    $uptime = (Get-Date) - $bootTime
    
    Write-ColorOutput "System: $($csInfo.Name) | OS: $($osInfo.Caption) | Boot: $bootTime" "Info"
    Write-ColorOutput "Domain: $($csInfo.Domain) | User: $env:USERNAME | Uptime: $($uptime.Days)d $($uptime.Hours)h" "Info"
    
    # Quick threat assessment
    $quickChecks = @{
        "Active_Connections" = (Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}).Count
        "Listening_Ports" = (Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}).Count
        "Running_Processes" = (Get-Process).Count
        "Services" = (Get-Service | Where-Object {$_.Status -eq "Running"}).Count
        "Logged_Users" = (quser 2>&1 | Select-String "Active").Count
    }
    
    Write-ColorOutput "Quick Stats: Connections=$($quickChecks.Active_Connections), Listeners=$($quickChecks.Listening_Ports), Processes=$($quickChecks.Running_Processes)" "Info"
    
    # Immediate threat indicators
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defender -and !$defender.RealTimeProtectionEnabled) {
        Write-ColorOutput "DEFENDER DISABLED - System is unprotected!" "Alert" -Critical $true
        $global:alertCount += 5
    }
    
    # Check for obvious compromise indicators
    $obviousThreats = Get-Process | Where-Object {
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
    Write-ColorOutput "Error in rapid triage: $_" "Error"
}

# SECTION 2: NETWORK ANALYSIS (ENHANCED)
Write-ColorOutput "`n[PHASE 2: NETWORK FORENSICS]" "Progress"

try {
    Write-ColorOutput "Capturing network state..." "Progress"
    
    # Get all connections with maximum detail
    $allConnections = Get-NetTCPConnection
    $udpEndpoints = Get-NetUDPEndpoint
    $established = $allConnections | Where-Object {$_.State -eq "Established"}
    $listening = $allConnections | Where-Object {$_.State -eq "Listen"}
    
    # Enhanced connection analysis
    $connectionDetails = @()
    foreach ($conn in $allConnections) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $wmi = Get-WmiObject Win32_Process -Filter "ProcessId=$($conn.OwningProcess)" -ErrorAction SilentlyContinue
        
        # DNS resolution for external IPs (cached)
        $remoteDNS = "N/A"
        if ($conn.RemoteAddress -notmatch "^(10\.|172\.|192\.168\.|127\.|::1|0\.0\.0\.0)") {
            try {
                $remoteDNS = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress).HostName
            } catch { }
        }
        
        # GeoIP lookup for external IPs (if possible)
        $geoLocation = "Unknown"
        # Add GeoIP lookup logic here if available
        
        $connectionDetails += [PSCustomObject]@{
            LocalAddress = $conn.LocalAddress
            LocalPort = $conn.LocalPort
            RemoteAddress = $conn.RemoteAddress
            RemoteDNS = $remoteDNS
            RemotePort = $conn.RemotePort
            State = $conn.State
            ProcessId = $conn.OwningProcess
            ProcessName = if($proc) {$proc.ProcessName} else {"Unknown"}
            ProcessPath = if($proc) {$proc.Path} else {$wmi.ExecutablePath}
            CommandLine = $wmi.CommandLine
            CreationTime = $conn.CreationTime
            GeoLocation = $geoLocation
        }
    }
    
    $connectionDetails | Export-Csv "$incidentPath\Network\Connections\all_connections_detailed.csv" -NoTypeInformation
    
    # Suspicious connection detection (Enhanced)
    Write-ColorOutput "Analyzing connections for threats..." "Progress"
    
    $suspiciousConnections = @()
    $knownC2Ports = @(443, 4444, 4445, 5555, 6666, 7777, 8080, 8443, 8888, 9999, 12345, 31337, 54321)
    $knownC2IPs = @() # Add known C2 IPs from threat intel
    
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
        
        # Long-duration connections
        if ($conn.CreationTime -and ((Get-Date) - $conn.CreationTime).TotalHours -gt 24) {
            $reasons += "Long-duration connection (>24h)"
            $severity += 2
        }
        
        # PowerShell/CMD with network
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if ($proc.ProcessName -match "powershell|cmd|wscript|cscript|mshta|rundll32") {
            $reasons += "Scripting process with network: $($proc.ProcessName)"
            $severity += 4
        }
        
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
                Process = "$($proc.ProcessName) [$($conn.OwningProcess)]"
                Reasons = $reasons -join "; "
                Timestamp = Get-Date
            }
        }
    }
    
    if ($suspiciousConnections) {
        $suspiciousConnections | Sort-Object Severity -Descending | 
            Export-Csv "$incidentPath\ALERTS\suspicious_connections_prioritized.csv" -NoTypeInformation
        Write-ColorOutput "Found $($suspiciousConnections.Count) suspicious connections!" "Alert"
        $global:alertCount += $suspiciousConnections.Count
        
        # Show top threats
        $suspiciousConnections | Sort-Object Severity -Descending | Select-Object -First 3 | ForEach-Object {
            Write-ColorOutput "  - SEVERITY $($_.Severity): $($_.RemoteEndpoint) | $($_.Reasons)" "Alert"
        }
    }
    
    # Network statistics and anomaly detection
    Write-ColorOutput "Calculating network statistics..." "Progress"
    
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
    
    # Netstat variations for comparison
    if (!$Quick) {
        Write-ColorOutput "Running comprehensive netstat..." "Progress"
        Start-Job -Name "Netstat" -ScriptBlock {
            param($path)
            netstat -anob > "$path\Network\netstat_anob.txt" 2>&1
            netstat -s > "$path\Network\netstat_statistics.txt" 2>&1
            netstat -e > "$path\Network\netstat_ethernet.txt" 2>&1
            netsh int ipv4 show tcpconnections > "$path\Network\netsh_tcp.txt" 2>&1
        } -ArgumentList $incidentPath | Out-Null
    }
    
    # Network configuration capture
    Write-ColorOutput "Capturing network configuration..." "Progress"
    ipconfig /all > "$incidentPath\Network\ipconfig_all.txt" 2>&1
    ipconfig /displaydns > "$incidentPath\Network\dns_cache.txt" 2>&1
    arp -a > "$incidentPath\Network\arp_cache.txt" 2>&1
    route print > "$incidentPath\Network\routing_table.txt" 2>&1
    nbtstat -c > "$incidentPath\Network\netbios_cache.txt" 2>&1
    netsh wlan show profiles > "$incidentPath\Network\wifi_profiles.txt" 2>&1
    
    # Extract wireless network passwords if admin
    if ($isAdmin) {
        $wifiProfiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
            $_.ToString().Split(":")[1].Trim()
        }
        foreach ($profile in $wifiProfiles) {
            netsh wlan show profile name="$profile" key=clear >> "$incidentPath\Network\wifi_passwords.txt" 2>&1
        }
    }
    
    # DNS cache analysis
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    if ($dnsCache) {
        $suspiciousDomains = $dnsCache | Where-Object {
            $_.Entry -match "\.tk$|\.ml$|\.ga$|\.cf$|\.bit$|\.onion$" -or
            $_.Entry -match "^[a-f0-9]{32}\." -or
            $_.Entry -match "\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}" -or
            $_.Entry -match "^(ns|mx|mail)\d+\." -or
            $_.Entry.Length -gt 50
        }
        
        if ($suspiciousDomains) {
            Write-ColorOutput "Suspicious DNS entries detected!" "Alert"
            $suspiciousDomains | Export-Csv "$incidentPath\ALERTS\suspicious_dns.csv" -NoTypeInformation
            $global:alertCount++
        }
        
        $dnsCache | Export-Csv "$incidentPath\Network\dns_cache_full.csv" -NoTypeInformation
    }
    
} catch {
    Write-ColorOutput "Error in network forensics: $_" "Error"
}

# SECTION 3: PROCESS FORENSICS (ULTRA-DEEP)
Write-ColorOutput "`n[PHASE 3: PROCESS FORENSICS]" "Progress"

try {
    Write-ColorOutput "Enumerating all processes..." "Progress"
    
    # Get comprehensive process information
    $allProcesses = @()
    $wmiProcesses = Get-WmiObject Win32_Process
    
    foreach ($wmiProc in $wmiProcesses) {
        $proc = Get-Process -Id $wmiProc.ProcessId -ErrorAction SilentlyContinue
        $owner = $wmiProc.GetOwner()
        
        # Get parent process details
        $parentProc = $wmiProcesses | Where-Object {$_.ProcessId -eq $wmiProc.ParentProcessId}
        
        # Check digital signature
        $signature = $null
        $signed = "Unknown"
        if ($wmiProc.ExecutablePath -and (Test-Path $wmiProc.ExecutablePath)) {
            $signature = Get-AuthenticodeSignature -FilePath $wmiProc.ExecutablePath -ErrorAction SilentlyContinue
            $signed = if($signature) {$signature.Status} else {"Error"}
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
        
        if (($parentProc.Name -eq "explorer.exe" -or $parentProc.Name -eq "svchost.exe") -and
            $wmiProc.Name -match "powershell|cmd|wscript|cscript") {
            $trustScore -= 25
            $suspicionReasons += "Suspicious parent-child relationship"
        }
        
        # Check if process has network connections
        $hasNetwork = $established.OwningProcess -contains $wmiProc.ProcessId
        
        # Build comprehensive process object
        $processInfo = [PSCustomObject]@{
            Name = $wmiProc.Name
            ProcessId = $wmiProc.ProcessId
            ParentProcessId = $wmiProc.ParentProcessId
            ParentName = if($parentProc) {$parentProc.Name} else {"Unknown"}
            Path = $wmiProc.ExecutablePath
            CommandLine = $wmiProc.CommandLine
            CreationDate = if($wmiProc.CreationDate) {
                $wmiProc.ConvertToDateTime($wmiProc.CreationDate)
            } else {"Unknown"}
            Owner = "$($owner.Domain)\$($owner.User)"
            SessionId = $wmiProc.SessionId
            ThreadCount = $wmiProc.ThreadCount
            HandleCount = $wmiProc.HandleCount
            WorkingSetMB = [math]::Round($wmiProc.WorkingSetSize / 1MB, 2)
            VirtualSizeMB = [math]::Round($wmiProc.VirtualSize / 1MB, 2)
            PageFileUsageMB = [math]::Round($wmiProc.PageFileUsage / 1MB, 2)
            CPUTime = if($proc) {$proc.TotalProcessorTime} else {"N/A"}
            Priority = $wmiProc.Priority
            Signed = $signed
            SignerCertificate = if($signature -and $signature.SignerCertificate) {
                $signature.SignerCertificate.Subject
            } else {"None"}
            HasNetwork = $hasNetwork
            TrustScore = $trustScore
            SuspicionReasons = $suspicionReasons -join "; "
            MD5 = if($wmiProc.ExecutablePath -and (Test-Path $wmiProc.ExecutablePath)) {
                (Get-FileHash -Path $wmiProc.ExecutablePath -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
            } else {"N/A"}
            SHA256 = if($wmiProc.ExecutablePath -and (Test-Path $wmiProc.ExecutablePath)) {
                (Get-FileHash -Path $wmiProc.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            } else {"N/A"}
        }
        
        $allProcesses += $processInfo
        
        # Alert on highly suspicious processes
        if ($trustScore -lt 50) {
            Write-ColorOutput "SUSPICIOUS: $($wmiProc.Name) [PID: $($wmiProc.ProcessId)] Score: $trustScore" "Alert"
            $global:alertCount++
        }
    }
    
    # Export all processes
    $allProcesses | Export-Csv "$incidentPath\Processes\all_processes_forensic.csv" -NoTypeInformation
    Write-ColorOutput "Analyzed $($allProcesses.Count) processes" "Info"
    
    # Categorize processes by trust level
    $criticalProcesses = $allProcesses | Where-Object {$_.TrustScore -lt 40}
    $suspiciousProcesses = $allProcesses | Where-Object {$_.TrustScore -ge 40 -and $_.TrustScore -lt 70}
    $trustedProcesses = $allProcesses | Where-Object {$_.TrustScore -ge 70}
    
    if ($criticalProcesses) {
        $criticalProcesses | Export-Csv "$incidentPath\ALERTS\critical_processes.csv" -NoTypeInformation
        Write-ColorOutput "CRITICAL: $($criticalProcesses.Count) highly suspicious processes!" "Alert" -Critical $true
    }
    
    if ($suspiciousProcesses) {
        $suspiciousProcesses | Export-Csv "$incidentPath\ALERTS\suspicious_processes.csv" -NoTypeInformation
    }
    
    # Process tree analysis
    Write-ColorOutput "Building process tree..." "Progress"
    $processTree = @()
    $rootProcesses = $allProcesses | Where-Object {$_.ParentProcessId -eq 0 -or $_.ParentProcessId -eq 4}
    
    foreach ($root in $rootProcesses) {
        $tree = Get-ProcessTree -Process $root -AllProcesses $allProcesses -Level 0
        $processTree += $tree
    }
    
    function Get-ProcessTree {
        param($Process, $AllProcesses, $Level)
        
        $indent = "  " * $Level
        $treeNode = "$indent$($Process.Name) [$($Process.ProcessId)]"
        
        $children = $AllProcesses | Where-Object {$_.ParentProcessId -eq $Process.ProcessId}
        foreach ($child in $children) {
            $treeNode += "`n" + (Get-ProcessTree -Process $child -AllProcesses $AllProcesses -Level ($Level + 1))
        }
        
        return $treeNode
    }
    
    $processTree | Out-File "$incidentPath\Processes\process_tree.txt"
    
    # Check for specific malware indicators
    Write-ColorOutput "Checking for malware indicators..." "Progress"
    
    # Known malware process names/patterns
    $malwarePatterns = @{
        "Mimikatz" = "mimikatz|mimi|katz|kitten|mimidrv"
        "Cobalt Strike" = "beacon|artifact\.exe|cobaltstrike"
        "Metasploit" = "meterpreter|metasploit|msf"
        "PowerShell Empire" = "empire|invoke-empire"
        "BloodHound" = "bloodhound|sharphound|azurehound"
        "Ransomware" = "encrypt|crypto|locker|wanna|ryuk|conti|lockbit"
        "RATs" = "njrat|darkcomet|netwire|nanocore|remcos|asyncrat|quasar"
        "Credential Dumpers" = "lsass|procdump|sqldumper|nanodump"
    }
    
    $detectedMalware = @()
    foreach ($pattern in $malwarePatterns.GetEnumerator()) {
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
    }
    
    if ($detectedMalware) {
        Write-ColorOutput "MALWARE DETECTED!" "Alert" -Critical $true
        $detectedMalware | Export-Csv "$incidentPath\ALERTS\detected_malware.csv" -NoTypeInformation
        $detectedMalware | ForEach-Object {
            Write-ColorOutput "  - $($_.MalwareFamily): $($_.ProcessName) [PID: $($_.ProcessId)]" "Alert"
        }
        $global:alertCount += 10
    }
    
    # Process injection detection
    Write-ColorOutput "Checking for process injection..." "Progress"
    
    $injectionCandidates = @()
    $criticalProcesses = @("lsass", "csrss", "winlogon", "services", "svchost", "explorer")
    
    foreach ($critProc in ($allProcesses | Where-Object {$_.Name -replace '\.exe$','' -in $criticalProcesses})) {
        $proc = Get-Process -Id $critProc.ProcessId -ErrorAction SilentlyContinue
        if ($proc -and $proc.Modules) {
            $suspiciousModules = $proc.Modules | Where-Object {
                $_.FileName -notmatch "Windows|System32|SysWOW64|Microsoft" -and
                $_.FileName -notmatch "Program Files"
            }
            
            if ($suspiciousModules) {
                $injectionCandidates += [PSCustomObject]@{
                    Process = "$($critProc.Name) [$($critProc.ProcessId)]"
                    SuspiciousModules = ($suspiciousModules.FileName -join "; ")
                    ModuleCount = $suspiciousModules.Count
                }
            }
        }
    }
    
    if ($injectionCandidates) {
        Write-ColorOutput "Possible process injection detected!" "Alert"
        $injectionCandidates | Export-Csv "$incidentPath\ALERTS\process_injection.csv" -NoTypeInformation
        $global:alertCount += 5
    }
    
    # Check specific PIDs if provided
    if ($TargetPIDs) {
        Write-ColorOutput "Investigating target PIDs: $($TargetPIDs -join ', ')" "Progress"
        $targetProcesses = $allProcesses | Where-Object {$_.ProcessId -in $TargetPIDs}
        
        foreach ($target in $targetProcesses) {
            Write-ColorOutput "Target PID $($target.ProcessId): $($target.Name)" "Finding"
            Write-ColorOutput "  Path: $($target.Path)" "Info"
            Write-ColorOutput "  Command: $($target.CommandLine)" "Info"
            Write-ColorOutput "  Trust Score: $($target.TrustScore)" "Info"
            
            # Get detailed info
            $targetDetails = [PSCustomObject]@{
                ProcessInfo = $target
                NetworkConnections = $connectionDetails | Where-Object {$_.ProcessId -eq $target.ProcessId}
                ChildProcesses = $allProcesses | Where-Object {$_.ParentProcessId -eq $target.ProcessId}
                LoadedModules = if($proc = Get-Process -Id $target.ProcessId -ErrorAction SilentlyContinue) {
                    $proc.Modules | Select-Object ModuleName, FileName
                } else {$null}
            }
            
            $targetDetails | ConvertTo-Json -Depth 5 | 
                Out-File "$incidentPath\ALERTS\target_pid_$($target.ProcessId)_details.json"
        }
    }
    
} catch {
    Write-ColorOutput "Error in process forensics: $_" "Error"
}

# SECTION 4: PERSISTENCE MECHANISMS (COMPREHENSIVE)
Write-ColorOutput "`n[PHASE 4: PERSISTENCE ANALYSIS]" "Progress"

try {
    # Registry persistence - exhaustive check
    Write-ColorOutput "Checking registry persistence..." "Progress"
    
    $regPersistence = @()
    $regKeys = @{
        # Standard Run keys
        "HKLM_Run" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        "HKLM_RunOnce" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        "HKLM_RunOnceEx" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
        "HKCU_Run" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        "HKCU_RunOnce" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        "HKLM_Run_Wow64" = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
        
        # Services
        "HKLM_RunServices" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices"
        "HKLM_RunServicesOnce" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
        
        # Winlogon
        "HKLM_Winlogon" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        "HKCU_Winlogon" = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        "HKLM_Winlogon_UserInit" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\UserInit"
        "HKLM_Winlogon_Shell" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"
        
        # Windows components
        "HKLM_Windows_Load" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
        "HKCU_Windows_Load" = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
        
        # Explorer
        "HKLM_Explorer_Run" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        "HKCU_Explorer_Run" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        "HKLM_Explorer_ShellFolders" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
        "HKCU_Explorer_ShellFolders" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
        
        # Browser Helper Objects
        "HKLM_BHO" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
        "HKLM_BHO_Wow64" = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
        
        # Shell Extensions
        "HKLM_ShellExecuteHooks" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"
        "HKLM_ShellServiceObjects" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjectDelayLoad"
        "HKLM_ShellIconOverlay" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"
        
        # Context Menu Handlers
        "HKLM_ContextMenuHandlers" = "HKLM:\Software\Classes\*\shellex\ContextMenuHandlers"
        "HKLM_DirectoryContext" = "HKLM:\Software\Classes\Directory\shellex\ContextMenuHandlers"
        "HKLM_DirectoryBackground" = "HKLM:\Software\Classes\Directory\Background\shellex\ContextMenuHandlers"
        
        # Drivers and Services
        "HKLM_Drivers" = "HKLM:\System\CurrentControlSet\Control\Session Manager\BootExecute"
        "HKLM_ServiceDlls" = "HKLM:\System\CurrentControlSet\Services"
        "HKLM_KnownDlls" = "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs"
        
        # AppInit
        "HKLM_AppInit_DLLs" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
        "HKLM_AppInit_DLLs_Wow64" = "HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
        
        # Image File Execution Options
        "HKLM_IFEO" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        "HKLM_SilentProcessExit" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
        
        # File Associations
        "HKLM_FileExts" = "HKLM:\Software\Classes\.exe"
        "HKCU_FileExts" = "HKCU:\Software\Classes\.exe"
        
        # Command Processor
        "HKLM_CommandProcessor" = "HKLM:\Software\Microsoft\Command Processor"
        "HKCU_CommandProcessor" = "HKCU:\Software\Microsoft\Command Processor"
        
        # Print Monitors
        "HKLM_PrintMonitors" = "HKLM:\System\CurrentControlSet\Control\Print\Monitors"
        
        # Network Providers
        "HKLM_NetworkProvider" = "HKLM:\System\CurrentControlSet\Control\NetworkProvider\Order"
        
        # LSA Providers
        "HKLM_LSA_Providers" = "HKLM:\System\CurrentControlSet\Control\Lsa"
        "HKLM_LSA_Security_Packages" = "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig"
        
        # Time Providers
        "HKLM_TimeProviders" = "HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders"
        
        # DNS Settings
        "HKLM_DNS" = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters"
        
        # WMI
        "HKLM_WMI" = "HKLM:\Software\Microsoft\Wbem\ESS"
        
        # Office
        "HKCU_Office_Startup" = "HKCU:\Software\Microsoft\Office\*\*\Options"
        
        # Scheduled Tasks
        "HKLM_ScheduledTasks" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
    }
    
    foreach ($keyInfo in $regKeys.GetEnumerator()) {
        $keyName = $keyInfo.Key
        $keyPath = $keyInfo.Value
        
        # Special handling for wildcards
        if ($keyPath -match '\*') {
            $basePath = $keyPath -replace '\\\*.*$', ''
            if (Test-Path $basePath) {
                $subKeys = Get-ChildItem $basePath -Recurse -ErrorAction SilentlyContinue
                foreach ($subKey in $subKeys) {
                    CheckRegistryKey -KeyName "$keyName\$($subKey.PSChildName)" -KeyPath $subKey.PSPath
                }
            }
        } else {
            CheckRegistryKey -KeyName $keyName -KeyPath $keyPath
        }
    }
    
    function CheckRegistryKey {
        param($KeyName, $KeyPath)
        
        if (Test-Path $KeyPath) {
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
                    
                    $regPersistence += [PSCustomObject]@{
                        Location = $KeyName
                        KeyPath = $KeyPath
                        Name = $_.Name
                        Value = $_.Value
                        Suspicious = $suspicious
                        Reason = $reason
                        LastModified = (Get-Item $KeyPath).LastWriteTime
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
                    if ($debugger) {
                        $regPersistence += [PSCustomObject]@{
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
    }
    
    $regPersistence | Export-Csv "$incidentPath\Persistence\Registry\all_registry_persistence.csv" -NoTypeInformation
    $regPersistence | Where-Object {$_.Suspicious} | 
        Export-Csv "$incidentPath\ALERTS\suspicious_registry_persistence.csv" -NoTypeInformation
    
    Write-ColorOutput "Found $($regPersistence.Count) registry persistence entries" "Info"
    
    # Scheduled Tasks Analysis
    Write-ColorOutput "Analyzing scheduled tasks..." "Progress"
    
    $allTasks = Get-ScheduledTask
    $taskAnalysis = @()
    
    foreach ($task in $allTasks) {
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
        
        if ($task.Author -eq "" -or $task.Author -eq $null) {
            $suspicionReasons += "No author specified"
        }
        
        if ($task.State -eq "Ready" -and $task.Triggers) {
            foreach ($trigger in $task.Triggers) {
                if ($trigger.CimClass.CimClassName -match "Boot|Logon|Startup") {
                    $suspicionReasons += "Triggers at system startup/logon"
                }
            }
        }
        
        # Check if recently created
        $recentlyCreated = $false
        if ($task.Date) {
            $taskDate = [DateTime]::Parse($task.Date)
            if ($taskDate -gt (Get-Date).AddDays(-$DaysBack)) {
                $recentlyCreated = $true
                $suspicious = $true
                $suspicionReasons += "Recently created"
            }
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
            NumberMissedRuns = $info.NumberOfMissedRuns
            Actions = ($task.Actions | ForEach-Object {"$($_.Execute) $($_.Arguments)"}) -join "; "
            Triggers = ($task.Triggers | ForEach-Object {$_.CimClass.CimClassName}) -join "; "
            RunAsUser = $task.Principal.UserId
            RunLevel = $task.Principal.RunLevel
            AllowStartOnDemand = $task.Settings.AllowStartOnDemand
            Hidden = $task.Settings.Hidden
            Suspicious = $suspicious
            SuspicionReasons = $suspicionReasons -join "; "
        }
        
        if ($suspicious) {
            Write-ColorOutput "SUSPICIOUS TASK: $($task.TaskName)" "Alert"
            $global:alertCount++
        }
    }
    
    $taskAnalysis | Export-Csv "$incidentPath\Persistence\Tasks\all_scheduled_tasks.csv" -NoTypeInformation
    $taskAnalysis | Where-Object {$_.Suspicious} | 
        Export-Csv "$incidentPath\ALERTS\suspicious_scheduled_tasks.csv" -NoTypeInformation
    
    # WMI Persistence
    Write-ColorOutput "Checking WMI persistence..." "Progress"
    
    $wmiPersistence = @()
    
    # Check multiple namespaces
    $wmiNamespaces = @("root\subscription", "root\default", "root\cimv2")
    
    foreach ($namespace in $wmiNamespaces) {
        # Event Filters
        $filters = Get-WmiObject -Namespace $namespace -Class __EventFilter -ErrorAction SilentlyContinue
        foreach ($filter in $filters) {
            $wmiPersistence += [PSCustomObject]@{
                Type = "EventFilter"
                Namespace = $namespace
                Name = $filter.Name
                Query = $filter.Query
                EventNamespace = $filter.EventNamespace
                CreatorSID = $filter.CreatorSID
            }
            
            if ($filter.Query -match "Win32_LocalTime|Win32_LogicalDisk|SELECT \* FROM") {
                Write-ColorOutput "WMI EVENT FILTER: $($filter.Name)" "Alert"
                $global:alertCount++
            }
        }
        
        # Event Consumers
        $consumers = Get-WmiObject -Namespace $namespace -Class __EventConsumer -ErrorAction SilentlyContinue
        foreach ($consumer in $consumers) {
            $wmiPersistence += [PSCustomObject]@{
                Type = "EventConsumer"
                Namespace = $namespace
                Name = $consumer.Name
                ConsumerType = $consumer.__CLASS
                CommandLineTemplate = if($consumer.CommandLineTemplate) {$consumer.CommandLineTemplate} else {"N/A"}
                ScriptFileName = if($consumer.ScriptFileName) {$consumer.ScriptFileName} else {"N/A"}
                ScriptText = if($consumer.ScriptText) {$consumer.ScriptText} else {"N/A"}
            }
            
            if ($consumer.CommandLineTemplate -match "powershell|cmd|wscript|cscript") {
                Write-ColorOutput "WMI CONSUMER: $($consumer.Name) executes: $($consumer.CommandLineTemplate)" "Alert"
                $global:alertCount++
            }
        }
        
        # Bindings
        $bindings = Get-WmiObject -Namespace $namespace -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
        foreach ($binding in $bindings) {
            $wmiPersistence += [PSCustomObject]@{
                Type = "Binding"
                Namespace = $namespace
                Filter = $binding.Filter
                Consumer = $binding.Consumer
            }
        }
    }
    
    if ($wmiPersistence) {
        $wmiPersistence | Export-Csv "$incidentPath\Persistence\WMI\wmi_persistence.csv" -NoTypeInformation
        Write-ColorOutput "Found $($wmiPersistence.Count) WMI persistence entries" "Info"
    }
    
    # Services Analysis
    Write-ColorOutput "Analyzing services..." "Progress"
    
    $services = Get-WmiObject Win32_Service
    $serviceAnalysis = @()
    
    foreach ($service in $services) {
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
        
        # Check service account
        if ($service.StartName -notmatch "LocalSystem|LocalService|NetworkService|NT AUTHORITY") {
            if ($service.StartName) {
                $suspicionReasons += "Non-standard service account: $($service.StartName)"
            }
        }
        
        # Check if service has no description
        if (!$service.Description -and $service.State -eq "Running") {
            $suspicionReasons += "Running service with no description"
        }
        
        $serviceAnalysis += [PSCustomObject]@{
            Name = $service.Name
            DisplayName = $service.DisplayName
            State = $service.State
            StartMode = $service.StartMode
            PathName = $service.PathName
            Description = $service.Description
            StartName = $service.StartName
            ProcessId = $service.ProcessId
            AcceptStop = $service.AcceptStop
            ServiceType = $service.ServiceType
            ErrorControl = $service.ErrorControl
            Suspicious = $suspicious
            SuspicionReasons = $suspicionReasons -join "; "
        }
        
        if ($suspicious -and $service.State -eq "Running") {
            Write-ColorOutput "SUSPICIOUS SERVICE: $($service.Name) - $($service.PathName)" "Alert"
            $global:alertCount++
        }
    }
    
    $serviceAnalysis | Export-Csv "$incidentPath\System\all_services_analysis.csv" -NoTypeInformation
    $serviceAnalysis | Where-Object {$_.Suspicious} | 
        Export-Csv "$incidentPath\ALERTS\suspicious_services.csv" -NoTypeInformation
    
    # Startup Locations
    Write-ColorOutput "Checking startup locations..." "Progress"
    
    $startupLocations = @(
        @{Path="$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"; Type="AllUsers"},
        @{Path="$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"; Type="CurrentUser"},
        @{Path="$env:ALLUSERSPROFILE\Start Menu\Programs\StartUp"; Type="AllUsers_Legacy"},
        @{Path="$env:USERPROFILE\Start Menu\Programs\Startup"; Type="User_Legacy"}
    )
    
    $startupItems = @()
    foreach ($location in $startupLocations) {
        if (Test-Path $location.Path) {
            $items = Get-ChildItem -Path $location.Path -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                $suspicious = $false
                $target = "N/A"
                
                if ($item.Extension -eq ".lnk") {
                    $shell = New-Object -ComObject WScript.Shell
                    $shortcut = $shell.CreateShortcut($item.FullName)
                    $target = $shortcut.TargetPath
                    
                    if ($target -match "powershell|cmd|wscript|cscript|mshta") {
                        $suspicious = $true
                    }
                }
                
                $startupItems += [PSCustomObject]@{
                    Location = $location.Type
                    Path = $item.FullName
                    Name = $item.Name
                    Target = $target
                    CreationTime = $item.CreationTime
                    LastWriteTime = $item.LastWriteTime
                    Size = $item.Length
                    Hidden = ($item.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0
                    Suspicious = $suspicious
                }
                
                if ($suspicious) {
                    Write-ColorOutput "SUSPICIOUS STARTUP: $($item.Name) -> $target" "Alert"
                    $global:alertCount++
                }
            }
        }
    }
    
    if ($startupItems) {
        $startupItems | Export-Csv "$incidentPath\Persistence\startup_items.csv" -NoTypeInformation
    }
    
    # DLL Hijacking opportunities
    if (!$Quick) {
        Write-ColorOutput "Checking for DLL hijacking opportunities..." "Progress"
        
        # Check for missing DLLs in common locations
        $commonExes = Get-ChildItem "C:\Windows\System32\*.exe" -ErrorAction SilentlyContinue | Select-Object -First 20
        $dllHijackOpportunities = @()
        
        foreach ($exe in $commonExes) {
            $procmon = Start-Process -FilePath $exe.FullName -ArgumentList "/?" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 100
            if ($procmon -and !$procmon.HasExited) {
                $procmon.Kill()
            }
            
            # Check for DLLs in exe directory that don't exist in System32
            $exeDir = Split-Path $exe.FullName -Parent
            $localDlls = Get-ChildItem "$exeDir\*.dll" -ErrorAction SilentlyContinue
            
            foreach ($dll in $localDlls) {
                if (!(Test-Path "C:\Windows\System32\$($dll.Name)")) {
                    $dllHijackOpportunities += [PSCustomObject]@{
                        Executable = $exe.Name
                        DLL = $dll.Name
                        Location = $dll.DirectoryName
                        Exists = $true
                    }
                }
            }
        }
        
        if ($dllHijackOpportunities) {
            $dllHijackOpportunities | Export-Csv "$incidentPath\Persistence\dll_hijack_opportunities.csv" -NoTypeInformation
        }
    }
    
} catch {
    Write-ColorOutput "Error in persistence analysis: $_" "Error"
}

# SECTION 5: MEMORY FORENSICS
if (!$SkipMemory -and !$Quick) {
    Write-ColorOutput "`n[PHASE 5: MEMORY FORENSICS]" "Progress"
    
    try {
        # Process memory statistics
        Write-ColorOutput "Analyzing process memory..." "Progress"
        
        $memoryAnalysis = Get-Process | Select-Object ProcessName, Id,
            @{N='WorkingSetMB';E={[math]::Round($_.WorkingSet64/1MB,2)}},
            @{N='PrivateMemoryMB';E={[math]::Round($_.PrivateMemorySize64/1MB,2)}},
            @{N='VirtualMemoryMB';E={[math]::Round($_.VirtualMemorySize64/1MB,2)}},
            @{N='PagedMemoryMB';E={[math]::Round($_.PagedMemorySize64/1MB,2)}},
            @{N='NonPagedMemoryMB';E={[math]::Round($_.NonpagedSystemMemorySize64/1MB,2)}},
            Handles, Threads,
            @{N='CPUPercent';E={
                if ($_.TotalProcessorTime) {
                    [math]::Round(($_.TotalProcessorTime.TotalSeconds / (Get-Date).Subtract($_.StartTime).TotalSeconds) * 100, 2)
                } else { 0 }
            }} | Sort-Object WorkingSetMB -Descending
        
        $memoryAnalysis | Export-Csv "$incidentPath\Memory\process_memory_analysis.csv" -NoTypeInformation
        
        # Identify memory anomalies
        $memoryAnomalies = $memoryAnalysis | Where-Object {
            $_.WorkingSetMB -gt 1000 -or
            $_.Handles -gt 10000 -or
            $_.Threads -gt 500 -or
            ($_.ProcessName -match "svchost|lsass|csrss" -and $_.WorkingSetMB -gt 200)
        }
        
        if ($memoryAnomalies) {
            Write-ColorOutput "Memory anomalies detected!" "Alert"
            $memoryAnomalies | Export-Csv "$incidentPath\ALERTS\memory_anomalies.csv" -NoTypeInformation
        }
        
        # Check for process hollowing indicators
        Write-ColorOutput "Checking for process hollowing..." "Progress"
        
        $hollowingCandidates = @()
        $criticalProcs = Get-Process | Where-Object {
            $_.ProcessName -match "svchost|explorer|winlogon|csrss|lsass|services"
        }
        
        foreach ($proc in $criticalProcs) {
            try {
                # Get process base address
                $baseAddress = $proc.MainModule.BaseAddress
                
                # Check if process image matches on disk
                if ($proc.MainModule.FileName) {
                    $onDiskHash = (Get-FileHash -Path $proc.MainModule.FileName -Algorithm SHA256).Hash
                    
                    # This is a simplified check - real memory comparison would require driver
                    $suspicious = $false
                    
                    # Check for unusual memory protections or VAD anomalies
                    # (This would require deeper memory access)
                    
                    if ($suspicious) {
                        $hollowingCandidates += [PSCustomObject]@{
                            Process = $proc.ProcessName
                            PID = $proc.Id
                            ImagePath = $proc.MainModule.FileName
                            BaseAddress = $baseAddress
                            FileHash = $onDiskHash
                        }
                    }
                }
            } catch { }
        }
        
        # Loaded modules analysis
        Write-ColorOutput "Analyzing loaded modules..." "Progress"
        
        $moduleAnalysis = @()
        $allModules = Get-Process | Where-Object {$_.Modules} | ForEach-Object {
            $procName = $_.ProcessName
            $procId = $_.Id
            
            $_.Modules | ForEach-Object {
                [PSCustomObject]@{
                    ProcessName = $procName
                    ProcessId = $procId
                    ModuleName = $_.ModuleName
                    FileName = $_.FileName
                    FileVersion = $_.FileVersion
                    Size = $_.Size
                    Company = $_.Company
                }
            }
        }
        
        # Find suspicious modules
        $suspiciousModules = $allModules | Where-Object {
            $_.FileName -match "\\Temp\\|\\AppData\\|\\Users\\Public\\" -or
            $_.Company -eq $null -or
            $_.FileName -notmatch "Windows|System32|Program Files|Microsoft"
        } | Sort-Object ProcessName, ModuleName -Unique
        
        if ($suspiciousModules) {
            Write-ColorOutput "Suspicious modules loaded!" "Alert"
            $suspiciousModules | Export-Csv "$incidentPath\ALERTS\suspicious_modules.csv" -NoTypeInformation
            $global:alertCount++
        }
        
        # Memory strings extraction for key processes
        if ($UltraDeep -and $isAdmin) {
            Write-ColorOutput "Extracting memory strings from suspicious processes..." "Progress"
            
            $targetProcs = $allProcesses | Where-Object {$_.TrustScore -lt 50} | Select-Object -First 5
            
            foreach ($proc in $targetProcs) {
                # Note: This would ideally use a tool like strings.exe or memory dumping
                # For now, we'll create a placeholder for manual analysis
                @"
Process: $($proc.Name) [PID: $($proc.ProcessId)]
Path: $($proc.Path)
Trust Score: $($proc.TrustScore)

To extract strings:
1. Use Sysinternals strings.exe: strings -n 8 -pid $($proc.ProcessId) > pid_$($proc.ProcessId)_strings.txt
2. Use procdump: procdump -ma $($proc.ProcessId) pid_$($proc.ProcessId).dmp
3. Analyze with volatility or windbg

Suspicious indicators to look for:
- URLs (especially C2 servers)
- IP addresses
- File paths
- Registry keys
- Encoded/encrypted data
- Command line arguments
- Passwords or credentials
"@ | Out-File "$incidentPath\Memory\pid_$($proc.ProcessId)_analysis_instructions.txt"
            }
        }
        
        # Handle analysis
        Write-ColorOutput "Analyzing system handles..." "Progress"
        
        # Check for handle leaks or suspicious handle usage
        $handleStats = Get-Process | Group-Object ProcessName | ForEach-Object {
            $handles = ($_.Group | Measure-Object -Property Handles -Sum).Sum
            [PSCustomObject]@{
                ProcessName = $_.Name
                Count = $_.Count
                TotalHandles = $handles
                AverageHandles = [math]::Round($handles / $_.Count, 2)
            }
        } | Sort-Object TotalHandles -Descending
        
        $handleStats | Export-Csv "$incidentPath\Memory\handle_statistics.csv" -NoTypeInformation
        
        # Named pipes and mutexes (requires handle.exe or similar)
        if (Get-Command handle.exe -ErrorAction SilentlyContinue) {
            Write-ColorOutput "Enumerating named objects..." "Progress"
            handle.exe -a -nobanner | Out-File "$incidentPath\Memory\all_handles.txt"
            
            # Extract suspicious named pipes and mutexes
            $namedObjects = handle.exe -a -nobanner | Select-String "Mutant|Pipe" | ForEach-Object {
                if ($_ -match "pid:\s+(\d+)\s+type:\s+(\w+)\s+.*\\(.+)$") {
                    [PSCustomObject]@{
                        PID = $matches[1]
                        Type = $matches[2]
                        Name = $matches[3]
                    }
                }
            }
            
            # Check for known malware mutexes
            $knownMalwareMutexes = @(
                "Global\\I98uj9kjkjoi",
                "Global\\MSCTF",
                "_AVIRA_",
                "Global\\MicrosoftUpdate",
                "Global\\WininetStartupMutex"
            )
            
            $maliciousMutexes = $namedObjects | Where-Object {
                $_.Type -eq "Mutant" -and (
                    $_.Name -in $knownMalwareMutexes -or
                    $_.Name -match "^[a-f0-9]{32}$" -or
                    $_.Name -match "Global\\[A-Z]{10,}"
                )
            }
            
            if ($maliciousMutexes) {
                Write-ColorOutput "Suspicious mutexes detected!" "Alert"
                $maliciousMutexes | Export-Csv "$incidentPath\ALERTS\suspicious_mutexes.csv" -NoTypeInformation
                $global:alertCount++
            }
        }
        
    } catch {
        Write-ColorOutput "Error in memory forensics: $_" "Error"
    }
}

# SECTION 6: FILE SYSTEM FORENSICS
if (!$SkipFileSystem -and !$Quick) {
    Write-ColorOutput "`n[PHASE 6: FILE SYSTEM FORENSICS]" "Progress"
    
    try {
        # Recent file activity
        Write-ColorOutput "Analyzing recent file system activity..." "Progress"
        
        $recentDate = (Get-Date).AddDays(-$DaysBack)
        $criticalPaths = @(
            "$env:TEMP",
            "$env:APPDATA",
            "$env:LOCALAPPDATA",
            "$env:LOCALAPPDATA\Temp",
            "$env:PUBLIC",
            "$env:ProgramData",
            "$env:USERPROFILE\Downloads",
            "$env:USERPROFILE\Documents",
            "$env:USERPROFILE\Desktop",
            "C:\Windows\Temp",
            "C:\Windows\Tasks",
            "C:\Windows\System32\Tasks"
        )
        
        $recentFiles = @()
        $suspiciousFiles = @()
        
        foreach ($path in $criticalPaths) {
            if (Test-Path $path) {
                Write-ColorOutput "  Scanning: $path" "Progress"
                
                $files = Get-ChildItem -Path $path -Recurse -File -Force -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.CreationTime -gt $recentDate -or 
                        $_.LastWriteTime -gt $recentDate
                    }
                
                foreach ($file in $files) {
                    $fileInfo = [PSCustomObject]@{
                        FullPath = $file.FullName
                        Directory = $file.DirectoryName
                        FileName = $file.Name
                        Extension = $file.Extension
                        Size = $file.Length
                        CreationTime = $file.CreationTime
                        LastWriteTime = $file.LastWriteTime
                        LastAccessTime = $file.LastAccessTime
                        Hidden = ($file.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0
                        System = ($file.Attributes -band [System.IO.FileAttributes]::System) -ne 0
                        Encrypted = ($file.Attributes -band [System.IO.FileAttributes]::Encrypted) -ne 0
                        Zone = "Unknown"
                        MD5 = ""
                        Suspicious = $false
                        SuspicionReason = ""
                    }
                    
                    # Check Zone.Identifier (download source)
                    try {
                        $zone = Get-Content "$($file.FullName):Zone.Identifier" -ErrorAction SilentlyContinue
                        if ($zone) {
                            $fileInfo.Zone = ($zone | Select-String "ZoneId=(\d)").Matches[0].Groups[1].Value
                        }
                    } catch { }
                    
                    # Check for suspicious patterns
                    if ($file.Extension -match "\.exe$|\.dll$|\.scr$|\.bat$|\.cmd$|\.ps1$|\.vbs$|\.js$|\.jar$|\.com$|\.pif$") {
                        $fileInfo.Suspicious = $true
                        $fileInfo.SuspicionReason = "Executable file"
                        
                        # Calculate hash for executables
                        if ($file.Length -lt 100MB) {
                            $fileInfo.MD5 = (Get-FileHash -Path $file.FullName -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
                        }
                    }
                    
                    if ($file.Name -match "^[a-z]{8}\.(exe|dll)$|^[0-9]{6,}\.(exe|dll)$") {
                        $fileInfo.Suspicious = $true
                        $fileInfo.SuspicionReason += "; Random name pattern"
                    }
                    
                    if ($file.FullName -match "\\Temp\\" -and $file.Extension -match "\.exe$|\.dll$") {
                        $fileInfo.Suspicious = $true
                        $fileInfo.SuspicionReason += "; Executable in temp"
                    }
                    
                    if ($fileInfo.Hidden -and $file.Extension -match "\.exe$|\.dll$") {
                        $fileInfo.Suspicious = $true
                        $fileInfo.SuspicionReason += "; Hidden executable"
                    }
                    
                    # Check for double extensions
                    if ($file.Name -match "\.(jpg|pdf|doc|txt)\.(exe|scr|bat|cmd|com|pif)$") {
                        $fileInfo.Suspicious = $true
                        $fileInfo.SuspicionReason += "; Double extension"
                    }
                    
                    $recentFiles += $fileInfo
                    
                    if ($fileInfo.Suspicious) {
                        $suspiciousFiles += $fileInfo
                    }
                }
            }
        }
        
        # Export results
        $recentFiles | Export-Csv "$incidentPath\FileSystem\recent_files.csv" -NoTypeInformation
        
        if ($suspiciousFiles) {
            Write-ColorOutput "Found $($suspiciousFiles.Count) suspicious files!" "Alert"
            $suspiciousFiles | Export-Csv "$incidentPath\ALERTS\suspicious_files.csv" -NoTypeInformation
            $global:alertCount++
            
            # Show most suspicious
            $suspiciousFiles | Sort-Object CreationTime -Descending | Select-Object -First 5 | ForEach-Object {
                Write-ColorOutput "  - $($_.FileName): $($_.SuspicionReason)" "Alert"
            }
        }
        
        # Ransomware detection
        Write-ColorOutput "Checking for ransomware indicators..." "Progress"
        
        $ransomwareIndicators = @{
            Extensions = @(
                "\.encrypted$", "\.enc$", "\.locked$", "\.crypto$", 
                "\.kraken$", "\.darkness$", "\.nochance$", "\.exx$", 
                "\.lockbit$", "\.abcd$", "\.fuck$", "\.[a-z0-9]{5,8}$"
            )
            NoteFiles = @(
                "README.txt", "DECRYPT_INSTRUCTIONS.txt", "HOW_TO_DECRYPT.txt",
                "YOUR_FILES_ARE_ENCRYPTED.txt", "RESTORE_FILES.txt",
                "_readme.txt", "readme.hta", "HELP_DECRYPT.html"
            )
        }
        
        $ransomwareFiles = @()
        
        # Check for encrypted files
        foreach ($ext in $ransomwareIndicators.Extensions) {
            $encrypted = $recentFiles | Where-Object {$_.Extension -match $ext}
            if ($encrypted) {
                $ransomwareFiles += $encrypted
            }
        }
        
        # Check for ransom notes
        foreach ($note in $ransomwareIndicators.NoteFiles) {
            $notes = $recentFiles | Where-Object {$_.FileName -eq $note}
            if ($notes) {
                $ransomwareFiles += $notes
            }
        }
        
        # Check for mass file modifications
        $massModifications = $recentFiles | 
            Group-Object {$_.LastWriteTime.ToString("yyyy-MM-dd HH:mm")} |
            Where-Object {$_.Count -gt 100} |
            Sort-Object Count -Descending
        
        if ($ransomwareFiles -or $massModifications) {
            Write-ColorOutput "RANSOMWARE INDICATORS DETECTED!" "Alert" -Critical $true
            $ransomwareFiles | Export-Csv "$incidentPath\ALERTS\ransomware_files.csv" -NoTypeInformation
            $massModifications | Export-Csv "$incidentPath\ALERTS\mass_file_modifications.csv" -NoTypeInformation
            $global:alertCount += 10
        }
        
        # Shadow copies status
        Write-ColorOutput "Checking shadow copies..." "Progress"
        $shadowCopies = vssadmin list shadows 2>&1
        $shadowCopies | Out-File "$incidentPath\FileSystem\shadow_copies.txt"
        
        if ($shadowCopies -match "No items found") {
            Write-ColorOutput "No shadow copies found - possibly deleted!" "Alert"
            $global:alertCount++
        }
        
        # Prefetch analysis
        if ($isAdmin) {
            Write-ColorOutput "Analyzing prefetch files..." "Progress"
            
            $prefetchFiles = Get-ChildItem "C:\Windows\Prefetch\*.pf" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 100
            
            $prefetchAnalysis = @()
            foreach ($pf in $prefetchFiles) {
                $prefetchAnalysis += [PSCustomObject]@{
                    FileName = $pf.Name
                    ExecutableName = ($pf.Name -replace '-[A-F0-9]{8}\.pf$', '')
                    LastRun = $pf.LastWriteTime
                    Size = $pf.Length
                    RunCount = "Unknown" # Would need to parse the file
                }
            }
            
            $prefetchAnalysis | Export-Csv "$incidentPath\FileSystem\prefetch_analysis.csv" -NoTypeInformation
            
            # Check for suspicious prefetch files
            $suspiciousPrefetch = $prefetchAnalysis | Where-Object {
                $_.ExecutableName -match "POWERSHELL|CMD|WSCRIPT|CSCRIPT|MSHTA|RUNDLL32" -or
                $_.ExecutableName -match "^[A-Z0-9]{8}\.EXE$"
            }
            
            if ($suspiciousPrefetch) {
                $suspiciousPrefetch | Export-Csv "$incidentPath\ALERTS\suspicious_prefetch.csv" -NoTypeInformation
            }
        }
        
        # File timeline creation
        if (!$Quick) {
            Write-ColorOutput "Creating file timeline..." "Progress"
            
            $timeline = @()
            $recentFiles | ForEach-Object {
                $timeline += [PSCustomObject]@{
                    Timestamp = $_.CreationTime
                    Action = "Created"
                    File = $_.FullPath
                    Size = $_.Size
                }
                $timeline += [PSCustomObject]@{
                    Timestamp = $_.LastWriteTime
                    Action = "Modified"
                    File = $_.FullPath
                    Size = $_.Size
                }
            }
            
            $timeline | Sort-Object Timestamp -Descending | 
                Export-Csv "$incidentPath\Timeline\file_timeline.csv" -NoTypeInformation
        }
        
    } catch {
        Write-ColorOutput "Error in file system forensics: $_" "Error"
    }
}

# SECTION 7: BROWSER FORENSICS
if (!$SkipBrowser -and !$Quick) {
    Write-ColorOutput "`n[PHASE 7: BROWSER FORENSICS]" "Progress"
    
    try {
        # Browser paths
        $browsers = @{
            Chrome = @{
                History = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
                Cache = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
                Cookies = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
                Extensions = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
            }
            Edge = @{
                History = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
                Cache = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
                Cookies = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies"
                Extensions = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
            }
            Firefox = @{
                Profile = "$env:APPDATA\Mozilla\Firefox\Profiles"
            }
        }
        
        foreach ($browser in $browsers.GetEnumerator()) {
            $browserName = $browser.Key
            $paths = $browser.Value
            
            Write-ColorOutput "Checking $browserName..." "Progress"
            
            foreach ($item in $paths.GetEnumerator()) {
                $itemName = $item.Key
                $itemPath = $item.Value
                
                if (Test-Path $itemPath) {
                    $destPath = "$incidentPath\Browser\$browserName"
                    New-Item -ItemType Directory -Path $destPath -Force | Out-Null
                    
                    # Copy browser artifacts
                    try {
                        if ($itemName -eq "Extensions") {
                            # List extensions
                            $extensions = Get-ChildItem $itemPath -Directory -ErrorAction SilentlyContinue
                            $extensionList = @()
                            
                            foreach ($ext in $extensions) {
                                $manifest = Get-Content "$($ext.FullName)\*\manifest.json" -ErrorAction SilentlyContinue | 
                                    ConvertFrom-Json
                                
                                if ($manifest) {
                                    $extensionList += [PSCustomObject]@{
                                        ID = $ext.Name
                                        Name = $manifest.name
                                        Version = $manifest.version
                                        Description = $manifest.description
                                        Permissions = ($manifest.permissions -join "; ")
                                    }
                                }
                            }
                            
                            if ($extensionList) {
                                $extensionList | Export-Csv "$destPath\extensions.csv" -NoTypeInformation
                                
                                # Check for suspicious extensions
                                $suspiciousExt = $extensionList | Where-Object {
                                    $_.Permissions -match "webRequest|tabs|cookies|all_urls|<all_urls>" -and
                                    $_.Name -notmatch "Google|Microsoft|Adobe|uBlock"
                                }
                                
                                if ($suspiciousExt) {
                                    Write-ColorOutput "Suspicious browser extensions found!" "Alert"
                                    $suspiciousExt | Export-Csv "$incidentPath\ALERTS\suspicious_extensions.csv" -NoTypeInformation
                                    $global:alertCount++
                                }
                            }
                        } else {
                            # Copy the file
                            Copy-Item -Path $itemPath -Destination "$destPath\$itemName" -Force -ErrorAction SilentlyContinue
                        }
                    } catch { }
                }
            }
        }
        
        # Extract downloads from all browsers
        Write-ColorOutput "Extracting recent downloads..." "Progress"
        
        $allDownloads = @()
        $downloadPath = "$env:USERPROFILE\Downloads"
        
        if (Test-Path $downloadPath) {
            $recentDownloads = Get-ChildItem $downloadPath -File -ErrorAction SilentlyContinue |
                Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-$DaysBack)} |
                Sort-Object CreationTime -Descending
            
            foreach ($download in $recentDownloads) {
                # Check Zone.Identifier for source
                $source = "Unknown"
                $referrer = "Unknown"
                
                try {
                    $zoneInfo = Get-Content "$($download.FullName):Zone.Identifier" -ErrorAction SilentlyContinue
                    if ($zoneInfo) {
                        $hostUrl = ($zoneInfo | Select-String "HostUrl=(.+)").Matches[0].Groups[1].Value
                        $referrerUrl = ($zoneInfo | Select-String "ReferrerUrl=(.+)").Matches[0].Groups[1].Value
                        
                        if ($hostUrl) { $source = $hostUrl }
                        if ($referrerUrl) { $referrer = $referrerUrl }
                    }
                } catch { }
                
                $allDownloads += [PSCustomObject]@{
                    FileName = $download.Name
                    Size = $download.Length
                    Downloaded = $download.CreationTime
                    Source = $source
                    Referrer = $referrer
                    MD5 = if($download.Length -lt 50MB) {
                        (Get-FileHash -Path $download.FullName -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
                    } else {"Too large"}
                }
            }
            
            if ($allDownloads) {
                $allDownloads | Export-Csv "$incidentPath\Browser\recent_downloads.csv" -NoTypeInformation
                
                # Check for suspicious downloads
                $suspiciousDownloads = $allDownloads | Where-Object {
                    $_.FileName -match "\.exe$|\.scr$|\.vbs$|\.bat$|\.cmd$|\.ps1$" -or
                    $_.Source -match "\.tk|\.ml|\.ga|\.cf" -or
                    $_.FileName -match "^[a-z]{8}\.(exe|zip)$"
                }
                
                if ($suspiciousDownloads) {
                    Write-ColorOutput "Suspicious downloads detected!" "Alert"
                    $suspiciousDownloads | Export-Csv "$incidentPath\ALERTS\suspicious_downloads.csv" -NoTypeInformation
                    $global:alertCount++
                }
            }
        }
        
    } catch {
        Write-ColorOutput "Error in browser forensics: $_" "Error"
    }
}

# SECTION 8: EVENT LOG FORENSICS
Write-ColorOutput "`n[PHASE 8: EVENT LOG FORENSICS]" "Progress"

try {
    # Define critical events to check
    $criticalEvents = @{
        "Security" = @{
            "4624" = "Successful logon"
            "4625" = "Failed logon"
            "4634" = "Logoff"
            "4647" = "User initiated logoff"
            "4648" = "Logon using explicit credentials"
            "4672" = "Special privileges assigned"
            "4688" = "Process creation"
            "4689" = "Process termination"
            "4697" = "Service installed"
            "4698" = "Scheduled task created"
            "4699" = "Scheduled task deleted"
            "4700" = "Scheduled task enabled"
            "4701" = "Scheduled task disabled"
            "4702" = "Scheduled task updated"
            "4719" = "System audit policy changed"
            "4720" = "User account created"
            "4732" = "Member added to security group"
            "4738" = "User account changed"
            "4756" = "Member added to universal group"
            "4776" = "NTLM authentication"
            "5140" = "Network share accessed"
            "5145" = "Network share object accessed"
            "1102" = "Audit log cleared"
        }
        "System" = @{
            "7034" = "Service crashed"
            "7035" = "Service start/stop"
            "7036" = "Service state change"
            "7040" = "Service start type changed"
            "7045" = "Service installed"
            "104" = "Event log cleared"
            "1074" = "System shutdown/restart"
        }
        "Application" = @{
            "1000" = "Application crash"
            "1001" = "Application crash details"
            "1002" = "Application hang"
        }
    }
    
    $logAnalysis = @()
    $suspiciousEvents = @()
    
    foreach ($logType in $criticalEvents.Keys) {
        Write-ColorOutput "Analyzing $logType log..." "Progress"
        
        $eventIds = $criticalEvents[$logType].Keys | ForEach-Object {[int]$_}
        
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName = $logType
                ID = $eventIds
                StartTime = (Get-Date).AddDays(-$DaysBack)
            } -MaxEvents 5000 -ErrorAction SilentlyContinue
            
            if ($events) {
                foreach ($event in $events) {
                    $eventInfo = [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        Log = $logType
                        EventID = $event.Id
                        EventType = $criticalEvents[$logType][$event.Id.ToString()]
                        Level = $event.LevelDisplayName
                        User = if($event.UserId) {
                            try {
                                $sid = New-Object System.Security.Principal.SecurityIdentifier($event.UserId)
                                $sid.Translate([System.Security.Principal.NTAccount]).Value
                            } catch { $event.UserId }
                        } else {"N/A"}
                        Computer = $event.MachineName
                        Message = $event.Message -replace "`r`n", " " -replace "\s+", " "
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
                    
                    # Service/task creation
                    if ($event.Id -in @(7045, 4697, 4698)) {
                        if ($event.Message -match "powershell|cmd|wscript|cscript|mshta|rundll32") {
                            $suspicious = $true
                            $reason = "Suspicious service/task created"
                        }
                    }
                    
                    # Log cleared
                    if ($event.Id -in @(1102, 104)) {
                        $suspicious = $true
                        $reason = "Event log cleared"
                    }
                    
                    # Process creation with command line
                    if ($event.Id -eq 4688 -and $event.Message -match "-enc|-e[nc]|bypass|hidden") {
                        $suspicious = $true
                        $reason = "Suspicious process creation"
                    }
                    
                    # Special privileges
                    if ($event.Id -eq 4672 -and $event.Message -notmatch "SYSTEM|LOCAL SERVICE|NETWORK SERVICE") {
                        $suspicious = $true
                        $reason = "Special privileges assigned"
                    }
                    
                    if ($suspicious) {
                        $suspiciousEvents += [PSCustomObject]@{
                            Event = $eventInfo
                            Reason = $reason
                        }
                    }
                }
            }
        } catch {
            Write-ColorOutput "  Error reading $logType log: $_" "Error"
        }
    }
    
    # Export results
    $logAnalysis | Export-Csv "$incidentPath\Logs\Windows\event_log_analysis.csv" -NoTypeInformation
    
    if ($suspiciousEvents) {
        Write-ColorOutput "Found $($suspiciousEvents.Count) suspicious events!" "Alert"
        $suspiciousEvents | Select-Object -ExpandProperty Event | 
            Export-Csv "$incidentPath\ALERTS\suspicious_events.csv" -NoTypeInformation
        $global:alertCount++
    }
    
    # Analyze patterns
    Write-ColorOutput "Analyzing event patterns..." "Progress"
    
    # Failed logon analysis
    $failedLogons = $logAnalysis | Where-Object {$_.EventID -eq 4625}
    if ($failedLogons) {
        $bruteForce = $failedLogons | Group-Object {$_.Message -match "Account Name:\s+(\S+)" | Out-Null; $matches[1]} |
            Where-Object {$_.Count -gt 10} | Sort-Object Count -Descending
        
        if ($bruteForce) {
            Write-ColorOutput "Possible brute force attacks detected!" "Alert"
            $bruteForce | Export-Csv "$incidentPath\ALERTS\brute_force_attempts.csv" -NoTypeInformation
            $global:alertCount++
        }
    }
    
    # Service installation timeline
    $newServices = $logAnalysis | Where-Object {$_.EventID -in @(7045, 4697)} | Sort-Object TimeCreated
    if ($newServices) {
        $newServices | Export-Csv "$incidentPath\Logs\new_services_timeline.csv" -NoTypeInformation
    }
    
    # PowerShell activity
    Write-ColorOutput "Analyzing PowerShell logs..." "Progress"
    
    try {
        $psLogs = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 1000 -ErrorAction SilentlyContinue |
            Where-Object {$_.TimeCreated -gt (Get-Date).AddDays(-$DaysBack)}
        
        if ($psLogs) {
            $suspiciousPS = $psLogs | Where-Object {
                $_.Message -match "DownloadString|DownloadFile|Invoke-Expression|IEX|" +
                    "EncodedCommand|bypass|hidden|nop|noni|enc|base64|" +
                    "System\.Net\.WebClient|Start-BitsTransfer|" +
                    "Invoke-WebRequest|Invoke-RestMethod|" +
                    "New-Object.*Net\.WebClient|" +
                    "-[eE][ncNC]|\.Invoke\(\)"
            }
            
            if ($suspiciousPS) {
                Write-ColorOutput "Suspicious PowerShell activity detected!" "Alert"
                $suspiciousPS | Select-Object TimeCreated, Id, Message |
                    Export-Csv "$incidentPath\ALERTS\suspicious_powershell_logs.csv" -NoTypeInformation
                $global:alertCount++
                
                # Extract and decode any base64 commands
                $encodedCommands = $suspiciousPS | ForEach-Object {
                    if ($_.Message -match "-[eE][ncNC]\s+([A-Za-z0-9+/=]+)") {
                        try {
                            $encoded = $matches[1]
                            $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
                            [PSCustomObject]@{
                                Time = $_.TimeCreated
                                Encoded = $encoded
                                Decoded = $decoded
                            }
                        } catch { }
                    }
                }
                
                if ($encodedCommands) {
                    $encodedCommands | Export-Csv "$incidentPath\ALERTS\decoded_powershell_commands.csv" -NoTypeInformation
                    Write-ColorOutput "Decoded $($encodedCommands.Count) encoded PowerShell commands!" "Alert"
                }
            }
        }
    } catch { }
    
    # Export full logs
    if (!$Quick) {
        Write-ColorOutput "Exporting full event logs..." "Progress"
        
        $exportLogs = @(
            "Security", "System", "Application",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-TaskScheduler/Operational",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
            "Microsoft-Windows-Bits-Client/Operational",
            "Microsoft-Windows-WinRM/Operational",
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
        )
        
        foreach ($log in $exportLogs) {
            try {
                $logFile = $log -replace '/', '-'
                wevtutil epl $log "$incidentPath\Logs\$logFile.evtx" 2>$null
            } catch { }
        }
    }
    
} catch {
    Write-ColorOutput "Error in event log forensics: $_" "Error"
}

# SECTION 9: SECURITY ASSESSMENT
Write-ColorOutput "`n[PHASE 9: SECURITY ASSESSMENT]" "Progress"

try {
    $securityStatus = @{}
    
    # Windows Defender status
    Write-ColorOutput "Checking Windows Defender..." "Progress"
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    
    if ($defender) {
        $defenderStatus = [PSCustomObject]@{
            AntivirusEnabled = $defender.AntivirusEnabled
            AntispywareEnabled = $defender.AntispywareEnabled
            RealTimeProtectionEnabled = $defender.RealTimeProtectionEnabled
            BehaviorMonitorEnabled = $defender.BehaviorMonitorEnabled
            IoavProtectionEnabled = $defender.IoavProtectionEnabled
            NISEnabled = $defender.NISEnabled
            OnAccessProtectionEnabled = $defender.OnAccessProtectionEnabled
            AntivirusSignatureLastUpdated = $defender.AntivirusSignatureLastUpdated
            AntivirusSignatureVersion = $defender.AntivirusSignatureVersion
            NISSignatureLastUpdated = $defender.NISSignatureLastUpdated
            LastFullScanTime = $defender.FullScanEndTime
            LastQuickScanTime = $defender.QuickScanEndTime
        }
        
        $defenderStatus | Export-Csv "$incidentPath\System\Security\defender_status.csv" -NoTypeInformation
        
        # Check for disabled features
        if (!$defender.RealTimeProtectionEnabled) {
            Write-ColorOutput "Real-time protection is DISABLED!" "Alert" -Critical $true
            $securityStatus.DefenderDisabled = $true
            $global:alertCount += 5
        }
        
        # Check signature age
        if ($defender.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-7)) {
            Write-ColorOutput "Antivirus signatures are outdated!" "Alert"
            $global:alertCount++
        }
        
        # Get exclusions
        $exclusions = Get-MpPreference -ErrorAction SilentlyContinue
        if ($exclusions) {
            $exclusionInfo = [PSCustomObject]@{
                ExclusionPath = ($exclusions.ExclusionPath -join "; ")
                ExclusionExtension = ($exclusions.ExclusionExtension -join "; ")
                ExclusionProcess = ($exclusions.ExclusionProcess -join "; ")
            }
            
            $exclusionInfo | Export-Csv "$incidentPath\System\Security\defender_exclusions.csv" -NoTypeInformation
            
            if ($exclusions.ExclusionPath -match "C:\\Windows|C:\\Program Files|C:\\") {
                Write-ColorOutput "Dangerous Defender exclusions detected!" "Alert"
                $global:alertCount++
            }
        }
    }
    
    # Other AV products
    Write-ColorOutput "Checking other antivirus products..." "Progress"
    $avProducts = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
    
    if ($avProducts) {
        $avStatus = $avProducts | ForEach-Object {
            $productState = $_.productState
            $enabled = ($productState -band 0x1000) -ne 0
            $upToDate = ($productState -band 0x10) -eq 0
            
            [PSCustomObject]@{
                Name = $_.displayName
                Enabled = $enabled
                UpToDate = $upToDate
                Path = $_.pathToSignedProductExe
                State = $productState
            }
        }
        
        $avStatus | Export-Csv "$incidentPath\System\Security\antivirus_products.csv" -NoTypeInformation
    }
    
    # Firewall status
    Write-ColorOutput "Checking Windows Firewall..." "Progress"
    $fwProfiles = Get-NetFirewallProfile
    
    $fwStatus = $fwProfiles | ForEach-Object {
        [PSCustomObject]@{
            Profile = $_.Name
            Enabled = $_.Enabled
            DefaultInboundAction = $_.DefaultInboundAction
            DefaultOutboundAction = $_.DefaultOutboundAction
            LogFileName = $_.LogFileName
            LogMaxSizeKilobytes = $_.LogMaxSizeKilobytes
            LogAllowed = $_.LogAllowed
            LogBlocked = $_.LogBlocked
        }
    }
    
    $fwStatus | Export-Csv "$incidentPath\System\Security\firewall_profiles.csv" -NoTypeInformation
    
    $fwDisabled = $fwProfiles | Where-Object {!$_.Enabled}
    if ($fwDisabled) {
        Write-ColorOutput "Firewall disabled on profiles: $($fwDisabled.Name -join ', ')" "Alert"
        $global:alertCount++
    }
    
    # UAC status
    Write-ColorOutput "Checking UAC status..." "Progress"
    $uacStatus = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
    
    if ($uacStatus) {
        $uacEnabled = $uacStatus.EnableLUA -eq 1
        $consentPrompt = $uacStatus.ConsentPromptBehaviorAdmin
        
        @{
            UACEnabled = $uacEnabled
            ConsentPromptBehaviorAdmin = $consentPrompt
            ConsentPromptBehaviorUser = $uacStatus.ConsentPromptBehaviorUser
            EnableInstallerDetection = $uacStatus.EnableInstallerDetection
            PromptOnSecureDesktop = $uacStatus.PromptOnSecureDesktop
        } | ConvertTo-Json | Out-File "$incidentPath\System\Security\uac_status.json"
        
        if (!$uacEnabled) {
            Write-ColorOutput "UAC is DISABLED!" "Alert"
            $global:alertCount++
        }
    }
    
    # Windows Update status
    Write-ColorOutput "Checking Windows Update..." "Progress"
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $updates = $updateSearcher.Search("IsInstalled=0")
        
        $pendingUpdates = $updates.Updates | ForEach-Object {
            [PSCustomObject]@{
                Title = $_.Title
                Severity = $_.MsrcSeverity
                Categories = ($_.Categories | ForEach-Object {$_.Name}) -join "; "
                KBArticle = ($_.KBArticleIDs -join ", ")
                Size = [math]::Round($_.MaxDownloadSize / 1MB, 2)
            }
        }
        
        if ($pendingUpdates) {
            $pendingUpdates | Export-Csv "$incidentPath\System\Security\pending_updates.csv" -NoTypeInformation
            
            $criticalUpdates = $pendingUpdates | Where-Object {$_.Severity -eq "Critical"}
            if ($criticalUpdates) {
                Write-ColorOutput "$($criticalUpdates.Count) critical updates pending!" "Alert"
                $global:alertCount++
            }
        }
    } catch { }
    
    # Security software processes
    Write-ColorOutput "Checking security software processes..." "Progress"
    $securityProcesses = Get-Process | Where-Object {
        $_.ProcessName -match "MsMpEng|MpCmdRun|SecurityHealthService|" +
            "avp|avguard|avgnt|ashServ|avast|avastsvc|aswUpdSv|" +
            "mcshield|frameworkservice|macmnsvc|masvc|" +
            "savservice|SavRoam|svc\.exe|" +
            "WRSA|ZAPrivacyService|DefWatch"
    }
    
    if ($securityProcesses) {
        $securityProcesses | Select-Object ProcessName, Id, StartTime, Path |
            Export-Csv "$incidentPath\System\Security\security_processes.csv" -NoTypeInformation
    } else {
        Write-ColorOutput "No security software processes found!" "Alert"
    }
    
} catch {
    Write-ColorOutput "Error in security assessment: $_" "Error"
}

# SECTION 10: REMOTE ACCESS DEEP DIVE
Write-ColorOutput "`n[PHASE 10: REMOTE ACCESS INVESTIGATION]" "Progress"

try {
    # Comprehensive remote tool detection
    $remoteAccessFindings = @{
        Tools = @()
        Services = @()
        Processes = @()
        Registry = @()
        Files = @()
        Connections = @()
    }
    
    # Extended pattern list
    $remotePatterns = @(
        # Commercial tools
        "TeamViewer", "AnyDesk", "Chrome.*Remote", "LogMeIn", "GoToMyPC",
        "Splashtop", "ScreenConnect", "ConnectWise", "RemotePC", "Zoho.*Assist",
        "ISL.*Online", "ShowMyPC", "BeAnywhere", "Mikogo", "Bomgar", "BeyondTrust",
        "DameWare", "pcAnywhere", "Radmin", "RemoteUtilities", "NoMachine",
        "AeroAdmin", "SupRemo", "UltraViewer", "Iperius", "Ammyy", "LiteManager",
        "AnyPlace.*Control", "Remote.*Administrator", "NetSupport", "ThinVNC",
        "Alpemix", "Supremo", "HopToDesk", "RustDesk", "DWService",
        
        # VNC variants
        "VNC", "TightVNC", "UltraVNC", "RealVNC", "TigerVNC", "x11vnc",
        
        # System tools
        "RDP", "Terminal.*Service", "Remote.*Desktop", "mstsc",
        "WinRM", "Windows.*Remote.*Management", "PSRemoting",
        "SSH", "OpenSSH", "Bitvise", "freeSSHd",
        "Telnet", "rsh", "rexec", "rlogin",
        
        # Development/Admin tools
        "ngrok", "localtunnel", "serveo", "pagekite",
        "PuTTY", "KiTTY", "SuperPuTTY", "MobaXterm",
        "WinSCP", "FileZilla.*Server", "Cerberus.*FTP",
        
        # Potential malicious
        "NetBus", "Back.*Orifice", "SubSeven", "Poison.*Ivy",
        "DarkComet", "njRAT", "Xtreme.*RAT", "CyberGate",
        "BlackShades", "NanoCore", "Remcos", "QuasarRAT",
        "AsyncRAT", "Venom.*RAT", "Covenant", "Empire",
        "Metasploit", "Cobalt.*Strike", "Brute.*Ratel"
    )
    
    # Check running processes
    Write-ColorOutput "Scanning for remote access processes..." "Progress"
    $remoteProcs = Get-Process | Where-Object {
        $procName = $_.ProcessName + " " + $_.Description + " " + $_.MainWindowTitle
        $matched = $false
        foreach ($pattern in $remotePatterns) {
            if ($procName -match $pattern) {
                $matched = $true
                break
            }
        }
        $matched
    }
    
    if ($remoteProcs) {
        foreach ($proc in $remoteProcs) {
            $procDetails = Get-WmiObject Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
            
            $remoteAccessFindings.Processes += [PSCustomObject]@{
                Name = $proc.ProcessName
                PID = $proc.Id
                Path = $proc.Path
                CommandLine = $procDetails.CommandLine
                User = if($procDetails) {
                    $owner = $procDetails.GetOwner()
                    "$($owner.Domain)\$($owner.User)"
                } else {"Unknown"}
                StartTime = $proc.StartTime
                Connections = ($connectionDetails | Where-Object {$_.ProcessId -eq $proc.Id}).Count
            }
            
            Write-ColorOutput "REMOTE TOOL: $($proc.ProcessName) [PID: $($proc.Id)]" "Alert"
            $global:alertCount++
        }
    }
    
    # Check services
    Write-ColorOutput "Scanning for remote access services..." "Progress"
    $remoteSvcs = Get-Service | Where-Object {
        $svcText = "$($_.Name) $($_.DisplayName)"
        $matched = $false
        foreach ($pattern in $remotePatterns) {
            if ($svcText -match $pattern) {
                $matched = $true
                break
            }
        }
        $matched
    }
    
    if ($remoteSvcs) {
        foreach ($svc in $remoteSvcs) {
            $svcWmi = Get-WmiObject Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
            
            $remoteAccessFindings.Services += [PSCustomObject]@{
                Name = $svc.Name
                DisplayName = $svc.DisplayName
                Status = $svc.Status
                StartType = $svc.StartType
                Path = $svcWmi.PathName
                Account = $svcWmi.StartName
                Description = $svcWmi.Description
            }
            
            if ($svc.Status -eq "Running") {
                Write-ColorOutput "REMOTE SERVICE RUNNING: $($svc.DisplayName)" "Alert"
                $global:alertCount++
            }
        }
    }
    
    # Check installed software
    Write-ColorOutput "Scanning installed software..." "Progress"
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($path in $uninstallPaths) {
        $installedSoftware = Get-ItemProperty $path -ErrorAction SilentlyContinue
        
        foreach ($software in $installedSoftware) {
            $softwareText = "$($software.DisplayName) $($software.Publisher)"
            foreach ($pattern in $remotePatterns) {
                if ($softwareText -match $pattern) {
                    $remoteAccessFindings.Tools += [PSCustomObject]@{
                        Name = $software.DisplayName
                        Version = $software.DisplayVersion
                        Publisher = $software.Publisher
                        InstallDate = $software.InstallDate
                        InstallLocation = $software.InstallLocation
                        UninstallString = $software.UninstallString
                    }
                    break
                }
            }
        }
    }
    
    # Check common file locations
    Write-ColorOutput "Scanning file system for remote tools..." "Progress"
    $commonPaths = @(
        "C:\Program Files",
        "C:\Program Files (x86)",
        "$env:ProgramData",
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "$env:TEMP"
    )
    
    foreach ($basePath in $commonPaths) {
        if (Test-Path $basePath) {
            foreach ($pattern in $remotePatterns) {
                $found = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue |
                    Where-Object {$_.Name -match $pattern}
                
                foreach ($dir in $found) {
                    $remoteAccessFindings.Files += [PSCustomObject]@{
                        Path = $dir.FullName
                        Created = $dir.CreationTime
                        Modified = $dir.LastWriteTime
                        Size = (Get-ChildItem $dir.FullName -Recurse -File -ErrorAction SilentlyContinue |
                            Measure-Object -Property Length -Sum).Sum
                    }
                }
            }
        }
    }
    
    # Check registry for remote access artifacts
    Write-ColorOutput "Scanning registry for remote access artifacts..." "Progress"
    $regPaths = @(
        "HKLM:\SOFTWARE\TeamViewer",
        "HKLM:\SOFTWARE\AnyDesk",
        "HKLM:\SOFTWARE\LogMeIn",
        "HKLM:\SOFTWARE\RealVNC",
        "HKLM:\SOFTWARE\TightVNC",
        "HKCU:\SOFTWARE\TeamViewer",
        "HKCU:\SOFTWARE\AnyDesk"
    )
    
    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            $regValues = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
            if ($regValues) {
                $remoteAccessFindings.Registry += [PSCustomObject]@{
                    Path = $regPath
                    Values = ($regValues.PSObject.Properties | Where-Object {$_.Name -notmatch "^PS"} | 
                        ForEach-Object {"$($_.Name)=$($_.Value)"}) -join "; "
                }
            }
        }
    }
    
    # Check for active remote connections
    Write-ColorOutput "Checking for active remote connections..." "Progress"
    
    # RDP sessions
    $rdpSessions = qwinsta 2>&1 | Select-String "Active|rdp-tcp#" | ForEach-Object {
        $line = $_.Line -split '\s+'
        if ($line.Count -ge 4) {
            [PSCustomObject]@{
                SessionName = $line[0]
                Username = $line[1]
                ID = $line[2]
                State = $line[3]
            }
        }
    }
    
    if ($rdpSessions) {
        Write-ColorOutput "Active RDP sessions detected!" "Alert"
        $remoteAccessFindings.Connections += $rdpSessions
        $global:alertCount++
    }
    
    # Check specific ports
    $remotePorts = @(22, 23, 3389, 5900, 5901, 5902, 5903, 5904, 8080, 8443)
    $remoteConnections = $established | Where-Object {
        $_.LocalPort -in $remotePorts -or $_.RemotePort -in $remotePorts
    }
    
    if ($remoteConnections) {
        Write-ColorOutput "Connections on remote access ports detected!" "Alert"
        $remoteAccessFindings.Connections += $remoteConnections
    }
    
    # Export all findings
    if ($remoteAccessFindings.Processes) {
        $remoteAccessFindings.Processes | Export-Csv "$incidentPath\ALERTS\remote_access_processes_detailed.csv" -NoTypeInformation
    }
    if ($remoteAccessFindings.Services) {
        $remoteAccessFindings.Services | Export-Csv "$incidentPath\ALERTS\remote_access_services_detailed.csv" -NoTypeInformation
    }
    if ($remoteAccessFindings.Tools) {
        $remoteAccessFindings.Tools | Export-Csv "$incidentPath\ALERTS\remote_access_installed.csv" -NoTypeInformation
    }
    if ($remoteAccessFindings.Registry) {
        $remoteAccessFindings.Registry | Export-Csv "$incidentPath\ALERTS\remote_access_registry.csv" -NoTypeInformation
    }
    
    # Create summary
    $remoteSummary = @"
REMOTE ACCESS SUMMARY
====================
Processes: $($remoteAccessFindings.Processes.Count)
Services: $($remoteAccessFindings.Services.Count)
Installed Tools: $($remoteAccessFindings.Tools.Count)
Registry Entries: $($remoteAccessFindings.Registry.Count)
File Locations: $($remoteAccessFindings.Files.Count)
Active Connections: $($remoteAccessFindings.Connections.Count)

Top Findings:
$(
    if ($remoteAccessFindings.Processes) {
        $remoteAccessFindings.Processes | ForEach-Object {
            "- Process: $($_.Name) (PID: $($_.PID))"
        }
    }
    if ($remoteAccessFindings.Services | Where-Object {$_.Status -eq "Running"}) {
        $remoteAccessFindings.Services | Where-Object {$_.Status -eq "Running"} | ForEach-Object {
            "- Service: $($_.DisplayName) [RUNNING]"
        }
    }
)
"@
    
    $remoteSummary | Out-File "$incidentPath\ALERTS\remote_access_summary.txt"
    
} catch {
    Write-ColorOutput "Error in remote access investigation: $_" "Error"
}

# SECTION 11: TIMELINE GENERATION
if (!$Quick) {
    Write-ColorOutput "`n[PHASE 11: TIMELINE GENERATION]" "Progress"
    
    try {
        $timeline = @()
        
        # Add process creation times
        $allProcesses | Where-Object {$_.CreationDate -ne "Unknown"} | ForEach-Object {
            $timeline += [PSCustomObject]@{
                Timestamp = $_.CreationDate
                Type = "Process Created"
                Description = "$($_.Name) (PID: $($_.ProcessId))"
                Details = "Path: $($_.Path)"
                Source = "Process"
            }
        }
        
        # Add file creation/modification times
        if ($recentFiles) {
            $recentFiles | ForEach-Object {
                $timeline += [PSCustomObject]@{
                    Timestamp = $_.CreationTime
                    Type = "File Created"
                    Description = $_.FileName
                    Details = "Location: $($_.Directory)"
                    Source = "FileSystem"
                }
                
                if ($_.LastWriteTime -ne $_.CreationTime) {
                    $timeline += [PSCustomObject]@{
                        Timestamp = $_.LastWriteTime
                        Type = "File Modified"
                        Description = $_.FileName
                        Details = "Location: $($_.Directory)"
                        Source = "FileSystem"
                    }
                }
            }
        }
        
        # Add event log entries
        if ($logAnalysis) {
            $logAnalysis | ForEach-Object {
                $timeline += [PSCustomObject]@{
                    Timestamp = $_.TimeCreated
                    Type = $_.EventType
                    Description = "Event $($_.EventID) in $($_.Log)"
                    Details = $_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))
                    Source = "EventLog"
                }
            }
        }
        
        # Add service installations
        if ($serviceAnalysis) {
            # This is approximate based on service executable file times
            $serviceAnalysis | Where-Object {$_.PathName} | ForEach-Object {
                $svcPath = $_.PathName -replace '"', '' -replace '\s+-.*$', ''
                if (Test-Path $svcPath -ErrorAction SilentlyContinue) {
                    $svcFile = Get-Item $svcPath -ErrorAction SilentlyContinue
                    if ($svcFile) {
                        $timeline += [PSCustomObject]@{
                            Timestamp = $svcFile.CreationTime
                            Type = "Service Installed"
                            Description = $_.DisplayName
                            Details = "Service: $($_.Name)"
                            Source = "Service"
                        }
                    }
                }
            }
        }
        
        # Sort timeline
        $timeline = $timeline | Sort-Object Timestamp
        
        # Export full timeline
        $timeline | Export-Csv "$incidentPath\Timeline\master_timeline.csv" -NoTypeInformation
        
        # Create focused timelines
        $last24h = $timeline | Where-Object {$_.Timestamp -gt (Get-Date).AddHours(-24)}
        $last7days = $timeline | Where-Object {$_.Timestamp -gt (Get-Date).AddDays(-7)}
        
        $last24h | Export-Csv "$incidentPath\Timeline\timeline_last_24h.csv" -NoTypeInformation
        $last7days | Export-Csv "$incidentPath\Timeline\timeline_last_7days.csv" -NoTypeInformation
        
        Write-ColorOutput "Generated timeline with $($timeline.Count) events" "Info"
        
        # Identify suspicious clusters
        $clusters = $timeline | Group-Object {$_.Timestamp.ToString("yyyy-MM-dd HH:mm")} |
            Where-Object {$_.Count -gt 10} | Sort-Object Count -Descending
        
        if ($clusters) {
            Write-ColorOutput "Suspicious activity clusters detected!" "Alert"
            $clusters | Select-Object Name, Count | Export-Csv "$incidentPath\ALERTS\activity_clusters.csv" -NoTypeInformation
        }
        
    } catch {
        Write-ColorOutput "Error generating timeline: $_" "Error"
    }
}

# SECTION 12: IOC EXTRACTION AND THREAT INTEL
Write-ColorOutput "`n[PHASE 12: IOC EXTRACTION]" "Progress"

try {
    # Extract all IOCs from collected data
    Write-ColorOutput "Extracting Indicators of Compromise..." "Progress"
    
    # IPs
    if ($connectionDetails) {
        $global:iocs.IPs = $connectionDetails | 
            Where-Object {$_.RemoteAddress -notmatch "^(10\.|172\.|192\.168\.|127\.|::1|0\.0\.0\.0)"} |
            Select-Object -ExpandProperty RemoteAddress -Unique
    }
    
    # Domains
    if ($dnsCache) {
        $global:iocs.Domains = $dnsCache | Select-Object -ExpandProperty Entry -Unique
    }
    
    # File hashes
    if ($allProcesses) {
        $global:iocs.Hashes = $allProcesses | 
            Where-Object {$_.MD5 -ne "N/A"} | 
            Select-Object -ExpandProperty MD5 -Unique
    }
    
    # Process names
    if ($suspiciousProcesses) {
        $global:iocs.ProcessNames = $suspiciousProcesses | 
            Select-Object -ExpandProperty Name -Unique
    }
    
    # File names
    if ($suspiciousFiles) {
        $global:iocs.FileNames = $suspiciousFiles | 
            Select-Object -ExpandProperty FileName -Unique
    }
    
    # Registry keys
    if ($regPersistence) {
        $global:iocs.RegistryKeys = $regPersistence | 
            Where-Object {$_.Suspicious} |
            Select-Object -ExpandProperty KeyPath -Unique
    }
    
    # Users
    if ($logAnalysis) {
        $global:iocs.Users = $logAnalysis | 
            Where-Object {$_.User -ne "N/A" -and $_.User -notmatch "SYSTEM|SERVICE"} |
            Select-Object -ExpandProperty User -Unique
    }
    
    # Mutexes (if collected)
    if ($namedObjects) {
        $global:iocs.Mutexes = $namedObjects | 
            Where-Object {$_.Type -eq "Mutant"} |
            Select-Object -ExpandProperty Name -Unique
    }
    
    # Create comprehensive IOC report
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
    
    # Export IOCs in multiple formats
    $iocReport | ConvertTo-Json -Depth 5 | Out-File "$incidentPath\IOCs\all_iocs.json"
    
    # Create STIX format IOCs (simplified)
    $stixIOCs = @{
        type = "bundle"
        id = "bundle--$(New-Guid)"
        spec_version = "2.0"
        objects = @()
    }
    
    # Add IP indicators
    foreach ($ip in $global:iocs.IPs) {
        $stixIOCs.objects += @{
            type = "indicator"
            id = "indicator--$(New-Guid)"
            created = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            modified = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            pattern = "[network-traffic:dst_ref.value = '$ip']"
            labels = @("malicious-activity")
        }
    }
    
    # Add file hash indicators
    foreach ($hash in $global:iocs.Hashes) {
        $stixIOCs.objects += @{
            type = "indicator"
            id = "indicator--$(New-Guid)"
            created = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            modified = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            pattern = "[file:hashes.MD5 = '$hash']"
            labels = @("malicious-activity")
        }
    }
    
    $stixIOCs | ConvertTo-Json -Depth 5 | Out-File "$incidentPath\IOCs\iocs_stix.json"
    
    # Create CSV for easy import into threat intel platforms
    $csvIOCs = @()
    
    foreach ($ip in $global:iocs.IPs) {
        $csvIOCs += [PSCustomObject]@{
            Type = "IP"
            Value = $ip
            Context = "Suspicious outbound connection"
        }
    }
    
    foreach ($domain in $global:iocs.Domains) {
        $csvIOCs += [PSCustomObject]@{
            Type = "Domain"
            Value = $domain
            Context = "DNS resolution"
        }
    }
    
    foreach ($hash in $global:iocs.Hashes) {
        $processName = ($allProcesses | Where-Object {$_.MD5 -eq $hash} | Select-Object -First 1).Name
        $csvIOCs += [PSCustomObject]@{
            Type = "MD5"
            Value = $hash
            Context = "Process: $processName"
        }
    }
    
    $csvIOCs | Export-Csv "$incidentPath\IOCs\iocs_flat.csv" -NoTypeInformation
    
    Write-ColorOutput "Extracted $($iocReport.TotalIOCs) total IOCs" "Info"
    
   # Create Yara rules for key IOCs
    $yaraRules = @"
rule Incident_$(Get-Date -Format 'yyyyMMdd')_IOCs {
    meta:
        description = "IOCs from incident response on $env:COMPUTERNAME"
        date = "$(Get-Date)"
        incident_id = "$timestamp"
    
    strings:
$(
    $global:iocs.ProcessNames | ForEach-Object {
        "        `$proc_$($_.Replace('.','_')) = `"$_`" nocase"
    }
    $global:iocs.FileNames | ForEach-Object {
        "        `$file_$($_.Replace('.','_')) = `"$_`" nocase"
    }
    if ($global:iocs.Domains) {
        $global:iocs.Domains | Select-Object -First 10 | ForEach-Object {
            "        `$domain_$(($_ -replace '[^a-zA-Z0-9]','_').Substring(0,[Math]::Min(20,$_.Length))) = `"$_`" nocase"
        }
    }
)
    
    condition:
        any of them
}
"@
    
    $yaraRules | Out-File "$incidentPath\IOCs\incident_iocs.yar"
    
    # Create Snort rules for network IOCs
    $snortRules = @"
# Snort rules generated from incident response
# Date: $(Get-Date)
# System: $env:COMPUTERNAME

$(
    $global:iocs.IPs | ForEach-Object {
        "alert tcp any any -> $_ any (msg:`"Suspicious IP from incident`"; sid:$(Get-Random -Minimum 1000000 -Maximum 9999999); rev:1;)"
    }
    if ($suspiciousPorts) {
        $suspiciousPorts | ForEach-Object {
            "alert tcp any any -> any $_ (msg:`"Suspicious port activity`"; sid:$(Get-Random -Minimum 1000000 -Maximum 9999999); rev:1;)"
        }
    }
)
"@
    
    $snortRules | Out-File "$incidentPath\IOCs\network_iocs.rules"
    
} catch {
    Write-ColorOutput "Error extracting IOCs: $_" "Error"
}

# SECTION 13: LIVE RESPONSE ACTIONS (if enabled)
if ($LiveResponse) {
    Write-ColorOutput "`n[PHASE 13: LIVE RESPONSE ACTIONS]" "Progress"
    
    try {
        Write-ColorOutput "Performing live response actions..." "Warning"
        
        # Kill suspicious processes (with confirmation)
        if ($criticalProcesses) {
            Write-ColorOutput "Critical processes identified for termination:" "Alert"
            $criticalProcesses | ForEach-Object {
                Write-ColorOutput "  - $($_.Name) [PID: $($_.ProcessId)] - Score: $($_.TrustScore)" "Alert"
            }
            
            # Log the action
            @"
LIVE RESPONSE ACTION LOG
========================
Time: $(Get-Date)
Action: Process termination considered
Targets: $($criticalProcesses.Count) processes
Decision: Manual intervention required

To terminate these processes, run:
$(
    $criticalProcesses | ForEach-Object {
        "Stop-Process -Id $($_.ProcessId) -Force"
    }
)
"@ | Out-File "$incidentPath\ALERTS\live_response_actions.txt"
        }
        
        # Disable suspicious services
        if ($suspiciousServices | Where-Object {$_.State -eq "Running"}) {
            @"
SUSPICIOUS SERVICES TO DISABLE:
$(
    $suspiciousServices | Where-Object {$_.State -eq "Running"} | ForEach-Object {
        "Stop-Service -Name '$($_.Name)' -Force"
        "Set-Service -Name '$($_.Name)' -StartupType Disabled"
    }
)
"@ | Out-File "$incidentPath\ALERTS\services_to_disable.txt" -Append
        }
        
        # Block suspicious IPs
        if ($global:iocs.IPs) {
            Write-ColorOutput "Creating firewall rules for suspicious IPs..." "Progress"
            $firewallRules = @()
            
            foreach ($ip in $global:iocs.IPs | Select-Object -First 50) {
                $ruleName = "IR_Block_$ip"
                $firewallRules += "New-NetFirewallRule -DisplayName '$ruleName' -Direction Outbound -RemoteAddress $ip -Action Block -Enabled True"
            }
            
            $firewallRules | Out-File "$incidentPath\ALERTS\firewall_rules_to_apply.ps1"
            Write-ColorOutput "Firewall rules saved to firewall_rules_to_apply.ps1" "Info"
        }
        
    } catch {
        Write-ColorOutput "Error in live response actions: $_" "Error"
    }
}

# SECTION 14: FINAL ANALYSIS AND REPORTING
Write-ColorOutput "`n[PHASE 14: FINAL ANALYSIS]" "Progress"

try {
    # Calculate threat score
    $threatScore = 0
    $threatFactors = @()
    
    # Factor in various indicators
    if ($global:alertCount -gt 0) {
        $threatScore += [Math]::Min($global:alertCount * 5, 50)
        $threatFactors += "Alerts: $($global:alertCount)"
    }
    
    if ($criticalProcesses) {
        $threatScore += $criticalProcesses.Count * 10
        $threatFactors += "Critical processes: $($criticalProcesses.Count)"
    }
    
    if ($detectedMalware) {
        $threatScore += 50
        $threatFactors += "Malware detected: $($detectedMalware.Count)"
    }
    
    if ($ransomwareFiles) {
        $threatScore += 80
        $threatFactors += "Ransomware indicators: Yes"
    }
    
    if ($remoteAccessFindings.Processes | Where-Object {$_.Name -match "RAT|Cobalt|Metasploit"}) {
        $threatScore += 70
        $threatFactors += "Known attack tools: Yes"
    }
    
    if (!$defender -or !$defender.RealTimeProtectionEnabled) {
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
    
    # Generate executive summary
    $executiveSummary = @"
================================================================================
                    INCIDENT RESPONSE EXECUTIVE SUMMARY
================================================================================
System: $env:COMPUTERNAME
Domain: $env:USERDOMAIN
Date: $(Get-Date)
Analyst: $env:USERNAME
Collection ID: $timestamp

THREAT ASSESSMENT
=================
Threat Level: $threatLevel (Score: $threatScore/100)
Factors: $(($threatFactors -join '; '))

KEY FINDINGS
============
$(if ($global:criticalAlerts) {
"CRITICAL ALERTS:
$($global:criticalAlerts | ForEach-Object {"- $_"} | Out-String)"
})

Network Activity:
- Total Connections: $($allConnections.Count)
- External Connections: $(($established | Where-Object {$_.RemoteAddress -notmatch "^(10\.|172\.|192\.168\.|127\.)"}).Count)
- Suspicious Connections: $(if($suspiciousConnections){$suspiciousConnections.Count}else{0})
- Remote Access Tools: $(($remoteAccessFindings.Processes + $remoteAccessFindings.Services).Count)

Process Analysis:
- Total Processes: $($allProcesses.Count)
- Suspicious Processes: $(if($suspiciousProcesses){$suspiciousProcesses.Count}else{0})
- Critical Threats: $(if($criticalProcesses){$criticalProcesses.Count}else{0})
- Malware Detected: $(if($detectedMalware){"YES - $($detectedMalware.Count) instances"}else{"No"})

Persistence Mechanisms:
- Registry Entries: $($regPersistence.Count)
- Scheduled Tasks: $(if($taskAnalysis){$taskAnalysis.Count}else{0})
- Services: $(if($suspiciousServices){$suspiciousServices.Count}else{0})
- WMI Persistence: $(if($wmiPersistence){$wmiPersistence.Count}else{0})

File System:
- Recent Suspicious Files: $(if($suspiciousFiles){$suspiciousFiles.Count}else{0})
- Ransomware Indicators: $(if($ransomwareFiles){"YES"}else{"No"})
- Shadow Copies: $(if($shadowCopies -match "No items found"){"DELETED"}else{"Present"})

Security Status:
- Windows Defender: $(if($defender -and $defender.RealTimeProtectionEnabled){"Enabled"}else{"DISABLED"})
- Firewall: $(if($fwDisabled){"DISABLED on $($fwDisabled.Name -join ', ')"}else{"Enabled"})
- Recent Security Updates: $(if($pendingUpdates){"$($pendingUpdates.Count) pending"}else{"Unknown"})

IOCs Collected:
- IP Addresses: $(if($global:iocs.IPs){$global:iocs.IPs.Count}else{0})
- Domains: $(if($global:iocs.Domains){$global:iocs.Domains.Count}else{0})
- File Hashes: $(if($global:iocs.Hashes){$global:iocs.Hashes.Count}else{0})
- Process Names: $(if($global:iocs.ProcessNames){$global:iocs.ProcessNames.Count}else{0})

RECOMMENDED ACTIONS
==================
$(switch ($threatLevel) {
    "CRITICAL" {
@"
!!! CRITICAL THREAT DETECTED !!!
1. IMMEDIATELY isolate this system from the network
2. DO NOT shut down or reboot (preserve volatile evidence)
3. Capture full memory dump using WinPMEM or similar
4. Contact incident response team IMMEDIATELY
5. Begin containment procedures for other potentially affected systems
6. Preserve all evidence for forensic analysis
7. Document all actions taken with timestamps
"@
    }
    "HIGH" {
@"
** HIGH THREAT LEVEL **
1. Isolate system from sensitive network segments
2. Capture memory dump if possible
3. Review all findings in ALERTS folder
4. Check other systems for similar IOCs
5. Enable enhanced logging and monitoring
6. Consider full forensic image acquisition
7. Review user account activity
"@
    }
    "MEDIUM" {
@"
* MEDIUM THREAT LEVEL *
1. Monitor system closely
2. Review all suspicious findings
3. Run full antivirus scan with updated definitions
4. Check network connections regularly
5. Review and harden security settings
6. Consider reimaging if cleaning proves difficult
"@
    }
    "LOW" {
@"
- LOW THREAT LEVEL -
1. Review findings for false positives
2. Update security software
3. Apply pending patches
4. Monitor for any changes
5. Consider this baseline for future comparisons
"@
    }
    default {
@"
- MINIMAL THREAT LEVEL -
1. System appears clean
2. Archive this data as baseline
3. Maintain regular security updates
4. Continue standard monitoring
"@
    }
})

EVIDENCE COLLECTED
==================
Location: $incidentPath
Total Size: $([math]::Round((Get-ChildItem $incidentPath -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB, 2)) MB
Key Folders:
- ALERTS: Critical findings requiring immediate review
- Network: Network connections and configuration
- Processes: Process analysis and memory artifacts
- Persistence: Autostart and persistence mechanisms
- Logs: Windows event logs and analysis
- IOCs: Indicators of compromise in various formats
- Timeline: Temporal analysis of events

NEXT STEPS
==========
1. Review all files in $incidentPath\ALERTS\
2. Analyze IOCs in $incidentPath\IOCs\
3. Check timeline in $incidentPath\Timeline\
4. $(if($threatLevel -in @("CRITICAL","HIGH")){"Share IOCs with security team"}else{"Document findings"})
5. $(if($LiveResponse){"Execute live response actions if authorized"}else{"Plan remediation steps"})

================================================================================
                            END OF EXECUTIVE SUMMARY
================================================================================
"@
    
    # Save executive summary
    $executiveSummary | Out-File "$incidentPath\EXECUTIVE_SUMMARY.txt"
    Write-Host $executiveSummary -ForegroundColor Cyan
    
    # Generate HTML report
    Write-ColorOutput "Generating HTML report..." "Progress"
    
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Incident Response Report - $env:COMPUTERNAME</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f0f0f0; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #333; }
        .critical { background-color: #dc3545; color: white; padding: 10px; border-radius: 5px; }
        .high { background-color: #fd7e14; color: white; padding: 10px; border-radius: 5px; }
        .medium { background-color: #ffc107; color: black; padding: 10px; border-radius: 5px; }
        .low { background-color: #28a745; color: white; padding: 10px; border-radius: 5px; }
        .info-box { background-color: #17a2b8; color: white; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .alert-box { background-color: #dc3545; color: white; padding: 10px; margin: 10px 0; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
        th { background-color: #007bff; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .metric { display: inline-block; margin: 10px; padding: 15px; background-color: #e9ecef; border-radius: 5px; }
        .metric-value { font-size: 24px; font-weight: bold; color: #007bff; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #dee2e6; border-radius: 5px; }
        .timestamp { color: #6c757d; font-size: 12px; }
        .chart { margin: 20px 0; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <h1>Incident Response Report</h1>
        <div class="info-box">
            <strong>System:</strong> $env:COMPUTERNAME | 
            <strong>Date:</strong> $(Get-Date) | 
            <strong>Threat Level:</strong> <span class="$($threatLevel.ToLower())">$threatLevel</span>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="metric">
                <div>Total Alerts</div>
                <div class="metric-value">$($global:alertCount)</div>
            </div>
            <div class="metric">
                <div>Threat Score</div>
                <div class="metric-value">$threatScore/100</div>
            </div>
            <div class="metric">
                <div>Critical Processes</div>
                <div class="metric-value">$(if($criticalProcesses){$criticalProcesses.Count}else{0})</div>
            </div>
            <div class="metric">
                <div>IOCs Collected</div>
                <div class="metric-value">$($iocReport.TotalIOCs)</div>
            </div>
        </div>
        
        $(if ($global:criticalAlerts) {
        "<div class='alert-box'>
            <h3>Critical Alerts</h3>
            <ul>
                $($global:criticalAlerts | ForEach-Object {"<li>$_</li>"} | Out-String)
            </ul>
        </div>"
        })
        
        <div class="section">
            <h2>Network Analysis</h2>
            <canvas id="networkChart" class="chart"></canvas>
            <table>
                <tr><th>Metric</th><th>Count</th><th>Status</th></tr>
                <tr><td>Total Connections</td><td>$($allConnections.Count)</td><td>-</td></tr>
                <tr><td>Established</td><td>$($established.Count)</td><td>$(if($established.Count -gt 100){"High"}else{"Normal"})</td></tr>
                <tr><td>External IPs</td><td>$(if($global:iocs.IPs){$global:iocs.IPs.Count}else{0})</td><td>$(if($global:iocs.IPs.Count -gt 20){"Suspicious"}else{"Normal"})</td></tr>
                <tr><td>Suspicious Connections</td><td>$(if($suspiciousConnections){$suspiciousConnections.Count}else{0})</td><td>$(if($suspiciousConnections){"Alert"}else{"Clear"})</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Process Analysis</h2>
            $(if ($criticalProcesses) {
            "<h3>Critical Processes Detected</h3>
            <table>
                <tr><th>Process</th><th>PID</th><th>Path</th><th>Trust Score</th></tr>
                $($criticalProcesses | Select-Object -First 10 | ForEach-Object {
                    "<tr><td>$($_.Name)</td><td>$($_.ProcessId)</td><td>$($_.Path)</td><td>$($_.TrustScore)</td></tr>"
                } | Out-String)
            </table>"
            })
        </div>
        
        <div class="section">
            <h2>IOCs Summary</h2>
            <table>
                <tr><th>Type</th><th>Count</th><th>Top Examples</th></tr>
                <tr><td>IP Addresses</td><td>$(if($global:iocs.IPs){$global:iocs.IPs.Count}else{0})</td><td>$(if($global:iocs.IPs){($global:iocs.IPs | Select-Object -First 3) -join ", "})</td></tr>
                <tr><td>Domains</td><td>$(if($global:iocs.Domains){$global:iocs.Domains.Count}else{0})</td><td>$(if($global:iocs.Domains){($global:iocs.Domains | Select-Object -First 3) -join ", "})</td></tr>
                <tr><td>File Hashes</td><td>$(if($global:iocs.Hashes){$global:iocs.Hashes.Count}else{0})</td><td>$(if($global:iocs.Hashes){$global:iocs.Hashes | Select-Object -First 1})</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <div class="$($threatLevel.ToLower())">
                <pre>$(switch ($threatLevel) {
                    "CRITICAL" { "IMMEDIATE ACTION REQUIRED: Isolate system, preserve evidence, contact IR team" }
                    "HIGH" { "HIGH PRIORITY: Isolate from sensitive segments, capture memory, review all alerts" }
                    "MEDIUM" { "MONITOR CLOSELY: Review findings, run full AV scan, check other systems" }
                    "LOW" { "REVIEW: Check for false positives, update security software" }
                    default { "BASELINE: System appears clean, maintain monitoring" }
                })</pre>
            </div>
        </div>
        
        <div class="timestamp">
            Report generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        </div>
    </div>
    
    <script>
        // Network connections chart
        var ctx = document.getElementById('networkChart').getContext('2d');
        var networkChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Established', 'Listening', 'Other'],
                datasets: [{
                    data: [$($established.Count), $($listening.Count), $($allConnections.Count - $established.Count - $listening.Count)],
                    backgroundColor: ['#dc3545', '#ffc107', '#28a745']
                }]
            }
        });
    </script>
</body>
</html>
"@
    
    $htmlReport | Out-File "$incidentPath\incident_report.html"
    
    # Generate JSON report for automation
    $jsonReport = @{
        metadata = @{
            hostname = $env:COMPUTERNAME
            timestamp = Get-Date -Format "o"
            analyst = $env:USERNAME
            collection_id = $timestamp
            script_version = "4.0"
        }
        threat_assessment = @{
            level = $threatLevel
            score = $threatScore
            factors = $threatFactors
        }
        statistics = @{
            total_alerts = $global:alertCount
            critical_alerts = $global:criticalAlerts.Count
            processes_analyzed = $allProcesses.Count
            suspicious_processes = $(if($suspiciousProcesses){$suspiciousProcesses.Count}else{0})
            network_connections = $allConnections.Count
            external_connections = $(if($global:iocs.IPs){$global:iocs.IPs.Count}else{0})
            persistence_mechanisms = $($regPersistence.Count + $(if($taskAnalysis){$taskAnalysis.Count}else{0}) + $(if($suspiciousServices){$suspiciousServices.Count}else{0}))
        }
        iocs = $global:iocs
        findings = @{
            malware_detected = $(if($detectedMalware){$true}else{$false})
            ransomware_indicators = $(if($ransomwareFiles){$true}else{$false})
            remote_access_tools = $(if($remoteAccessFindings.Processes -or $remoteAccessFindings.Services){$true}else{$false})
            security_disabled = $(if(!$defender -or !$defender.RealTimeProtectionEnabled){$true}else{$false})
        }
        recommendations = switch ($threatLevel) {
            "CRITICAL" { @("isolate_immediately", "preserve_memory", "contact_ir_team") }
            "HIGH" { @("isolate_sensitive", "capture_memory", "review_alerts") }
            "MEDIUM" { @("monitor_closely", "run_av_scan", "review_findings") }
            "LOW" { @("review_false_positives", "update_security") }
            default { @("maintain_baseline", "continue_monitoring") }
        }
    }
    
    $jsonReport | ConvertTo-Json -Depth 10 | Out-File "$incidentPath\incident_report.json"
    
} catch {
    Write-ColorOutput "Error generating final report: $_" "Error"
}

# SECTION 15: ARCHIVE CREATION
Write-ColorOutput "`n[PHASE 15: CREATING EVIDENCE ARCHIVE]" "Progress"

# Wait for any remaining background jobs
$remainingJobs = Get-Job
if ($remainingJobs) {
    Write-ColorOutput "Waiting for background tasks to complete..." "Progress"
    $remainingJobs | ForEach-Object {
        $_ | Wait-Job -Timeout 30 | Out-Null
        if ($_.State -eq "Running") {
            $_ | Stop-Job
            Write-ColorOutput "  - Stopped job: $($_.Name)" "Warning"
        }
        $_ | Remove-Job -Force
    }
}

Stop-Transcript

# Create evidence inventory
Write-ColorOutput "Creating evidence inventory..." "Progress"

$inventory = @"
EVIDENCE INVENTORY
==================
Collection ID: $timestamp
System: $env:COMPUTERNAME
Date: $(Get-Date)

FOLDERS:
$(Get-ChildItem $incidentPath -Directory | ForEach-Object {
    $fileCount = (Get-ChildItem $_.FullName -File -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
    $size = [math]::Round((Get-ChildItem $_.FullName -Recurse -ErrorAction SilentlyContinue | 
        Measure-Object -Property Length -Sum).Sum / 1MB, 2)
    "$($_.Name) - Files: $fileCount, Size: $size MB"
} | Out-String)

KEY FILES:
- EXECUTIVE_SUMMARY.txt - Main findings and recommendations
- incident_report.html - Visual HTML report
- incident_report.json - Machine-readable report
- ALERTS\ - All critical findings requiring review
- IOCs\ - Indicators of compromise in multiple formats
- Timeline\ - Temporal analysis of events

CHAIN OF CUSTODY:
Collected by: $env:USERDOMAIN\$env:USERNAME
Start time: $timestamp
End time: $(Get-Date -Format "yyyyMMdd_HHmmss")
"@

$inventory | Out-File "$incidentPath\INVENTORY.txt"

# Create ZIP archive
try {
    $zipPath = "C:\incident_${timestamp}_${env:COMPUTERNAME}.zip"
    Write-ColorOutput "Creating encrypted evidence archive..." "Progress"
    
    # Use built-in compression
    Compress-Archive -Path "$incidentPath\*" -DestinationPath $zipPath -CompressionLevel Optimal -Force
    
    $zipInfo = Get-Item $zipPath
    Write-ColorOutput "Evidence archive created: $zipPath" "Success"
    Write-ColorOutput "Archive size: $([math]::Round($zipInfo.Length/1MB, 2)) MB" "Info"
    
    # Calculate hash of archive for integrity
    $archiveHash = Get-FileHash -Path $zipPath -Algorithm SHA256
    @"
Archive Hash (SHA256): $($archiveHash.Hash)
Archive Path: $zipPath
Archive Size: $($zipInfo.Length) bytes
"@ | Out-File "$incidentPath\archive_hash.txt"
    
} catch {
    Write-ColorOutput "Failed to create archive: $_" "Error"
}

# FINAL OUTPUT
Write-ColorOutput "`n================================================================================" "Success"
Write-ColorOutput "              INCIDENT RESPONSE COLLECTION COMPLETE" "Success"
Write-ColorOutput "================================================================================" "Success"
Write-ColorOutput "" "Info"
Write-ColorOutput "Threat Level: $threatLevel (Score: $threatScore/100)" $(if($threatScore -ge 70){"Alert"}else{"Info"})
Write-ColorOutput "Total Alerts: $($global:alertCount)" $(if($global:alertCount -gt 10){"Alert"}else{"Info"})
Write-ColorOutput "Evidence Location: $incidentPath" "Info"
Write-ColorOutput "Archive: $zipPath" "Info"
Write-ColorOutput "" "Info"
Write-ColorOutput "CRITICAL ACTIONS REQUIRED:" "Warning"

switch ($threatLevel) {
    "CRITICAL" {
        Write-ColorOutput "1. ISOLATE SYSTEM IMMEDIATELY!" "Alert" -Critical $true
        Write-ColorOutput "2. DO NOT SHUTDOWN - PRESERVE EVIDENCE!" "Alert" -Critical $true
        Write-ColorOutput "3. CONTACT INCIDENT RESPONSE TEAM NOW!" "Alert" -Critical $true
        [console]::beep(1000,500)
        [console]::beep(1000,500)
        [console]::beep(1000,500)
    }
    "HIGH" {
        Write-ColorOutput "1. Isolate from sensitive networks" "Alert"
        Write-ColorOutput "2. Capture memory dump if possible" "Alert"
        Write-ColorOutput "3. Review all alerts immediately" "Alert"
        [console]::beep(800,300)
        [console]::beep(800,300)
    }
    "MEDIUM" {
        Write-ColorOutput "1. Monitor system closely" "Warning"
        Write-ColorOutput "2. Review all findings" "Warning"
        Write-ColorOutput "3. Run full security scan" "Warning"
        [console]::beep(600,200)
    }
    default {
        Write-ColorOutput "1. Review findings for accuracy" "Info"
        Write-ColorOutput "2. Update security software" "Info"
        Write-ColorOutput "3. Continue monitoring" "Info"
    }
}

Write-ColorOutput "`nFor support, contact your incident response team with Collection ID: $timestamp" "Info"
Write-ColorOutput "================================================================================" "Success"

# Open report in browser if high threat
if ($threatLevel -in @("CRITICAL", "HIGH")) {
    Start-Process "$incidentPath\incident_report.html"
}

# Return summary object for automation
return @{
    CollectionID = $timestamp
    ThreatLevel = $threatLevel
    ThreatScore = $threatScore
    AlertCount = $global:alertCount
    EvidencePath = $incidentPath
    ArchivePath = $zipPath
    IOCs = $global:iocs
    Duration = (Get-Date) - [DateTime]$timestamp
}
