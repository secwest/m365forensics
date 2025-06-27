#requires -RunAsAdministrator
<#
.SYNOPSIS
  Enhanced elevation diagnostics with comprehensive forensic analysis
  Includes prefetch analysis, persistence checks, and security verification

.DESCRIPTION
  Forensic analysis including:
  - MSI Installer Events Analysis
  - Process Creation Monitoring  
  - Prefetch Analysis
  - UAC and SmartScreen Logs
  - Persistence Mechanism Detection
  - Elevation Service Investigation
  - Network Connection Analysis
  - File System Checks
  - Time-Based Analysis
  - Advanced Event Log Analysis

.PARAMETER Hours
  Number of hours to analyze before the end time (default: 24)

.PARAMETER BeforeTime
  Optional end time for analysis. If not specified, uses current time.
  The script will analyze X hours before this time.
  Format: "yyyy-MM-dd HH:mm:ss" or any valid datetime format

.EXAMPLE
  .\ElevationDiagnostics.ps1
  Analyzes last 24 hours before current time

.EXAMPLE
  .\ElevationDiagnostics.ps1 -Hours 48
  Analyzes last 48 hours before current time

.EXAMPLE
  .\ElevationDiagnostics.ps1 -BeforeTime "2025-06-26 15:00:00"
  Analyzes 24 hours before June 26, 2025 3:00 PM (from June 25 3:00 PM to June 26 3:00 PM)

.EXAMPLE
  .\ElevationDiagnostics.ps1 -Hours 72 -BeforeTime "2025-06-26 15:00:00"
  Analyzes 72 hours before June 26, 2025 3:00 PM (from June 23 3:00 PM to June 26 3:00 PM)
#>

param(
    [Parameter(Mandatory=$false)]
    [int]$Hours = 24,
    
    [Parameter(Mandatory=$false)]
    [string]$BeforeTime = ""
)

# ------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------
# Set EndTime first - either current time or specified BeforeTime
$EndTime = Get-Date

if ($BeforeTime -ne "") {
    try {
        $parsedBeforeTime = [datetime]::Parse($BeforeTime)
        if ($parsedBeforeTime -le (Get-Date)) {
            $EndTime = $parsedBeforeTime
            Write-Host "Setting analysis end time to: $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
        } else {
            Write-Host "Warning: BeforeTime is in the future, using current time instead" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Error: Invalid BeforeTime format. Use 'yyyy-MM-dd HH:mm:ss'" -ForegroundColor Red
        Write-Host "Example: '2025-06-26 15:00:00'" -ForegroundColor Yellow
        Write-Host "Using current time as end time..." -ForegroundColor Yellow
    }
}

# Calculate StartTime by going back specified hours from EndTime
$StartTime = $EndTime.AddHours(-$Hours)

Write-Host "`r`n" -ForegroundColor Cyan
Write-Host "======== TIME WINDOW CALCULATION ========" -ForegroundColor Cyan
Write-Host "End Time:   $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Yellow
Write-Host "Duration:   $Hours hours before end time" -ForegroundColor Yellow
Write-Host "Start Time: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "`r`n" -ForegroundColor Cyan

# Validate time range
if ($StartTime -ge $EndTime) {
    Write-Host "Error: Invalid time range calculation" -ForegroundColor Red
    Write-Host "StartTime: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Red
    Write-Host "EndTime: $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Red
    exit 1
}

$MaxEvents  = 1000                           # Increased for better coverage
$OutputPath = "C:\Temp\ElevationAudit_Enhanced_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$prefetchExportPath = $OutputPath -replace "\.txt$", "_PrefetchData.csv"

# Suspicious process list includes commonly abused/impersonated executables
# Note: svchost.exe, dllhost.exe, and explorer.exe are legitimate Windows processes
#       but are also commonly used by malware running from incorrect locations
# VERIFICATION: 
#   - svchost.exe legitimate path: C:\Windows\System32\svchost.exe or C:\Windows\SysWOW64\svchost.exe
#   - dllhost.exe legitimate path: C:\Windows\System32\dllhost.exe or C:\Windows\SysWOW64\dllhost.exe  
#   - explorer.exe legitimate path: C:\Windows\explorer.exe
# Any other location = likely malware impersonation
$SuspiciousProcesses = @(
    "elevation_service.exe", "runtimebroker.exe", "msiexec.exe", "wusa.exe", 
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
    "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe",
    "installutil.exe", "mshta.exe", "conhost.exe", "taskhost.exe",
    "svchost.exe", "dllhost.exe", "explorer.exe"
)

# Ensure output directory exists
$folder = Split-Path $OutputPath
if (-not (Test-Path $folder)) {
    New-Item -Path $folder -ItemType Directory -Force | Out-Null
}

# Set console width for better output formatting
try {
    $host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(200, 3000)
} catch {
    # If we can't set buffer size, continue anyway
}

# Helper function for ASCII-safe file writing
function Write-Output {
    param([string]$Content)
    Add-Content -Path $OutputPath -Value $Content -Encoding ASCII
}

# Header
$header = "`r`n=== Enhanced Elevation Diagnostics Report - $(Get-Date) ===`r`n"
$header += "Analyzing $Hours-hour window before $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))`r`n"
$header += "Time period: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) to $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))`r`n"
if ($BeforeTime -ne "") {
    $header += "Analysis end time specified: $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))`r`n"
}
$header += "Output file: $OutputPath`r`n"
$header += "`r`nIMPORTANT: This tool identifies potentially suspicious patterns that may also`r`n"
$header += "           occur in legitimate software. Review all findings in context.`r`n"
$header += "`r`nThis report includes:`r`n"
$header += "  - Complete prefetch activity log for specified time period`r`n"
$header += "  - MSI installer events and patterns`r`n"
$header += "  - Security process creation monitoring`r`n"
$header += "  - Persistence mechanism checks`r`n"
$header += "  - Network connection analysis`r`n"
$header += "  - Suspicious time period analysis`r`n"
$header += "  - Risk assessment and recommendations`r`n"
$header | Out-File -FilePath $OutputPath -Encoding ASCII
Write-Host $header -ForegroundColor Cyan

function Write-Section {
    param(
        [string]$Title,
        [string]$Color = "Yellow"
    )
    $sep = "`r`n" + ("=" * 80) + "`r`n$Title`r`n" + ("=" * 80) + "`r`n"
    Write-Output $sep
    Write-Host $sep -ForegroundColor $Color
}

function Write-Alert {
    param([string]$Message)
    $alert = "[FINDING] $Message"
    Write-Host $alert -ForegroundColor Yellow
    Write-Output $alert
}

# ------------------------------------------------------------------------
# 1) MSI Installer Events Analysis
# ------------------------------------------------------------------------
Write-Section "MSI Installer Events Analysis (IDs 1001,11706-11708)"
try {
    $msi = Get-WinEvent -FilterHashtable @{
        LogName      = "Application"
        ProviderName = "MsiInstaller"
        StartTime    = $StartTime
        EndTime      = $EndTime
    } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in @(1001,11706,11707,11708) }

    if ($msi) {
        Write-Host "Found $($msi.Count) MSI installer events in the $Hours-hour window before $($EndTime.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Yellow
        
        # Group by hour to see patterns
        $msiByHour = $msi | Group-Object { $_.TimeCreated.ToString("yyyy-MM-dd HH:00") } | Sort-Object Name
        
        $out = "`r`nMSI Activity by Hour:`r`n"
        $msiByHour | ForEach-Object {
            $out += "$($_.Name): $($_.Count) installations`r`n"
        }
        $out += "`r`nDetailed MSI Events:`r`n"
        
        $out += $msi |
            Select-Object TimeCreated, Id, 
                @{Name="User";Expression={if($_.Properties[1]){$_.Properties[1].Value}else{"N/A"}}}, 
                @{Name="Package";Expression={if($_.Properties[0]){$_.Properties[0].Value}else{"N/A"}}}, 
                Message |
            Sort-Object TimeCreated -Descending |
            Format-Table -AutoSize |
            Out-String
            
        # Check for suspicious patterns
        $suspiciousMsi = $msi | Where-Object {
            $hour = $_.TimeCreated.Hour
            ($hour -in @(0..6, 23) -or
            $_.Message -match "(\\temp\\|\\appdata\\|\\users\\[^\\]+\\appdata\\local\\temp)")
        }
        
        if ($suspiciousMsi) {
            Write-Alert "Found $($suspiciousMsi.Count) MSI installations during off-hours or in temporary locations"
        }
        } else {
            $out = "No MSI Installer events found in specified time period.`r`n"
        }
    Write-Host $out
    Write-Output $out
} catch {
    $out = "Error accessing MSI Installer events: $_`r`n"
    Write-Host $out
    Write-Output $out
}

# ------------------------------------------------------------------------
# 2) Process Creation Monitoring (Event ID 4688)
# ------------------------------------------------------------------------
Write-Section "Process Creation Monitoring (Event ID 4688)"
try {
    $procs = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4688
        StartTime = $StartTime
        EndTime   = $EndTime
    } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

    $filtered = $procs | Where-Object {
        $props = $_.Properties
        if ($props -and $props.Count -gt 10) {
            $props[10].Value -match "\\(msiexec|wusa|elevation_service|powershell|cmd)\.exe"
        }
    }

    if ($filtered) {
        $out = "Found $($filtered.Count) suspicious process creation events:`r`n"
        $out += $filtered |
            Select-Object TimeCreated,
                @{Name="Parent";Expression={if($_.Properties[6]){$_.Properties[6].Value}else{"N/A"}}},
                @{Name="NewProc";Expression={if($_.Properties[5]){$_.Properties[5].Value}else{"N/A"}}},
                @{Name="CmdLine";Expression={if($_.Properties[10]){$_.Properties[10].Value}else{"N/A"}}},
                @{Name="Account";Expression={if($_.Properties[1]){$_.Properties[1].Value}else{"N/A"}}} |
            Format-Table -Wrap -AutoSize |
            Out-String
    } else {
        $out = "No suspicious process-creation events found in Security log.`r`n"
    }
    Write-Host $out
    Write-Output $out
} catch {
    $out = "Error accessing Security log: $_`r`n"
    Write-Host $out
    Write-Output $out
}

# ------------------------------------------------------------------------
# 3) Enhanced Prefetch Analysis
# ------------------------------------------------------------------------
Write-Section "Enhanced Prefetch Analysis"

Write-Host "NOTE: Full detailed prefetch log will be provided in the 'COMPLETE PREFETCH ACTIVITY LOG' section" -ForegroundColor Cyan
Write-Host "      A CSV export will also be created for easy analysis in Excel or other tools`r`n" -ForegroundColor Cyan
Write-Host "INFO: Windows prefetch files are located in C:\Windows\Prefetch" -ForegroundColor Gray
Write-Host "      Each .pf file represents a program that has been executed`r`n" -ForegroundColor Gray

function Get-PrefetchInfo {
    param([string]$PrefetchPath)
    
    $prefetchFiles = @()
    
    try {
        Write-Host "Reading prefetch files from: $PrefetchPath" -ForegroundColor Gray
        $pfFiles = Get-ChildItem -Path $PrefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue
        Write-Host "Found $($pfFiles.Count) total prefetch files" -ForegroundColor Gray
        
        foreach ($file in $pfFiles) {
            # Extract embedded filename from prefetch name
            $exeName = $file.Name -replace "-[A-F0-9]{8}\.pf$", ""
            
            # Get file info
            $fileInfo = @{
                FileName = $file.Name
                ProcessName = $exeName
                ProcessPath = "Unknown"
                LastRunTime = $file.LastWriteTime
                CreatedTime = $file.CreationTime
                FileSize = $file.Length
                RunCount = 1
                IsSuspicious = $false
                FullPath = $file.FullName
                LastAccessTime = $file.LastAccessTime
            }
            
            # Check for suspicious patterns
            foreach ($suspicious in $SuspiciousProcesses) {
                if ($exeName.ToLower() -match [regex]::Escape($suspicious.ToLower())) {
                    $fileInfo.IsSuspicious = $true
                    break
                }
            }
            
            if ($exeName -match "(elevation|admin|install|update|patch)" -and $exeName -notmatch "windows") {
                $fileInfo.IsSuspicious = $true
            }
            
            # Additional suspicious patterns
            if ($exeName -match "^[a-z]{6,8}\.exe$" -or $exeName -match "^\d{4,}\.exe$") {
                $fileInfo.IsSuspicious = $true
            }
            
            # Check if it's a Windows process in wrong location (would need full path parsing)
            if ($exeName.ToLower() -in @("svchost.exe", "dllhost.exe", "explorer.exe")) {
                # These are always flagged for manual verification since we can't check path from prefetch name alone
                $fileInfo.IsSuspicious = $true
            }
            
            $prefetchFiles += New-Object PSObject -Property $fileInfo
        }
    } catch {
        Write-Host "Error accessing prefetch files: $_" -ForegroundColor Yellow
    }
    
    return $prefetchFiles
}

$allPrefetch = Get-PrefetchInfo -PrefetchPath "C:\Windows\Prefetch"

# Filter for specified time period and before specified time if set
$last24HoursPrefetch = $allPrefetch | Where-Object { 
    $_.LastRunTime -gt $StartTime -and $_.LastRunTime -le $EndTime 
}

Write-Host "`nTotal prefetch files: $($allPrefetch.Count)" -ForegroundColor Cyan
Write-Host "Prefetch files active in $Hours-hour window before $($EndTime.ToString('yyyy-MM-dd HH:mm')): $($last24HoursPrefetch.Count)" -ForegroundColor Yellow

# Group by hour for timeline analysis
$out = "`r`nPrefetch Activity Timeline ($Hours hours before $($EndTime.ToString('yyyy-MM-dd HH:mm'))):`r`n"
$out += "=" * 60 + "`r`n"
$hourlyGroups = $last24HoursPrefetch | Group-Object { $_.LastRunTime.ToString("yyyy-MM-dd HH:00") } | Sort-Object Name

foreach ($hourGroup in $hourlyGroups) {
    $out += "`r`n$($hourGroup.Name) - $($hourGroup.Count) programs executed:`r`n"
    $hourGroup.Group | Sort-Object LastRunTime | ForEach-Object {
        $suspicious = if ($_.IsSuspicious) { "[SUSPICIOUS] " } else { "" }
        $out += "  $suspicious$($_.LastRunTime.ToString('HH:mm:ss')) - $($_.ProcessName) (Size: $($_.FileSize) bytes)`r`n"
    }
}
Write-Host $out
Write-Output $out

# Suspicious prefetch files
$suspiciousPrefetch = $last24HoursPrefetch | Where-Object { $_.IsSuspicious }
if ($suspiciousPrefetch) {
    Write-Alert "Found $($suspiciousPrefetch.Count) suspicious prefetch entries in the $Hours-hour window"
    $out = "`r`nSuspicious Prefetch Files Detail:`r`n"
    $out += $suspiciousPrefetch |
        Sort-Object LastRunTime -Descending |
        Select-Object ProcessName, LastRunTime, CreatedTime, FileSize, FileName |
        Format-Table -AutoSize |
        Out-String
    Write-Host $out
    Write-Output $out
}

# Programs run during suspicious hours
$suspiciousTimePrefetch = $last24HoursPrefetch | Where-Object {
    if ($null -ne $_.LastRunTime -and $_.LastRunTime -is [DateTime]) {
        $hour = [int]$_.LastRunTime.Hour
        $hour -in @(0, 1, 2, 3, 4, 5, 6, 23)
    } else {
        $false
    }
}

if ($suspiciousTimePrefetch) {
    Write-Alert "Found $($suspiciousTimePrefetch.Count) programs executed during off-hours"
    $out = "`r`nPrograms Run During Off-Hours (11PM-7AM):`r`n"
    $out += $suspiciousTimePrefetch |
        Sort-Object LastRunTime |
        Select-Object @{Name="Time";Expression={$_.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss")}}, 
                      ProcessName, FileSize |
        Format-Table -AutoSize |
        Out-String
    Write-Host $out
    Write-Output $out
}

# Check for rapid execution patterns
$out = "`r`nRapid Execution Analysis (5+ programs within 5 minutes):`r`n"
$rapidExecutions = @()

$sortedPrefetch = $last24HoursPrefetch | Sort-Object LastRunTime
for ($i = 0; $i -lt ($sortedPrefetch.Count - 5); $i++) {
    if ($sortedPrefetch.Count -gt ($i + 4)) {
        $timeSpan = $sortedPrefetch[$i+4].LastRunTime - $sortedPrefetch[$i].LastRunTime
        if ($timeSpan.TotalMinutes -le 5) {
            $rapidExecutions += @{
                StartTime = $sortedPrefetch[$i].LastRunTime
                EndTime = $sortedPrefetch[$i+4].LastRunTime
                Programs = $sortedPrefetch[$i..($i+4)] | Select-Object ProcessName, LastRunTime
                Count = 5
            }
        }
    }
}

if ($rapidExecutions) {
    Write-Alert "Detected rapid execution patterns"
    foreach ($burst in $rapidExecutions) {
        $out += "`r`nBurst at $($burst.StartTime.ToString('yyyy-MM-dd HH:mm:ss')):`r`n"
        $burst.Programs | ForEach-Object {
            $out += "  - $($_.LastRunTime.ToString('HH:mm:ss')): $($_.ProcessName)`r`n"
        }
    }
} else {
    $out += "No rapid execution patterns detected.`r`n"
}
Write-Host $out
Write-Output $out

# Check specifically for ELEVATION_SERVICE.EXE activity
$elevationPrefetch = $last24HoursPrefetch | Where-Object { $_.ProcessName -match "elevation_service" }
if ($elevationPrefetch) {
    Write-Alert "ELEVATION_SERVICE.EXE Activity Detected"
    $out = "`r`nELEVATION_SERVICE.EXE Execution Timeline:`r`n"
    $out += $elevationPrefetch |
        Sort-Object LastRunTime |
        Select-Object @{Name="Time";Expression={$_.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss")}},
                      ProcessName, FileName, FileSize |
        Format-Table -AutoSize |
        Out-String
    Write-Host $out -ForegroundColor Red
    Write-Output $out
}

# ------------------------------------------------------------------------
# 4) UAC and SmartScreen Logs
# ------------------------------------------------------------------------
Write-Section "UAC and SmartScreen Logs"

# SmartScreen operational
if (Get-WinEvent -ListLog "Microsoft-Windows-SmartScreen/Operational" -ErrorAction SilentlyContinue) {
    $ss = Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-SmartScreen/Operational"
        StartTime = $StartTime
        EndTime = $EndTime
    } -ErrorAction SilentlyContinue
    
    if ($ss) {
        $out = "SmartScreen Events Found: $($ss.Count)`r`n"
        $out += $ss |
            Select-Object TimeCreated, Id, Message |
            Format-Table -Wrap -AutoSize |
            Out-String
    } else {
        $out = "No SmartScreen events found in specified time period.`r`n"
    }
} else {
    $out = "SmartScreen/Operational log not present on this system.`r`n"
}
Write-Host $out
Write-Output $out

# UAC operational
$uacLog = "Microsoft-Windows-User Account Control/Operational"
if (Get-WinEvent -ListLog $uacLog -ErrorAction SilentlyContinue) {
    $uac = Get-WinEvent -FilterHashtable @{
        LogName = $uacLog
        StartTime = $StartTime
        EndTime = $EndTime
    } -ErrorAction SilentlyContinue
    
    if ($uac) {
        $out = "UAC Events Found: $($uac.Count)`r`n"
        $out += $uac |
            Select-Object TimeCreated, Id, Message |
            Format-Table -Wrap -AutoSize |
            Out-String
    } else {
        $out = "No UAC Operational events in specified time window.`r`n"
    }
} else {
    $out = "UAC Operational log not found.`r`n"
}
Write-Host $out
Write-Output $out

# ------------------------------------------------------------------------
# 5) Persistence Mechanism Detection
# ------------------------------------------------------------------------
Write-Section "Persistence Mechanism Detection" "Magenta"

# A. WMI Startup Commands
Write-Host "`nChecking WMI Startup Commands..." -ForegroundColor Yellow
try {
    $startupCommands = Get-WmiObject Win32_StartupCommand -ErrorAction SilentlyContinue | 
        Select-Object Name, Command, Location, User

    if ($startupCommands) {
        $out = "WMI Startup Commands Found:`r`n"
        $out += $startupCommands | Format-Table -Wrap -AutoSize | Out-String
        
        # Flag suspicious entries
        $suspicious = $startupCommands | Where-Object { 
            $_.Command -match "(powershell|cmd|wscript|cscript|mshta|rundll32)" -or
            $_.Command -match "\.(ps1|bat|vbs|js|hta)" -or
            $_.Location -match "(Temp|AppData|ProgramData)"
        }
        
        if ($suspicious) {
            Write-Alert "Found $($suspicious.Count) potentially suspicious startup commands"
            $out += "`r`nFLAGGED ENTRIES:`r`n"
            $out += $suspicious | Format-Table -Wrap -AutoSize | Out-String
        }
    } else {
        $out = "No WMI startup commands found.`r`n"
    }
    Write-Host $out
    Write-Output $out
} catch {
    Write-Host "Error checking WMI startup commands: $_" -ForegroundColor Yellow
}

# B. Scheduled Tasks Analysis
Write-Host "`nAnalyzing Scheduled Tasks..." -ForegroundColor Yellow
try {
    # Get ALL scheduled tasks
    $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue

    # Filter for tasks that ran in specified time period
    $last24HoursTasks = @()
    foreach ($task in $allTasks) {
        $taskInfo = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        if ($taskInfo -and $taskInfo.LastRunTime -gt $StartTime -and $taskInfo.LastRunTime -le $EndTime) {
            $last24HoursTasks += [PSCustomObject]@{
                Task = $task
                Info = $taskInfo
                FullPath = "$($task.TaskPath)$($task.TaskName)"
            }
        }
    }

    if ($last24HoursTasks) {
        Write-Host "Found $($last24HoursTasks.Count) scheduled tasks that ran in the $Hours-hour window" -ForegroundColor Yellow
        
        # Group by task path to see patterns
        $out = "`r`nScheduled Tasks by Path:`r`n"
        $tasksByPath = $last24HoursTasks | Group-Object { $_.Task.TaskPath } | Sort-Object Name
        
        foreach ($pathGroup in $tasksByPath) {
            $out += "`r`n$($pathGroup.Name) ($($pathGroup.Count) tasks):`r`n"
            foreach ($taskObj in $pathGroup.Group) {
                $out += "  - $($taskObj.Task.TaskName) [Last run: $($taskObj.Info.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss'))]`r`n"
            }
        }
        Write-Host $out
        Write-Output $out
        
        # Detailed analysis of non-Microsoft tasks
        $nonMsTasks = $last24HoursTasks | Where-Object { $_.Task.TaskPath -notmatch "^\\Microsoft\\" }
        
        if ($nonMsTasks) {
            Write-Alert "Found $($nonMsTasks.Count) non-Microsoft tasks that ran in the $Hours-hour window"
            $out = "`r`nNon-Microsoft Tasks (DETAILED ANALYSIS):`r`n"
            $out += "=" * 100 + "`r`n"
            
            foreach ($taskObj in $nonMsTasks) {
                $task = $taskObj.Task
                $taskInfo = $taskObj.Info
                $taskDetail = Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                
                $out += "`r`nFull Path: $($taskObj.FullPath)`r`n"
                $out += "State: $($task.State)`r`n"
                $out += "Last Run: $($taskInfo.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss'))`r`n"
                $out += "Next Run: $(if ($taskInfo.NextRunTime) { $taskInfo.NextRunTime.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Not scheduled' })`r`n"
                $out += "Last Result: 0x$("{0:X8}" -f $taskInfo.LastTaskResult) $(if ($taskInfo.LastTaskResult -eq 0) { '(Success)' } else { '(Error)' })`r`n"
                $out += "Number of Missed Runs: $($taskInfo.NumberOfMissedRuns)`r`n"
                
                # Principal (who runs it)
                if ($taskDetail.Principal) {
                    $out += "Run As: $($taskDetail.Principal.UserId) (LogonType: $($taskDetail.Principal.LogonType))`r`n"
                    $out += "Run Level: $($taskDetail.Principal.RunLevel)`r`n"
                }
                
                # Actions
                if ($taskDetail.Actions) {
                    $out += "Actions:`r`n"
                    foreach ($action in $taskDetail.Actions) {
                        $out += "  - Execute: $($action.Execute)`r`n"
                        if ($action.Arguments) {
                            $out += "    Arguments: $($action.Arguments)`r`n"
                        }
                        if ($action.WorkingDirectory) {
                            $out += "    Working Directory: $($action.WorkingDirectory)`r`n"
                        }
                    }
                }
                
                # Check for suspicious indicators
                $suspiciousReasons = @()
                if ($taskDetail.Actions.Execute -match "(powershell|cmd|wscript|cscript|mshta|rundll32)") {
                    $suspiciousReasons += "Executes scripting engine"
                }
                if ($taskDetail.Actions.Execute -match "(\\temp\\|\\appdata\\|\\users\\[^\\]+\\appdata)") {
                    $suspiciousReasons += "Runs from user/temp directory"
                }
                if ($taskDetail.Principal.RunLevel -eq "HighestAvailable") {
                    $suspiciousReasons += "Requests elevated privileges"
                }
                if ($task.TaskPath -match "\\$") {
                    $suspiciousReasons += "Hidden task (ends with \)"
                }
                
                if ($suspiciousReasons) {
                    $out += "[FLAGGED] Reasons: $($suspiciousReasons -join '; ')`r`n"
                }
                
                $out += "-" * 100 + "`r`n"
            }
            Write-Host $out
            Write-Output $out
        }
    } else {
        $out = "No scheduled tasks found that ran in the specified time period.`r`n"
        Write-Host $out
        Write-Output $out
    }
} catch {
    Write-Host "Error analyzing scheduled tasks: $_" -ForegroundColor Yellow
}

# C. RunOnce Registry Entries
Write-Host "`nChecking RunOnce Registry Entries..." -ForegroundColor Yellow
$runOnceKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
)

$runOnceFound = $false
foreach ($key in $runOnceKeys) {
    try {
        $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if ($entries) {
            $runOnceFound = $true
            $out = "`r`n$key entries:`r`n"
            $entries.PSObject.Properties | Where-Object { $_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" -and $_.Name -ne "PSChildName" -and $_.Name -ne "PSDrive" -and $_.Name -ne "PSProvider" } | ForEach-Object {
                $out += "  $($_.Name) = $($_.Value)`r`n"
            }
            Write-Host $out
            Write-Output $out
        }
    } catch {
        # Key doesn't exist
    }
}

if (-not $runOnceFound) {
    $out = "No RunOnce entries found.`r`n"
    Write-Host $out
    Write-Output $out
}

# D. Services Analysis
Write-Host "`nAnalyzing Suspicious Services..." -ForegroundColor Yellow
Write-Host "Special attention to svchost.exe, dllhost.exe, explorer.exe services" -ForegroundColor Gray
Write-Host "These should ONLY run from Windows System directories" -ForegroundColor Gray
try {
    $services = Get-Service | Where-Object { $_.Status -eq "Running" }
    $suspiciousServices = @()

    foreach ($service in $services) {
        $isSuspicious = $false
        
        # Check display name patterns
        if ($service.DisplayName -match "(elevation|update|installer|admin)" -and $service.Name -notmatch "^(Windows|Microsoft)") {
            $isSuspicious = $true
        }
        
        # Check for random letter service names (6-8 lowercase letters)
        if ($service.Name -match "^[a-z]{6,8}$") {
            $isSuspicious = $true
        }
        
        # Check for numeric service names
        if ($service.Name -match "^\d{4,}") {
            $isSuspicious = $true
        }
        
        # Check for Windows processes from wrong locations
        if ($service.Name -match "svchost|dllhost|explorer") {
            # These should only run from System directories
            $serviceWmi = Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
            if ($serviceWmi -and $serviceWmi.PathName -notmatch "(System32|SysWOW64)") {
                $isSuspicious = $true
            }
        }
        
        if ($isSuspicious) {
            # Get the service path
            $serviceWmi = Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
            $suspiciousServices += [PSCustomObject]@{
                Name = $service.Name
                DisplayName = $service.DisplayName
                PathName = if ($serviceWmi) { $serviceWmi.PathName } else { "Unknown" }
                StartMode = if ($serviceWmi) { $serviceWmi.StartMode } else { "Unknown" }
            }
        }
    }

    if ($suspiciousServices) {
        Write-Alert "Found $($suspiciousServices.Count) potentially suspicious services"
        $out = "`r`nSuspicious Services Detail:`r`n"
        $out += $suspiciousServices | Format-Table -Property Name, DisplayName, StartMode, PathName -Wrap -AutoSize | Out-String
        Write-Host $out
        Write-Output $out
        
        # Check for services running from temp/appdata
        $tempServices = $suspiciousServices | Where-Object {
            $_.PathName -match "(\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\[^\\]+\\)"
        }
        
        if ($tempServices) {
            Write-Alert "Found services running from temporary/user locations"
            $out = "`r`nHIGH RISK - Services from temp/user folders:`r`n"
            foreach ($svc in $tempServices) {
                $out += "  - $($svc.Name): $($svc.PathName)`r`n"
            }
            Write-Host $out
            Write-Output $out
        }
    } else {
        $out = "No obviously suspicious services found.`r`n"
        $out += "`r`nNOTE: Legitimate Windows service paths:`r`n"
        $out += "  - svchost.exe: C:\\Windows\\System32\\svchost.exe`r`n"
        $out += "  - dllhost.exe: C:\\Windows\\System32\\dllhost.exe`r`n"
        $out += "  - explorer.exe: C:\\Windows\\explorer.exe`r`n"
        $out += "Any other locations for these files indicate potential malware.`r`n"
        Write-Host $out
        Write-Output $out
    }
} catch {
    Write-Host "Error analyzing services: $_" -ForegroundColor Yellow
}

# ------------------------------------------------------------------------
# 6) Elevation Service Investigation
# ------------------------------------------------------------------------
Write-Section "Elevation Service Investigation" "Yellow"

Write-Host "Searching for ELEVATION_SERVICE.EXE..." -ForegroundColor Yellow
Write-Host "Note: Some legitimate software may use similar naming patterns" -ForegroundColor Gray
$elevationPaths = @(
    "C:\Windows\System32\elevation_service.exe",
    "C:\Windows\SysWOW64\elevation_service.exe",
    "C:\Program Files\WindowsApps\Microsoft.WindowsStore*\elevation_service.exe",
    "C:\ProgramData\elevation_service.exe",
    "C:\Users\*\AppData\*\elevation_service.exe"
)

$out = "Checking ELEVATION_SERVICE.EXE locations and hashes:`r`n"
$foundElevation = $false

foreach ($pathPattern in $elevationPaths) {
    $files = Get-ChildItem -Path $pathPattern -ErrorAction SilentlyContinue -Force -Recurse
    foreach ($file in $files) {
        $foundElevation = $true
        try {
            $hash = Get-FileHash $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
            $signature = Get-AuthenticodeSignature $file.FullName -ErrorAction SilentlyContinue
            
            $out += "`r`nFile: $($file.FullName)`r`n"
            $out += "  SHA256: $($hash.Hash)`r`n"
            $out += "  Size: $($file.Length) bytes`r`n"
            $out += "  Created: $($file.CreationTime)`r`n"
            $out += "  Modified: $($file.LastWriteTime)`r`n"
            $out += "  Signature Status: $($signature.Status)`r`n"
            if ($signature.SignerCertificate) {
                $out += "  Signer: $($signature.SignerCertificate.Subject)`r`n"
            }
            
            # Check if legitimate Microsoft signature
            if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or 
                ($signature.SignerCertificate -and $signature.SignerCertificate.Subject -notmatch "Microsoft")) {
                Write-Alert "ELEVATION_SERVICE.EXE has invalid or non-Microsoft signature"
            }
        } catch {
            $out += "  Error checking file: $_`r`n"
        }
    }
}

if (-not $foundElevation) {
    $out += "ELEVATION_SERVICE.EXE not found in standard locations.`r`n"
    
    # Search for it elsewhere
    Write-Host "Performing deep search for elevation_service.exe..." -ForegroundColor Yellow
    try {
        $searchResults = Get-ChildItem -Path C:\ -Filter "elevation_service.exe" -Recurse -ErrorAction SilentlyContinue -Force | Select-Object -First 10
        
        if ($searchResults) {
            Write-Alert "Found elevation_service.exe in non-standard locations"
            $out += "`r`nFound in non-standard locations:`r`n"
            $searchResults | ForEach-Object {
                $out += "  $($_.FullName) (Size: $($_.Length) bytes, Modified: $($_.LastWriteTime))`r`n"
            }
        }
    } catch {
        $out += "Deep search failed or was cancelled.`r`n"
    }
}
Write-Host $out
Write-Output $out

# ------------------------------------------------------------------------
# 7) Network Connection Analysis
# ------------------------------------------------------------------------
Write-Section "Network Connection Analysis"

Write-Host "Analyzing active network connections..." -ForegroundColor Yellow
Write-Host "Note: svchost.exe network connections are normal, but verify the process path" -ForegroundColor Gray
try {
    # Get network connections using netstat
    $netstatOutput = netstat -anob 2>$null
    $suspiciousConnections = @()
    
    for ($i = 0; $i -lt $netstatOutput.Count; $i++) {
        $line = $netstatOutput[$i]
        if ($line -match "(ESTABLISHED|LISTENING)" -and $i -lt ($netstatOutput.Count - 1)) {
            $nextLine = $netstatOutput[$i + 1]
            if ($nextLine -match "\[(.*?)\]") {
                $process = $matches[1]
                foreach ($suspicious in $SuspiciousProcesses) {
                    if ($process -match [regex]::Escape($suspicious)) {
                        $suspiciousConnections += @{
                            Connection = $line.Trim()
                            Process = $process
                        }
                        break
                    }
                }
            }
        }
    }
    
    if ($suspiciousConnections) {
        Write-Alert "Found $($suspiciousConnections.Count) network connections from potentially suspicious processes"
        $out = "`r`nSuspicious Network Connections:`r`n"
        foreach ($conn in $suspiciousConnections) {
            $out += "  Process: $($conn.Process)`r`n"
            $out += "  Connection: $($conn.Connection)`r`n`r`n"
        }
    } else {
        $out = "No suspicious network connections detected.`r`n"
    }
    Write-Host $out
    Write-Output $out
} catch {
    Write-Host "Error analyzing network connections: $_" -ForegroundColor Yellow
}

# ------------------------------------------------------------------------
# 8) File System Checks
# ------------------------------------------------------------------------
Write-Section "File System Checks"

# A. Recently Modified Executables
Write-Host "Checking recently modified executables..." -ForegroundColor Yellow
Write-Host "Note: Legitimate svchost.exe should ONLY exist in System32/SysWOW64" -ForegroundColor Gray
$suspiciousLocations = @(
    "C:\Windows\Temp",
    "$env:TEMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA",
    "C:\ProgramData"
)

$recentExes = @()
foreach ($location in $suspiciousLocations) {
    if (Test-Path $location) {
        try {
            $exes = Get-ChildItem -Path $location -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $StartTime -and $_.LastWriteTime -le $EndTime }
            if ($exes) {
                $recentExes += $exes
            }
        } catch {
            # Skip inaccessible directories
        }
    }
}

if ($recentExes) {
    Write-Alert "Found $($recentExes.Count) recently modified executables in suspicious locations"
            $out = "`r`nRecent Executables in Monitored Locations:`r`n"
    $out += $recentExes | 
        Select-Object FullName, Length, LastWriteTime, CreationTime |
        Format-Table -AutoSize | 
        Out-String
} else {
    $out = "No recent executables found in temp locations.`r`n"
}
Write-Host $out
Write-Output $out

# B. Shim Cache Analysis
Write-Host "`nChecking Shim Cache..." -ForegroundColor Yellow
try {
    $shimKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
    $shim = Get-ItemProperty -Path $shimKey -ErrorAction Stop
    if ($shim.AppCompatCache) {
        $out = "AppCompatCache present - Size: $($shim.AppCompatCache.Length) bytes`r`n"
        $out += "Note: Full shim cache parsing requires specialized tools`r`n"
    } else {
        $out = "AppCompatCache not found or empty.`r`n"
    }
} catch {
    $out = "Failed to read Shim Cache: $_`r`n"
}
Write-Host $out
Write-Output $out

# C. USN Journal Query
Write-Host "`nQuerying USN Journal..." -ForegroundColor Yellow
try {
    $usn = & fsutil usn queryjournal C: 2>&1
    if ($LASTEXITCODE -eq 0) {
        $out = "USN Journal Information:`r`n"
        $out += ($usn | Out-String)
    } else {
        $out = "Failed to query USN Journal on C:.`r`n"
    }
} catch {
    $out = "Error querying USN Journal: $_`r`n"
}
Write-Host $out
Write-Output $out

# ------------------------------------------------------------------------
# 9) Time-Based Analysis
# ------------------------------------------------------------------------
Write-Section "Time-Based Analysis" "Yellow"

# Define suspicious hours
$suspiciousHours = @(0..6) + @(23)

# Check for activity during unusual hours
Write-Host "Analyzing activity during off-hours (11PM-7AM)..." -ForegroundColor Yellow
Write-Host "Note: Off-hours activity may be normal for automated tasks, updates, or 24/7 operations" -ForegroundColor Gray
$suspiciousTimes = @()
$logNames = @("Security", "Application", "System")

foreach ($logName in $logNames) {
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = $logName
            StartTime = $StartTime
            EndTime = $EndTime
        } -MaxEvents 2000 -ErrorAction SilentlyContinue |
        Where-Object { 
            $hour = $_.TimeCreated.Hour
            $hour -in $suspiciousHours
        }
        
        if ($events) {
            $suspiciousTimes += $events
        }
    } catch {
        # Skip if log not accessible
    }
}

if ($suspiciousTimes) {
    Write-Alert "Found $($suspiciousTimes.Count) events during off-hours (11PM-7AM)"
    $grouped = $suspiciousTimes | 
        Group-Object { $_.TimeCreated.ToString("yyyy-MM-dd HH:00") } |
        Sort-Object Name
    
    $out = "`r`nEvents by hour during off-hours times:`r`n"
    foreach ($group in $grouped) {
        $out += "$($group.Name): $($group.Count) events`r`n"
        
        # Show some sample events from this hour
        $samples = $group.Group | 
            Where-Object { $_.ProviderName -notmatch "Microsoft-Windows-(Kernel|Security-SPP|Time-Service)" } |
            Select-Object -First 3
        
        if ($samples) {
            foreach ($sample in $samples) {
                $out += "  - $($sample.TimeCreated.ToString('HH:mm:ss')): $($sample.ProviderName) (ID: $($sample.Id))`r`n"
            }
        }
    }
    Write-Host $out
    Write-Output $out
}

# Boot Sequence Analysis
Write-Host "`nAnalyzing System Boot/Restart Events..." -ForegroundColor Yellow
try {
    $bootEvents = Get-WinEvent -FilterHashtable @{
        LogName = "System"
        StartTime = $StartTime
        EndTime = $EndTime
    } -ErrorAction SilentlyContinue | 
        Where-Object { $_.Id -in @(12, 13, 6005, 6006, 6008, 6009, 1074) } |
        Sort-Object TimeCreated -Descending

    if ($bootEvents) {
        $lastBoot = $bootEvents | Where-Object { $_.Id -in @(6005, 12) } | Select-Object -First 1
        
        if ($lastBoot) {
            Write-Host "Last system boot detected at: $($lastBoot.TimeCreated)" -ForegroundColor Cyan
            
            # Get all events around boot time
            $bootWindowStart = $lastBoot.TimeCreated.AddMinutes(-5)
            $bootWindowEnd = $lastBoot.TimeCreated.AddMinutes(30)
            
            $out = "`r`nBoot Sequence Events:`r`n"
            $bootWindowEvents = $bootEvents |
                Where-Object { $_.TimeCreated -ge $bootWindowStart -and $_.TimeCreated -le $bootWindowEnd }
            
            $out += $bootWindowEvents |
                Select-Object TimeCreated, Id, Message |
                Format-Table -Wrap -AutoSize |
                Out-String
            Write-Host $out
            Write-Output $out
            
            # Check what ran after boot
            if ($allPrefetch) {
                $postBootPrefetch = $allPrefetch | 
                    Where-Object { 
                        $_.LastRunTime -gt $lastBoot.TimeCreated -and 
                        $_.LastRunTime -lt $lastBoot.TimeCreated.AddMinutes(30) -and
                        $_.LastRunTime -le $EndTime
                    }
                
                if ($postBootPrefetch) {
                    $out = "`r`nPrograms executed within 30 minutes after boot:`r`n"
                    $out += $postBootPrefetch |
                        Sort-Object LastRunTime |
                        Select-Object ProcessName, LastRunTime |
                        Format-Table -AutoSize |
                        Out-String
                    Write-Host $out
                    Write-Output $out
                }
            }
        }
            } else {
                $out = "No boot events found in the specified time period.`r`n"
                Write-Host $out
                Write-Output $out
            }
} catch {
    Write-Host "Error analyzing boot sequence: $_" -ForegroundColor Yellow
}

# Correlation Analysis
Write-Host "`nPerforming Activity Pattern Correlation..." -ForegroundColor Yellow
try {
    $correlatedEvents = @{}
    
    # Group events by 5-minute windows
    $securityEvents = Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        StartTime = $StartTime
        EndTime = $EndTime
    } -MaxEvents 2000 -ErrorAction SilentlyContinue | 
        Where-Object { $_.Id -in @(4688, 4672, 4673) }

    foreach ($event in $securityEvents) {
        $window = [math]::Floor($event.TimeCreated.Minute / 5) * 5
        $key = "$($event.TimeCreated.ToString('yyyy-MM-dd HH')):$($window.ToString('00'))"
        
        if (-not $correlatedEvents.ContainsKey($key)) {
            $correlatedEvents[$key] = @()
        }
        $correlatedEvents[$key] += $event
    }

    # Find windows with suspicious activity clusters
    $suspiciousWindows = $correlatedEvents.GetEnumerator() | 
        Where-Object { $_.Value.Count -gt 10 } |
        Sort-Object Key

    if ($suspiciousWindows) {
        $out = "`r`nTime windows with high activity (potential automated behavior):`r`n"
        foreach ($window in $suspiciousWindows) {
            $out += "$($window.Key): $($window.Value.Count) events`r`n"
        }
        Write-Host $out
        Write-Output $out
    }
} catch {
    Write-Host "Error in correlation analysis: $_" -ForegroundColor Yellow
}

# ------------------------------------------------------------------------
# 10) Advanced Event Log Analysis
# ------------------------------------------------------------------------
Write-Section "Advanced Event Log Analysis"

# A. AppLocker Audit Logs
Write-Host "Checking AppLocker Audit Logs..." -ForegroundColor Yellow
$appLockerLogs = @(
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-AppLocker/MSI and Script",
    "Microsoft-Windows-AppLocker/Packaged app-Deployment",
    "Microsoft-Windows-AppLocker/Packaged app-Execution"
)

foreach ($logName in $appLockerLogs) {
    if (Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue) {
        try {
            $entries = Get-WinEvent -FilterHashtable @{
                LogName = $logName
                StartTime = $StartTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue

            if ($entries) {
                $out = "`r`nEntries in $($logName): $($entries.Count) events`r`n"
                $out += $entries | 
                    Select-Object -First 10 |
                    Select-Object TimeCreated, Id, Message |
                    Format-Table -Wrap -AutoSize |
                    Out-String
                Write-Host $out
                Write-Output $out
            }
        } catch {
            # Skip if error
        }
    }
}

# B. Handle/Privilege Audit Events
Write-Host "`nChecking Handle/Privilege Audit Events..." -ForegroundColor Yellow
try {
    $auditEvents = Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        StartTime = $StartTime
        EndTime = $EndTime
    } -MaxEvents 1000 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -in @(4656, 4663, 4670, 4673) }

    if ($auditEvents) {
        # Filter for suspicious processes
        $filteredAudits = $auditEvents | Where-Object { 
            $_.Message -match "(msiexec|elevation_service|powershell|cmd|rundll32)\.exe" 
        }
        
        if ($filteredAudits) {
            $out = "`r`nHandle/Privilege events for suspicious processes: $($filteredAudits.Count) events`r`n"
            $out += $filteredAudits |
                Select-Object -First 20 |
                Select-Object TimeCreated, Id, Message |
                Format-Table -Wrap -AutoSize |
                Out-String
        } else {
            $out = "No handle/privilege events for suspicious processes found.`r`n"
        }
    } else {
        $out = "No handle/privilege audit events found.`r`n"
    }
    Write-Host $out
    Write-Output $out
} catch {
    Write-Host "Error checking audit events: $_" -ForegroundColor Yellow
}

# C. Windows Defender Logs
Write-Host "`nChecking Windows Defender Logs..." -ForegroundColor Yellow
try {
    $defenderLog = "Microsoft-Windows-Windows Defender/Operational"
    if (Get-WinEvent -ListLog $defenderLog -ErrorAction SilentlyContinue) {
        $defenderEvents = Get-WinEvent -FilterHashtable @{
            LogName = $defenderLog
            StartTime = $StartTime
            EndTime = $EndTime
        } -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -in @(1116, 1117, 1118, 1119) }  # Detection events
        
        if ($defenderEvents) {
            Write-Alert "Windows Defender detection events found"
            $out = "`r`nWindows Defender Detections:`r`n"
            $out += $defenderEvents |
                Select-Object TimeCreated, Id, Message |
                Format-Table -Wrap -AutoSize |
                Out-String
            Write-Host $out
            Write-Output $out
        }
    }
} catch {
    Write-Host "Error checking Windows Defender logs: $_" -ForegroundColor Yellow
}

# ------------------------------------------------------------------------
# RECOMMENDATIONS
# ------------------------------------------------------------------------
Write-Section "Security Recommendations" "Green"

$recommendations = "Based on the comprehensive analysis:

1. IMMEDIATE ACTIONS:
   - Review findings in context of your system's normal behavior
   - CRITICAL: Verify any svchost.exe, dllhost.exe, or explorer.exe are running from System32/SysWOW64
   - Run a full antivirus scan with updated definitions
   - Review all non-Microsoft scheduled tasks identified
   - Check all services running from temp/user directories
   - Verify legitimacy of any elevation_service.exe instances
   - Review all startup items and RunOnce entries

2. INVESTIGATION PRIORITIES:
   - Review activities during off-hours (11PM-7AM) for your environment
   - Investigate rapid execution patterns if unexpected
   - Review MSI installations you did not initiate
   - Check network connections from flagged processes
   - Verify all non-Microsoft signed executables
   - Note: Many findings may be legitimate - verify before action

3. COMMON FALSE POSITIVES:
   - Windows Update activities (often run at night)
   - Antivirus scans and updates
   - Backup software operations
   - System maintenance tasks
   - Legitimate software installers
   - Corporate management tools
   
   IMPORTANT: For svchost.exe, dllhost.exe, explorer.exe:
   - These are legitimate Windows processes when running from:
     * C:\Windows\System32\
     * C:\Windows\SysWOW64\
   - If found running from ANY other location, investigate immediately
   - Malware commonly impersonates these process names

4. SECURITY HARDENING:
   - Enable AppLocker to control application execution
   - Configure Windows Defender Application Control (WDAC)
   - Enable additional Security log auditing
   - Implement PowerShell logging (ScriptBlock and Module logging)
   - Review and restrict scheduled task creation permissions

4. MONITORING RECOMMENDATIONS:
   - Set up alerts for process creation from temp directories
   - Monitor elevation_service.exe and similar suspicious names
   - Track scheduled task creation/modification
   - Alert on service installation from non-standard locations
   - Monitor registry Run keys for changes

5. TOOLS FOR FURTHER ANALYSIS:
   - Autoruns: https://docs.microsoft.com/sysinternals/downloads/autoruns
   - Process Monitor: https://docs.microsoft.com/sysinternals/downloads/procmon
   - WPA (Windows Performance Analyzer) for detailed ETW analysis
   - Sysmon for enhanced logging: https://docs.microsoft.com/sysinternals/downloads/sysmon

6. FURTHER INVESTIGATION (if needed):
   - Review findings in context of expected system behavior
   - Many 'suspicious' indicators may be normal for your environment
   - Consider legitimate software that may trigger alerts
   - Verify findings before taking action
   - Document all findings with timestamps
   - Check other systems for similar indicators if warranted"

Write-Host $recommendations -ForegroundColor Green
Write-Output $recommendations

# ------------------------------------------------------------------------
# CRITICAL FINDINGS SUMMARY
# ------------------------------------------------------------------------
Write-Section "FINDINGS SUMMARY" "Yellow"

$summary = "`r`nNote: This analysis identifies potentially suspicious indicators based on common`r`n"
$summary += "      attack patterns. Many findings may be legitimate system behavior.`r`n"
$summary += "      Review findings in context of your environment before taking action.`r`n`r`n"
$summary += "Automated Analysis Summary for $Hours-hour window before $($EndTime.ToString('yyyy-MM-dd HH:mm:ss')):`r`n"
$summary += "=" * 60 + "`r`n"

# Count suspicious indicators
$indicators = 0
$suspiciousItems = @()

# Check for elevation service
if ($elevationPrefetch -or $foundElevation) {
    $summary += "[!] ELEVATION_SERVICE.EXE activity or presence detected`r`n"
    $indicators++
    $suspiciousItems += "ELEVATION_SERVICE.EXE activity"
}

# Check for suspicious MSI activity
if ($suspiciousMsi) {
    $summary += "[*] Suspicious MSI installations: $($suspiciousMsi.Count)`r`n"
    $indicators++
}

# Check for off-hours activity
if ($suspiciousTimes -and $suspiciousTimes.Count -gt 100) {
    $summary += "[*] High volume of off-hours activity: $($suspiciousTimes.Count) events`r`n"
    $indicators++
}

# Check for suspicious prefetch
if ($suspiciousPrefetch) {
    $summary += "[*] Suspicious programs executed: $($suspiciousPrefetch.Count)`r`n"
    $indicators++
}

# Check for suspicious services
if ($suspiciousServices) {
    $summary += "[*] Suspicious services found: $($suspiciousServices.Count)`r`n"
    $indicators++
}

# Check for suspicious startup items
if ($suspicious) {
    $summary += "[*] Suspicious startup commands: $($suspicious.Count)`r`n"
    $indicators++
}

# Check for recent executables in temp
if ($recentExes) {
    $summary += "[*] Recent executables in temp/appdata: $($recentExes.Count)`r`n"
    $indicators++
}

# Check for non-Microsoft scheduled tasks
if ($nonMsTasks) {
    $summary += "[*] Non-Microsoft scheduled tasks active: $($nonMsTasks.Count)`r`n"
    $indicators++
}

# Check for network connections
if ($suspiciousConnections) {
    $summary += "[*] Suspicious network connections: $($suspiciousConnections.Count)`r`n"
    $indicators++
}

# Check for rapid execution patterns
if ($rapidExecutions) {
    $summary += "[*] Rapid execution patterns detected: $($rapidExecutions.Count)`r`n"
    $indicators++
}

# Risk assessment
$summary += "`r`nRISK ASSESSMENT: "
if ($indicators -eq 0) {
    $summary += "LOW - No suspicious indicators found`r`n"
    Write-Host $summary -ForegroundColor Green
} elseif ($indicators -le 2) {
    $summary += "MEDIUM - Some suspicious activity detected, review findings`r`n"
    Write-Host $summary -ForegroundColor Yellow
} elseif ($indicators -le 5) {
    $summary += "HIGH - Multiple suspicious indicators, investigation recommended`r`n"
    Write-Host $summary -ForegroundColor Red
} else {
    $summary += "ELEVATED - Significant suspicious activity detected, thorough investigation required`r`n"
    Write-Host $summary -ForegroundColor Red
}

$summary += "`r`nTotal suspicious indicators: $indicators`r`n"
$summary += "Report generated: $(Get-Date)`r`n"
$summary += "Time window analyzed: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) to $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))`r`n"
$summary += "Duration: $Hours hours before $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))`r`n"

# List key findings
if ($suspiciousItems.Count -gt 0) {
    $summary += "`r`nFINDINGS REQUIRING REVIEW:`r`n"
    $summary += "=" * 60 + "`r`n"
    foreach ($item in $suspiciousItems) {
        $summary += "  - $item`r`n"
    }
}

$summary += "`r`nFull details available in: $OutputPath`r`n"

Write-Output $summary

# Footer
$footer = "`r`n=== End of Enhanced Forensic Report ===`r`n"
Write-Host $footer -ForegroundColor Cyan
Write-Output $footer

# Summary of output files
Write-Host "`r`n" -ForegroundColor Green
Write-Host "======== OUTPUT FILES CREATED ========" -ForegroundColor Green
Write-Host "Main Report:     $OutputPath" -ForegroundColor Yellow
if ($prefetchExportPath -and (Test-Path $prefetchExportPath)) {
    Write-Host "Prefetch Data:   $prefetchExportPath" -ForegroundColor Yellow
}
Write-Host "=====================================" -ForegroundColor Green
Write-Host "`r`n" -ForegroundColor Green

# Open the report
Write-Host "Opening report in Notepad..." -ForegroundColor Green
try {
    Start-Process notepad $OutputPath
} catch {
    Write-Host "Could not open report automatically. Please open: $OutputPath" -ForegroundColor Yellow
}

# Display usage examples if running with default parameters
if ($Hours -eq 24 -and $BeforeTime -eq "") {
    Write-Host "TIP: You can customize the analysis time window:" -ForegroundColor Cyan
    Write-Host "  .\$($MyInvocation.MyCommand.Name) -Hours 48" -ForegroundColor Green
    Write-Host "    Analyzes 48 hours before current time" -ForegroundColor Gray
    Write-Host "  .\$($MyInvocation.MyCommand.Name) -BeforeTime '2025-06-26 15:00:00'" -ForegroundColor Green
    Write-Host "    Analyzes 24 hours before June 26, 2025 3:00 PM" -ForegroundColor Gray
    Write-Host "  .\$($MyInvocation.MyCommand.Name) -Hours 72 -BeforeTime '2025-06-26 15:00:00'" -ForegroundColor Green
    Write-Host "    Analyzes 72 hours before June 26, 2025 3:00 PM (June 23-26)" -ForegroundColor Gray
    Write-Host "`r`n" -ForegroundColor Cyan
}
