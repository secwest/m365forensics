#requires -RunAsAdministrator
<#
.SYNOPSIS
  Enhanced elevation diagnostics with prefetch analysis similar to NirSoft WinPrefetchView
  Now with automatic 24-hour analysis window and comprehensive security checks
  [FIXED VERSION - Corrected type conversion errors]

.DESCRIPTION
  Includes all original sections plus:
  - Detailed prefetch file analysis
  - Suspicious pattern detection
  - Timeline correlation
  - Persistence mechanism checks
  - Service verification
  - Network connection analysis
  - Automatic 24-hour time window
#>

# ------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------
$StartTime  = (Get-Date).AddHours(-24)       # Automatic 24-hour window
$EndTime    = Get-Date
$MaxEvents  = 1000                           # Increased for better coverage
$OutputPath = "C:\Temp\ElevationAudit_Enhanced_$(Get-Date -Format "yyyyMMdd_HHmmss").txt"
$SuspiciousProcesses = @(
    "elevation_service.exe", "runtimebroker.exe", "msiexec.exe", "wusa.exe", 
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
    "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe",
    "installutil.exe", "mshta.exe", "conhost.exe"
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
$header += "Analyzing 24-hour period: $($StartTime.ToString("yyyy-MM-dd HH:mm:ss")) to $($EndTime.ToString("yyyy-MM-dd HH:mm:ss"))`r`n"
$header += "Output file: $OutputPath`r`n"
$header += "`r`nThis report includes:`r`n"
$header += "  - Complete prefetch activity log for last 24 hours`r`n"
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
    $alert = "[ALERT] $Message"
    Write-Host $alert -ForegroundColor Red
    Write-Output $alert
}

# ------------------------------------------------------------------------
# 1) MSI Installer events
# ------------------------------------------------------------------------
Write-Section "MSI Installer Events (IDs 1001,11706-11708)"
$msi = Get-WinEvent -FilterHashtable @{
  LogName      = "Application"
  ProviderName = "MsiInstaller"
  StartTime    = $StartTime
  EndTime      = $EndTime
} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue |
  Where-Object { $_.Id -in @(1001,11706,11707,11708) }

if ($msi) {
  Write-Host "Found $($msi.Count) MSI installer events in last 24 hours" -ForegroundColor Yellow
  
  # Group by hour to see patterns
  $msiByHour = $msi | Group-Object { $_.TimeCreated.ToString("yyyy-MM-dd HH:00") } | Sort-Object Name
  
  $out = "`r`nMSI Activity by Hour:`r`n"
  $msiByHour | ForEach-Object {
    $out += "$($_.Name): $($_.Count) installations`r`n"
  }
  $out += "`r`nDetailed MSI Events:`r`n"
  
  $out += $msi |
    Select-Object TimeCreated, Id, @{Name="User";Expression={$_.Properties[1].Value}}, @{Name="Package";Expression={$_.Properties[0].Value}}, Message |
    Sort-Object TimeCreated -Descending |
    Format-Table -AutoSize |
    Out-String
    
  # Check for suspicious patterns
  $suspiciousMsi = $msi | Where-Object {
    $hour = $_.TimeCreated.Hour
    $hour -in @(0..6, 23) -or
    $_.Message -match "(temp|appdata|users\\[^\\]+\\appdata)"
  }
  
  if ($suspiciousMsi) {
    Write-Alert "Found $($suspiciousMsi.Count) MSI installations during suspicious hours or locations!"
  }
} else {
  $out = "No MSI Installer events found between $StartTime and $EndTime.`r`n"
}
Write-Host $out
Write-Output $out

# ------------------------------------------------------------------------
# 2) Security process creation (Event ID 4688 for msiexec/wusa)
# ------------------------------------------------------------------------
Write-Section "Process Creation Events (Event ID 4688 filtered for msiexec/wusa)"
$procs = Get-WinEvent -FilterHashtable @{
  LogName   = "Security"
  Id        = 4688
  StartTime = $StartTime
  EndTime   = $EndTime
} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

$filtered = $procs | Where-Object {
  ($_.Properties | Where-Object {$_.Id -eq 10}).Value -match "\\(msiexec|wusa)\.exe$"
}

if ($filtered) {
  $out = $filtered |
    Select-Object TimeCreated,
           @{Name="Parent";Expression={($_.Properties | Where-Object {$_.Id -eq 6}).Value}},
           @{Name="NewProc";Expression={($_.Properties | Where-Object {$_.Id -eq 5}).Value}},
           @{Name="CmdLine";Expression={($_.Properties | Where-Object {$_.Id -eq 10}).Value}},
           @{Name="Account";Expression={($_.Properties | Where-Object {$_.Id -eq 1}).Value}} |
    Format-Table -Wrap -AutoSize |
    Out-String
} else {
  $out = "No msiexec/wusa process-creation events found in Security log.`r`n"
}
Write-Host $out
Write-Output $out

# ------------------------------------------------------------------------
# 3) SmartScreen operational
# ------------------------------------------------------------------------
Write-Section "SmartScreen Operational Events"
if (Get-WinEvent -ListLog "Microsoft-Windows-SmartScreen/Operational" -ErrorAction SilentlyContinue) {
  $ss = Get-WinEvent -LogName "Microsoft-Windows-SmartScreen/Operational" -ErrorAction SilentlyContinue |
        Where-Object {$_.TimeCreated -ge $StartTime -and $_.TimeCreated -le $EndTime}
  if ($ss) {
    $out = $ss |
      Select-Object TimeCreated, Id, Message |
      Format-Table -Wrap -AutoSize |
      Out-String
  } else {
    $out = "No SmartScreen events found between $StartTime and $EndTime.`r`n"
  }
} else {
  $out = "SmartScreen/Operational log not present on this system.`r`n"
}
Write-Host $out
Write-Output $out

# ------------------------------------------------------------------------
# 4) UAC operational
# ------------------------------------------------------------------------
Write-Section "UAC Operational Events"
$uacLog = "Microsoft-Windows-User Account Control/Operational"
if (Get-WinEvent -ListLog $uacLog -ErrorAction SilentlyContinue) {
  $uac = Get-WinEvent -LogName $uacLog -ErrorAction SilentlyContinue |
         Where-Object {$_.TimeCreated -ge $StartTime -and $_.TimeCreated -le $EndTime}
  if ($uac) {
    $out = $uac |
      Select-Object TimeCreated, Id, Message |
      Format-Table -Wrap -AutoSize |
      Out-String
  } else {
    $out = "No UAC Operational events in time window.`r`n"
  }
} else {
  $out = "UAC Operational log not found.`r`n"
}
Write-Host $out
Write-Output $out

# ------------------------------------------------------------------------
# 5) Shim Cache dump
# ------------------------------------------------------------------------
Write-Section "Shim Cache (AppCompatCache) Dump"
try {
  $shim = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache" -ErrorAction Stop
  $out  = "AppCompatCache size: {0} bytes`r`n" -f $shim.AppCompatCache.Length
} catch {
  $out = "Failed to read Shim Cache or not present.`r`n"
}
Write-Host $out
Write-Output $out

# ------------------------------------------------------------------------
# ENHANCED PREFETCH ANALYSIS (Similar to WinPrefetchView)
# ------------------------------------------------------------------------
Write-Section "Enhanced Prefetch File Analysis"

function Get-PrefetchInfo {
    param([string]$PrefetchPath)
    
    $prefetchFiles = @()
    
    Get-ChildItem -Path $PrefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue | ForEach-Object {
        $file = $_
        
        # Extract embedded filename from prefetch name
        $exeName = $file.Name -replace "-[A-F0-9]{8}\.pf$", ""
        
        # Get file info
        $fileInfo = @{
            FileName = $file.Name
            ProcessName = $exeName
            ProcessPath = "Unknown" # Would need to parse .pf file for full path
            LastRunTime = $file.LastWriteTime
            CreatedTime = $file.CreationTime
            FileSize = $file.Length
            RunCount = 1 # Would need to parse .pf file for actual count
            IsSuspicious = $SuspiciousProcesses -contains $exeName.ToLower()
        }
        
        # Check for suspicious patterns
        if ($exeName -match "(elevation|admin|install|update|patch)" -and $exeName -notmatch "windows") {
            $fileInfo.IsSuspicious = $true
        }
        
        $prefetchFiles += New-Object PSObject -Property $fileInfo
    }
    
    return $prefetchFiles
}

$allPrefetch = Get-PrefetchInfo -PrefetchPath "C:\Windows\Prefetch"

# Filter for last 24 hours
$last24HoursPrefetch = $allPrefetch | Where-Object { $_.LastRunTime -gt $StartTime }

Write-Host "`nTotal prefetch files: $($allPrefetch.Count)" -ForegroundColor Cyan
Write-Host "Prefetch files active in last 24 hours: $($last24HoursPrefetch.Count)" -ForegroundColor Yellow

# Group by hour for timeline analysis
$out = "`r`nPrefetch Activity Timeline (Last 24 Hours):`r`n"
$out += "=" * 60 + "`r`n"
$hourlyGroups = $last24HoursPrefetch | Group-Object { $_.LastRunTime.ToString("yyyy-MM-dd HH:00") } | Sort-Object Name

foreach ($hourGroup in $hourlyGroups) {
    $out += "`r`n$($hourGroup.Name) - $($hourGroup.Count) programs executed:`r`n"
    $hourGroup.Group | Sort-Object LastRunTime | ForEach-Object {
        $suspicious = if ($_.IsSuspicious) { "[SUSPICIOUS] " } else { "" }
        $out += "  $suspicious$($_.LastRunTime.ToString("HH:mm:ss")) - $($_.ProcessName) (Size: $($_.FileSize) bytes)`r`n"
    }
}
Write-Host $out
Write-Output $out

# Suspicious prefetch files
$suspiciousPrefetch = $last24HoursPrefetch | Where-Object { $_.IsSuspicious }
if ($suspiciousPrefetch) {
    Write-Alert "Found $($suspiciousPrefetch.Count) suspicious prefetch entries in last 24 hours!"
    $out = "`r`nSuspicious Prefetch Files Detail:`r`n"
    $out += $suspiciousPrefetch |
        Sort-Object LastRunTime -Descending |
        Select-Object ProcessName, LastRunTime, CreatedTime, FileSize, FileName |
        Format-Table -AutoSize |
        Out-String
    Write-Host $out
    Write-Output $out
}

# Most frequently run programs
$out = "`r`nMost Active Programs (by prefetch count in last 24 hours):`r`n"
$frequentPrograms = $last24HoursPrefetch | 
    Group-Object ProcessName | 
    Sort-Object Count -Descending | 
    Select-Object -First 20

$out += $frequentPrograms | ForEach-Object {
    "$($_.Count.ToString().PadLeft(4)) executions: $($_.Name)"
} | Out-String
Write-Host $out
Write-Output $out

# Programs run during suspicious hours - FIXED VERSION
$suspiciousTimePrefetch = $last24HoursPrefetch | Where-Object {
    if ($null -ne $_.LastRunTime -and $_.LastRunTime -is [DateTime]) {
        $hour = [int]$_.LastRunTime.Hour
        $hour -in @(0, 1, 2, 3, 4, 5, 6, 23)
    } else {
        $false
    }
}

if ($suspiciousTimePrefetch) {
    Write-Alert "Found $($suspiciousTimePrefetch.Count) programs executed during off-hours!"
    $out = "`r`nPrograms Run During Suspicious Hours (11PM-6AM):`r`n"
    $out += $suspiciousTimePrefetch |
        Sort-Object LastRunTime |
        Select-Object @{Name="Time";Expression={$_.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss")}}, 
                      ProcessName, FileSize |
        Format-Table -AutoSize |
        Out-String
    Write-Host $out
    Write-Output $out
}

# Check for rapid execution patterns (multiple programs in short time)
$out = "`r`nRapid Execution Analysis (5+ programs within 5 minutes):`r`n"
$rapidExecutions = @()

$sortedPrefetch = $last24HoursPrefetch | Sort-Object LastRunTime
for ($i = 0; $i -lt $sortedPrefetch.Count - 5; $i++) {
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

if ($rapidExecutions) {
    Write-Alert "Detected rapid execution patterns!"
    foreach ($burst in $rapidExecutions) {
        $out += "`r`nBurst at $($burst.StartTime.ToString("yyyy-MM-dd HH:mm:ss")):`r`n"
        $burst.Programs | ForEach-Object {
            $out += "  - $($_.LastRunTime.ToString("HH:mm:ss")): $($_.ProcessName)`r`n"
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
    Write-Alert "ELEVATION_SERVICE.EXE Activity Detected!"
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

# Process execution frequency analysis
$out = "`r`nProcess Execution Frequency Analysis:`r`n"
$processFrequency = $last24HoursPrefetch | 
    Group-Object ProcessName |
    Where-Object { $_.Count -gt 5 } |
    Sort-Object Count -Descending

if ($processFrequency) {
    $out += "Programs executed more than 5 times:`r`n"
    $processFrequency | ForEach-Object {
        $isSuspicious = $SuspiciousProcesses -contains $_.Name.ToLower()
        $flag = if ($isSuspicious) { " [SUSPICIOUS]" } else { "" }
        $out += "  $($_.Count.ToString().PadLeft(4)) times: $($_.Name)$flag`r`n"
    }
} else {
    $out += "No programs executed more than 5 times.`r`n"
}
Write-Host $out
Write-Output $out

# Full listing of ALL prefetch activity in last 24 hours
$out = "`r`n" + ("=" * 80) + "`r`n"
$out += "COMPLETE PREFETCH ACTIVITY LOG (Last 24 Hours)`r`n"
$out += ("=" * 80) + "`r`n"
$out += "Total entries: $($last24HoursPrefetch.Count)`r`n`r`n"

$out += $last24HoursPrefetch |
    Sort-Object LastRunTime -Descending |
    Select-Object @{Name="LastRun";Expression={$_.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss")}},
                  @{Name="Created";Expression={$_.CreatedTime.ToString("yyyy-MM-dd HH:mm:ss")}},
                  ProcessName,
                  @{Name="Size";Expression={"{0:N0}" -f $_.FileSize}},
                  @{Name="Suspicious";Expression={if($_.IsSuspicious){"YES"}else{""}}},
                  FileName |
    Format-Table -AutoSize |
    Out-String

Write-Host $out
Write-Output $out

# ------------------------------------------------------------------------
# SUSPICIOUS TIME ANALYSIS
# ------------------------------------------------------------------------
Write-Section "Suspicious Time Period Analysis" "Red"

# Define suspicious hours (customize based on your normal usage)
$suspiciousHours = @(0..6)  # Midnight to 6 AM
$suspiciousHours += @(23)   # 11 PM

# Check for activity during unusual hours
$suspiciousTimes = @()
$logNames = @("Security", "Application", "System")
foreach ($logName in $logNames) {
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
}

if ($suspiciousTimes) {
    Write-Alert "Found $($suspiciousTimes.Count) events during suspicious hours (midnight-6AM, 11PM)!"
    $grouped = $suspiciousTimes | 
        Group-Object { $_.TimeCreated.ToString("yyyy-MM-dd HH:00") } |
        Sort-Object Name
    
    $out = "Events by hour during suspicious times:`r`n"
    $grouped | ForEach-Object {
        $out += "$($_.Name): $($_.Count) events`r`n"
        
        # Show some sample events from this hour
        $samples = $_.Group | 
            Where-Object { $_.ProviderName -notmatch "Microsoft-Windows-(Kernel|Security-SPP|Time-Service)" } |
            Select-Object -First 3
        
        if ($samples) {
            $samples | ForEach-Object {
                $out += "  - $($_.TimeCreated.ToString("HH:mm:ss")): $($_.ProviderName) (ID: $($_.Id))`r`n"
            }
        }
    }
    Write-Host $out
    Write-Output $out
}

# ------------------------------------------------------------------------
# ELEVATION SERVICE ANALYSIS
# ------------------------------------------------------------------------
Write-Section "Elevation Service Deep Dive" "Red"

# Check elevation service activity
$elevationEvents = @()
foreach ($logName in @("Security", "Application")) {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = $logName
        StartTime = $StartTime
        EndTime = $EndTime
    } -MaxEvents 1000 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match "elevation_service|elevation service" }
    
    if ($events) {
        $elevationEvents += $events
    }
}

if ($elevationEvents) {
    $out = "Elevation Service Activity Timeline:`r`n"
    $out += $elevationEvents |
        Select-Object TimeCreated, Id, LogName, Message |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 20 |
        Format-Table -Wrap -AutoSize |
        Out-String
    Write-Host $out
    Write-Output $out
}

# ------------------------------------------------------------------------
# BOOT SEQUENCE ANALYSIS
# ------------------------------------------------------------------------
Write-Section "System Boot/Restart Analysis"

# Find recent boot events
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
        
        $out = "Boot Sequence Events:`r`n"
        $out += $bootEvents |
            Where-Object { $_.TimeCreated -ge $bootWindowStart -and $_.TimeCreated -le $bootWindowEnd } |
            Select-Object TimeCreated, Id, Message |
            Format-Table -Wrap -AutoSize |
            Out-String
        Write-Host $out
        Write-Output $out
        
        # Check what ran after boot
        $postBootPrefetch = $allPrefetch | 
            Where-Object { 
                $_.LastRunTime -gt $lastBoot.TimeCreated -and 
                $_.LastRunTime -lt $lastBoot.TimeCreated.AddMinutes(30)
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
} else {
    $out = "No boot events found in the last 24 hours.`r`n"
    Write-Host $out
    Write-Output $out
}

# ------------------------------------------------------------------------
# CORRELATION ANALYSIS
# ------------------------------------------------------------------------
Write-Section "Suspicious Pattern Correlation"

# Find processes that elevated around the same time
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
    $out = "Time windows with high activity (potential automated behavior):`r`n"
    $suspiciousWindows | ForEach-Object {
        $out += "$($_.Key): $($_.Value.Count) events`r`n"
    }
    Write-Host $out
    Write-Output $out
}

# ------------------------------------------------------------------------
# COMPREHENSIVE SCHEDULED TASKS ANALYSIS
# ------------------------------------------------------------------------
Write-Section "Comprehensive Scheduled Tasks Analysis" "Yellow"

Write-Host "Gathering all scheduled tasks that ran in the last 24 hours..." -ForegroundColor Cyan

# Get ALL scheduled tasks
$allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue

# Filter for tasks that ran in last 24 hours
$last24HoursTasks = @()
foreach ($task in $allTasks) {
    $taskInfo = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
    if ($taskInfo -and $taskInfo.LastRunTime -gt $StartTime) {
        $last24HoursTasks += [PSCustomObject]@{
            Task = $task
            Info = $taskInfo
            FullPath = "$($task.TaskPath)$($task.TaskName)"
        }
    }
}

if ($last24HoursTasks) {
    Write-Host "Found $($last24HoursTasks.Count) scheduled tasks that ran in the last 24 hours" -ForegroundColor Yellow
    
    # Group by task path to see patterns
    $out = "`r`nScheduled Tasks by Path:`r`n"
    $tasksByPath = $last24HoursTasks | Group-Object { $_.Task.TaskPath } | Sort-Object Name
    
    foreach ($pathGroup in $tasksByPath) {
        $out += "`r`n$($pathGroup.Name) ($($pathGroup.Count) tasks):`r`n"
        foreach ($taskObj in $pathGroup.Group) {
            $out += "  - $($taskObj.Task.TaskName) [Last run: $($taskObj.Info.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss"))]`r`n"
        }
    }
    Write-Host $out
    Write-Output $out
    
    # Detailed analysis of non-Microsoft tasks
    $nonMsTasks = $last24HoursTasks | Where-Object { $_.Task.TaskPath -notmatch "^\\Microsoft\\" }
    
    if ($nonMsTasks) {
        Write-Alert "Found $($nonMsTasks.Count) non-Microsoft tasks that ran in last 24 hours!"
        $out = "`r`nNon-Microsoft Tasks (DETAILED ANALYSIS):`r`n"
        $out += "=" * 100 + "`r`n"
        
        foreach ($taskObj in $nonMsTasks) {
            $task = $taskObj.Task
            $taskInfo = $taskObj.Info
            $taskDetail = Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            
            $out += "`r`nFull Path: $($taskObj.FullPath)`r`n"
            $out += "State: $($task.State)`r`n"
            $out += "Last Run: $($taskInfo.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss"))`r`n"
            $out += "Next Run: $(if ($taskInfo.NextRunTime) { $taskInfo.NextRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Not scheduled" })`r`n"
            $out += "Last Result: 0x$("{0:X8}" -f $taskInfo.LastTaskResult) $(if ($taskInfo.LastTaskResult -eq 0) { "(Success)" } else { "(Error)" })`r`n"
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
                $out += "[SUSPICIOUS] Reasons: $($suspiciousReasons -join '; ')`r`n"
            }
            
            $out += "-" * 100 + "`r`n"
        }
        Write-Host $out
        Write-Output $out
    }
    
    # Tasks that ran during suspicious hours - FIXED VERSION
    $suspiciousTimeTasks = $last24HoursTasks | Where-Object {
        if ($null -ne $_.Info.LastRunTime -and $_.Info.LastRunTime -is [DateTime]) {
            $hour = [int]$_.Info.LastRunTime.Hour
            $hour -in @(0, 1, 2, 3, 4, 5, 6, 23)
        } else {
            $false
        }
    }
    
    if ($suspiciousTimeTasks) {
        Write-Alert "Found $($suspiciousTimeTasks.Count) tasks that ran during suspicious hours (11PM-6AM)!"
        $out = "`r`nTasks Run During Suspicious Hours:`r`n"
        $out += $suspiciousTimeTasks | ForEach-Object {
            [PSCustomObject]@{
                "Time" = $_.Info.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss")
                "Full Path" = $_.FullPath
                "Execute" = if ($_.Task | Get-ScheduledTask) { 
                    $actions = ($_.Task | Get-ScheduledTask).Actions
                    if ($actions) {
                        ($actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
                    } else { "Unknown" }
                } else { "Unknown" }
            }
        } | Sort-Object Time | Format-Table -Property * -Wrap -AutoSize | Out-String
        Write-Host $out
        Write-Output $out
    }
    
} else {
    $out = "No scheduled tasks found that ran in the last 24 hours.`r`n"
    Write-Host $out
    Write-Output $out
}

# ------------------------------------------------------------------------
# SECURITY VERIFICATION CHECKS
# ------------------------------------------------------------------------
Write-Section "Security Verification Checks" "Magenta"

# 1. Check for persistence mechanisms
Write-Host "`nChecking WMI Startup Commands..." -ForegroundColor Yellow
$startupCommands = Get-WmiObject Win32_StartupCommand -ErrorAction SilentlyContinue | 
    Select-Object Name, Command, Location, User

if ($startupCommands) {
    $out = "WMI Startup Commands Found:`r`n"
    $out += $startupCommands | Format-Table -Wrap -AutoSize | Out-String
    
    # Flag suspicious entries
    $suspicious = $startupCommands | Where-Object { 
        $_.Command -match "(powershell|cmd|wscript|cscript|mshta|rundll32)" -or
        $_.Command -match "\.(ps1|bat|vbs|js|hta)" -or
        $_.Location -match "Temp|AppData|ProgramData"
    }
    
    if ($suspicious) {
        Write-Alert "Found $($suspicious.Count) potentially suspicious startup commands!"
        $out += "`r`nSUSPICIOUS ENTRIES:`r`n"
        $out += $suspicious | Format-Table -Wrap -AutoSize | Out-String
    }
} else {
    $out = "No WMI startup commands found.`r`n"
}
Write-Host $out
Write-Output $out

# 2. Check scheduled tasks created in last 24 hours
Write-Host "`nChecking Recently Created Scheduled Tasks..." -ForegroundColor Yellow
$recentTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { 
    $taskInfo = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
    $taskInfo -and $taskInfo.LastRunTime -gt $StartTime
}

if ($recentTasks) {
    $out = "Recently Active Scheduled Tasks (Full Details):`r`n"
    $out += "=" * 100 + "`r`n"
    
    # Process each task individually to show full details
    foreach ($task in $recentTasks) {
        $taskInfo = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        $taskDetail = Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
        
        $out += "`r`nTask Name: $($task.TaskName)`r`n"
        $out += "Full Path: $($task.TaskPath)$($task.TaskName)`r`n"
        $out += "State: $($task.State)`r`n"
        $out += "Last Run: $($taskInfo.LastRunTime)`r`n"
        $out += "Next Run: $($taskInfo.NextRunTime)`r`n"
        
        # Get action details
        if ($taskDetail.Actions) {
            $out += "Actions:`r`n"
            foreach ($action in $taskDetail.Actions) {
                $out += "  - Execute: $($action.Execute)`r`n"
                if ($action.Arguments) {
                    $out += "    Arguments: $($action.Arguments)`r`n"
                }
                if ($action.WorkingDirectory) {
                    $out += "    Working Dir: $($action.WorkingDirectory)`r`n"
                }
            }
        }
        
        # Get trigger details
        if ($taskDetail.Triggers) {
            $out += "Triggers:`r`n"
            foreach ($trigger in $taskDetail.Triggers) {
                $out += "  - Type: $($trigger.CimClass.CimClassName -replace 'MSFT_TaskTrigger','')`r`n"
                if ($trigger.StartBoundary) {
                    $out += "    Start: $($trigger.StartBoundary)`r`n"
                }
            }
        }
        
        # Check if suspicious
        $isSuspicious = $false
        if ($task.TaskPath -notmatch "^\\Microsoft\\Windows\\" -or
            $task.TaskName -match "(update|install|elevation|admin)" -or
            ($taskDetail.Actions.Execute -match "(powershell|cmd|wscript|cscript|mshta|rundll32)") -or
            ($taskDetail.Actions.Execute -match "(\\temp\\|\\appdata\\|\\users\\)")) {
            $isSuspicious = $true
            $out += "[SUSPICIOUS] This task has suspicious characteristics!`r`n"
        }
        
        $out += "-" * 100 + "`r`n"
    }
    
    # Summary table with full paths
    $out += "`r`nScheduled Tasks Summary Table:`r`n"
    $taskSummary = $recentTasks | ForEach-Object {
        $taskInfo = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            "Full Path" = "$($_.TaskPath)$($_.TaskName)"
            "State" = $_.State
            "Last Run" = if ($taskInfo.LastRunTime) { $taskInfo.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
            "Next Run" = if ($taskInfo.NextRunTime) { $taskInfo.NextRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Not scheduled" }
        }
    }
    
    $out += $taskSummary | Format-Table -Property * -Wrap -AutoSize | Out-String
    
    # Check for suspicious tasks
    $suspiciousTasks = $recentTasks | Where-Object {
        $_.TaskName -match "(update|install|elevation|admin)" -and
        $_.TaskPath -notmatch "^\\Microsoft\\Windows\\"
    }
    
    if ($suspiciousTasks) {
        Write-Alert "Found potentially suspicious scheduled tasks!"
        $out += "`r`nSUSPICIOUS TASKS DETAIL:`r`n"
        foreach ($task in $suspiciousTasks) {
            $taskDetail = Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            $out += "`r`nSuspicious Task: $($task.TaskPath)$($task.TaskName)`r`n"
            if ($taskDetail.Actions) {
                foreach ($action in $taskDetail.Actions) {
                    $out += "Executes: $($action.Execute) $($action.Arguments)`r`n"
                }
            }
        }
    }
} else {
    $out = "No recently active scheduled tasks found.`r`n"
}
Write-Host $out
Write-Output $out

# 3. Verify ELEVATION_SERVICE.EXE legitimacy
Write-Host "`nVerifying ELEVATION_SERVICE.EXE..." -ForegroundColor Yellow
$elevationPaths = @(
    "C:\Windows\System32\elevation_service.exe",
    "C:\Windows\SysWOW64\elevation_service.exe",
    "C:\Program Files\WindowsApps\Microsoft.WindowsStore*\elevation_service.exe"
)

$out = "Checking ELEVATION_SERVICE.EXE locations and hashes:`r`n"
$foundElevation = $false

foreach ($path in $elevationPaths) {
    $files = Get-ChildItem -Path $path -ErrorAction SilentlyContinue -Force
    foreach ($file in $files) {
        $foundElevation = $true
        $hash = Get-FileHash $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
        $signature = Get-AuthenticodeSignature $file.FullName -ErrorAction SilentlyContinue
        
        $out += "`r`nFile: $($file.FullName)`r`n"
        $out += "  SHA256: $($hash.Hash)`r`n"
        $out += "  Size: $($file.Length) bytes`r`n"
        $out += "  Created: $($file.CreationTime)`r`n"
        $out += "  Modified: $($file.LastWriteTime)`r`n"
        $out += "  Signature Status: $($signature.Status)`r`n"
        $out += "  Signer: $($signature.SignerCertificate.Subject)`r`n"
        
        # Check if legitimate Microsoft signature
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or $signature.SignerCertificate.Subject -notmatch "Microsoft") {
            Write-Alert "ELEVATION_SERVICE.EXE has invalid or non-Microsoft signature!"
        }
    }
}

if (-not $foundElevation) {
    $out += "ELEVATION_SERVICE.EXE not found in standard locations.`r`n"
    # Search for it elsewhere
    Write-Host "Searching system for elevation_service.exe..." -ForegroundColor Yellow
    $searchResults = Get-ChildItem -Path C:\ -Filter "elevation_service.exe" -Recurse -ErrorAction SilentlyContinue -Force | Select-Object -First 5
    
    if ($searchResults) {
        Write-Alert "Found elevation_service.exe in non-standard locations!"
        $out += "`r`nFound in non-standard locations:`r`n"
        $searchResults | ForEach-Object {
            $out += "  $($_.FullName)`r`n"
        }
    }
}
Write-Host $out
Write-Output $out

# 4. Check for unusual/suspicious services
Write-Host "`nChecking Running Services..." -ForegroundColor Yellow
$allRunningServices = @()
$services = Get-Service | Where-Object { $_.Status -eq "Running" }
foreach ($svc in $services) {
    if ($svc.StartType -eq "Automatic") {
        $allRunningServices += $svc
    }
}

$suspiciousServices = @()

foreach ($service in $allRunningServices) {
    $isSuspicious = $false
    
    # Check display name patterns
    if ($service.DisplayName -match "(elevation|update|installer|admin)") {
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
    
    if ($isSuspicious) {
        # Get the service path
        $serviceWmi = Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
        $suspiciousServices += [PSCustomObject]@{
            Name = $service.Name
            DisplayName = $service.DisplayName
            PathName = if ($serviceWmi) { $serviceWmi.PathName } else { "Unknown" }
        }
    }
}

if ($suspiciousServices) {
    $out = "Potentially Suspicious Running Services:`r`n"
    $out += "=" * 100 + "`r`n"
    
    # Show detailed info for each suspicious service
    foreach ($service in $suspiciousServices) {
        $out += "`r`nService Name: $($service.Name)`r`n"
        $out += "Display Name: $($service.DisplayName)`r`n"
        $out += "Full Path: $($service.PathName)`r`n"
        
        # Check if running from suspicious location
        if ($service.PathName -match "(\\temp\\|\\appdata\\|\\programdata\\|\\users\\[^\\]+\\)") {
            $out += "[WARNING] Running from suspicious location!`r`n"
        }
        $out += "-" * 100 + "`r`n"
    }
    
    # Summary table
    $out += "`r`nSuspicious Services Summary:`r`n"
    $out += $suspiciousServices | Format-Table -Property Name, DisplayName, @{Name="Path";Expression={$_.PathName}} -Wrap -AutoSize | Out-String
    
    # Check for services running from temp/appdata
    $tempServices = $suspiciousServices | Where-Object {
        $_.PathName -match "(Temp|AppData|ProgramData|Users\\[^\\]+\\[^\\]+\\)"
    }
    
    if ($tempServices) {
        Write-Alert "Found services running from temporary/user locations!"
        $out += "`r`nHIGH RISK - Services from temp/user folders:`r`n"
        foreach ($svc in $tempServices) {
            $out += "  - $($svc.Name): $($svc.PathName)`r`n"
        }
    }
} else {
    $out = "No obviously suspicious services found.`r`n"
}
Write-Host $out
Write-Output $out

# 5. Check for active network connections from suspicious processes
Write-Host "`nChecking Network Connections..." -ForegroundColor Yellow
$netConnections = netstat -anob 2>$null | Select-String -Pattern "ESTABLISHED|LISTENING" -Context 0,1
$suspiciousConnections = @()

foreach ($conn in $netConnections) {
    $line = $conn.Line
    if ($conn.Context.PostContext -match "\[(.*?)\]") {
        $process = $matches[1]
        if ($process -match "(elevation|msiexec|wusa|rundll32|powershell|cmd)") {
            $suspiciousConnections += "$line - Process: $process"
        }
    }
}

if ($suspiciousConnections) {
    Write-Alert "Found network connections from potentially suspicious processes!"
    $out = "Suspicious Network Connections:`r`n"
    $suspiciousConnections | ForEach-Object {
        $out += "  $_`r`n"
    }
} else {
    $out = "No suspicious network connections detected.`r`n"
}
Write-Host $out
Write-Output $out

# 6. Quick malware scan of recent files
Write-Host "`nChecking Recently Modified Executables..." -ForegroundColor Yellow
$recentExes = Get-ChildItem -Path @("C:\Windows\Temp", "$env:TEMP", "$env:APPDATA") -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt $StartTime } |
    Select-Object FullName, Length, LastWriteTime, CreationTime

if ($recentExes) {
    Write-Alert "Found recently modified executables in temp/appdata locations!"
    $out = "Recent Executables in Suspicious Locations:`r`n"
    $out += $recentExes | Format-Table -AutoSize | Out-String
} else {
    $out = "No recent executables found in temp locations.`r`n"
}
Write-Host $out
Write-Output $out

# ------------------------------------------------------------------------
# 7) RunOnce registry entries
# ------------------------------------------------------------------------
Write-Section "RunOnce Registry Entries"
$rk1 = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue
$rk2 = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue

if ($rk1 -or $rk2) {
  $out = "HKLM RunOnce:`r`n"
  $out += ($rk1.PSObject.Properties |
           Where-Object {$_.Name -ne "(default)"} |
           ForEach-Object { "$($_.Name) = $($_.Value)" } |
           Out-String)
  $out += "`r`nHKCU RunOnce:`r`n"
  $out += ($rk2.PSObject.Properties |
           Where-Object {$_.Name -ne "(default)"} |
           ForEach-Object { "$($_.Name) = $($_.Value)" } |
           Out-String)
} else {
  $out = "No RunOnce entries in HKLM or HKCU.`r`n"
}
Write-Host $out
Write-Output $out

# ------------------------------------------------------------------------
# 8) Installer scheduled tasks
# ------------------------------------------------------------------------
Write-Section "Scheduled Tasks under Microsoft\Windows\Installer"
try {
  $tasks = Get-ScheduledTask -TaskPath "\Microsoft\Windows\Installer\" -ErrorAction Stop
  
  if ($tasks) {
    $out = "Installer Scheduled Tasks (Full Details):`r`n"
    $out += "=" * 80 + "`r`n"
    
    foreach ($task in $tasks) {
      $taskInfo = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
      
      $out += "`r`nTask: \Microsoft\Windows\Installer\$($task.TaskName)`r`n"
      $out += "State: $($task.State)`r`n"
      $out += "Last Run: $($taskInfo.LastRunTime)`r`n"
      $out += "Next Run: $($taskInfo.NextRunTime)`r`n"
      $out += "Last Result: 0x$("{0:X8}" -f $taskInfo.LastTaskResult)`r`n"
      
      # Get action details
      $taskDetail = Get-ScheduledTask -TaskName $task.TaskName -TaskPath "\Microsoft\Windows\Installer\" -ErrorAction SilentlyContinue
      if ($taskDetail.Actions) {
        $out += "Actions:`r`n"
        foreach ($action in $taskDetail.Actions) {
          $out += "  Execute: $($action.Execute)`r`n"
          if ($action.Arguments) {
            $out += "  Arguments: $($action.Arguments)`r`n"
          }
        }
      }
      $out += "-" * 80 + "`r`n"
    }
    
    # Summary table
    $out += "`r`nInstaller Tasks Summary:`r`n"
    $out += $tasks | ForEach-Object {
      $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
      [PSCustomObject]@{
        "Full Task Path" = "\Microsoft\Windows\Installer\$($_.TaskName)"
        "State" = $_.State
        "Last Run" = if ($info.LastRunTime) { $info.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
        "Next Run" = if ($info.NextRunTime) { $info.NextRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Not scheduled" }
      }
    } | Format-Table -Wrap | Out-String
  } else {
    $out = "No tasks found under \Microsoft\Windows\Installer\`r`n"
  }
} catch {
  $out = "No Installer tasks found or access denied.`r`n"
}
Write-Host $out
Write-Output $out

# ------------------------------------------------------------------------
# 9) Handle/Privilege audit events
# ------------------------------------------------------------------------
Write-Section "Handle/Privilege Audit Events (4656,4663,4670)"
$audits = Get-WinEvent -FilterHashtable @{
  LogName   = "Security"
  StartTime = $StartTime
  EndTime   = $EndTime
} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue |
  Where-Object { $_.Id -in @(4656,4663,4670) }

if ($audits) {
  $filteredAudits = $audits | Where-Object { $_.Message -match "msiexec\.exe" }
  
  if ($filteredAudits) {
    $out = $filteredAudits |
      Select-Object TimeCreated, Id, Message |
      Format-Table -Wrap -AutoSize |
      Out-String
  } else {
    $out = "No handle/privilege events referencing msiexec.exe.`r`n"
  }
} else {
  $out = "No handle/privilege audit events found.`r`n"
}
Write-Host $out
Write-Output $out

# ------------------------------------------------------------------------
# 10) AppLocker audit logs
# ------------------------------------------------------------------------
Write-Section "AppLocker Audit Logs"
$exeLog = "Microsoft-Windows-AppLocker/EXE and DLL"
$msiLog = "Microsoft-Windows-AppLocker/MSI and Script"

foreach ($logName in $exeLog, $msiLog) {
  if ( Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue ) {
    $entries = Get-WinEvent -LogName $logName -ErrorAction SilentlyContinue |
               Where-Object { $_.TimeCreated -ge $StartTime -and $_.TimeCreated -le $EndTime }

    if ($entries) {
      $out = "Entries in $($logName):`r`n" + (
        $entries |
        Select-Object TimeCreated, Id, Message |
        Format-Table -Wrap -AutoSize |
        Out-String
      )
    } else {
      $out = "No entries in $($logName) for time window.`r`n"
    }
  } else {
    $out = "$logName not present on this system.`r`n"
  }

  Write-Host $out
  Write-Output $out
}

# ------------------------------------------------------------------------
# 11) USN Journal info
# ------------------------------------------------------------------------
Write-Section "USN Journal Query (C:)"
try {
  $usn = fsutil usn queryjournal C: 2>&1
  $out = $usn | Out-String
} catch {
  $out = "Failed to query USN Journal on C:.`r`n"
}
Write-Host $out
Write-Output $out

# ------------------------------------------------------------------------
# RECOMMENDATIONS
# ------------------------------------------------------------------------
Write-Section "Security Recommendations" "Green"

$recommendations = "Based on the analysis:

1. IMMEDIATE ACTIONS:
   - Run a full antivirus scan with updated definitions
   - Check Task Scheduler for suspicious tasks created around the flagged times
   - Review installed programs for anything unfamiliar
   - Check running services: Get-Service | Where-Object {\$_.Status -eq 'Running'}

2. SUSPICIOUS INDICATORS FOUND:
   - Check the summary section for specific findings
   - Review any elevation service activity during off-hours
   - Investigate any MSI installations you did not initiate
   - Verify RuntimeBroker elevations

3. FURTHER INVESTIGATION:
   - Check autoruns: https://docs.microsoft.com/sysinternals/downloads/autoruns
   - Review Windows Defender logs
   - Check for unusual network connections: netstat -anob
   - Review scheduled tasks: schtasks /query /fo LIST /v

4. MONITORING:
   - Enable additional auditing for process creation
   - Monitor elevation_service.exe closely
   - Set up alerts for off-hours system activity"

Write-Host $recommendations -ForegroundColor Green
Write-Output $recommendations

# ------------------------------------------------------------------------
# CRITICAL FINDINGS SUMMARY
# ------------------------------------------------------------------------
Write-Section "CRITICAL FINDINGS SUMMARY" "Red"

$summary = "`r`nAutomated Analysis Summary for past 24 hours:`r`n"
$summary += "=" * 60 + "`r`n"

# Count suspicious indicators
$indicators = 0
$suspiciousItems = @()

# Check for elevation service in last 24 hours
if ($allPrefetch | Where-Object { $_.ProcessName -match "elevation_service" }) {
    $elevationCount = ($allPrefetch | Where-Object { $_.ProcessName -match "elevation_service" }).Count
    $summary += "[!] ELEVATION_SERVICE.EXE activity detected - $elevationCount executions`r`n"
    $indicators++
    $suspiciousItems += "ELEVATION_SERVICE.EXE"
}

# Check for off-hours activity
if ($suspiciousTimes -and $suspiciousTimes.Count -gt 50) {
    $summary += "[!] High volume of off-hours activity: $($suspiciousTimes.Count) events`r`n"
    $indicators++
}

# Check for suspicious prefetch activity during off-hours - FIXED VERSION
if ($allPrefetch) {
    $offHoursPrefetch = $allPrefetch | Where-Object {
        if ($null -ne $_.LastRunTime -and $_.LastRunTime -is [DateTime]) {
            $hour = [int]$_.LastRunTime.Hour
            $hour -in @(0, 1, 2, 3, 4, 5, 6, 23) -and $_.LastRunTime -gt $StartTime
        } else {
            $false
        }
    }
    if ($offHoursPrefetch -and $offHoursPrefetch.Count -gt 10) {
        $summary += "[!] Suspicious off-hours program execution: $($offHoursPrefetch.Count) programs`r`n"
        $indicators++
    }
}

# Check for suspicious services
if ($suspiciousServices) {
    $summary += "[!] Suspicious services found: $($suspiciousServices.Count)`r`n"
    $indicators++
    foreach ($svc in $suspiciousServices) {
        $suspiciousItems += "Service: $($svc.Name) - $($svc.PathName)"
    }
}

# Check for suspicious startup items
if ($suspicious) {
    $summary += "[!] Suspicious startup commands found: $($suspicious.Count)`r`n"
    $indicators++
    foreach ($item in $suspicious) {
        $suspiciousItems += "Startup: $($item.Name) - $($item.Command)"
    }
}

# Check for recent executables in temp
if ($recentExes) {
    $summary += "[!] Recent executables in temp/appdata: $($recentExes.Count)`r`n"
    $indicators++
    foreach ($exe in $recentExes) {
        $suspiciousItems += "Recent EXE: $($exe.FullName)"
    }
}

# Check for non-Microsoft scheduled tasks
if ($last24HoursTasks) {
    $nonMsTaskCount = ($last24HoursTasks | Where-Object { $_.Task.TaskPath -notmatch "^\\Microsoft\\" }).Count
    if ($nonMsTaskCount -gt 0) {
        $summary += "[!] Non-Microsoft scheduled tasks active: $nonMsTaskCount`r`n"
        $indicators++
        $last24HoursTasks | Where-Object { $_.Task.TaskPath -notmatch "^\\Microsoft\\" } | ForEach-Object {
            $suspiciousItems += "Task: $($_.FullPath)"
        }
    }
}

# Risk assessment
$summary += "`r`nRISK ASSESSMENT: "
if ($indicators -eq 0) {
    $summary += "LOW - No major indicators found`r`n"
    Write-Host $summary -ForegroundColor Green
} elseif ($indicators -le 2) {
    $summary += "MEDIUM - Some suspicious activity detected`r`n"
    Write-Host $summary -ForegroundColor Yellow
} else {
    $summary += "HIGH - Multiple suspicious indicators present!`r`n"
    Write-Host $summary -ForegroundColor Red
}

$summary += "`r`nTotal suspicious indicators: $indicators`r`n"
$summary += "Report generated: $(Get-Date)`r`n"
$summary += "Time window analyzed: $StartTime to $EndTime`r`n"

# List all suspicious items with full paths
if ($suspiciousItems) {
    $summary += "`r`nSUSPICIOUS ITEMS FOUND (Full Paths):`r`n"
    $summary += "=" * 60 + "`r`n"
    foreach ($item in $suspiciousItems) {
        $summary += "  - $item`r`n"
    }
}

Write-Output $summary

# Footer
$footer = "`r`n=== End of Enhanced Report - Check $OutputPath for full details ===`r`n"
Write-Host $footer -ForegroundColor Cyan
Write-Output $footer

# Open the report
Write-Host "`r`nOpening report in Notepad..." -ForegroundColor Green
Start-Process notepad $OutputPath
