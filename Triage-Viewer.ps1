# INCIDENT RESPONSE DATA VIEWER v2.0 - FULLY CORRECTED
# Purpose: View and export data collected by the IR triage script
# No live data collection - only reads existing incident directories
# Usage: powershell -ExecutionPolicy Bypass -File .\IR_Viewer.ps1

param(
    [string]$Path = "",
    [int]$PageSize = 25
)

# Initialize
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$Host.UI.RawUI.WindowTitle = "IR Data Viewer v2.0"

# Colors
$colors = @{
    Header = "Cyan"
    Critical = "Red"
    High = "Magenta"
    Medium = "Yellow" 
    Low = "Green"
    Info = "White"
    Data = "Gray"
    Menu = "DarkCyan"
    Progress = "DarkGray"
    Success = "Green"
    Warning = "DarkYellow"
}

# Display header
function Show-Header {
    param([string]$Title = "INCIDENT RESPONSE DATA VIEWER v2.0")
    Clear-Host
    Write-Host ("=" * 80) -ForegroundColor $colors.Header
    Write-Host $Title.PadLeft(40 + ($Title.Length / 2)) -ForegroundColor $colors.Header
    Write-Host ("=" * 80) -ForegroundColor $colors.Header
    Write-Host ""
}

# Find incident directories with enhanced info
function Select-IncidentDirectory {
    Show-Header "SELECT INCIDENT DIRECTORY"
    
    # Search multiple locations
    $searchPaths = @(
        (Get-Location).Path,
        "C:\",
        "D:\",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:TEMP"
    )
    
    $allIncidents = @()
    Write-Host "Searching for incident directories..." -ForegroundColor $colors.Info
    
    foreach ($searchPath in $searchPaths) {
        if (Test-Path $searchPath) {
            Write-Host "." -NoNewline -ForegroundColor $colors.Progress
            $incidents = Get-ChildItem -Path $searchPath -Filter "incident_*" -Directory -ErrorAction SilentlyContinue -Depth 2
            if ($incidents) {
                $allIncidents += $incidents
            }
        }
    }
    
    Write-Host ""
    
    if ($allIncidents.Count -eq 0) {
        Write-Host "`nNo incident directories found!" -ForegroundColor $colors.Critical
        Write-Host "Searched in: $($searchPaths -join ', ')" -ForegroundColor $colors.Data
        Read-Host "`nPress Enter to exit"
        return $null
    }
    
    # Remove duplicates and sort by date
    $allIncidents = $allIncidents | Sort-Object -Property FullName -Unique | Sort-Object CreationTime -Descending
    
    Write-Host "`nFound $($allIncidents.Count) incident directories:" -ForegroundColor $colors.Success
    Write-Host ""
    
    # Create detailed incident list
    $incidentDetails = @()
    
    Write-Host "Analyzing incidents..." -ForegroundColor $colors.Progress
    foreach ($inc in $allIncidents) {
        Write-Host "." -NoNewline -ForegroundColor $colors.Progress
        
        $details = [PSCustomObject]@{
            Path = $inc.FullName
            Name = $inc.Name
            Created = $inc.CreationTime
            ThreatLevel = "Unknown"
            AlertCount = 0
            SizeMB = 0
            HasAlerts = $false
            HasNetwork = $false
            HasLogs = $false
        }
        
        # Get threat level and alerts from summary
        $summaryPath = Join-Path $inc.FullName "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryContent = Get-Content $summaryPath -ErrorAction SilentlyContinue
            $threatLine = $summaryContent | Select-String "THREAT LEVEL:" | Select-Object -First 1
            if ($threatLine) {
                $details.ThreatLevel = $threatLine.Line.Split(":")[1].Trim()
            }
            $alertLine = $summaryContent | Select-String "TOTAL ALERTS:" | Select-Object -First 1
            if ($alertLine) {
                $details.AlertCount = [int]($alertLine.Line.Split(":")[1].Trim())
            }
        }
        
        # Check for key directories
        $details.HasAlerts = Test-Path (Join-Path $inc.FullName "ALERTS")
        $details.HasNetwork = Test-Path (Join-Path $inc.FullName "Network")
        $details.HasLogs = Test-Path (Join-Path $inc.FullName "Logs")
        
        # Calculate size
        try {
            $details.SizeMB = [Math]::Round((Get-ChildItem $inc.FullName -Recurse -File | Measure-Object Length -Sum).Sum/1MB, 2)
        } catch {
            $details.SizeMB = 0
        }
        
        $incidentDetails += $details
    }
    
    Write-Host "`n`n"
    
    # Display header
    Write-Host "  #  Incident Name                    Threat     Alerts  Size      Created" -ForegroundColor $colors.Header
    Write-Host "  -  ------------------------------    ---------  ------  --------  ----------------" -ForegroundColor $colors.Menu
    
    # Display incidents with details
    for ($i = 0; $i -lt $incidentDetails.Count; $i++) {
        $inc = $incidentDetails[$i]
        
        # Determine color based on threat level
        $threatColor = switch ($inc.ThreatLevel) {
            "CRITICAL" { $colors.Critical }
            "HIGH" { $colors.High }
            "MEDIUM" { $colors.Medium }
            "LOW" { $colors.Low }
            default { $colors.Data }
        }
        
        # Format line
        Write-Host ("{0,3}  " -f ($i + 1)) -NoNewline -ForegroundColor $colors.Menu
        Write-Host ("{0,-32}  " -f $inc.Name) -NoNewline -ForegroundColor $colors.Info
        Write-Host ("{0,-9}  " -f $inc.ThreatLevel) -NoNewline -ForegroundColor $threatColor
        Write-Host ("{0,6}  " -f $inc.AlertCount) -NoNewline -ForegroundColor $(if($inc.AlertCount -gt 0){$colors.Warning}else{$colors.Data})
        Write-Host ("{0,6}MB  " -f $inc.SizeMB) -NoNewline -ForegroundColor $colors.Data
        Write-Host ("{0}" -f $inc.Created.ToString("yyyy-MM-dd HH:mm")) -ForegroundColor $colors.Data
        
        # Show indicators
        if ($inc.HasAlerts -or $inc.HasNetwork -or $inc.HasLogs) {
            Write-Host "     +- " -NoNewline -ForegroundColor $colors.Menu
            if ($inc.HasAlerts) { Write-Host "[ALERTS]" -NoNewline -ForegroundColor $colors.High }
            if ($inc.HasNetwork) { Write-Host "[NETWORK]" -NoNewline -ForegroundColor $colors.Info }
            if ($inc.HasLogs) { Write-Host "[LOGS]" -NoNewline -ForegroundColor $colors.Warning }
            Write-Host ""
        }
    }
    
    Write-Host "`n" -NoNewline
    $selection = Read-Host "Select incident number (1-$($incidentDetails.Count)) or Q to quit"
    
    if ($selection -match '^[Qq]') {
        return $null
    }
    
    if ($selection -match '^\d+$') {
        $index = [int]$selection - 1
        if ($index -ge 0 -and $index -lt $incidentDetails.Count) {
            return $incidentDetails[$index].Path
        }
    }
    
    Write-Host "Invalid selection!" -ForegroundColor $colors.Critical
    Start-Sleep -Seconds 2
    return Select-IncidentDirectory
}

# Read and format CSV files with enhanced options
function Show-CsvFile {
    param([string]$FilePath)
    
    try {
        Write-Host "Loading CSV data..." -ForegroundColor $colors.Info
        $data = Import-Csv $FilePath
        
        if ($data.Count -eq 0) {
            return @("No data in CSV file")
        }
        
        $output = @()
        $output += "CSV File: $(Split-Path $FilePath -Leaf)"
        $output += "Total Records: $($data.Count)"
        $output += "Columns: $($data[0].PSObject.Properties.Name -join ', ')"
        $output += ("=" * 60)
        $output += ""
        
        # Ask if user wants to filter for large datasets
        if ($data.Count -gt 50) {
            Write-Host "Large dataset detected. Options:" -ForegroundColor $colors.Info
            Write-Host "1. View all records" -ForegroundColor $colors.Menu
            Write-Host "2. View first 50 records" -ForegroundColor $colors.Menu
            Write-Host "3. Search/filter records" -ForegroundColor $colors.Menu
            Write-Host "4. View summary only" -ForegroundColor $colors.Menu
            Write-Host "5. Export to separate file" -ForegroundColor $colors.Menu
            
            $viewChoice = Read-Host "Select option (1-5)"
            
            switch ($viewChoice) {
                "2" { 
                    $data = $data | Select-Object -First 50
                    $output += "Showing first 50 records"
                    $output += ""
                }
                "3" {
                    Write-Host "Available columns:" -ForegroundColor $colors.Info
                    $data[0].PSObject.Properties.Name | ForEach-Object { Write-Host "  - $_" -ForegroundColor $colors.Data }
                    
                    $column = Read-Host "Enter column name to search"
                    $searchValue = Read-Host "Enter search value (supports wildcards)"
                    
                    $filtered = $data | Where-Object { $_.$column -like "*$searchValue*" }
                    $output += "Filtered Results: $($filtered.Count) records matching '$searchValue' in column '$column'"
                    $output += ""
                    $data = $filtered
                }
                "4" {
                    # Just show summary statistics
                    $output += "Summary Statistics:"
                    foreach ($prop in $data[0].PSObject.Properties.Name) {
                        $values = $data.$prop | Where-Object { $_ -ne "" -and $_ -ne $null }
                        $unique = $values | Select-Object -Unique
                        $output += ""
                        $output += "Column: $prop"
                        $output += "  - Non-empty values: $($values.Count)"
                        $output += "  - Unique values: $($unique.Count)"
                        if ($unique.Count -le 10 -and $unique.Count -gt 0) {
                            $output += "  - Values: $($unique -join ', ')"
                        }
                        elseif ($unique.Count -gt 10) {
                            $output += "  - Sample values: $(($unique | Select-Object -First 5) -join ', ')..."
                        }
                    }
                    return $output
                }
                "5" {
                    $exportPath = Join-Path ([System.IO.Path]::GetTempPath()) "CSV_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                    $data | Export-Csv $exportPath -NoTypeInformation
                    $output += "Data exported to: $exportPath"
                    return $output
                }
            }
        }
        
        # Format each record
        $recordNum = 1
        foreach ($record in $data) {
            $output += "----- Record $recordNum -----"
            foreach ($prop in $record.PSObject.Properties) {
                if ($prop.Value) {
                    # Truncate long values
                    $value = if ($prop.Value.Length -gt 100) {
                        $prop.Value.Substring(0, 97) + "..."
                    } else {
                        $prop.Value
                    }
                    $output += "  $($prop.Name): $value"
                }
            }
            $output += ""
            $recordNum++
        }
        
        return $output
    }
    catch {
        return @("Error reading CSV: $_")
    }
}

# Read and format JSON files
function Show-JsonFile {
    param([string]$FilePath)
    
    try {
        $jsonContent = Get-Content $FilePath -Raw
        $jsonObject = $jsonContent | ConvertFrom-Json
        
        # Convert to formatted string
        $formatted = $jsonObject | ConvertTo-Json -Depth 10
        return $formatted -split "`n"
    }
    catch {
        return @("Error reading JSON: $_")
    }
}

# Enhanced event log parsing with full options
function Show-EventLog {
    param([string]$FilePath)
    
    Write-Host "Loading event log..." -ForegroundColor $colors.Info
    
    try {
        # Get total event count first
        Write-Host "Checking event log size..." -ForegroundColor $colors.Progress
        $totalCount = (Get-WinEvent -Path $FilePath -MaxEvents 1 -ErrorAction Stop).Count
        
        # Ask user how many events to load
        Write-Host "Event log options:" -ForegroundColor $colors.Info
        Write-Host "1. First 100 events (newest)" -ForegroundColor $colors.Menu
        Write-Host "2. Last 100 events (oldest)" -ForegroundColor $colors.Menu
        Write-Host "3. First 500 events" -ForegroundColor $colors.Menu
        Write-Host "4. First 1000 events" -ForegroundColor $colors.Menu
        Write-Host "5. All events (may take time and memory)" -ForegroundColor $colors.Menu
        Write-Host "6. Custom range" -ForegroundColor $colors.Menu
        Write-Host "7. Filter by criteria" -ForegroundColor $colors.Menu
        
        $choice = Read-Host "Select option (1-7)"
        
        $events = switch ($choice) {
            "1" { Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop }
            "2" { Get-WinEvent -Path $FilePath -MaxEvents 100 -Oldest -ErrorAction Stop }
            "3" { Get-WinEvent -Path $FilePath -MaxEvents 500 -ErrorAction Stop }
            "4" { Get-WinEvent -Path $FilePath -MaxEvents 1000 -ErrorAction Stop }
            "5" { 
                Write-Host "WARNING: Loading all events may use significant memory!" -ForegroundColor $colors.Warning
                $confirm = Read-Host "Continue? (Y/N)"
                if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                    Write-Host "Loading all events... This may take several minutes." -ForegroundColor $colors.Info
                    Get-WinEvent -Path $FilePath -ErrorAction Stop 
                } else {
                    Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop
                }
            }
            "6" {
                $maxEvents = Read-Host "Enter number of events to load"
                if ($maxEvents -match '^\d+$') {
                    Get-WinEvent -Path $FilePath -MaxEvents ([int]$maxEvents) -ErrorAction Stop
                } else {
                    Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop
                }
            }
            "7" {
                Write-Host "Filter options:" -ForegroundColor $colors.Menu
                Write-Host "1. By Level (Error/Warning/Info)" -ForegroundColor $colors.Menu
                Write-Host "2. By Event ID" -ForegroundColor $colors.Menu
                Write-Host "3. By Time Range" -ForegroundColor $colors.Menu
                Write-Host "4. By Provider/Source" -ForegroundColor $colors.Menu
                
                $filterType = Read-Host "Select filter type (1-4)"
                
                $filterTable = @{LogName='*'}
                
                switch ($filterType) {
                    "1" {
                        Write-Host "Select level:" -ForegroundColor $colors.Menu
                        Write-Host "1. Critical (1)" -ForegroundColor $colors.Menu
                        Write-Host "2. Error (2)" -ForegroundColor $colors.Menu
                        Write-Host "3. Warning (3)" -ForegroundColor $colors.Menu
                        Write-Host "4. Information (4)" -ForegroundColor $colors.Menu
                        Write-Host "5. Critical + Error" -ForegroundColor $colors.Menu
                        
                        $levelChoice = Read-Host "Select level"
                        switch ($levelChoice) {
                            "1" { $filterTable['Level'] = 1 }
                            "2" { $filterTable['Level'] = 2 }
                            "3" { $filterTable['Level'] = 3 }
                            "4" { $filterTable['Level'] = 4 }
                            "5" { $filterTable['Level'] = @(1,2) }
                        }
                    }
                    "2" {
                        $eventId = Read-Host "Enter Event ID"
                        if ($eventId -match '^\d+$') {
                            $filterTable['ID'] = [int]$eventId
                        }
                    }
                    "3" {
                        $hours = Read-Host "Events from last X hours"
                        if ($hours -match '^\d+$') {
                            $filterTable['StartTime'] = (Get-Date).AddHours(-[int]$hours)
                        }
                    }
                    "4" {
                        $provider = Read-Host "Enter Provider/Source name (or partial)"
                        $filterTable['ProviderName'] = $provider + '*'
                    }
                }
                
                Get-WinEvent -Path $FilePath -FilterHashtable $filterTable -ErrorAction Stop
            }
            default { Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop }
        }
        
        Write-Host "Processing $($events.Count) events..." -ForegroundColor $colors.Info
        
        $output = @()
        $output += "Event Log: $(Split-Path $FilePath -Leaf)"
        $output += "Total Events Loaded: $($events.Count)"
        $output += ("=" * 60)
        $output += ""
        
        # Add additional filter option after loading
        Write-Host "Apply additional filter? (Y/N)" -NoNewline -ForegroundColor $colors.Info
        $filter = Read-Host
        
        if ($filter -eq 'Y' -or $filter -eq 'y') {
            Write-Host "Filter by:" -ForegroundColor $colors.Menu
            Write-Host "1. Error/Critical only" -ForegroundColor $colors.Menu
            Write-Host "2. Specific Event ID" -ForegroundColor $colors.Menu
            Write-Host "3. Time range" -ForegroundColor $colors.Menu
            Write-Host "4. Keyword in message" -ForegroundColor $colors.Menu
            Write-Host "5. No filter" -ForegroundColor $colors.Menu
            
            $filterChoice = Read-Host "Select filter (1-5)"
            
            $events = switch ($filterChoice) {
                "1" { $events | Where-Object { $_.Level -le 2 } }
                "2" {
                    $eventId = Read-Host "Enter Event ID"
                    if ($eventId -match '^\d+$') {
                        $events | Where-Object { $_.Id -eq [int]$eventId }
                    } else { $events }
                }
                "3" {
                    $hours = Read-Host "Events from last X hours"
                    if ($hours -match '^\d+$') {
                        $cutoff = (Get-Date).AddHours(-[int]$hours)
                        $events | Where-Object { $_.TimeCreated -gt $cutoff }
                    } else { $events }
                }
                "4" {
                    $keyword = Read-Host "Enter keyword to search in messages"
                    $events | Where-Object { $_.Message -match $keyword }
                }
                default { $events }
            }
            
            $output += "Filtered Events: $($events.Count)"
            $output += ""
        }
        
        # Option for summary view or detailed view
        Write-Host "View mode:" -ForegroundColor $colors.Menu
        Write-Host "1. Detailed (full messages)" -ForegroundColor $colors.Menu
        Write-Host "2. Summary (truncated messages)" -ForegroundColor $colors.Menu
        Write-Host "3. Statistics only" -ForegroundColor $colors.Menu
        
        $viewMode = Read-Host "Select view mode (1-3)"
        
        if ($viewMode -eq "3") {
            # Statistics only
            $output += "EVENT STATISTICS"
            $output += "-" * 40
            
            $levelGroups = $events | Group-Object Level | Sort-Object Name
            $output += "Events by Level:"
            foreach ($group in $levelGroups) {
                $levelName = switch ($group.Name) {
                    1 { "Critical" }
                    2 { "Error" }
                    3 { "Warning" }
                    4 { "Information" }
                    5 { "Verbose" }
                    default { "Unknown" }
                }
                $output += "  - $levelName`: $($group.Count)"
            }
            
            $output += ""
            $output += "Top Event IDs:"
            $topIds = $events | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10
            foreach ($id in $topIds) {
                $output += "  - ID $($id.Name): $($id.Count) occurrences"
            }
            
            $output += ""
            $output += "Top Sources:"
            $topSources = $events | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 10
            foreach ($source in $topSources) {
                $output += "  - $($source.Name): $($source.Count) events"
            }
            
            if ($events.Count -gt 0) {
                $output += ""
                $output += "Time Range:"
                $oldest = $events | Select-Object -Last 1
                $newest = $events | Select-Object -First 1
                $output += "  - Oldest: $($oldest.TimeCreated)"
                $output += "  - Newest: $($newest.TimeCreated)"
            }
            
            return $output
        }
        
        # Format events
        $eventNum = 1
        foreach ($event in $events) {
            $output += "===== Event $eventNum ====="
            $output += "Time: $($event.TimeCreated)"
            $output += "Level: $($event.LevelDisplayName) | ID: $($event.Id)"
            $output += "Source: $($event.ProviderName)"
            $output += "Computer: $($event.MachineName)"
            
            if ($event.UserId) {
                $output += "User: $($event.UserId)"
            }
            
            if ($event.Message) {
                $output += "Message:"
                if ($viewMode -eq "2") {
                    # Summary mode - truncate messages
                    $truncated = if ($event.Message.Length -gt 200) {
                        $event.Message.Substring(0, 197) + "..."
                    } else {
                        $event.Message
                    }
                    $output += "  $truncated"
                } else {
                    # Detailed mode - full messages
                    $event.Message -split "`n" | ForEach-Object { $output += "  $_" }
                }
            }
            
            $output += ""
            $eventNum++
        }
        
        return $output
    }
    catch {
        $output = @()
        $output += "Unable to parse event log on this system."
        $output += "Event logs can only be viewed on Windows systems with appropriate permissions."
        $output += ""
        $output += "Error: $_"
        $output += ""
        $output += "Raw file location: $FilePath"
        $output += "File size: $([Math]::Round((Get-Item $FilePath).Length/1MB, 2)) MB"
        
        return $output
    }
}

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        ".xml" {
            try {
                [xml]$xmlContent = Get-Content $FilePath
                return $xmlContent.OuterXml -split "`n"
            } catch {
                return Get-Content $FilePath
            }
        }
        default { 
            return @(
                "Cannot display file type: $extension",
                "File size: $([Math]::Round((Get-Item $FilePath).Length/1KB, 2)) KB"
            )
        }
    }
}

# Enhanced paged display with all features
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        Write-Host "Total items: $($Content.Count) | Page size: $PageSize" -ForegroundColor $colors.Info
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content with line numbers
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            $lineNum = "{0,6}: " -f ($i + 1)
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $lineNum -NoNewline -ForegroundColor $colors.Menu
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $lineNum -NoNewline -ForegroundColor $colors.Menu
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS|ENABLED") {
                Write-Host $lineNum -NoNewline -ForegroundColor $colors.Menu
                Write-Host $line -ForegroundColor $colors.Success
            }
            elseif ($line -match "===== Event") {
                Write-Host $lineNum -NoNewline -ForegroundColor $colors.Menu
                Write-Host $line -ForegroundColor $colors.Header
            }
            elseif ($line -match "^Time:|^Level:|^Source:|^ID:|^Computer:|^User:") {
                Write-Host $lineNum -NoNewline -ForegroundColor $colors.Menu
                Write-Host $line -ForegroundColor $colors.Info
            }
            elseif ($line -match "^-{3,}|^={3,}") {
                Write-Host $lineNum -NoNewline -ForegroundColor $colors.Menu
                Write-Host $line -ForegroundColor $colors.Menu
            }
            else {
                Write-Host $lineNum -NoNewline -ForegroundColor $colors.Menu
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation bar
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]rev [F]irst [L]ast [G]oto page [J]ump line [S]earch [E]xport [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { 
                if ($currentPage -lt $totalPages - 1) { 
                    $currentPage++ 
                } else {
                    Write-Host "Already on last page" -ForegroundColor $colors.Warning
                    Start-Sleep -Seconds 1
                }
            }
            "P" { 
                if ($currentPage -gt 0) { 
                    $currentPage-- 
                } else {
                    Write-Host "Already on first page" -ForegroundColor $colors.Warning
                    Start-Sleep -Seconds 1
                }
            }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "G" {
                $goto = Read-Host "Enter page number (1-$totalPages)"
                if ($goto -match '^\d+$') {
                    $pageNum = [int]$goto - 1
                    if ($pageNum -ge 0 -and $pageNum -lt $totalPages) {
                        $currentPage = $pageNum
                    } else {
                        Write-Host "Invalid page number" -ForegroundColor $colors.Warning
                        Start-Sleep -Seconds 1
                    }
                }
            }
            "J" {
                $jumpLine = Read-Host "Enter line number (1-$($Content.Count))"
                if ($jumpLine -match '^\d+$') {
                    $lineNum = [int]$jumpLine - 1
                    if ($lineNum -ge 0 -and $lineNum -lt $Content.Count) {
                        # Calculate which page contains this line
                        $currentPage = [Math]::Floor($lineNum / $PageSize)
                    } else {
                        Write-Host "Invalid line number" -ForegroundColor $colors.Warning
                        Start-Sleep -Seconds 1
                    }
                }
            }
            "S" {
                $searchTerm = Read-Host "Enter search term (supports regex)"
                if ($searchTerm) {
                    Write-Host "Searching..." -ForegroundColor $colors.Progress
                    $matches = @()
                    for ($i = 0; $i -lt $Content.Count; $i++) {
                        try {
                            if ($Content[$i] -match $searchTerm) {
                                $matches += "Line $($i+1): $($Content[$i])"
                            }
                        } catch {
                            # If regex fails, try literal match
                            if ($Content[$i] -match [regex]::Escape($searchTerm)) {
                                $matches += "Line $($i+1): $($Content[$i])"
                            }
                        }
                    }
                    if ($matches.Count -gt 0) {
                        Write-Host "Found $($matches.Count) matches" -ForegroundColor $colors.Success
                        Read-Host "Press Enter to view"
                        Show-PagedContent -Content $matches -Title "Search Results: '$searchTerm'"
                    } else {
                        Write-Host "No matches found" -ForegroundColor $colors.Warning
                        Start-Sleep -Seconds 2
                    }
                }
            }
            "E" {
                $exportPath = Join-Path ([System.IO.Path]::GetTempPath()) "IR_PageExport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                @"
$Title
Exported: $(Get-Date)
Total Items: $($Content.Count)
$('='*80)

"@ + ($Content -join "`r`n") | Out-File $exportPath -Encoding UTF8
                
                Write-Host "Exported to: $exportPath" -ForegroundColor $colors.Success
                $open = Read-Host "Open file? (Y/N)"
                if ($open -eq 'Y' -or $open -eq 'y') {
                    notepad.exe $exportPath
                }
            }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Current Incident: " -NoNewline
        Write-Host $incidentName -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:|Collection Time:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host ("-" * 40) -ForegroundColor $colors.Menu
        Write-Host " 1. View Summary Report" -ForegroundColor $colors.Menu
        Write-Host " 2. Browse ALERTS (Critical Findings)" -ForegroundColor $colors.Critical
        Write-Host " 3. Network Analysis" -ForegroundColor $colors.Menu
        Write-Host " 4. Process Information" -ForegroundColor $colors.Menu
        Write-Host " 5. Persistence Mechanisms" -ForegroundColor $colors.Menu
        Write-Host " 6. System Information" -ForegroundColor $colors.Menu
        Write-Host " 7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host " 8. IOCs (Indicators of Compromise)" -ForegroundColor $colors.Menu
        Write-Host " 9. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "10. Search Across All Files" -ForegroundColor $colors.Menu
        Write-Host "11. Export Complete Report (Text)" -ForegroundColor $colors.Success
        Write-Host " Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Show-IOCs -IncidentPath $IncidentPath }
            "9" { Browse-Files -IncidentPath $IncidentPath }
            "10" { Search-AllFiles -IncidentPath $IncidentPath }
            "11" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
            default {
                Write-Host "Invalid option" -ForegroundColor $colors.Warning
                Start-Sleep -Seconds 1
            }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts with enhanced categorization
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "CRITICAL ALERTS AND FINDINGS"
        
        $alertFiles = Get-ChildItem $alertsPath -File -ErrorAction SilentlyContinue | Sort-Object Name
        
        if ($alertFiles.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to return"
            return
        }
        
        # Categorize alerts
        $categories = @{
            "Suspicious Processes" = @()
            "Network Alerts" = @()
            "Persistence" = @()
            "Remote Access" = @()
            "IOCs" = @()
            "Other" = @()
        }
        
        foreach ($file in $alertFiles) {
            if ($file.Name -match "process|proc|pid") { $categories["Suspicious Processes"] += $file }
            elseif ($file.Name -match "network|connection|ip|external") { $categories["Network Alerts"] += $file }
            elseif ($file.Name -match "persistence|autorun|service|task") { $categories["Persistence"] += $file }
            elseif ($file.Name -match "remote|rdp|teamviewer") { $categories["Remote Access"] += $file }
            elseif ($file.Name -match "ioc") { $categories["IOCs"] += $file }
            else { $categories["Other"] += $file }
        }
        
        # Display categorized alerts
        $fileIndex = 1
        $fileMap = @{}
        
        foreach ($category in $categories.Keys | Sort-Object) {
            if ($categories[$category].Count -gt 0) {
                Write-Host ""
                Write-Host "=== $category ===" -ForegroundColor $colors.High
                
                foreach ($file in $categories[$category]) {
                    $sizeKB = [Math]::Round($file.Length / 1KB, 2)
                    
                    Write-Host ("{0,3}. " -f $fileIndex) -NoNewline -ForegroundColor $colors.Menu
                    Write-Host ("{0,-40}" -f $file.Name) -NoNewline -ForegroundColor $colors.Critical
                    Write-Host (" {0,8} KB" -f $sizeKB) -ForegroundColor $colors.Data
                    
                    $fileMap[$fileIndex] = $file
                    $fileIndex++
                }
            }
        }
        
        Write-Host ""
        Write-Host "Enter file number to view (1-$($fileIndex-1)), A for all, or Q to go back: " -NoNewline -ForegroundColor $colors.Menu
        $selection = Read-Host
        
        if ($selection -match '^[Qq]') {
            return
        }
        elseif ($selection -match '^[Aa]') {
            # View all alerts in sequence
            foreach ($file in $alertFiles) {
                $content = Show-FileContent -FilePath $file.FullName
                Show-PagedContent -Content $content -Title "ALERT: $($file.Name)"
                
                Write-Host "`nContinue to next alert? (Y/N): " -NoNewline -ForegroundColor $colors.Menu
                $continue = Read-Host
                if ($continue -ne 'Y' -and $continue -ne 'y') {
                    break
                }
            }
        }
        elseif ($selection -match '^\d+$') {
            $index = [int]$selection
            if ($fileMap.ContainsKey($index)) {
                $content = Show-FileContent -FilePath $fileMap[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($fileMap[$index].Name)"
            }
        }
    }
}

# Show network data with enhanced options
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK ANALYSIS"
        
        # Quick network summary if connections file exists
        $connFile = Join-Path $networkPath "connections_basic.csv"
        if (Test-Path $connFile) {
            $connections = Import-Csv $connFile -ErrorAction SilentlyContinue
            if ($connections) {
                $established = @($connections | Where-Object {$_.State -eq "Established"})
                $listening = @($connections | Where-Object {$_.State -eq "Listen"})
                $external = @($established | Where-Object {
                    $_.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fe80:)"
                })
                
                Write-Host "Network Summary:" -ForegroundColor $colors.Info
                Write-Host "  Total Connections: $($connections.Count)" -ForegroundColor $colors.Data
                Write-Host "  Established: $($established.Count)" -ForegroundColor $colors.Data
                Write-Host "  Listening: $($listening.Count)" -ForegroundColor $colors.Data
                Write-Host "  External: $($external.Count)" -ForegroundColor $(if($external.Count -gt 0){$colors.Warning}else{$colors.Data})
                Write-Host ""
            }
        }
        
        Write-Host "Available Data:" -ForegroundColor $colors.Header
        Write-Host " 1. Network Connections (CSV)" -ForegroundColor $colors.Menu
        Write-Host " 2. External IPs List" -ForegroundColor $colors.Menu
        Write-Host " 3. DNS Cache" -ForegroundColor $colors.Menu
        Write-Host " 4. Active Sessions" -ForegroundColor $colors.Menu
        Write-Host " 5. Network Configuration" -ForegroundColor $colors.Menu
        Write-Host " 6. ARP Table" -ForegroundColor $colors.Menu
        Write-Host " 7. Routing Table" -ForegroundColor $colors.Menu
        Write-Host " 8. Open Ports (netstat)" -ForegroundColor $colors.Menu
        Write-Host " 9. View All Network Files" -ForegroundColor $colors.Menu
        Write-Host " Q. Back to Main Menu" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" {
                $file = Join-Path $networkPath "connections_basic.csv"
                if (Test-Path $file) {
                    $content = Show-FileContent -FilePath $file
                    Show-PagedContent -Content $content -Title "Network Connections"
                } else {
                    Write-Host "File not found" -ForegroundColor $colors.Warning
                    Start-Sleep -Seconds 1
                }
            }
            "2" {
                $file = Join-Path $networkPath "external_ips.txt"
                if (Test-Path $file) {
                    $content = Get-Content $file
                    Show-PagedContent -Content $content -Title "External IPs"
                } else {
                    Write-Host "File not found" -ForegroundColor $colors.Warning
                    Start-Sleep -Seconds 1
                }
            }
            "3" {
                $file = Join-Path $networkPath "dns_cache.csv"
                if (Test-Path $file) {
                    $content = Show-FileContent -FilePath $file
                    Show-PagedContent -Content $content -Title "DNS Cache"
                } else {
                    Write-Host "File not found" -ForegroundColor $colors.Warning
                    Start-Sleep -Seconds 1
                }
            }
            "4" {
                $file = Join-Path $networkPath "active_sessions.txt"
                if (Test-Path $file) {
                    $content = Get-Content $file
                    Show-PagedContent -Content $content -Title "Active Sessions"
                } else {
                    Write-Host "File not found" -ForegroundColor $colors.Warning
                    Start-Sleep -Seconds 1
                }
            }
            "5" {
                $file = Join-Path $networkPath "ipconfig.txt"
                if (Test-Path $file) {
                    $content = Get-Content $file
                    Show-PagedContent -Content $content -Title "Network Configuration"
                } else {
                    Write-Host "File not found" -ForegroundColor $colors.Warning
                    Start-Sleep -Seconds 1
                }
            }
            "6" {
                $file = Join-Path $networkPath "arp.txt"
                if (Test-Path $file) {
                    $content = Get-Content $file
                    Show-PagedContent -Content $content -Title "ARP Table"
                } else {
                    Write-Host "File not found" -ForegroundColor $colors.Warning
                    Start-Sleep -Seconds 1
                }
            }
            "7" {
                $file = Join-Path $networkPath "routes.txt"
                if (Test-Path $file) {
                    $content = Get-Content $file
                    Show-PagedContent -Content $content -Title "Routing Table"
                } else {
                    Write-Host "File not found" -ForegroundColor $colors.Warning
                    Start-Sleep -Seconds 1
                }
            }
            "8" {
                $file = Join-Path $networkPath "netstat_full.txt"
                if (Test-Path $file) {
                    $content = Get-Content $file
                    Show-PagedContent -Content $content -Title "Open Ports (netstat)"
                } else {
                    Write-Host "File not found" -ForegroundColor $colors.Warning
                    Start-Sleep -Seconds 1
                }
            }
            "9" {
                Browse-Directory -Path $networkPath -Title "ALL NETWORK FILES"
            }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
        $files += Get-ChildItem $alertsPath -Filter "*shell*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS INFORMATION"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $location = if ($files[$i].DirectoryName -match "ALERTS") { "[ALERT]" } else { "[DATA]" }
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            
            Write-Host ("{0,3}. " -f ($i + 1)) -NoNewline -ForegroundColor $colors.Menu
            Write-Host ("{0,-40}" -f $files[$i].Name) -NoNewline -ForegroundColor $color
            Write-Host (" {0}" -f $location) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE MECHANISMS"
        
        # Categorize persistence mechanisms
        Write-Host "Detected Persistence Mechanisms:" -ForegroundColor $colors.Header
        Write-Host ""
        
        $categories = @{
            "Registry Autoruns" = $files | Where-Object {$_.Name -match "autorun|registry"}
            "Scheduled Tasks" = $files | Where-Object {$_.Name -match "task"}
            "Services" = $files | Where-Object {$_.Name -match "service"}
            "Other" = $files | Where-Object {$_.Name -notmatch "autorun|registry|task|service"}
        }
        
        $fileIndex = 1
        $fileMap = @{}
        
        foreach ($cat in $categories.Keys | Sort-Object) {
            if ($categories[$cat].Count -gt 0) {
                Write-Host "--- $cat ---" -ForegroundColor $colors.Warning
                foreach ($file in $categories[$cat]) {
                    $location = if ($file.DirectoryName -match "ALERTS") { "[ALERT]" } else { "[DATA]" }
                    Write-Host ("{0,3}. " -f $fileIndex) -NoNewline -ForegroundColor $colors.Menu
                    Write-Host ("{0,-40}" -f $file.Name) -NoNewline -ForegroundColor $colors.High
                    Write-Host (" {0}" -f $location) -ForegroundColor $colors.High
                    $fileMap[$fileIndex] = $file
                    $fileIndex++
                }
                Write-Host ""
            }
        }
        
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice
            if ($fileMap.ContainsKey($index)) {
                $content = Show-FileContent -FilePath $fileMap[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($fileMap[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            # Add descriptions
            $description = switch -Wildcard ($files[$i].Name) {
                "basic_info.txt" { "System Overview" }
                "defender_status.csv" { "Windows Defender Status" }
                "firewall_status.csv" { "Firewall Configuration" }
                default { "" }
            }
            
            Write-Host ("{0,3}. " -f ($i + 1)) -NoNewline -ForegroundColor $colors.Menu
            Write-Host ("{0,-30}" -f $files[$i].Name) -NoNewline
            if ($description) {
                Write-Host (" - $description") -ForegroundColor $colors.Data
            } else {
                Write-Host ""
            }
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs with enhanced options
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = switch ($files[$i].Name) {
                "Security.evtx" { $colors.High }
                "System.evtx" { $colors.Warning }
                "Application.evtx" { $colors.Info }
                "PowerShell.evtx" { $colors.Critical }
                default { $colors.Data }
            }
            
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view, A for analysis summary, or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^[Aa]') {
            # Quick analysis of all event logs
            Show-EventLogSummary -LogsPath $logsPath
        }
        elseif ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Event log summary analysis
function Show-EventLogSummary {
    param([string]$LogsPath)
    
    Write-Host "Analyzing event logs..." -ForegroundColor $colors.Progress
    $summary = @()
    $summary += "EVENT LOG SUMMARY ANALYSIS"
    $summary += "="*60
    $summary += ""
    
    $evtxFiles = Get-ChildItem $LogsPath -Filter "*.evtx"
    
    foreach ($file in $evtxFiles) {
        Write-Host "." -NoNewline -ForegroundColor $colors.Progress
        
        $summary += "Log: $($file.Name)"
        $summary += "Size: $([Math]::Round($file.Length/1MB, 2)) MB"
        
        try {
            # Try to get basic stats
            $events = Get-WinEvent -Path $file.FullName -MaxEvents 1000 -ErrorAction Stop
            
            $errorCount = ($events | Where-Object { $_.Level -eq 2 }).Count
            $warningCount = ($events | Where-Object { $_.Level -eq 3 }).Count
            $infoCount = ($events | Where-Object { $_.Level -eq 4 }).Count
            
            $summary += "Sample of 1000 events:"
            $summary += "  - Errors: $errorCount"
            $summary += "  - Warnings: $warningCount"
            $summary += "  - Information: $infoCount"
            
            # Get time range
            if ($events.Count -gt 0) {
                $oldest = $events | Select-Object -Last 1
                $newest = $events | Select-Object -First 1
                $summary += "  - Time range: $($oldest.TimeCreated) to $($newest.TimeCreated)"
            }
            
            # Common event IDs
            $commonIds = $events | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5
            if ($commonIds) {
                $summary += "  - Common Event IDs:"
                foreach ($id in $commonIds) {
                    $summary += "    - ID $($id.Name): $($id.Count) occurrences"
                }
            }
            
            # Security specific analysis
            if ($file.Name -eq "Security.evtx") {
                $logons = $events | Where-Object {$_.Id -eq 4624}
                $failedLogons = $events | Where-Object {$_.Id -eq 4625}
                $summary += ""
                $summary += "Security Analysis:"
                $summary += "  - Successful Logons: $($logons.Count)"
                $summary += "  - Failed Logons: $($failedLogons.Count)"
            }
        }
        catch {
            $summary += "  - Unable to parse on this system"
        }
        
        $summary += ""
    }
    
    Write-Host ""
    Show-PagedContent -Content $summary -Title "EVENT LOG SUMMARY"
}

# Show IOCs
function Show-IOCs {
    param([string]$IncidentPath)
    
    $iocFile = Join-Path $IncidentPath "ALERTS\quick_iocs.json"
    
    if (!(Test-Path $iocFile)) {
        Write-Host "No IOC file found (quick_iocs.json)" -ForegroundColor $colors.Info
        Write-Host "Looking for other IOC files..." -ForegroundColor $colors.Progress
        
        # Try to find other IOC files
        $alertsPath = Join-Path $IncidentPath "ALERTS"
        if (Test-Path $alertsPath) {
            $iocFiles = Get-ChildItem $alertsPath -Filter "*ioc*" -File
            if ($iocFiles) {
                Write-Host "Found $($iocFiles.Count) IOC-related files" -ForegroundColor $colors.Success
                foreach ($file in $iocFiles) {
                    Write-Host "  - $($file.Name)" -ForegroundColor $colors.Data
                }
                Read-Host "`nPress Enter to continue"
                return
            }
        }
        
        Write-Host "No IOC files found" -ForegroundColor $colors.Warning
        Read-Host "Press Enter to continue"
        return
    }
    
    try {
        $iocContent = Get-Content $iocFile -Raw
        $iocs = $iocContent | ConvertFrom-Json
        
        $output = @()
        $output += "INDICATORS OF COMPROMISE (IOCs)"
        $output += "="*60
        $output += "Source: $iocFile"
        $output += ""
        
        if ($iocs.SuspiciousIPs -and $iocs.SuspiciousIPs.Count -gt 0) {
            $output += "SUSPICIOUS IP ADDRESSES ($($iocs.SuspiciousIPs.Count)):"
            $output += "-"*40
            foreach ($ip in $iocs.SuspiciousIPs) {
                $output += "  * $ip"
            }
            $output += ""
        }
        
        if ($iocs.SuspiciousProcesses -and $iocs.SuspiciousProcesses.Count -gt 0) {
            $output += "SUSPICIOUS PROCESSES ($($iocs.SuspiciousProcesses.Count)):"
            $output += "-"*40
            foreach ($proc in $iocs.SuspiciousProcesses) {
                $output += "  * $proc"
            }
            $output += ""
        }
        
        if ($iocs.SuspiciousFiles -and $iocs.SuspiciousFiles.Count -gt 0) {
            $output += "SUSPICIOUS FILES ($($iocs.SuspiciousFiles.Count)):"
            $output += "-"*40
            foreach ($file in $iocs.SuspiciousFiles) {
                $output += "  * $file"
            }
            $output += ""
        }
        
        if ($iocs.PersistenceLocations -and $iocs.PersistenceLocations.Count -gt 0) {
            $output += "PERSISTENCE LOCATIONS ($($iocs.PersistenceLocations.Count)):"
            $output += "-"*40
            foreach ($pers in $iocs.PersistenceLocations) {
                if ($pers.PSObject.Properties["Location"] -and $pers.PSObject.Properties["Name"]) {
                    $output += "  * Location: $($pers.Location)"
                    $output += "    Name: $($pers.Name)"
                    if ($pers.PSObject.Properties["Value"]) {
                        $val = if ($pers.Value.Length -gt 100) {
                            $pers.Value.Substring(0, 97) + "..."
                        } else {
                            $pers.Value
                        }
                        $output += "    Value: $val"
                    }
                    $output += ""
                }
            }
        }
        
        # Export IOCs option
        $output += ""
        $output += "Export Options:"
        $output += "  - Press E when viewing to export to text file"
        $output += "  - Original JSON: $iocFile"
        
        Show-PagedContent -Content $output -Title "INDICATORS OF COMPROMISE"
    }
    catch {
        Write-Host "Error parsing IOC file: $_" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file tree..." -ForegroundColor $colors.Progress
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $fileList += "Total Files: $($allFiles.Count)"
    $fileList += "Total Size: $([Math]::Round((($allFiles | Measure-Object Length -Sum).Sum/1MB), 2)) MB"
    $fileList += ""
    
    $currentDir = ""
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Browse specific directory
function Browse-Directory {
    param(
        [string]$Path,
        [string]$Title
    )
    
    if (!(Test-Path $Path)) {
        Write-Host "Directory not found: $Path" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header $Title
        
        $files = Get-ChildItem $Path -File | Sort-Object Name
        
        if ($files.Count -eq 0) {
            Write-Host "No files in this directory" -ForegroundColor $colors.Info
            Read-Host "Press Enter to return"
            return
        }
        
        Write-Host "Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1} ({2:N2} KB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1KB)) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "$Title - $($files[$index].Name)"
            }
        }
    }
}

# Search across all files
function Search-AllFiles {
    param([string]$IncidentPath)
    
    Show-Header "SEARCH ALL FILES"
    
    Write-Host "Search Options:" -ForegroundColor $colors.Header
    Write-Host "1. Search file contents (text files only)" -ForegroundColor $colors.Menu
    Write-Host "2. Search file names" -ForegroundColor $colors.Menu
    Write-Host "3. Search by file extension" -ForegroundColor $colors.Menu
    Write-Host "4. Search by date modified" -ForegroundColor $colors.Menu
    Write-Host "5. Search by file size" -ForegroundColor $colors.Menu
    Write-Host "Q. Cancel" -ForegroundColor $colors.Menu
    Write-Host ""
    
    $searchType = Read-Host "Select search type"
    
    switch ($searchType) {
        "1" {
            $searchTerm = Read-Host "Enter search term (supports regex)"
            if (!$searchTerm) { return }
            
            Write-Host "Searching file contents..." -ForegroundColor $colors.Progress
            $results = @()
            $fileCount = 0
            
            Get-ChildItem -Path $IncidentPath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                $file = $_
                $fileCount++
                
                if ($fileCount % 10 -eq 0) {
                    Write-Host "." -NoNewline -ForegroundColor $colors.Progress
                }
                
                # Skip binary files
                if ($file.Extension -match "\.(exe|dll|sys|evtx|bin|zip)$") { return }
                
                try {
                    $matches = Select-String -Path $file.FullName -Pattern $searchTerm -ErrorAction Stop
                    foreach ($match in $matches) {
                        $relativePath = $file.FullName.Replace($IncidentPath, "").TrimStart("\")
                        $results += "$relativePath : Line $($match.LineNumber) : $($match.Line.Trim())"
                    }
                }
                catch {
                    # Try with simple match if regex fails
                    try {
                        $matches = Select-String -Path $file.FullName -Pattern ([regex]::Escape($searchTerm)) -ErrorAction Stop
                        foreach ($match in $matches) {
                            $relativePath = $file.FullName.Replace($IncidentPath, "").TrimStart("\")
                            $results += "$relativePath : Line $($match.LineNumber) : $($match.Line.Trim())"
                        }
                    } catch {
                        # Skip files that can't be read
                    }
                }
            }
            
            Write-Host ""
            
            if ($results.Count -eq 0) {
                Write-Host "No matches found" -ForegroundColor $colors.Warning
                Read-Host "Press Enter to continue"
            } else {
                Show-PagedContent -Content $results -Title "SEARCH RESULTS: '$searchTerm' ($($results.Count) matches)"
            }
        }
        
        "2" {
            $searchTerm = Read-Host "Enter file name pattern (supports wildcards)"
            if (!$searchTerm) { return }
            
            $files = Get-ChildItem -Path $IncidentPath -Recurse -Filter "*$searchTerm*" -File -ErrorAction SilentlyContinue
            
            if ($files.Count -eq 0) {
                Write-Host "No files found matching '$searchTerm'" -ForegroundColor $colors.Warning
                Read-Host "Press Enter to continue"
            } else {
                $results = $files | ForEach-Object {
                    $relativePath = $_.FullName.Replace($IncidentPath, "").TrimStart("\")
                    "$relativePath ($([Math]::Round($_.Length/1KB, 2)) KB) - Modified: $($_.LastWriteTime)"
                }
                Show-PagedContent -Content $results -Title "FILES MATCHING: '$searchTerm' ($($files.Count) found)"
            }
        }
        
        "3" {
            $extension = Read-Host "Enter file extension (e.g., csv, txt, log)"
            if (!$extension) { return }
            
            $extension = if ($extension.StartsWith(".")) { $extension } else { ".$extension" }
            
            $files = Get-ChildItem -Path $IncidentPath -Recurse -Filter "*$extension" -File -ErrorAction SilentlyContinue
            
            if ($files.Count -eq 0) {
                Write-Host "No files found with extension '$extension'" -ForegroundColor $colors.Warning
                Read-Host "Press Enter to continue"
            } else {
                $results = $files | ForEach-Object {
                    $relativePath = $_.FullName.Replace($IncidentPath, "").TrimStart("\")
                    "$relativePath ($([Math]::Round($_.Length/1KB, 2)) KB)"
                }
                Show-PagedContent -Content $results -Title "FILES WITH EXTENSION: '$extension' ($($files.Count) found)"
            }
        }
        
        "4" {
            $days = Read-Host "Files modified in the last X days"
            if (!$days -or !($days -match '^\d+$')) { return }
            
            $cutoffDate = (Get-Date).AddDays(-[int]$days)
            
            $files = Get-ChildItem -Path $IncidentPath -Recurse -File -ErrorAction SilentlyContinue | 
                     Where-Object { $_.LastWriteTime -gt $cutoffDate }
            
            if ($files.Count -eq 0) {
                Write-Host "No files modified in the last $days days" -ForegroundColor $colors.Warning
                Read-Host "Press Enter to continue"
            } else {
                $results = $files | Sort-Object LastWriteTime -Descending | ForEach-Object {
                    $relativePath = $_.FullName.Replace($IncidentPath, "").TrimStart("\")
                    "$($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) - $relativePath"
                }
                Show-PagedContent -Content $results -Title "FILES MODIFIED IN LAST $days DAYS ($($files.Count) found)"
            }
        }
        
        "5" {
            Write-Host "Size options:" -ForegroundColor $colors.Menu
            Write-Host "1. Larger than X KB" -ForegroundColor $colors.Menu
            Write-Host "2. Smaller than X KB" -ForegroundColor $colors.Menu
            Write-Host "3. Between X and Y KB" -ForegroundColor $colors.Menu
            
            $sizeOption = Read-Host "Select option"
            
            $files = switch ($sizeOption) {
                "1" {
                    $minSize = Read-Host "Minimum size in KB"
                    if ($minSize -match '^\d+$') {
                        Get-ChildItem -Path $IncidentPath -Recurse -File | 
                            Where-Object { $_.Length -gt ([int]$minSize * 1KB) }
                    }
                }
                "2" {
                    $maxSize = Read-Host "Maximum size in KB"
                    if ($maxSize -match '^\d+$') {
                        Get-ChildItem -Path $IncidentPath -Recurse -File | 
                            Where-Object { $_.Length -lt ([int]$maxSize * 1KB) }
                    }
                }
                "3" {
                    $minSize = Read-Host "Minimum size in KB"
                    $maxSize = Read-Host "Maximum size in KB"
                    if ($minSize -match '^\d+$' -and $maxSize -match '^\d+$') {
                        Get-ChildItem -Path $IncidentPath -Recurse -File | 
                            Where-Object { $_.Length -gt ([int]$minSize * 1KB) -and $_.Length -lt ([int]$maxSize * 1KB) }
                    }
                }
            }
            
            if ($files -and $files.Count -gt 0) {
                $results = $files | Sort-Object Length -Descending | ForEach-Object {
                    $relativePath = $_.FullName.Replace($IncidentPath, "").TrimStart("\")
                    "$([Math]::Round($_.Length/1KB, 2)) KB - $relativePath"
                }
                Show-PagedContent -Content $results -Title "FILES BY SIZE ($($files.Count) found)"
            } else {
                Write-Host "No files found matching criteria" -ForegroundColor $colors.Warning
                Read-Host "Press Enter to continue"
            }
        }
        
        "Q" { return }
        "q" { return }
        default { return }
    }
}

# Export all data to comprehensive text file
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT COMPLETE REPORT"
    
    Write-Host "This will export all readable incident data to a comprehensive text report." -ForegroundColor $colors.Info
    Write-Host "The process may take several minutes for large incidents." -ForegroundColor $colors.Warning
    Write-Host ""
    Write-Host "Export options:" -ForegroundColor $colors.Header
    Write-Host "1. Standard export (skip event logs)" -ForegroundColor $colors.Menu
    Write-Host "2. Full export (attempt to parse event logs)" -ForegroundColor $colors.Menu
    Write-Host "3. Summary only (key findings and statistics)" -ForegroundColor $colors.Menu
    Write-Host "Q. Cancel" -ForegroundColor $colors.Menu
    Write-Host ""
    
    $exportChoice = Read-Host "Select export type"
    
    if ($exportChoice -match '^[Qq]') { return }
    
    $exportFile = Join-Path $IncidentPath "IR_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "COMPREHENSIVE INCIDENT RESPONSE REPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Full Path: $IncidentPath"
    $output += "Export Tool: IR Data Viewer v2.0"
    $output += "Export Type: $(switch($exportChoice){'1'{'Standard'}'2'{'Full'}'3'{'Summary'}})"
    $output += "="*80
    $output += ""
    
    # Progress tracking
    $totalSteps = 10
    $currentStep = 0
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Progress
    
    # 1. Summary (always included)
    $currentStep++
    Write-Host "[$currentStep/$totalSteps] Exporting summary..." -ForegroundColor $colors.Progress
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $output += ""
        $output += "="*80
        $output += "EXECUTIVE SUMMARY"
        $output += "="*80
        $summaryContent = Get-Content $summaryFile
        $output += $summaryContent
    }
    
    if ($exportChoice -eq "3") {
        # Summary only - add statistics and key findings
        $currentStep++
        Write-Host "[$currentStep/$totalSteps] Generating statistics..." -ForegroundColor $colors.Progress
        
        $output += ""
        $output += "="*80
        $output += "INCIDENT STATISTICS"
        $output += "="*80
        
        # File counts
        $alertFiles = (Get-ChildItem "$IncidentPath\ALERTS" -File -ErrorAction SilentlyContinue).Count
        $networkFiles = (Get-ChildItem "$IncidentPath\Network" -File -ErrorAction SilentlyContinue).Count
        $logFiles = (Get-ChildItem "$IncidentPath\Logs" -File -ErrorAction SilentlyContinue).Count
        
        $output += "Alert Files: $alertFiles"
        $output += "Network Files: $networkFiles"
        $output += "Log Files: $logFiles"
        
        # Key IOCs if available
        $iocFile = Join-Path $IncidentPath "ALERTS\quick_iocs.json"
        if (Test-Path $iocFile) {
            try {
                $iocs = Get-Content $iocFile | ConvertFrom-Json
                $output += ""
                $output += "IOC Summary:"
                if ($iocs.SuspiciousIPs) { $output += "  - Suspicious IPs: $($iocs.SuspiciousIPs.Count)" }
                if ($iocs.SuspiciousProcesses) { $output += "  - Suspicious Processes: $($iocs.SuspiciousProcesses.Count)" }
                if ($iocs.PersistenceLocations) { $output += "  - Persistence Locations: $($iocs.PersistenceLocations.Count)" }
            } catch {}
        }
    }
    else {
        # Full or standard export - include all data
        
        # 2. Critical Alerts
        $currentStep++
        Write-Host "[$currentStep/$totalSteps] Exporting alerts..." -ForegroundColor $colors.Progress
        
        $alertsPath = Join-Path $IncidentPath "ALERTS"
        if (Test-Path $alertsPath) {
            $output += ""
            $output += "="*80
            $output += "CRITICAL ALERTS AND FINDINGS"
            $output += "="*80
            
            $alertFiles = Get-ChildItem -Path $alertsPath -File -ErrorAction SilentlyContinue | Sort-Object Name
            foreach ($file in $alertFiles) {
                $output += ""
                $output += "-"*60
                $output += "ALERT FILE: $($file.Name)"
                $output += "SIZE: $([Math]::Round($file.Length/1KB, 2)) KB"
                $output += "-"*60
                
                $content = Show-FileContent -FilePath $file.FullName
                $output += $content
            }
        }
        
        # 3. Network Analysis
        $currentStep++
        Write-Host "[$currentStep/$totalSteps] Exporting network data..." -ForegroundColor $colors.Progress
        
        $networkPath = Join-Path $IncidentPath "Network"
        if (Test-Path $networkPath) {
            $output += ""
            $output += "="*80
            $output += "NETWORK ANALYSIS"
            $output += "="*80
            
            # Key network files in order
            $netFiles = @(
                @{Name="connections_basic.csv"; Title="Network Connections"},
                @{Name="external_ips.txt"; Title="External IP Addresses"},
                @{Name="dns_cache.csv"; Title="DNS Cache"},
                @{Name="active_sessions.txt"; Title="Active Sessions"},
                @{Name="ipconfig.txt"; Title="Network Configuration"},
                @{Name="arp.txt"; Title="ARP Table"},
                @{Name="routes.txt"; Title="Routing Table"}
            )
            
            foreach ($netFile in $netFiles) {
                $filePath = Join-Path $networkPath $netFile.Name
                if (Test-Path $filePath) {
                    $output += ""
                    $output += "-"*60
                    $output += $netFile.Title
                    $output += "-"*60
                    $content = Show-FileContent -FilePath $filePath
                    $output += $content
                }
            }
        }
        
        # 4. Process Information
        $currentStep++
        Write-Host "[$currentStep/$totalSteps] Exporting process data..." -ForegroundColor $colors.Progress
        
        $processPath = Join-Path $IncidentPath "Processes"
        if (Test-Path $processPath) {
            $output += ""
            $output += "="*80
            $output += "PROCESS ANALYSIS"
            $output += "="*80
            
            $procFiles = Get-ChildItem -Path $processPath -File -ErrorAction SilentlyContinue
            foreach ($file in $procFiles) {
                $output += ""
                $output += "-"*60
                $output += "PROCESS FILE: $($file.Name)"
                $output += "-"*60
                $content = Show-FileContent -FilePath $file.FullName
                $output += $content
            }
        }
        
        # 5. Persistence Mechanisms
        $currentStep++
        Write-Host "[$currentStep/$totalSteps] Exporting persistence data..." -ForegroundColor $colors.Progress
        
        $persistPath = Join-Path $IncidentPath "Persistence"
        if (Test-Path $persistPath) {
            $output += ""
            $output += "="*80
            $output += "PERSISTENCE MECHANISMS"
            $output += "="*80
            
            $persFiles = Get-ChildItem -Path $persistPath -File -ErrorAction SilentlyContinue
            foreach ($file in $persFiles) {
                $output += ""
                $output += "-"*60
                $output += "PERSISTENCE: $($file.Name)"
                $output += "-"*60
                $content = Show-FileContent -FilePath $file.FullName
                $output += $content
            }
        }
        
        # 6. System Information
        $currentStep++
        Write-Host "[$currentStep/$totalSteps] Exporting system info..." -ForegroundColor $colors.Progress
        
        $systemPath = Join-Path $IncidentPath "System"
        if (Test-Path $systemPath) {
            $output += ""
            $output += "="*80
            $output += "SYSTEM INFORMATION"
            $output += "="*80
            
            $sysFiles = Get-ChildItem -Path $systemPath -File -ErrorAction SilentlyContinue
            foreach ($file in $sysFiles) {
                $output += ""
                $output += "-"*60
                $output += "SYSTEM: $($file.Name)"
                $output += "-"*60
                $content = Show-FileContent -FilePath $file.FullName
                $output += $content
            }
        }
        
        # 7. Event Logs
        $currentStep++
        Write-Host "[$currentStep/$totalSteps] Processing event logs..." -ForegroundColor $colors.Progress
        
        $logsPath = Join-Path $IncidentPath "Logs"
        if (Test-Path $logsPath) {
            $output += ""
            $output += "="*80
            $output += "EVENT LOG INFORMATION"
            $output += "="*80
            
            $logFiles = Get-ChildItem -Path $logsPath -Filter "*.evtx" -ErrorAction SilentlyContinue
            
            if ($exportChoice -eq "2") {
                # Full export - try to parse event logs
                foreach ($logFile in $logFiles) {
                    Write-Host "  Parsing $($logFile.Name)..." -ForegroundColor $colors.Progress
                    
                    $output += ""
                    $output += "-"*60
                    $output += "EVENT LOG: $($logFile.Name)"
                    $output += "SIZE: $([Math]::Round($logFile.Length/1MB, 2)) MB"
                    $output += "-"*60
                    
                    try {
                        # Limit to recent critical events for export
                        $events = Get-WinEvent -Path $logFile.FullName -MaxEvents 100 -ErrorAction Stop | 
                                  Where-Object { $_.Level -le 3 } # Errors and warnings only
                        
                        $output += "Showing $($events.Count) recent error/warning events"
                        $output += ""
                        
                        foreach ($event in $events) {
                            $output += "Time: $($event.TimeCreated) | Level: $($event.LevelDisplayName) | ID: $($event.Id)"
                            if ($event.Message) {
                                $msg = if ($event.Message.Length -gt 200) {
                                    $event.Message.Substring(0, 197) + "..."
                                } else {
                                    $event.Message
                                }
                                $output += "Message: $msg"
                            }
                            $output += ""
                        }
                    }
                    catch {
                        $output += "Unable to parse event log file"
                        $output += "Event logs require Windows Event Log service to parse"
                    }
                }
            }
            else {
                # Standard export - just list event log files
                foreach ($logFile in $logFiles) {
                    $output += "  - $($logFile.Name) ($([Math]::Round($logFile.Length/1MB, 2)) MB)"
                }
                $output += ""
                $output += "Note: Event logs not parsed in standard export"
                $output += "Use 'Full export' option or view individually for event log contents"
            }
        }
        
        # 8. IOCs
        $currentStep++
        Write-Host "[$currentStep/$totalSteps] Exporting IOCs..." -ForegroundColor $colors.Progress
        
        $iocFile = Join-Path $IncidentPath "ALERTS\quick_iocs.json"
        if (Test-Path $iocFile) {
            $output += ""
            $output += "="*80
            $output += "INDICATORS OF COMPROMISE (IOCs)"
            $output += "="*80
            
            try {
                $iocs = Get-Content $iocFile | ConvertFrom-Json
                $output += $iocs | ConvertTo-Json -Depth 10
            }
            catch {
                $output += "Error parsing IOCs: $_"
            }
        }
        
        # 9. File listing
        $currentStep++
        Write-Host "[$currentStep/$totalSteps] Creating file inventory..." -ForegroundColor $colors.Progress
        
        $output += ""
        $output += "="*80
        $output += "COMPLETE FILE INVENTORY"
        $output += "="*80
        
        $allFiles = Get-ChildItem -Path $IncidentPath -Recurse -File -ErrorAction SilentlyContinue | 
                    Sort-Object DirectoryName, Name
        
        $output += "Total Files Collected: $($allFiles.Count)"
        $output += "Total Size: $([Math]::Round((($allFiles | Measure-Object Length -Sum).Sum / 1MB), 2)) MB"
        $output += ""
        
        $currentDir = ""
        foreach ($file in $allFiles) {
            $dir = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
            if ($dir -ne $currentDir) {
                $output += ""
                $output += "[$dir]"
                $currentDir = $dir
            }
            $output += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB) - Modified: $($file.LastWriteTime)"
        }
    }
    
    # 10. Save the export
    $currentStep++
    Write-Host "[$currentStep/$totalSteps] Saving report..." -ForegroundColor $colors.Progress
    
    $output | Out-File -FilePath $exportFile -Encoding UTF8
    
    # Summary
    $fileInfo = Get-Item $exportFile
    Write-Host ""
    Write-Host "Export completed successfully!" -ForegroundColor $colors.Success
    Write-Host "Report saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Report size: $([Math]::Round($fileInfo.Length / 1MB, 2)) MB" -ForegroundColor $colors.Info
    Write-Host "Total lines: $($output.Count)" -ForegroundColor $colors.Info
    Write-Host ""
    
    $open = Read-Host "Open the report now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    $compress = Read-Host "Create compressed archive? (Y/N)"
    if ($compress -eq 'Y' -or $compress -eq 'y') {
        $zipPath = "$exportFile.zip"
        Compress-Archive -Path $exportFile -DestinationPath $zipPath -Force
        Write-Host "Archive created: $zipPath" -ForegroundColor $colors.Success
        Write-Host "Archive size: $([Math]::Round((Get-Item $zipPath).Length / 1MB, 2)) MB" -ForegroundColor $colors.Info
    }
    
    Read-Host "`nPress Enter to continue"
}

# Main execution
Show-Header

Write-Host "Welcome to the Incident Response Data Viewer" -ForegroundColor $colors.Info
Write-Host "This tool displays data collected by the IR Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Check if running with admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$isAdmin) {
    Write-Host "Note: Running without admin rights. Some event logs may not be accessible." -ForegroundColor $colors.Warning
    Write-Host ""
}

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "No incident selected. Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer!" -ForegroundColor $colors.Success
Write-Host ""
Write-Host "Features used:" -ForegroundColor $colors.Header
Write-Host "  * View collected incident response data" -ForegroundColor $colors.Data
Write-Host "  * Parse CSV, JSON, TXT, and LOG files" -ForegroundColor $colors.Data
Write-Host "  * Navigate event logs with full viewing options" -ForegroundColor $colors.Data
Write-Host "  * Search and filter large datasets" -ForegroundColor $colors.Data
Write-Host "  * Export comprehensive text reports" -ForegroundColor $colors.Data
Write-Host "  * Analyze IOCs and persistence mechanisms" -ForegroundColor $colors.Data
Write-Host ""
Write-Host "Stay vigilant, stay secure." -ForegroundColor $colors.Info
