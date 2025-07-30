# Connect to SharePoint Online
Connect-SPOService -Url "https://<replace-with-tenant-name>-admin.sharepoint.com"

# Function to handle retries with exponential backoff
function Invoke-SPOCommandWithRetry {
    param(
        [ScriptBlock]$Command,
        [int]$MaxRetries = 3,
        [int]$InitialDelay = 2,
        [string]$OperationName = "Operation"
    )
    
    $retryCount = 0
    $delay = $InitialDelay
    
    while ($retryCount -lt $MaxRetries) {# Enhanced SharePoint User Audit Script
# Parameterized and auto-detecting version

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantName,
    
    [Parameter(Mandatory=$false)]
    [string]$AdminUrl,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = (Join-Path $env:USERPROFILE "Documents\SharePointAudits"),
    
    [Parameter(Mandatory=$false)]
    [int]$MaxRetries = 3,
    
    [Parameter(Mandatory=$false)]
    [int]$InitialRetryDelay = 2,
    
    [Parameter(Mandatory=$false)]
    [int]$SiteDelay = 500,
    
    [Parameter(Mandatory=$false)]
    [int]$BatchPauseInterval = 20,
    
    [Parameter(Mandatory=$false)]
    [int]$BatchPauseDuration = 10,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludePersonalSites = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportOnly,
    
    [Parameter(Mandatory=$false)]
    [string[]]$SiteFilter = @(),
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipSystemAccounts,
    
    [Parameter(Mandatory=$false)]
    [hashtable]$CustomUserPatterns = @{}
)

# Function to detect tenant from existing connection
function Get-SPOTenantInfo {
    try {
        $context = Get-SPOSite -Limit 1 -ErrorAction SilentlyContinue
        if ($context) {
            $url = $context.Url
            if ($url -match "https://([^-]+)") {
                return $matches[1]
            }
        }
    }
    catch {
        return $null
    }
    return $null
}

# Function to prompt for parameters interactively
function Get-ScriptParameters {
    Write-Host "`n=== SharePoint User Audit Configuration ===" -ForegroundColor Cyan
    
    # Tenant detection/prompt
    if (-not $TenantName -and -not $AdminUrl) {
        $detectedTenant = Get-SPOTenantInfo
        if ($detectedTenant) {
            $useDetected = Read-Host "Detected tenant: '$detectedTenant'. Use this? (Y/n)"
            if ($useDetected -ne 'n') {
                $script:TenantName = $detectedTenant
            }
        }
        
        if (-not $TenantName) {
            $script:TenantName = Read-Host "Enter your tenant name (e.g., 'contoso' from contoso.sharepoint.com)"
        }
    }
    
    # Build admin URL if not provided
    if (-not $AdminUrl -and $TenantName) {
        $script:AdminUrl = "https://$TenantName-admin.sharepoint.com"
    }
    
    # Export path
    $useDefaultPath = Read-Host "Use default export path '$ExportPath'? (Y/n)"
    if ($useDefaultPath -eq 'n') {
        $script:ExportPath = Read-Host "Enter export path"
    }
    
    # Performance tuning
    Write-Host "`nPerformance Settings (press Enter to use defaults):" -ForegroundColor Yellow
    $customRetries = Read-Host "Max retries per operation [$MaxRetries]"
    if ($customRetries) { $script:MaxRetries = [int]$customRetries }
    
    $customDelay = Read-Host "Delay between sites in ms [$SiteDelay]"
    if ($customDelay) { $script:SiteDelay = [int]$customDelay }
    
    # Filter options
    $filterSites = Read-Host "`nFilter to specific sites? (y/N)"
    if ($filterSites -eq 'y') {
        $script:SiteFilter = @()
        Write-Host "Enter site URLs (one per line, empty line to finish):"
        while ($true) {
            $site = Read-Host
            if ([string]::IsNullOrWhiteSpace($site)) { break }
            $script:SiteFilter += $site
        }
    }
    
    $skipSystem = Read-Host "Skip system/service accounts? (y/N)"
    if ($skipSystem -eq 'y') {
        $script:SkipSystemAccounts = $true
    }
}

# Enhanced retry function with telemetry
function Invoke-SPOCommandWithRetry {
    param(
        [ScriptBlock]$Command,
        [int]$MaxRetries = $script:MaxRetries,
        [int]$InitialDelay = $script:InitialRetryDelay,
        [string]$OperationName = "Operation"
    )
    
    $retryCount = 0
    $delay = $InitialDelay
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    while ($retryCount -lt $MaxRetries) {
        try {
            $result = & $Command
            $stopwatch.Stop()
            
            if ($retryCount -gt 0) {
                Write-Verbose "    $OperationName succeeded after $retryCount retries (${stopwatch.ElapsedMilliseconds}ms)"
            }
            
            return $result
        }
        catch {
            $errorType = switch -Regex ($_.Exception.Message) {
                "429|Too Many Requests" { "RateLimit" }
                "401|Unauthorized" { "Auth" }
                "503|Service Unavailable" { "ServiceDown" }
                default { "Other" }
            }
            
            if ($errorType -eq "RateLimit" -and $retryCount -lt $MaxRetries - 1) {
                $retryCount++
                Write-Host "    Rate limited on $OperationName. Waiting $delay seconds (attempt $retryCount/$MaxRetries)..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
                $delay = [Math]::Min($delay * 2, 60)  # Cap at 60 seconds
            }
            elseif ($errorType -eq "Auth") {
                Write-Host "    Authentication error. Attempting reconnection..." -ForegroundColor Red
                Connect-SPOService -Url $AdminUrl
                $retryCount++
            }
            else {
                throw $_
            }
        }
    }
}

# Configurable user type detection
function Get-UserType {
    param([string]$LoginName)
    
    # Check custom patterns first
    foreach ($pattern in $CustomUserPatterns.GetEnumerator()) {
        if ($LoginName -match $pattern.Key) {
            return $pattern.Value
        }
    }
    
    # Default patterns
    switch -Regex ($LoginName) {
        "#EXT#" { return "Guest User" }
        "app@sharepoint|\.app\." { return "SharePoint App" }
        "spo-grid-all-users|spocsid-" { return "System Account" }
        "c:0[\(\.]\.s\||c:0\.t\|" { return "Security Group" }
        "SHAREPOINT\\system|NT AUTHORITY" { return "System Account" }
        "@.*\.onmicrosoft\.com$" { return "Internal User" }
        "^i:0#\.f\|membership\|" { return "Forms Auth User" }
        "^i:0e\.t\|" { return "SAML User" }
        default { 
            if ($LoginName -match "@.*\.(com|org|net|edu)$") {
                return "External User"
            }
            return "Other"
        }
    }
}

# Main execution
try {
    # Interactive parameter collection if needed
    if (-not $PSBoundParameters.Count -or -not $AdminUrl) {
        Get-ScriptParameters
    }
    
    # Ensure export directory exists
    if (!(Test-Path $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    }
    
    # Connection with retry
    Write-Host "`nConnecting to SharePoint Online..." -ForegroundColor Cyan
    Invoke-SPOCommandWithRetry -Command {
        Connect-SPOService -Url $AdminUrl -ErrorAction Stop
    } -OperationName "SPO Connection"
    
    Write-Host "Connected successfully!" -ForegroundColor Green
    
    # Get all sites
    Write-Host "`nRetrieving sites..." -ForegroundColor Cyan
    $getSitesParams = @{
        Limit = "All"
        IncludePersonalSite = $IncludePersonalSites
    }
    
    $allSites = Invoke-SPOCommandWithRetry -Command {
        Get-SPOSite @getSitesParams
    } -OperationName "Get Sites"
    
    # Apply site filter if specified
    if ($SiteFilter.Count -gt 0) {
        $allSites = $allSites | Where-Object { $_.Url -in $SiteFilter }
        Write-Host "Filtered to $($allSites.Count) sites" -ForegroundColor Yellow
    } else {
        Write-Host "Found $($allSites.Count) total sites" -ForegroundColor Green
    }
    
    # Initialize collections
    $fullReport = @()
    $processedCount = 0
    $failedSites = @()
    $totalSites = $allSites.Count
    $statistics = @{
        StartTime = Get-Date
        TotalAPICallsAttempted = 0
        TotalAPICallsSucceeded = 0
        RateLimitHits = 0
    }
    
    # Progress tracking
    $progress = @{
        Activity = "SharePoint User Audit"
        Status = "Processing sites..."
        PercentComplete = 0
    }
    
    # Process each site
    foreach ($site in $allSites) {
        $processedCount++
        $progress.PercentComplete = [int](($processedCount / $totalSites) * 100)
        $progress.CurrentOperation = "Site $processedCount of $totalSites: $($site.Url)"
        Write-Progress @progress
        
        if (-not $ExportOnly) {
            Write-Host "`n[$processedCount/$totalSites] Processing: $($site.Url)" -ForegroundColor Green
            $siteType = if($site.Url -like "*-my.sharepoint.com/personal/*") {"OneDrive"} else {"SharePoint"}
            Write-Host "Type: $siteType | Title: $($site.Title)" -ForegroundColor Gray
        }
        
        # Adaptive delay based on failure rate
        if ($statistics.RateLimitHits -gt 5) {
            $adaptiveDelay = $SiteDelay * 2
            Write-Verbose "Increasing delay due to rate limits"
        } else {
            $adaptiveDelay = $SiteDelay
        }
        Start-Sleep -Milliseconds $adaptiveDelay
        
        try {
            $statistics.TotalAPICallsAttempted++
            $users = Invoke-SPOCommandWithRetry -Command {
                Get-SPOUser -Site $site.Url -Limit All
            } -OperationName "Get Users"
            
            $statistics.TotalAPICallsSucceeded++
            
            if ($users) {
                $siteUsers = @()
                
                foreach ($user in $users) {
                    $userType = Get-UserType -LoginName $user.LoginName
                    
                    # Skip if filtering system accounts
                    if ($SkipSystemAccounts -and $userType -in @("System Account", "SharePoint App")) {
                        continue
                    }
                    
                    # Determine guest source
                    $guestSource = ""
                    if ($userType -eq "Guest User" -or $userType -eq "External User") {
                        $guestSource = switch -Regex ($user.LoginName) {
                            "gmail\.com" { "Gmail" }
                            "outlook\.com|live\.com" { "Microsoft Personal" }
                            "hotmail\.com" { "Hotmail" }
                            "yahoo\." { "Yahoo" }
                            "@([^.]+\.[^.]+)#EXT#" { $matches[1] }
                            default { "Other External" }
                        }
                    }
                    
                    # Get group memberships
                    $groups = Invoke-SPOCommandWithRetry -Command {
                        Get-SPOSiteGroup -Site $site.Url
                    } -OperationName "Get Groups" -MaxRetries 2
                    
                    $userGroups = @()
                    foreach ($group in $groups) {
                        try {
                            $groupMembers = Get-SPOUser -Site $site.Url -Group $group.LoginName -ErrorAction Stop
                            if ($groupMembers.LoginName -contains $user.LoginName) {
                                $permissionLevel = switch -Wildcard ($group.Title) {
                                    "*Owner*" { "Full Control" }
                                    "*Member*" { "Edit" }
                                    "*Visitor*" { "Read" }
                                    "*Contribute*" { "Contribute" }
                                    "*Design*" { "Design" }
                                    "*Limited*" { "Limited Access" }
                                    default { "Custom" }
                                }
                                
                                $userGroups += [PSCustomObject]@{
                                    GroupName = $group.Title
                                    Permission = $permissionLevel
                                }
                            }
                        }
                        catch {
                            # Group access error - skip
                        }
                    }
                    
                    # Create user record(s)
                    if ($userGroups.Count -gt 0) {
                        foreach ($userGroup in $userGroups) {
                            $fullReport += [PSCustomObject]@{
                                Site = $site.Url
                                SiteType = $siteType
                                SiteTitle = $site.Title
                                UserName = $user.DisplayName
                                UserLogin = $user.LoginName
                                UserType = $userType
                                GuestSource = $guestSource
                                Group = $userGroup.GroupName
                                Permission = $userGroup.Permission
                                IsSiteAdmin = $user.IsSiteAdmin
                                ProcessedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            }
                        }
                    } else {
                        $fullReport += [PSCustomObject]@{
                            Site = $site.Url
                            SiteType = $siteType
                            SiteTitle = $site.Title
                            UserName = $user.DisplayName
                            UserLogin = $user.LoginName
                            UserType = $userType
                            GuestSource = $guestSource
                            Group = "Direct Permission"
                            Permission = if ($user.IsSiteAdmin) { "Site Admin" } else { "Custom" }
                            IsSiteAdmin = $user.IsSiteAdmin
                            ProcessedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        }
                    }
                    
                    $siteUsers += $user.DisplayName
                }
                
                if (-not $ExportOnly -and $siteUsers.Count -gt 0) {
                    Write-Host "  Found $($siteUsers.Count) users$(if($SkipSystemAccounts){' (excluding system accounts)'})" -ForegroundColor White
                }
            }
        }
        catch {
            Write-Host "  Error: $_" -ForegroundColor Red
            $failedSites += [PSCustomObject]@{
                Site = $site.Url
                Error = $_.Exception.Message
                Timestamp = Get-Date
            }
        }
        
        # Batch pause
        if ($processedCount % $BatchPauseInterval -eq 0 -and $processedCount -lt $totalSites) {
            Write-Host "`nBatch pause: Processed $processedCount/$totalSites sites. Pausing $BatchPauseDuration seconds..." -ForegroundColor Magenta
            Start-Sleep -Seconds $BatchPauseDuration
        }
    }
    
    Write-Progress -Activity "SharePoint User Audit" -Completed
    
    # Generate reports
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPrefix = "SPOUserAudit_${TenantName}_${timestamp}"
    
    # Export main report
    $mainReportPath = Join-Path $ExportPath "${reportPrefix}_Full.csv"
    $fullReport | Export-Csv -Path $mainReportPath -NoTypeInformation
    Write-Host "`nExported full report: $mainReportPath" -ForegroundColor Green
    
    # Summary statistics
    $statistics.EndTime = Get-Date
    $statistics.Duration = $statistics.EndTime - $statistics.StartTime
    $statistics.ProcessedSites = $processedCount
    $statistics.FailedSites = $failedSites.Count
    $statistics.TotalUsers = ($fullReport | Select-Object -Unique UserLogin).Count
    $statistics.TotalAssignments = $fullReport.Count
    
    # Generate summary report
    $summaryReport = @"
SharePoint User Audit Summary
=============================
Tenant: $TenantName
Run Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Duration: $($statistics.Duration.ToString("hh\:mm\:ss"))

Sites Processed: $($statistics.ProcessedSites)
Sites Failed: $($statistics.FailedSites)
Total Unique Users: $($statistics.TotalUsers)
Total Assignments: $($statistics.TotalAssignments)

User Type Breakdown:
$($fullReport | Group-Object UserType | ForEach-Object { "  $($_.Name): $($_.Count)" } | Out-String)

Permission Level Summary:
$($fullReport | Group-Object Permission | ForEach-Object { "  $($_.Name): $($_.Count)" } | Out-String)
"@
    
    $summaryPath = Join-Path $ExportPath "${reportPrefix}_Summary.txt"
    $summaryReport | Out-File -FilePath $summaryPath
    Write-Host "Exported summary: $summaryPath" -ForegroundColor Green
    
    # Export specialized reports
    $guestUsers = $fullReport | Where-Object { $_.UserType -in @("Guest User", "External User") }
    if ($guestUsers) {
        $guestPath = Join-Path $ExportPath "${reportPrefix}_GuestUsers.csv"
        $guestUsers | Export-Csv -Path $guestPath -NoTypeInformation
        Write-Host "Exported guest users: $guestPath" -ForegroundColor Green
    }
    
    if ($failedSites) {
        $failedPath = Join-Path $ExportPath "${reportPrefix}_FailedSites.csv"
        $failedSites | Export-Csv -Path $failedPath -NoTypeInformation
        Write-Host "Exported failed sites: $failedPath" -ForegroundColor Yellow
    }
    
    # Display summary unless export-only mode
    if (-not $ExportOnly) {
        Write-Host "`n$summaryReport" -ForegroundColor Cyan
    }
    
    Write-Host "`nAudit complete! All reports saved to: $ExportPath" -ForegroundColor Green
    
} catch {
    Write-Host "`nFATAL ERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
} finally {
    # Disconnect
    Disconnect-SPOService -ErrorAction SilentlyContinue
}
        try {
            $result = & $Command
            return $result
        }
        catch {
            if ($_.Exception.Message -like "*429*" -or $_.Exception.Message -like "*Too Many Requests*") {
                $retryCount++
                if ($retryCount -lt $MaxRetries) {
                    Write-Host "    Rate limited on $OperationName. Waiting $delay seconds before retry $retryCount/$MaxRetries..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $delay
                    $delay = $delay * 2  # Exponential backoff
                }
                else {
                    throw $_
                }
            }
            else {
                throw $_
            }
        }
    }
}

# Get all sites with retry
Write-Host "Retrieving all sites (this may take a while)..." -ForegroundColor Cyan
$allSites = Invoke-SPOCommandWithRetry -Command {
    Get-SPOSite -Limit All -IncludePersonalSite $true
} -OperationName "Get Sites"

Write-Host "Found $($allSites.Count) total sites" -ForegroundColor Green

# Initialize tracking
$fullReport = @()
$processedCount = 0
$failedSites = @()
$totalSites = $allSites.Count

# Process each site
foreach ($site in $allSites) {
    $processedCount++
    Write-Host "`n[$processedCount/$totalSites] Checking site: $($site.Url)" -ForegroundColor Green
    Write-Host "Site Type: $(if($site.Url -like '*-my.sharepoint.com/personal/*') {'OneDrive'} else {'SharePoint'})" -ForegroundColor Gray
    
    # Add small delay between sites
    Start-Sleep -Milliseconds 500
    
    try {
        # Get all users with retry
        $users = Invoke-SPOCommandWithRetry -Command {
            Get-SPOUser -Site $site.Url -Limit All
        } -OperationName "Get Users for $($site.Url)"
        
        if ($users) {
            Write-Host "  Found $($users.Count) total users in this site" -ForegroundColor White
            
            foreach ($user in $users) {
                # Categorize user type
                $userType = switch -Regex ($user.LoginName) {
                    "#EXT#" { "Guest User" }
                    "app@sharepoint" { "SharePoint App" }
                    "spo-grid-all-users" { "System Account" }
                    "c:0(.s|.t)" { "Security Group" }
                    "@<tenant>.onmicrosoft.com$" { "Internal User" }
                    "SHAREPOINT\\system" { "System Account" }
                    default { "Other" }
                }
                
                # Determine guest source if applicable
                $guestSource = ""
                if ($userType -eq "Guest User") {
                    $guestSource = switch -Regex ($user.LoginName) {
                        "gmail.com" { "Gmail" }
                        "outlook.com" { "Outlook" }
                        "hotmail.com" { "Hotmail" }
                        default { "Other External" }
                    }
                }
                
                # Print ALL users as they're found
                $userColor = switch ($userType) {
                    "Guest User" { "Yellow" }
                    "Internal User" { "Green" }
                    "System Account" { "DarkGray" }
                    "SharePoint App" { "Cyan" }
                    "Security Group" { "Magenta" }
                    default { "White" }
                }
                
                Write-Host "`n  Found User: $($user.DisplayName)" -ForegroundColor $userColor
                Write-Host "    Type: $userType" -ForegroundColor Gray
                Write-Host "    Login: $($user.LoginName)" -ForegroundColor Gray
                if ($userType -eq "Guest User" -and $guestSource) {
                    Write-Host "    Guest Source: $guestSource" -ForegroundColor Cyan
                }
                if ($user.IsSiteAdmin) {
                    Write-Host "    *** SITE ADMIN ***" -ForegroundColor Red
                }
                
                # Get groups with retry and delay
                if ($processedCount % 10 -eq 0) {
                    Start-Sleep -Seconds 1  # Extra delay every 10 sites
                }
                
                $groups = Invoke-SPOCommandWithRetry -Command {
                    Get-SPOSiteGroup -Site $site.Url
                } -OperationName "Get Groups" -MaxRetries 2
                
                $userGroups = @()
                $foundInGroup = $false
                
                foreach ($group in $groups) {
                    try {
                        $groupMembers = Invoke-SPOCommandWithRetry -Command {
                            Get-SPOUser -Site $site.Url -Group $group.LoginName -ErrorAction Stop
                        } -OperationName "Get Group Members" -MaxRetries 2 -InitialDelay 1
                        
                        if ($groupMembers.LoginName -contains $user.LoginName) {
                            $foundInGroup = $true
                            $permissionLevel = switch -Wildcard ($group.Title) {
                                "*Owner*" { "Full Control" }
                                "*Member*" { "Edit" }
                                "*Visitor*" { "Read Only" }
                                "*Limited Access*" { "Limited Access" }
                                default { "Custom" }
                            }
                            
                            $userGroups += [PSCustomObject]@{
                                GroupName = $group.Title
                                Permission = $permissionLevel
                            }
                            
                            # Print group membership for ALL users
                            Write-Host "    - In group: $($group.Title) ($permissionLevel)" -ForegroundColor Cyan
                        }
                    }
                    catch {
                        # Skip if can't access this group
                        continue
                    }
                }
                
                # If user not in any groups, they have direct permissions
                if (-not $foundInGroup) {
                    Write-Host "    - Has direct permissions (not in any group)" -ForegroundColor Magenta
                }
                
                # Add to report
                if ($userGroups.Count -gt 0) {
                    foreach ($userGroup in $userGroups) {
                        $fullReport += [PSCustomObject]@{
                            Site = $site.Url
                            SiteType = if($site.Url -like "*-my.sharepoint.com/personal/*") {"OneDrive"} else {"SharePoint"}
                            SiteTitle = $site.Title
                            UserName = $user.DisplayName
                            UserLogin = $user.LoginName
                            UserType = $userType
                            GuestSource = $guestSource
                            Group = $userGroup.GroupName
                            Permission = $userGroup.Permission
                            IsSiteAdmin = $user.IsSiteAdmin
                        }
                    }
                } else {
                    # User with no groups (direct permissions)
                    $fullReport += [PSCustomObject]@{
                        Site = $site.Url
                        SiteType = if($site.Url -like "*-my.sharepoint.com/personal/*") {"OneDrive"} else {"SharePoint"}
                        SiteTitle = $site.Title
                        UserName = $user.DisplayName
                        UserLogin = $user.LoginName
                        UserType = $userType
                        GuestSource = $guestSource
                        Group = "Direct Permission"
                        Permission = "Custom"
                        IsSiteAdmin = $user.IsSiteAdmin
                    }
                }
            }
        }
        else {
            Write-Host "  No users found in this site" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  Error accessing site: $_" -ForegroundColor Red
        $failedSites += [PSCustomObject]@{
            Site = $site.Url
            Error = $_.Exception.Message
        }
    }
    
    # Progress checkpoint with extended pause
    if ($processedCount % 20 -eq 0 -and $processedCount -lt $totalSites) {
        Write-Host "`nProgress: $processedCount/$totalSites sites processed. Pausing 10 seconds to avoid rate limiting..." -ForegroundColor Magenta
        Start-Sleep -Seconds 10
    }
}

# Retry failed sites
if ($failedSites.Count -gt 0) {
    Write-Host "`n`nRetrying $($failedSites.Count) failed sites..." -ForegroundColor Yellow
    Start-Sleep -Seconds 15  # Longer pause before retrying
    
    foreach ($failedSite in $failedSites) {
        Write-Host "`nRetrying site: $($failedSite.Site)" -ForegroundColor Yellow
        
        try {
            # Attempt to process with longer delays
            Start-Sleep -Seconds 3
            
            $users = Invoke-SPOCommandWithRetry -Command {
                Get-SPOUser -Site $failedSite.Site -Limit All
            } -MaxRetries 5 -InitialDelay 5
            
            if ($users) {
                Write-Host "  Successfully retrieved $($users.Count) users on retry" -ForegroundColor Green
                
                # Process users same as above
                foreach ($user in $users) {
                    $userType = switch -Regex ($user.LoginName) {
                        "#EXT#" { "Guest User" }
                        "app@sharepoint" { "SharePoint App" }
                        "spo-grid-all-users" { "System Account" }
                        "c:0(.s|.t)" { "Security Group" }
                        "@<tenant>.onmicrosoft.com$" { "Internal User" }
                        "SHAREPOINT\\system" { "System Account" }
                        default { "Other" }
                    }
                    
                    $userColor = switch ($userType) {
                        "Guest User" { "Yellow" }
                        "Internal User" { "Green" }
                        "System Account" { "DarkGray" }
                        "SharePoint App" { "Cyan" }
                        default { "White" }
                    }
                    
                    Write-Host "  Found $userType - $($user.DisplayName)" -ForegroundColor $userColor
                }
            }
        }
        catch {
            Write-Host "  Still failing: $_" -ForegroundColor Red
        }
    }
}

# Display summary table of all users
Write-Host "`n`n========== COMPLETE USER REPORT TABLE ==========" -ForegroundColor Cyan
$fullReport | Format-Table Site, UserName, UserType, GuestSource, Group, Permission -AutoSize

# Generate summary statistics
Write-Host "`n`n========== SUMMARY STATISTICS ==========" -ForegroundColor Cyan

$stats = @{
    TotalSites = $allSites.Count
    TotalUserAssignments = $fullReport.Count
    InternalUsers = ($fullReport | Where-Object {$_.UserType -eq "Internal User"} | Select-Object -Unique UserLogin).Count
    GuestUsers = ($fullReport | Where-Object {$_.UserType -eq "Guest User"} | Select-Object -Unique UserLogin).Count
    ServiceAccounts = ($fullReport | Where-Object {$_.UserType -in @("System Account", "SharePoint App")} | Select-Object -Unique UserLogin).Count
    SecurityGroups = ($fullReport | Where-Object {$_.UserType -eq "Security Group"} | Select-Object -Unique UserLogin).Count
    FailedSites = $failedSites.Count
}

Write-Host "Total Sites Processed: $($stats.TotalSites)" -ForegroundColor White
Write-Host "Total User Assignments: $($stats.TotalUserAssignments)" -ForegroundColor White
Write-Host "Unique Internal Users: $($stats.InternalUsers)" -ForegroundColor Green
Write-Host "Unique Guest Users: $($stats.GuestUsers)" -ForegroundColor Yellow
Write-Host "Security Groups: $($stats.SecurityGroups)" -ForegroundColor Magenta
Write-Host "Service/System Accounts: $($stats.ServiceAccounts)" -ForegroundColor Gray
Write-Host "Failed Sites: $($stats.FailedSites)" -ForegroundColor Red

# User type summary
$userTypeSummary = $fullReport | Group-Object UserType | Select-Object Name, Count | Sort-Object Count -Descending
Write-Host "`n========== USER TYPE BREAKDOWN ==========" -ForegroundColor Cyan
$userTypeSummary | Format-Table -AutoSize

# Guest sources summary
$guestReport = $fullReport | Where-Object {$_.UserType -eq "Guest User"}
if ($guestReport) {
    $guestSources = $guestReport | Group-Object GuestSource | Select-Object Name, Count | Sort-Object Count -Descending
    Write-Host "`n========== GUEST SOURCE BREAKDOWN ==========" -ForegroundColor Cyan
    $guestSources | Format-Table -AutoSize
    
    Write-Host "`n========== ALL GUEST USERS ==========" -ForegroundColor Yellow
    $guestReport | Format-Table Site, UserName, GuestSource, Group, Permission -AutoSize
}

# Permission level summary
$permissionSummary = $fullReport | Group-Object Permission | Select-Object Name, Count | Sort-Object Count -Descending
Write-Host "`n========== PERMISSION LEVEL SUMMARY ==========" -ForegroundColor Cyan
$permissionSummary | Format-Table -AutoSize

# Sites with most users
Write-Host "`n========== TOP 10 SITES BY USER COUNT ==========" -ForegroundColor Cyan
$fullReport | Group-Object Site | 
    Select-Object @{Name="Site";Expression={$_.Name}}, @{Name="UserCount";Expression={$_.Count}} | 
    Sort-Object UserCount -Descending | 
    Select-Object -First 10 | 
    Format-Table -AutoSize

# Export reports
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$basePath = "C:\temp"

# Ensure directory exists
if (!(Test-Path $basePath)) {
    New-Item -ItemType Directory -Path $basePath | Out-Null
}

# Export files
$fullReport | Export-Csv -Path "$basePath\FullUserReport_$timestamp.csv" -NoTypeInformation
Write-Host "`nFull report exported to: $basePath\FullUserReport_$timestamp.csv" -ForegroundColor Green

if ($guestReport) {
    $guestReport | Export-Csv -Path "$basePath\GuestUserReport_$timestamp.csv" -NoTypeInformation
    Write-Host "Guest report exported to: $basePath\GuestUserReport_$timestamp.csv" -ForegroundColor Green
}

# Export internal users
$internalReport = $fullReport | Where-Object {$_.UserType -eq "Internal User"}
if ($internalReport) {
    $internalReport | Export-Csv -Path "$basePath\InternalUserReport_$timestamp.csv" -NoTypeInformation
    Write-Host "Internal user report exported to: $basePath\InternalUserReport_$timestamp.csv" -ForegroundColor Green
}

if ($failedSites.Count -gt 0) {
    $failedSites | Export-Csv -Path "$basePath\FailedSites_$timestamp.csv" -NoTypeInformation
    Write-Host "Failed sites exported to: $basePath\FailedSites_$timestamp.csv" -ForegroundColor Red
    
    Write-Host "`n========== FAILED SITES ==========" -ForegroundColor Red
    $failedSites | Format-Table -AutoSize
}

Write-Host "`n`nProcessing complete! All data has been displayed above and exported to CSV files." -ForegroundColor Green
