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
    
    while ($retryCount -lt $MaxRetries) {
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
                    "@matrixcoca.onmicrosoft.com$" { "Internal User" }
                    "SHAREPOINT\\system" { "System Account" }
                    default { "Other" }
                }
                
                # Determine guest source if applicable
                $guestSource = ""
                if ($userType -eq "Guest User") {
                    $guestSource = switch -Regex ($user.LoginName) {
                        "matrixhelicopter" { "MatrixHelicopter" }
                        "matrixco.ca" { "MatrixCo.ca" }
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
                        "@matrixcoca.onmicrosoft.com$" { "Internal User" }
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
