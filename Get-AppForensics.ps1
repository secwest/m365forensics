# M365 Tenant Application Registration Forensics Script
# Enumerates all applications, service principals, permissions, and ownership data

param(
    [string]$OutputPath = ".\AppRegistrationForensics_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$IncludeBuiltInApps = $false
)

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
Write-Host "Output will be saved to: $OutputPath" -ForegroundColor Green

# Function to safely get property values
function Get-SafeProperty {
    param($Object, $Property, $Default = "N/A")
    try {
        $value = $Object.$Property
        if ($null -eq $value -or $value -eq "") { return $Default }
        return $value
    }
    catch { return $Default }
}

# Function to safely filter by date
function Test-RecentlyCreated {
    param($CreatedDateTime, $DaysAgo = 30)
    
    if ($CreatedDateTime -eq "N/A" -or $null -eq $CreatedDateTime -or $CreatedDateTime -eq "") {
        return $false
    }
    
    try {
        $date = [DateTime]$CreatedDateTime
        return $date -gt (Get-Date).AddDays(-$DaysAgo)
    }
    catch {
        return $false
    }
}

# Function to convert permissions to readable format
function Convert-PermissionsToReadable {
    param($Permissions)
    if (-not $Permissions) { return @() }
    
    $readablePerms = @()
    foreach ($perm in $Permissions) {
        $permObj = [PSCustomObject]@{
            Type = Get-SafeProperty $perm "Type"
            Value = Get-SafeProperty $perm "Value" 
            Id = Get-SafeProperty $perm "Id"
        }
        $readablePerms += $permObj
    }
    return $readablePerms
}

# Function to determine if an application is a Microsoft built-in
function Test-IsMicrosoftBuiltIn {
    param($ServicePrincipal)
    
    # Well-known Microsoft Application IDs (partial list of common ones)
    $wellKnownMicrosoftAppIds = @{
        "00000003-0000-0000-c000-000000000000" = "Microsoft Graph"
        "00000002-0000-0000-c000-000000000000" = "Microsoft Graph (Legacy)"
        "797f4846-ba00-4fd7-ba43-dac1f8f63013" = "Windows Azure Service Management API"
        "00000001-0000-0000-c000-000000000000" = "Azure Active Directory Graph"
        "00000007-0000-0000-c000-000000000000" = "Microsoft Dynamics CRM"
        "48ac35b8-9aa8-4d74-927d-1f4a14a0b239" = "Microsoft Intune Web Company Portal"
        "0000000c-0000-0000-c000-000000000000" = "Microsoft App Access Panel"
        "89bee1f7-5e6e-4d8a-9f3d-ecd601259da7" = "Office365 Shell WCSS-Client"
        "c5393580-f805-4401-95e8-94b7a6ef2fc2" = "Office365 Management APIs"
        "4345a7b9-9a63-4910-a426-35363201d503" = "Office 365 Management APIs"
        "d3590ed6-52b3-4102-aeff-aad2292ab01c" = "Microsoft Office"
        "00000006-0000-0000-c000-000000000000" = "Microsoft Office 365 Portal"
        "67e3df25-268a-4324-a550-0de1c7f97287" = "Microsoft Office Web Apps Service"
    }
    
    $appId = Get-SafeProperty $ServicePrincipal "AppId"
    $publisherName = Get-SafeProperty $ServicePrincipal "PublisherName"
    $appOwnerOrgId = Get-SafeProperty $ServicePrincipal "AppOwnerOrganizationId"
    $servicePrincipalType = Get-SafeProperty $ServicePrincipal "ServicePrincipalType"
    $displayName = Get-SafeProperty $ServicePrincipal "DisplayName"
    
    # Check if it's a well-known Microsoft app
    if ($wellKnownMicrosoftAppIds.ContainsKey($appId)) {
        return @{
            IsMicrosoft = $true
            Category = "Microsoft Built-in"
            Reason = "Well-known Microsoft AppId: $($wellKnownMicrosoftAppIds[$appId])"
        }
    }
    
    # Check publisher name
    if ($publisherName -like "*Microsoft*" -or $publisherName -eq "Microsoft Services") {
        return @{
            IsMicrosoft = $true
            Category = "Microsoft Built-in"
            Reason = "Microsoft Publisher: $publisherName"
        }
    }
    
    # Check for Microsoft-owned organization
    if ($appOwnerOrgId -eq "f8cdef31-a31e-4b4a-93e4-5f571e91255a" -or  # Microsoft Services
        $appOwnerOrgId -eq "72f988bf-86f1-41af-91ab-2d7cd011db47") {      # Microsoft Corp
        return @{
            IsMicrosoft = $true
            Category = "Microsoft Built-in"
            Reason = "Microsoft Organization ID: $appOwnerOrgId"
        }
    }
    
    # Check for Microsoft-specific naming patterns
    if ($displayName -like "Microsoft*" -or 
        $displayName -like "Office*" -or 
        $displayName -like "Azure*" -or
        $displayName -like "Windows*" -or
        $displayName -like "*Graph*" -or
        $displayName -like "OneDrive*" -or
        $displayName -like "SharePoint*" -or
        $displayName -like "Exchange*" -or
        $displayName -like "Outlook*") {
        return @{
            IsMicrosoft = $true
            Category = "Microsoft Built-in"
            Reason = "Microsoft naming pattern: $displayName"
        }
    }
    
    # Check if owned by current tenant (user-created apps)
    if ($appOwnerOrgId -eq "63ad9bfc-1f87-4b03-918e-81434c7ae363") {
        return @{
            IsMicrosoft = $false
            Category = "Tenant-Created"
            Reason = "Owned by current tenant: $appOwnerOrgId"
        }
    }
    
    # If none of the above, likely third-party
    return @{
        IsMicrosoft = $false
        Category = "Third-Party/External"
        Reason = "External organization or unknown publisher: $publisherName"
    }
}

Write-Host "Starting comprehensive application enumeration..." -ForegroundColor Yellow

# 1. Get all Application Registrations
Write-Host "`n[1/6] Enumerating Application Registrations..." -ForegroundColor Cyan
try {
    $applications = Get-MgApplication -All -Property *
    Write-Host "Found $($applications.Count) application registrations" -ForegroundColor Green
    
    $appData = @()
    foreach ($app in $applications) {
        Write-Progress -Activity "Processing Applications" -Status "Processing $($app.DisplayName)" -PercentComplete (($appData.Count / $applications.Count) * 100)
        
        # Get owners
        $owners = @()
        try {
            $appOwners = Get-MgApplicationOwner -ApplicationId $app.Id
            foreach ($owner in $appOwners) {
                $ownerDetails = Get-MgDirectoryObject -DirectoryObjectId $owner.Id
                $owners += "$($ownerDetails.AdditionalProperties.displayName) ($($ownerDetails.AdditionalProperties.userPrincipalName))"
            }
        }
        catch { $owners = @("Unable to retrieve") }
        
        # Get API permissions
        $apiPermissions = @()
        if ($app.RequiredResourceAccess) {
            foreach ($resource in $app.RequiredResourceAccess) {
                foreach ($access in $resource.ResourceAccess) {
                    $apiPermissions += [PSCustomObject]@{
                        ResourceId = $resource.ResourceAppId
                        PermissionId = $access.Id
                        Type = $access.Type
                    }
                }
            }
        }
        
        $appInfo = [PSCustomObject]@{
            DisplayName = Get-SafeProperty $app "DisplayName"
            ApplicationId = Get-SafeProperty $app "AppId"
            ObjectId = Get-SafeProperty $app "Id"
            CreatedDateTime = Get-SafeProperty $app "CreatedDateTime"
            PublisherDomain = Get-SafeProperty $app "PublisherDomain"
            Homepage = Get-SafeProperty $app "Web.HomePageUrl"
            ReplyUrls = ($app.Web.RedirectUris -join "; ")
            LogoutUrl = Get-SafeProperty $app "Web.LogoutUrl"
            Owners = ($owners -join "; ")
            SignInAudience = Get-SafeProperty $app "SignInAudience"
            AppType = "Application Registration"
            Tags = ($app.Tags -join "; ")
            ApiPermissionsCount = $apiPermissions.Count
            ApiPermissions = ($apiPermissions | ConvertTo-Json -Compress)
            KeyCredentialsCount = $app.KeyCredentials.Count
            PasswordCredentialsCount = $app.PasswordCredentials.Count
            IsEnabled = "N/A"
        }
        $appData += $appInfo
    }
    
    # Export applications data
    $appData | Export-Csv -Path "$OutputPath\ApplicationRegistrations.csv" -NoTypeInformation
    Write-Host "Application registrations exported to ApplicationRegistrations.csv" -ForegroundColor Green
}
catch {
    Write-Host "Error retrieving applications: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Get all Service Principals (Enterprise Applications)
Write-Host "`n[2/6] Enumerating Service Principals (Enterprise Applications)..." -ForegroundColor Cyan
try {
    # Get ALL service principals first
    $allServicePrincipals = Get-MgServicePrincipal -All -Property *
    Write-Host "Found $($allServicePrincipals.Count) total service principals" -ForegroundColor Green
    
    $spData = @()
    $microsoftBuiltIns = 0
    $tenantCreated = 0
    $thirdParty = 0
    
    foreach ($sp in $allServicePrincipals) {
        Write-Progress -Activity "Processing Service Principals" -Status "Processing $($sp.DisplayName)" -PercentComplete (($spData.Count / $allServicePrincipals.Count) * 100)
        
        # Categorize the application
        $category = Test-IsMicrosoftBuiltIn -ServicePrincipal $sp
        
        # Count by category
        switch ($category.Category) {
            "Microsoft Built-in" { $microsoftBuiltIns++ }
            "Tenant-Created" { $tenantCreated++ }
            "Third-Party/External" { $thirdParty++ }
        }
        
        # Get owners
        $owners = @()
        try {
            $spOwners = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id
            foreach ($owner in $spOwners) {
                $ownerDetails = Get-MgDirectoryObject -DirectoryObjectId $owner.Id
                $owners += "$($ownerDetails.AdditionalProperties.displayName) ($($ownerDetails.AdditionalProperties.userPrincipalName))"
            }
        }
        catch { $owners = @("Unable to retrieve") }
        
        # Get delegated permissions (OAuth2PermissionGrants)
        $delegatedPerms = @()
        try {
            $oauth2Grants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)'"
            foreach ($grant in $oauth2Grants) {
                $delegatedPerms += [PSCustomObject]@{
                    ResourceId = $grant.ResourceId
                    Scope = $grant.Scope
                    ConsentType = $grant.ConsentType
                    PrincipalId = $grant.PrincipalId
                }
            }
        }
        catch { }
        
        # Get app role assignments
        $appRoleAssignments = @()
        try {
            $roleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
            foreach ($assignment in $roleAssignments) {
                $appRoleAssignments += [PSCustomObject]@{
                    ResourceId = $assignment.ResourceId
                    AppRoleId = $assignment.AppRoleId
                    PrincipalType = $assignment.PrincipalType
                    CreatedDateTime = $assignment.CreatedDateTime
                }
            }
        }
        catch { }
        
        $spInfo = [PSCustomObject]@{
            DisplayName = Get-SafeProperty $sp "DisplayName"
            ApplicationId = Get-SafeProperty $sp "AppId"
            ObjectId = Get-SafeProperty $sp "Id"
            CreatedDateTime = Get-SafeProperty $sp "CreatedDateTime"
            PublisherName = Get-SafeProperty $sp "PublisherName"
            Homepage = Get-SafeProperty $sp "Homepage"
            ReplyUrls = ($sp.ReplyUrls -join "; ")
            LogoutUrl = Get-SafeProperty $sp "LogoutUrl"
            Owners = ($owners -join "; ")
            ServicePrincipalType = Get-SafeProperty $sp "ServicePrincipalType"
            AppType = "Service Principal"
            Tags = ($sp.Tags -join "; ")
            AccountEnabled = Get-SafeProperty $sp "AccountEnabled"
            AppOwnerOrganizationId = Get-SafeProperty $sp "AppOwnerOrganizationId"
            DelegatedPermissionsCount = $delegatedPerms.Count
            DelegatedPermissions = ($delegatedPerms | ConvertTo-Json -Compress)
            AppRoleAssignmentsCount = $appRoleAssignments.Count
            AppRoleAssignments = ($appRoleAssignments | ConvertTo-Json -Compress)
            KeyCredentialsCount = $sp.KeyCredentials.Count
            PasswordCredentialsCount = $sp.PasswordCredentials.Count
            IsEnabled = Get-SafeProperty $sp "AccountEnabled"
            # New categorization fields
            Category = $category.Category
            IsMicrosoftBuiltIn = $category.IsMicrosoft
            CategoryReason = $category.Reason
        }
        $spData += $spInfo
    }
    
    Write-Host "Categorization Summary:" -ForegroundColor Yellow
    Write-Host "  Microsoft Built-ins: $microsoftBuiltIns" -ForegroundColor Cyan
    Write-Host "  Tenant-Created: $tenantCreated" -ForegroundColor Green
    Write-Host "  Third-Party/External: $thirdParty" -ForegroundColor Magenta
    
    # Export all service principals data
    $spData | Export-Csv -Path "$OutputPath\ServicePrincipals_All.csv" -NoTypeInformation
    
    # Export only non-Microsoft applications (high priority for forensics)
    $nonMicrosoftApps = $spData | Where-Object { -not $_.IsMicrosoftBuiltIn }
    $nonMicrosoftApps | Export-Csv -Path "$OutputPath\ServicePrincipals_NonMicrosoft.csv" -NoTypeInformation
    
    # Export tenant-created applications
    $tenantApps = $spData | Where-Object { $_.Category -eq "Tenant-Created" }
    $tenantApps | Export-Csv -Path "$OutputPath\ServicePrincipals_TenantCreated.csv" -NoTypeInformation
    
    Write-Host "Service principals exported to:" -ForegroundColor Green
    Write-Host "  - ServicePrincipals_All.csv (all $($spData.Count) apps)" -ForegroundColor White
    Write-Host "  - ServicePrincipals_NonMicrosoft.csv ($($nonMicrosoftApps.Count) non-Microsoft apps)" -ForegroundColor White
    Write-Host "  - ServicePrincipals_TenantCreated.csv ($($tenantApps.Count) tenant-created apps)" -ForegroundColor White
}
catch {
    Write-Host "Error retrieving service principals: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Get OAuth2 Permission Grants (Delegated Permissions)
Write-Host "`n[3/6] Enumerating OAuth2 Permission Grants..." -ForegroundColor Cyan
try {
    $oauth2Grants = Get-MgOauth2PermissionGrant -All
    Write-Host "Found $($oauth2Grants.Count) OAuth2 permission grants" -ForegroundColor Green
    
    $grantData = @()
    foreach ($grant in $oauth2Grants) {
        # Get client and resource details
        $clientName = "Unknown"
        $resourceName = "Unknown"
        
        try {
            $client = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction SilentlyContinue
            $clientName = $client.DisplayName
        } catch { }
        
        try {
            $resource = Get-MgServicePrincipal -ServicePrincipalId $grant.ResourceId -ErrorAction SilentlyContinue
            $resourceName = $resource.DisplayName
        } catch { }
        
        $grantInfo = [PSCustomObject]@{
            Id = $grant.Id
            ClientId = $grant.ClientId
            ClientName = $clientName
            ResourceId = $grant.ResourceId
            ResourceName = $resourceName
            Scope = $grant.Scope
            ConsentType = $grant.ConsentType
            PrincipalId = $grant.PrincipalId
            ExpiryTime = $grant.ExpiryTime
        }
        $grantData += $grantInfo
    }
    
    $grantData | Export-Csv -Path "$OutputPath\OAuth2PermissionGrants.csv" -NoTypeInformation
    Write-Host "OAuth2 permission grants exported to OAuth2PermissionGrants.csv" -ForegroundColor Green
}
catch {
    Write-Host "Error retrieving OAuth2 permission grants: $($_.Exception.Message)" -ForegroundColor Red
}

# 4. Get App Role Assignments
Write-Host "`n[4/6] Enumerating App Role Assignments..." -ForegroundColor Cyan
try {
    $allAppRoleAssignments = @()
    
    # Get assignments for each service principal
    foreach ($sp in $allServicePrincipals) {
        try {
            $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
            foreach ($assignment in $assignments) {
                $resourceName = "Unknown"
                try {
                    $resource = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId -ErrorAction SilentlyContinue
                    $resourceName = $resource.DisplayName
                } catch { }
                
                $assignmentInfo = [PSCustomObject]@{
                    Id = $assignment.Id
                    PrincipalId = $assignment.PrincipalId
                    PrincipalDisplayName = $sp.DisplayName
                    ResourceId = $assignment.ResourceId
                    ResourceDisplayName = $resourceName
                    AppRoleId = $assignment.AppRoleId
                    PrincipalType = $assignment.PrincipalType
                    CreatedDateTime = $assignment.CreatedDateTime
                }
                $allAppRoleAssignments += $assignmentInfo
            }
        }
        catch { }
    }
    
    Write-Host "Found $($allAppRoleAssignments.Count) app role assignments" -ForegroundColor Green
    $allAppRoleAssignments | Export-Csv -Path "$OutputPath\AppRoleAssignments.csv" -NoTypeInformation
    Write-Host "App role assignments exported to AppRoleAssignments.csv" -ForegroundColor Green
}
catch {
    Write-Host "Error retrieving app role assignments: $($_.Exception.Message)" -ForegroundColor Red
}

# 5. Get Application Credentials (Certificates and Secrets)
Write-Host "`n[5/6] Enumerating Application Credentials..." -ForegroundColor Cyan
try {
    $credentialData = @()
    
    # Check both applications and service principals for credentials
    $allEntities = @()
    $allEntities += $applications | Select-Object Id, DisplayName, @{Name="Type"; Expression={"Application"}}, KeyCredentials, PasswordCredentials
    $allEntities += $allServicePrincipals | Select-Object Id, DisplayName, @{Name="Type"; Expression={"ServicePrincipal"}}, KeyCredentials, PasswordCredentials
    
    foreach ($entity in $allEntities) {
        # Process key credentials (certificates)
        foreach ($keyCred in $entity.KeyCredentials) {
            $credInfo = [PSCustomObject]@{
                EntityId = $entity.Id
                EntityName = $entity.DisplayName
                EntityType = $entity.Type
                CredentialType = "Certificate"
                KeyId = $keyCred.KeyId
                Usage = $keyCred.Usage
                Type = $keyCred.Type
                StartDateTime = $keyCred.StartDateTime
                EndDateTime = $keyCred.EndDateTime
                DisplayName = $keyCred.DisplayName
                CustomKeyIdentifier = try { [System.Convert]::ToBase64String($keyCred.CustomKeyIdentifier) } catch { "N/A" }
            }
            $credentialData += $credInfo
        }
        
        # Process password credentials (secrets)
        foreach ($passCred in $entity.PasswordCredentials) {
            $credInfo = [PSCustomObject]@{
                EntityId = $entity.Id
                EntityName = $entity.DisplayName
                EntityType = $entity.Type
                CredentialType = "Secret"
                KeyId = $passCred.KeyId
                Usage = "N/A"
                Type = "N/A"
                StartDateTime = $passCred.StartDateTime
                EndDateTime = $passCred.EndDateTime
                DisplayName = $passCred.DisplayName
                CustomKeyIdentifier = "N/A"
            }
            $credentialData += $credInfo
        }
    }
    
    Write-Host "Found $($credentialData.Count) credentials across all applications" -ForegroundColor Green
    $credentialData | Export-Csv -Path "$OutputPath\ApplicationCredentials.csv" -NoTypeInformation
    Write-Host "Application credentials exported to ApplicationCredentials.csv" -ForegroundColor Green
}
catch {
    Write-Host "Error retrieving application credentials: $($_.Exception.Message)" -ForegroundColor Red
}

# 6. Generate Summary Report and Pretty Print Results
Write-Host "`n[6/6] Generating Summary Report and Analysis..." -ForegroundColor Cyan

# Function to generate HTML report
function New-ForensicsHtmlReport {
    param(
        $Applications,
        $AllServicePrincipals, 
        $TenantApps,
        $NonMicrosoftApps,
        $OAuth2Grants,
        $AppRoleAssignments,
        $Credentials,
        $MicrosoftCount,
        $TenantCount,
        $ThirdPartyCount,
        $OutputPath
    )
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>M365 Application Forensics Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; margin: -30px -30px 30px -30px; border-radius: 10px 10px 0 0; }
        .tenant-info { background-color: #e8f4f8; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #2196F3; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-box { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 15px; border-radius: 8px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; }
        .stat-label { font-size: 0.9em; opacity: 0.9; }
        .priority-high { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%); }
        .priority-medium { background: linear-gradient(135deg, #feca57 0%, #ff9ff3 100%); }
        .priority-low { background: linear-gradient(135deg, #48dbfb 0%, #0abde3 100%); }
        .section { margin: 30px 0; padding: 20px; background-color: #fafafa; border-radius: 8px; border-left: 4px solid #4CAF50; }
        .section-title { color: #2c3e50; font-size: 1.3em; font-weight: bold; margin-bottom: 15px; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; background-color: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        th { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px; text-align: left; font-weight: bold; }
        td { padding: 10px 12px; border-bottom: 1px solid #ddd; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f0f8ff; }
        .alert-danger { background-color: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; border-left: 4px solid #dc3545; margin: 10px 0; }
        .alert-warning { background-color: #fff3cd; color: #856404; padding: 10px; border-radius: 5px; border-left: 4px solid #ffc107; margin: 10px 0; }
        .alert-info { background-color: #d1ecf1; color: #0c5460; padding: 10px; border-radius: 5px; border-left: 4px solid #17a2b8; margin: 10px 0; }
        .recommendations { background-color: #e8f5e8; padding: 20px; border-radius: 8px; border-left: 4px solid #28a745; }
        .file-list { background-color: #f8f9fa; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; }
        .timestamp { color: #6c757d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 M365 Application Forensics Report</h1>
            <p>Comprehensive security analysis of application registrations and enterprise applications</p>
        </div>
        
        <div class="tenant-info">
            <h3>📋 Tenant Information</h3>
            <strong>Organization:</strong> Matrix Helicopter Solutions Inc<br>
            <strong>Tenant ID:</strong> 63ad9bfc-1f87-4b03-918e-81434c7ae363<br>
            <strong>Analysis Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
            <strong>Domain:</strong> MatrixHelicopter.onmicrosoft.com, matrixco.ca
        </div>

        <div class="stats-grid">
            <div class="stat-box priority-high">
                <div class="stat-number">$TenantCount</div>
                <div class="stat-label">Tenant-Created Apps</div>
            </div>
            <div class="stat-box priority-medium">
                <div class="stat-number">$ThirdPartyCount</div>
                <div class="stat-label">Third-Party Apps</div>
            </div>
            <div class="stat-box priority-low">
                <div class="stat-number">$MicrosoftCount</div>
                <div class="stat-label">Microsoft Built-ins</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">$($Applications.Count)</div>
                <div class="stat-label">App Registrations</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">$($OAuth2Grants.Count)</div>
                <div class="stat-label">OAuth2 Grants</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">$($Credentials.Count)</div>
                <div class="stat-label">Credentials</div>
            </div>
        </div>

        <div class="alert-danger">
            <strong>🚨 CRITICAL FINDINGS:</strong> Focus your investigation on the $TenantCount tenant-created applications and $ThirdPartyCount third-party applications listed below.
        </div>
"@

    # Add Tenant-Created Applications section
    if ($TenantApps.Count -gt 0) {
        $htmlContent += @"
        <div class="section">
            <div class="section-title">🔴 Tenant-Created Applications (HIGHEST PRIORITY)</div>
            <div class="alert-danger">These applications were created directly in your tenant and require immediate review.</div>
            <table>
                <tr>
                    <th>Application Name</th>
                    <th>Created Date</th>
                    <th>Publisher</th>
                    <th>Permissions</th>
                    <th>Enabled</th>
                    <th>Credentials</th>
                </tr>
"@
        foreach ($app in $TenantApps) {
            $permCount = [int]$app.DelegatedPermissionsCount + [int]$app.AppRoleAssignmentsCount
            $credCount = [int]$app.KeyCredentialsCount + [int]$app.PasswordCredentialsCount
            $htmlContent += @"
                <tr>
                    <td><strong>$($app.DisplayName)</strong></td>
                    <td>$($app.CreatedDateTime)</td>
                    <td>$($app.PublisherName)</td>
                    <td>$permCount</td>
                    <td>$($app.IsEnabled)</td>
                    <td>$credCount</td>
                </tr>
"@
        }
        $htmlContent += "</table></div>"
    }

    # Add Third-Party Applications section
    $thirdPartyApps = $NonMicrosoftApps | Where-Object { $_.Category -eq "Third-Party/External" } | Select-Object -First 20
    if ($thirdPartyApps.Count -gt 0) {
        $htmlContent += @"
        <div class="section">
            <div class="section-title">🟡 Third-Party/External Applications (HIGH PRIORITY)</div>
            <div class="alert-warning">These applications are from external organizations and should be reviewed for legitimacy.</div>
            <table>
                <tr>
                    <th>Application Name</th>
                    <th>Publisher</th>
                    <th>Created Date</th>
                    <th>Category Reason</th>
                    <th>Permissions</th>
                </tr>
"@
        foreach ($app in $thirdPartyApps) {
            $permCount = [int]$app.DelegatedPermissionsCount + [int]$app.AppRoleAssignmentsCount
            $htmlContent += @"
                <tr>
                    <td><strong>$($app.DisplayName)</strong></td>
                    <td>$($app.PublisherName)</td>
                    <td>$($app.CreatedDateTime)</td>
                    <td><small>$($app.CategoryReason)</small></td>
                    <td>$permCount</td>
                </tr>
"@
        }
        $htmlContent += "</table></div>"
    }

    # Add Recent Applications section
    $recentApps = $NonMicrosoftApps | Where-Object { Test-RecentlyCreated -CreatedDateTime $_.CreatedDateTime -DaysAgo 30 } | Select-Object -First 10
    if ($recentApps.Count -gt 0) {
        $htmlContent += @"
        <div class="section">
            <div class="section-title">📅 Recently Created Applications (Last 30 Days)</div>
            <div class="alert-info">Applications created recently may correlate with security incidents.</div>
            <table>
                <tr>
                    <th>Application Name</th>
                    <th>Created Date</th>
                    <th>Category</th>
                    <th>Publisher</th>
                    <th>Permissions</th>
                </tr>
"@
        foreach ($app in $recentApps) {
            $permCount = [int]$app.DelegatedPermissionsCount + [int]$app.AppRoleAssignmentsCount
            $htmlContent += @"
                <tr>
                    <td><strong>$($app.DisplayName)</strong></td>
                    <td>$($app.CreatedDateTime)</td>
                    <td>$($app.Category)</td>
                    <td>$($app.PublisherName)</td>
                    <td>$permCount</td>
                </tr>
"@
        }
        $htmlContent += "</table></div>"
    }

    # Add High-Permission Applications section
    $highPermApps = $NonMicrosoftApps | Where-Object { ([int]$_.DelegatedPermissionsCount + [int]$_.AppRoleAssignmentsCount) -gt 5 } | 
                    Sort-Object { [int]$_.DelegatedPermissionsCount + [int]$_.AppRoleAssignmentsCount } -Descending | Select-Object -First 15
    if ($highPermApps.Count -gt 0) {
        $htmlContent += @"
        <div class="section">
            <div class="section-title">⚠️ Applications with Excessive Permissions</div>
            <div class="alert-warning">Applications with many permissions may pose security risks.</div>
            <table>
                <tr>
                    <th>Application Name</th>
                    <th>Total Permissions</th>
                    <th>Category</th>
                    <th>Publisher</th>
                    <th>Created Date</th>
                </tr>
"@
        foreach ($app in $highPermApps) {
            $permCount = [int]$app.DelegatedPermissionsCount + [int]$app.AppRoleAssignmentsCount
            $htmlContent += @"
                <tr>
                    <td><strong>$($app.DisplayName)</strong></td>
                    <td><strong>$permCount</strong></td>
                    <td>$($app.Category)</td>
                    <td>$($app.PublisherName)</td>
                    <td>$($app.CreatedDateTime)</td>
                </tr>
"@
        }
        $htmlContent += "</table></div>"
    }

    # Add Credentials Analysis section
    $multiCredApps = $Credentials | Where-Object { $_.EntityName -in $NonMicrosoftApps.DisplayName } | 
                     Group-Object EntityName | Where-Object Count -gt 1 | Select-Object -First 10
    if ($multiCredApps.Count -gt 0) {
        $htmlContent += @"
        <div class="section">
            <div class="section-title">🔑 Applications with Multiple Credentials</div>
            <div class="alert-info">Applications with multiple authentication methods may indicate sophistication or misuse.</div>
            <table>
                <tr>
                    <th>Application Name</th>
                    <th>Credential Count</th>
                    <th>Credential Types</th>
                </tr>
"@
        foreach ($group in $multiCredApps) {
            $credTypes = ($group.Group.CredentialType | Sort-Object -Unique) -join ", "
            $htmlContent += @"
                <tr>
                    <td><strong>$($group.Name)</strong></td>
                    <td>$($group.Count)</td>
                    <td>$credTypes</td>
                </tr>
"@
        }
        $htmlContent += "</table></div>"
    }

    # Add recommendations and files section
    $htmlContent += @"
        <div class="recommendations">
            <h3>📋 Recommended Actions</h3>
            <h4>🔴 IMMEDIATE (Next 24 Hours):</h4>
            <ul>
                <li>Review all $TenantCount tenant-created applications for legitimacy</li>
                <li>Investigate applications created by non-administrative users</li>
                <li>Check for applications with suspicious names or unexpected permissions</li>
                <li>Disable any unauthorized applications immediately</li>
            </ul>
            
            <h4>🟡 HIGH PRIORITY (Next 72 Hours):</h4>
            <ul>
                <li>Audit all $ThirdPartyCount third-party applications for business justification</li>
                <li>Review applications with broad Microsoft Graph permissions</li>
                <li>Check for expired or soon-to-expire credentials</li>
                <li>Validate OAuth consent grants, especially admin consent</li>
            </ul>
            
            <h4>🟢 ONGOING MONITORING:</h4>
            <ul>
                <li>Implement alerts for new application registrations</li>
                <li>Regular review of applications accessing sensitive resources</li>
                <li>Monitor for applications with escalating permissions</li>
                <li>Establish application governance policies</li>
            </ul>
        </div>

        <div class="section">
            <div class="section-title">📁 Generated Files</div>
            <div class="file-list">
                <strong>🔴 High Priority Files:</strong><br>
                • ServicePrincipals_TenantCreated.csv ($TenantCount apps)<br>
                • ServicePrincipals_NonMicrosoft.csv ($($NonMicrosoftApps.Count) apps)<br><br>
                
                <strong>📊 Complete Analysis Files:</strong><br>
                • ApplicationRegistrations.csv ($($Applications.Count) apps)<br>
                • ServicePrincipals_All.csv ($($AllServicePrincipals.Count) apps)<br>
                • OAuth2PermissionGrants.csv ($($OAuth2Grants.Count) grants)<br>
                • AppRoleAssignments.csv ($($AppRoleAssignments.Count) assignments)<br>
                • ApplicationCredentials.csv ($($Credentials.Count) credentials)<br>
                • ForensicsSummary.txt (Text summary)<br>
                • ForensicsReport.html (This report)<br>
            </div>
        </div>

        <div class="section">
            <div class="section-title">🔍 Threat Hunting Queries</div>
            <div class="alert-info">
                <strong>Suspicious Permission Patterns:</strong><br>
                Search OAuth2PermissionGrants.csv for: Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory, User.ReadWrite.All<br><br>
                
                <strong>Admin Consent Grants:</strong><br>
                Filter OAuth2PermissionGrants.csv where ConsentType = "AllPrincipals"<br><br>
                
                <strong>External Publishers:</strong><br>
                Review ServicePrincipals_NonMicrosoft.csv for unfamiliar publisher names<br><br>
                
                <strong>Correlation Analysis:</strong><br>
                Cross-reference application creation dates with security incident timelines
            </div>
        </div>

        <div class="timestamp">
            <hr>
            <p><em>Report generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") by M365 Application Forensics Tool</em></p>
        </div>
    </div>
</body>
</html>
"@

    return $htmlContent
}

# Generate HTML Report
$htmlReport = New-ForensicsHtmlReport -Applications $applications -AllServicePrincipals $spData -TenantApps $tenantApps -NonMicrosoftApps $nonMicrosoftApps -OAuth2Grants $oauth2Grants -AppRoleAssignments $allAppRoleAssignments -Credentials $credentialData -MicrosoftCount $microsoftBuiltIns -TenantCount $tenantCreated -ThirdPartyCount $thirdParty -OutputPath $OutputPath

$htmlReport | Out-File -FilePath "$OutputPath\ForensicsReport.html" -Encoding UTF8

# Console Pretty Print
Write-Host "`n" -NoNewline
Write-Host "="*80 -ForegroundColor Blue
Write-Host "🔍 M365 APPLICATION FORENSICS ANALYSIS COMPLETE" -ForegroundColor White -BackgroundColor Blue
Write-Host "="*80 -ForegroundColor Blue

Write-Host "`n📋 TENANT INFORMATION:" -ForegroundColor Cyan
Write-Host "   Organization: Matrix Helicopter Solutions Inc" -ForegroundColor White
Write-Host "   Tenant ID: 63ad9bfc-1f87-4b03-918e-81434c7ae363" -ForegroundColor White
Write-Host "   Analysis Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White

Write-Host "`n📊 SUMMARY STATISTICS:" -ForegroundColor Cyan
Write-Host "   ├─ Application Registrations: $($applications.Count)" -ForegroundColor White
Write-Host "   ├─ Total Service Principals: $($spData.Count)" -ForegroundColor White
Write-Host "   │  ├─ 🔴 Tenant-Created: $tenantCreated" -ForegroundColor Red
Write-Host "   │  ├─ 🟡 Third-Party/External: $thirdParty" -ForegroundColor Yellow
Write-Host "   │  └─ 🟢 Microsoft Built-ins: $microsoftBuiltIns" -ForegroundColor Green
Write-Host "   ├─ OAuth2 Permission Grants: $($oauth2Grants.Count)" -ForegroundColor White
Write-Host "   ├─ App Role Assignments: $($allAppRoleAssignments.Count)" -ForegroundColor White
Write-Host "   └─ Total Credentials: $($credentialData.Count)" -ForegroundColor White

if ($tenantCreated -gt 0) {
    Write-Host "`n🔴 TENANT-CREATED APPLICATIONS (HIGHEST PRIORITY):" -ForegroundColor Red
    $tenantApps | Select-Object DisplayName, CreatedDateTime, PublisherName, 
        @{Name="Permissions";Expression={[int]$_.DelegatedPermissionsCount + [int]$_.AppRoleAssignmentsCount}},
        @{Name="Credentials";Expression={[int]$_.KeyCredentialsCount + [int]$_.PasswordCredentialsCount}} |
        Format-Table -AutoSize | Out-String | Write-Host
}

$thirdPartyApps = $nonMicrosoftApps | Where-Object { $_.Category -eq "Third-Party/External" } | Select-Object -First 10
if ($thirdPartyApps.Count -gt 0) {
    Write-Host "🟡 THIRD-PARTY APPLICATIONS (HIGH PRIORITY - Top 10):" -ForegroundColor Yellow
    $thirdPartyApps | Select-Object DisplayName, PublisherName, CreatedDateTime,
        @{Name="Permissions";Expression={[int]$_.DelegatedPermissionsCount + [int]$_.AppRoleAssignmentsCount}} |
        Format-Table -AutoSize | Out-String | Write-Host
}

$recentApps = $nonMicrosoftApps | Where-Object { Test-RecentlyCreated -CreatedDateTime $_.CreatedDateTime -DaysAgo 30 } | Select-Object -First 5
if ($recentApps.Count -gt 0) {
    Write-Host "📅 RECENTLY CREATED APPLICATIONS (Last 30 Days - Top 5):" -ForegroundColor Magenta
    $recentApps | Select-Object DisplayName, CreatedDateTime, Category, PublisherName |
        Format-Table -AutoSize | Out-String | Write-Host
}

$highPermApps = $nonMicrosoftApps | Where-Object { ([int]$_.DelegatedPermissionsCount + [int]$_.AppRoleAssignmentsCount) -gt 5 } | 
                Sort-Object { [int]$_.DelegatedPermissionsCount + [int]$_.AppRoleAssignmentsCount } -Descending | Select-Object -First 5
if ($highPermApps.Count -gt 0) {
    Write-Host "⚠️  APPLICATIONS WITH EXCESSIVE PERMISSIONS (Top 5):" -ForegroundColor DarkYellow
    $highPermApps | Select-Object DisplayName, Category,
        @{Name="TotalPermissions";Expression={[int]$_.DelegatedPermissionsCount + [int]$_.AppRoleAssignmentsCount}},
        PublisherName | Format-Table -AutoSize | Out-String | Write-Host
}

Write-Host "📋 RECOMMENDED IMMEDIATE ACTIONS:" -ForegroundColor Cyan
Write-Host "   🔴 Review $tenantCreated tenant-created applications" -ForegroundColor Red
Write-Host "   🟡 Audit $thirdParty third-party applications" -ForegroundColor Yellow
Write-Host "   ⚠️  Check applications with >5 permissions" -ForegroundColor DarkYellow
Write-Host "   📅 Investigate recent application registrations" -ForegroundColor Magenta
Write-Host "   🔑 Review applications with multiple credentials" -ForegroundColor Cyan

Write-Host "`n📁 GENERATED FILES:" -ForegroundColor Cyan
Write-Host "   🔴 ServicePrincipals_TenantCreated.csv ($tenantCreated apps)" -ForegroundColor Red
Write-Host "   🟡 ServicePrincipals_NonMicrosoft.csv ($($nonMicrosoftApps.Count) apps)" -ForegroundColor Yellow
Write-Host "   📊 ForensicsReport.html (Interactive HTML report)" -ForegroundColor Green
Write-Host "   📋 ForensicsSummary.txt (Text summary)" -ForegroundColor White
Write-Host "   📄 All other CSV files for detailed analysis" -ForegroundColor Gray

Write-Host "`n🌐 OPEN HTML REPORT:" -ForegroundColor Green
Write-Host "   File: $OutputPath\ForensicsReport.html" -ForegroundColor White

$summary = @"
=== M365 Tenant Application Registration Forensics Summary ===
Tenant: Matrix Helicopter Solutions Inc (63ad9bfc-1f87-4b03-918e-81434c7ae363)
Analysis Date: $(Get-Date)

COUNTS:
- Application Registrations: $($applications.Count)
- Total Service Principals: $($spData.Count)
  * Microsoft Built-ins: $microsoftBuiltIns
  * Tenant-Created: $tenantCreated  
  * Third-Party/External: $thirdParty
- OAuth2 Permission Grants: $($oauth2Grants.Count)
- App Role Assignments: $($allAppRoleAssignments.Count)
- Total Credentials: $($credentialData.Count)

=== FORENSIC PRIORITY ANALYSIS ===

1. TENANT-CREATED APPLICATIONS (Highest Priority):
$($tenantApps | Select-Object DisplayName, CreatedDateTime, PublisherName, @{Name="Permissions";Expression={$_.DelegatedPermissionsCount + $_.AppRoleAssignmentsCount}} | Format-Table -AutoSize | Out-String)

2. THIRD-PARTY/EXTERNAL APPLICATIONS (High Priority):
$($spData | Where-Object { $_.Category -eq "Third-Party/External" } | Select-Object DisplayName, CreatedDateTime, PublisherName, CategoryReason | Format-Table -AutoSize | Out-String)

3. NON-MICROSOFT APPLICATIONS WITH EXCESSIVE PERMISSIONS:
$($nonMicrosoftApps | Where-Object { ([int]$_.DelegatedPermissionsCount + [int]$_.AppRoleAssignmentsCount) -gt 5 } | Select-Object DisplayName, Category, @{Name="TotalPermissions";Expression={[int]$_.DelegatedPermissionsCount + [int]$_.AppRoleAssignmentsCount}}, PublisherName | Format-Table -AutoSize | Out-String)

4. RECENTLY CREATED NON-MICROSOFT APPLICATIONS (Last 30 days):
$($nonMicrosoftApps | Where-Object { Test-RecentlyCreated -CreatedDateTime $_.CreatedDateTime -DaysAgo 30 } | Select-Object DisplayName, CreatedDateTime, Category, PublisherName | Format-Table -AutoSize | Out-String)

5. NON-MICROSOFT APPLICATIONS WITH MULTIPLE CREDENTIALS:
$($credentialData | Where-Object { $_.EntityName -in $nonMicrosoftApps.DisplayName } | Group-Object EntityName | Where-Object Count -gt 1 | ForEach-Object { [PSCustomObject]@{ApplicationName = $_.Name; CredentialCount = $_.Count; CredentialTypes = ($_.Group.CredentialType | Sort-Object -Unique) -join ", "} } | Format-Table -AutoSize | Out-String)

FILES GENERATED:
- ApplicationRegistrations.csv: All registered applications ($($applications.Count) apps)
- ServicePrincipals_All.csv: All enterprise applications ($($spData.Count) apps)
- ServicePrincipals_NonMicrosoft.csv: Non-Microsoft applications ($($nonMicrosoftApps.Count) apps) ⚠️ HIGH PRIORITY
- ServicePrincipals_TenantCreated.csv: Tenant-created applications ($($tenantApps.Count) apps) ⚠️ HIGHEST PRIORITY
- OAuth2PermissionGrants.csv: Delegated permissions ($($oauth2Grants.Count) grants)
- AppRoleAssignments.csv: Application role assignments ($($allAppRoleAssignments.Count) assignments)
- ApplicationCredentials.csv: Certificates and secrets ($($credentialData.Count) credentials)
- ForensicsSummary.txt: This summary report

RECOMMENDED FORENSIC ACTIONS:
🔴 IMMEDIATE:
1. Review all applications in ServicePrincipals_TenantCreated.csv - these were created in your tenant
2. Investigate any applications created by non-admin users
3. Check for applications with suspicious names or excessive permissions

🟡 HIGH PRIORITY:
1. Audit third-party applications in ServicePrincipals_NonMicrosoft.csv
2. Review applications with broad Microsoft Graph permissions (User.ReadWrite.All, Mail.ReadWrite, etc.)
3. Check for applications with expired or expiring credentials
4. Look for unusual OAuth consent grants

🟢 GENERAL:
1. Review applications created in the last 30 days for timing correlation with security incidents
2. Audit applications with multiple authentication credentials
3. Check for applications accessing sensitive resources (Exchange, SharePoint, etc.)

THREAT HUNTING QUERIES:
- Apps with admin consent: Look for ConsentType = "AllPrincipals" in OAuth2PermissionGrants.csv
- Suspicious permissions: Search for "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory"
- Recent activity: Filter by CreatedDateTime in the last 30-90 days
- External publishers: Review apps where PublisherName doesn't match known vendors
"@

$summary | Out-File -FilePath "$OutputPath\ForensicsSummary.txt" -Encoding UTF8
Write-Host "`nForensic analysis complete!" -ForegroundColor Green
Write-Host "Summary report saved to ForensicsSummary.txt" -ForegroundColor Green
Write-Host "All output files are in: $OutputPath" -ForegroundColor Yellow

# Display quick stats
Write-Host "`n=== FORENSIC ANALYSIS SUMMARY ===" -ForegroundColor Magenta
Write-Host "Application Registrations: $($applications.Count)" -ForegroundColor White
Write-Host "Service Principals (Total): $($spData.Count)" -ForegroundColor White
Write-Host "├─ Microsoft Built-ins: $microsoftBuiltIns" -ForegroundColor Cyan
Write-Host "├─ Tenant-Created: $tenantCreated" -ForegroundColor Green  
Write-Host "└─ Third-Party/External: $thirdParty" -ForegroundColor Magenta
Write-Host "OAuth2 Grants: $($oauth2Grants.Count)" -ForegroundColor White
Write-Host "App Role Assignments: $($allAppRoleAssignments.Count)" -ForegroundColor White
Write-Host "Total Credentials: $($credentialData.Count)" -ForegroundColor White

Write-Host "`n🔴 HIGH PRIORITY FILES FOR REVIEW:" -ForegroundColor Red
Write-Host "  - ServicePrincipals_TenantCreated.csv ($tenantCreated apps)" -ForegroundColor Yellow
Write-Host "  - ServicePrincipals_NonMicrosoft.csv ($($nonMicrosoftApps.Count) apps)" -ForegroundColor Yellow
