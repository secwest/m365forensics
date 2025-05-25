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

# 6. Generate Summary Report
Write-Host "`n[6/6] Generating Summary Report..." -ForegroundColor Cyan

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
$($nonMicrosoftApps | Where-Object { $_.CreatedDateTime -ne "N/A" -and [DateTime]$_.CreatedDateTime -gt (Get-Date).AddDays(-30) } | Select-Object DisplayName, CreatedDateTime, Category, PublisherName | Format-Table -AutoSize | Out-String)

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
Write-Host "`n=== QUICK STATISTICS ===" -ForegroundColor Magenta
Write-Host "Application Registrations: $($applications.Count)" -ForegroundColor White
Write-Host "Service Principals: $($servicePrincipals.Count)" -ForegroundColor White  
Write-Host "OAuth2 Grants: $($oauth2Grants.Count)" -ForegroundColor White
Write-Host "App Role Assignments: $($allAppRoleAssignments.Count)" -ForegroundColor White
Write-Host "Total Credentials: $($credentialData.Count)" -ForegroundColor White
