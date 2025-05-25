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
    # Filter out built-in Microsoft apps unless specifically requested
    if ($IncludeBuiltInApps) {
        $servicePrincipals = Get-MgServicePrincipal -All -Property *
    } else {
        $servicePrincipals = Get-MgServicePrincipal -All -Property * | Where-Object { 
            $_.AppOwnerOrganizationId -eq "63ad9bfc-1f87-4b03-918e-81434c7ae363" -or 
            $_.PublisherName -notlike "*Microsoft*"
        }
    }
    
    Write-Host "Found $($servicePrincipals.Count) service principals" -ForegroundColor Green
    
    $spData = @()
    foreach ($sp in $servicePrincipals) {
        Write-Progress -Activity "Processing Service Principals" -Status "Processing $($sp.DisplayName)" -PercentComplete (($spData.Count / $servicePrincipals.Count) * 100)
        
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
        }
        $spData += $spInfo
    }
    
    # Export service principals data
    $spData | Export-Csv -Path "$OutputPath\ServicePrincipals.csv" -NoTypeInformation
    Write-Host "Service principals exported to ServicePrincipals.csv" -ForegroundColor Green
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
    foreach ($sp in $servicePrincipals) {
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
    $allEntities += $servicePrincipals | Select-Object Id, DisplayName, @{Name="Type"; Expression={"ServicePrincipal"}}, KeyCredentials, PasswordCredentials
    
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
- Service Principals: $($servicePrincipals.Count) 
- OAuth2 Permission Grants: $($oauth2Grants.Count)
- App Role Assignments: $($allAppRoleAssignments.Count)
- Total Credentials: $($credentialData.Count)

HIGH-RISK INDICATORS TO INVESTIGATE:

1. Applications with Excessive Permissions:
$($appData + $spData | Where-Object { $_.ApiPermissionsCount -gt 10 -or $_.DelegatedPermissionsCount -gt 10 } | Select-Object DisplayName, ApiPermissionsCount, DelegatedPermissionsCount | Format-Table -AutoSize | Out-String)

2. Recently Created Applications (Last 30 days):
$($appData + $spData | Where-Object { $_.CreatedDateTime -ne "N/A" -and [DateTime]$_.CreatedDateTime -gt (Get-Date).AddDays(-30) } | Select-Object DisplayName, CreatedDateTime, AppType | Format-Table -AutoSize | Out-String)

3. Applications with Multiple Credentials:
$($credentialData | Group-Object EntityId | Where-Object Count -gt 2 | ForEach-Object { $_.Group | Select-Object EntityName, CredentialType -First 1 } | Format-Table -AutoSize | Out-String)

4. External Applications (Non-Microsoft):
$($spData | Where-Object { $_.PublisherName -notlike "*Microsoft*" -and $_.AppOwnerOrganizationId -ne "63ad9bfc-1f87-4b03-918e-81434c7ae363" } | Select-Object DisplayName, PublisherName, CreatedDateTime | Format-Table -AutoSize | Out-String)

FILES GENERATED:
- ApplicationRegistrations.csv: All registered applications
- ServicePrincipals.csv: All enterprise applications  
- OAuth2PermissionGrants.csv: Delegated permissions
- AppRoleAssignments.csv: Application role assignments
- ApplicationCredentials.csv: Certificates and secrets
- ForensicsSummary.txt: This summary report

RECOMMENDED NEXT STEPS:
1. Review applications created by non-admin users
2. Audit applications with broad Microsoft Graph permissions
3. Check for applications with expired or expiring credentials
4. Investigate any applications with suspicious names or external publishers
5. Review OAuth consent grants for unusual patterns
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
