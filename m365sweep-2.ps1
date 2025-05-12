<#
.SYNOPSIS
    Exchange Online Forensics Module for M365 Compromise Assessment
.DESCRIPTION
    This module performs detailed forensic analysis of Exchange Online configurations
    to identify potential attacker persistence mechanisms following admin-level compromise.
.NOTES
    Author: Dragos Ruiu
    Version 2.0
    Requires: Exchange Online PowerShell V2 module, Microsoft Graph PowerShell
    License: MIT
#>

#Requires -Modules ExchangeOnlineManagement, Microsoft.Graph.Authentication, Microsoft.Graph.Users

function Start-ExchangeOnlineForensics {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$DetailedLogging,
        
        [Parameter()]
        [ValidateSet("All", "OutboundSpam", "RemoteDomains", "TransportRules", "MailboxForwarding", 
                     "InboxRules", "MailboxPermissions", "MailConnectors", "JournalingRules", "EmailSecurity")]
        [string[]]$Checks = @("All"),
        
        [Parameter()]
        [int]$ThrottleLimit = 10,
        
        [Parameter()]
        [switch]$SkipExistingResults
    )
    
    begin {
        # Initialize logging
        $script:LogFile = Join-Path -Path $OutputPath -ChildPath "ExchangeOnlineForensics_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $script:ResultPath = Join-Path -Path $OutputPath -ChildPath "Results"
        
        if (-not (Test-Path -Path $OutputPath)) {
            try {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created output directory: $OutputPath" -Level Info
            }
            catch {
                throw "Failed to create output directory: $($_.Exception.Message)"
            }
        }
        
        if (-not (Test-Path -Path $script:ResultPath)) {
            try {
                New-Item -Path $script:ResultPath -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created results directory: $script:ResultPath" -Level Info
            }
            catch {
                throw "Failed to create results directory: $($_.Exception.Message)"
            }
        }
        
        # Script-level variables
        $script:DetailedLogging = $DetailedLogging
        $script:ExchangeOnlineSession = $null
        $script:GraphSession = $null
        $script:AllFindings = @()
    }
    
    process {
        try {
            Write-Log -Message "Starting Exchange Online Forensics analysis" -Level Info
            
            # Connect to required services
            Connect-Services
            
            # Determine which checks to run
            $checksToRun = @()
            if ($Checks -contains "All") {
                $checksToRun = @("OutboundSpam", "RemoteDomains", "TransportRules", "MailboxForwarding", 
                                "InboxRules", "MailboxPermissions", "MailConnectors", "JournalingRules", "EmailSecurity")
            }
            else {
                $checksToRun = $Checks
            }
            
            # Run selected checks
            foreach ($check in $checksToRun) {
                $checkResultPath = Join-Path -Path $script:ResultPath -ChildPath "$check.json"
                
                if ($SkipExistingResults -and (Test-Path -Path $checkResultPath)) {
                    Write-Log -Message "Skipping $check check as results already exist" -Level Info
                    continue
                }
                
                Write-Log -Message "Running $check check" -Level Info
                
                switch ($check) {
                    "OutboundSpam" { 
                        $findings = Invoke-OutboundSpamCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "RemoteDomains" { 
                        $findings = Invoke-RemoteDomainCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "TransportRules" { 
                        $findings = Invoke-TransportRuleCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "MailboxForwarding" { 
                        $findings = Invoke-MailboxForwardingCheck -ThrottleLimit $ThrottleLimit
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "InboxRules" { 
                        $findings = Invoke-InboxRuleCheck -ThrottleLimit $ThrottleLimit
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "MailboxPermissions" { 
                        $findings = Invoke-MailboxPermissionCheck -ThrottleLimit $ThrottleLimit
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "MailConnectors" { 
                        $findings = Invoke-MailConnectorCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "JournalingRules" { 
                        $findings = Invoke-JournalingRuleCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "EmailSecurity" { 
                        $findings = Invoke-EmailSecurityCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                }
            }
            
            # Generate summary report
            $summaryPath = Join-Path -Path $OutputPath -ChildPath "ExchangeOnlineForensics_Summary.json"
            Export-FindingsToJson -Findings $script:AllFindings -FilePath $summaryPath
            
            Write-Log -Message "Exchange Online Forensics analysis completed successfully" -Level Info
        }
        catch {
            Write-Log -Message "Error during Exchange Online Forensics analysis: $($_.Exception.Message)" -Level Error
            Write-Log -Message "Stack Trace: $($_.ScriptStackTrace)" -Level Error
            throw "Exchange Online Forensics analysis failed: $($_.Exception.Message)"
        }
    }
    
    end {
        # Disconnect from services
        Disconnect-Services
        Write-Log -Message "Exchange Online Forensics analysis finished" -Level Info
    }
}

function Connect-Services {
    [CmdletBinding()]
    param()
    
    try {
        # Connect to Exchange Online if not already connected
        if (-not (Get-Command Get-OrganizationConfig -ErrorAction SilentlyContinue)) {
            Write-Log -Message "Connecting to Exchange Online" -Level Info
            
            try {
                $script:ExchangeOnlineSession = Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
                
                # Verify connection by running a simple command
                $orgConfig = Get-OrganizationConfig -ErrorAction Stop
                Write-Log -Message "Successfully connected to Exchange Online for tenant: $($orgConfig.Name)" -Level Info
            }
            catch {
                Write-Log -Message "Failed to connect to Exchange Online: $($_.Exception.Message)" -Level Error
                throw "Exchange Online connection failed. Please ensure you have the ExchangeOnlineManagement module installed and appropriate permissions."
            }
        }
        
        # Connect to Microsoft Graph if not already connected
        try {
            $graphConnection = Get-MgContext -ErrorAction SilentlyContinue
            if (-not $graphConnection) {
                Write-Log -Message "Connecting to Microsoft Graph" -Level Info
                
                Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All" -ErrorAction Stop
                $graphConnection = Get-MgContext
                
                if (-not $graphConnection) {
                    throw "Failed to establish Microsoft Graph connection"
                }
                
                Write-Log -Message "Successfully connected to Microsoft Graph for tenant: $($graphConnection.TenantId)" -Level Info
            }
        }
        catch {
            Write-Log -Message "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
            throw "Microsoft Graph connection failed. Please ensure you have the Microsoft.Graph PowerShell modules installed and appropriate permissions."
        }
    }
    catch {
        Write-Log -Message "Error connecting to required services: $($_.Exception.Message)" -Level Error
        throw "Failed to connect to required services: $($_.Exception.Message)"
    }
}

function Disconnect-Services {
    [CmdletBinding()]
    param()
    
    try {
        # Disconnect from Exchange Online
        if ($script:ExchangeOnlineSession) {
            Write-Log -Message "Disconnecting from Exchange Online" -Level Info
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        }
        
        # Disconnect from Microsoft Graph
        if (Get-MgContext -ErrorAction SilentlyContinue) {
            Write-Log -Message "Disconnecting from Microsoft Graph" -Level Info
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log -Message "Error during service disconnection: $($_.Exception.Message)" -Level Warning
    }
}

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("Info", "Warning", "Error", "Debug")]
        [string]$Level = "Info"
    )
    
    # Only log debug messages if detailed logging is enabled
    if ($Level -eq "Debug" -and -not $script:DetailedLogging) {
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Output to console based on level
    switch ($Level) {
        "Info" { Write-Host $logMessage }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Debug" { Write-Host $logMessage -ForegroundColor Cyan }
    }
    
    # Write to log file
    Add-Content -Path $script:LogFile -Value $logMessage
}

function Export-FindingsToJson {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Findings,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        $Findings | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding utf8 -Force
        Write-Log -Message "Exported findings to $FilePath" -Level Info
        
        # Add to master findings list
        $script:AllFindings += $Findings
    }
    catch {
        Write-Log -Message "Error exporting findings to $FilePath : $($_.Exception.Message)" -Level Error
    }
}

function Add-Finding {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("High", "Medium", "Low", "Informational")]
        [string]$Severity,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter()]
        [string]$Recommendation,
        
        [Parameter()]
        [PSObject]$Data,
        
        [Parameter()]
        [DateTime]$Timestamp = (Get-Date)
    )
    
    $finding = [PSCustomObject]@{
        Category = $Category
        Title = $Title
        Severity = $Severity
        Description = $Description
        Recommendation = $Recommendation
        Data = $Data
        Timestamp = $Timestamp
        Id = [Guid]::NewGuid().ToString()
    }
    
    return $finding
}

function Invoke-OutboundSpamCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing outbound spam policies" -Level Info
        
        # Get all outbound spam policies
        $policies = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop
        
        # Check policies that allow auto-forwarding
        $suspiciousPolicies = $policies | Where-Object { $_.AutoForwardingMode -ne "Automatic" }
        
        if ($suspiciousPolicies) {
            foreach ($policy in $suspiciousPolicies) {
                $severityLevel = "Medium"
                
                if ($policy.AutoForwardingMode -eq "On") {
                    $severityLevel = "High"
                }
                
                $findings += Add-Finding -Category "OutboundSpam" -Title "Outbound spam policy allows auto-forwarding" `
                    -Severity $severityLevel `
                    -Description "Policy '$($policy.Name)' has auto-forwarding set to '$($policy.AutoForwardingMode)', which could allow data exfiltration." `
                    -Recommendation "Review and set AutoForwardingMode to 'Automatic' unless explicitly required." `
                    -Data $policy
            }
        }
        
        # Check for recently modified policies
        $recentCutoff = (Get-Date).AddDays(-30)
        $recentlyModified = $policies | Where-Object { $_.WhenChanged -gt $recentCutoff }
        
        if ($recentlyModified) {
            foreach ($policy in $recentlyModified) {
                $findings += Add-Finding -Category "OutboundSpam" -Title "Recently modified outbound spam policy" `
                    -Severity "Medium" `
                    -Description "Policy '$($policy.Name)' was modified on $($policy.WhenChanged). Recent modifications to spam policies could indicate attacker activity." `
                    -Recommendation "Verify that the changes to this policy were authorized and legitimate." `
                    -Data $policy
            }
        }
        
        Write-Log -Message "Completed outbound spam policy analysis. Found $($findings.Count) suspicious configurations." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing outbound spam policies: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "OutboundSpam" -Title "Error analyzing outbound spam policies" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing outbound spam policies: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of outbound spam policies is recommended."
    }
    
    return $findings
}

function Invoke-RemoteDomainCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing remote domain configurations" -Level Info
        
        # Get all remote domains
        $remoteDomains = Get-RemoteDomain -ErrorAction Stop
        
        # Check for wildcard domains
        $wildcardDomains = $remoteDomains | Where-Object { $_.DomainName -eq "*" -or $_.DomainName -like "*.*" }
        
        if ($wildcardDomains) {
            foreach ($domain in $wildcardDomains) {
                $findings += Add-Finding -Category "RemoteDomains" -Title "Wildcard remote domain configuration" `
                    -Severity "Medium" `
                    -Description "Remote domain '$($domain.DomainName)' is configured with a wildcard pattern, which could affect a large number of domains." `
                    -Recommendation "Review the wildcard domain configuration and ensure it's necessary and secure." `
                    -Data $domain
            }
        }
        
        # Check for auto-forwarding enabled
        $autoForwardDomains = $remoteDomains | Where-Object { $_.AutoForwardEnabled -eq $true }
        
        if ($autoForwardDomains) {
            foreach ($domain in $autoForwardDomains) {
                $findings += Add-Finding -Category "RemoteDomains" -Title "Remote domain allows auto-forwarding" `
                    -Severity "High" `
                    -Description "Remote domain '$($domain.DomainName)' has auto-forwarding enabled, which could allow data exfiltration." `
                    -Recommendation "Disable auto-forwarding for this remote domain unless explicitly required." `
                    -Data $domain
            }
        }
        
        # Check for auto-reply enabled
        $autoReplyDomains = $remoteDomains | Where-Object { $_.AutoReplyEnabled -eq $true }
        
        if ($autoReplyDomains) {
            foreach ($domain in $autoReplyDomains) {
                $findings += Add-Finding -Category "RemoteDomains" -Title "Remote domain allows auto-reply" `
                    -Severity "Medium" `
                    -Description "Remote domain '$($domain.DomainName)' has auto-reply enabled, which could lead to information disclosure." `
                    -Recommendation "Disable auto-reply for this remote domain unless explicitly required." `
                    -Data $domain
            }
        }
        
        # Check for TNEF disabled (potential data exfil)
        $tnefDisabledDomains = $remoteDomains | Where-Object { $_.TNEFEnabled -eq $false }
        
        if ($tnefDisabledDomains) {
            foreach ($domain in $tnefDisabledDomains) {
                $findings += Add-Finding -Category "RemoteDomains" -Title "Remote domain has TNEF disabled" `
                    -Severity "Low" `
                    -Description "Remote domain '$($domain.DomainName)' has TNEF disabled, which could potentially be used for data exfiltration in specific scenarios." `
                    -Recommendation "Review whether TNEF should be enabled for this remote domain." `
                    -Data $domain
            }
        }
        
        # Check for recently modified domains
        $recentCutoff = (Get-Date).AddDays(-30)
        $recentlyModified = $remoteDomains | Where-Object { $_.WhenChanged -gt $recentCutoff }
        
        if ($recentlyModified) {
            foreach ($domain in $recentlyModified) {
                $findings += Add-Finding -Category "RemoteDomains" -Title "Recently modified remote domain" `
                    -Severity "Medium" `
                    -Description "Remote domain '$($domain.DomainName)' was modified on $($domain.WhenChanged). Recent modifications could indicate attacker activity." `
                    -Recommendation "Verify that the changes to this remote domain were authorized and legitimate." `
                    -Data $domain
            }
        }
        
        Write-Log -Message "Completed remote domain analysis. Found $($findings.Count) suspicious configurations." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing remote domains: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "RemoteDomains" -Title "Error analyzing remote domains" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing remote domains: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of remote domains is recommended."
    }
    
    return $findings
}

function Invoke-TransportRuleCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing transport rules" -Level Info
        
        # Get all transport rules with expanded properties
        $transportRules = Get-TransportRule -ErrorAction Stop | ForEach-Object {
            Get-TransportRule -Identity $_.Identity -ErrorAction Stop
        }
        
        # Check for forwarding rules
        $forwardingRules = $transportRules | Where-Object {
            $_.RedirectMessageTo -or 
            $_.BlindCopyTo -or 
            $_.AddToRecipients -or 
            $_.CopyTo
        }
        
        if ($forwardingRules) {
            foreach ($rule in $forwardingRules) {
                $externalRecipients = @()
                
                if ($rule.RedirectMessageTo) { $externalRecipients += $rule.RedirectMessageTo }
                if ($rule.BlindCopyTo) { $externalRecipients += $rule.BlindCopyTo }
                if ($rule.AddToRecipients) { $externalRecipients += $rule.AddToRecipients }
                if ($rule.CopyTo) { $externalRecipients += $rule.CopyTo }
                
                # Check if any recipients are external
                $hasExternalRecipients = $externalRecipients | Where-Object { $_ -like "*@*" -and $_ -notlike "*$($script:TenantDomain)*" }
                
                if ($hasExternalRecipients) {
                    $findings += Add-Finding -Category "TransportRules" -Title "Transport rule forwards to external recipients" `
                        -Severity "High" `
                        -Description "Rule '$($rule.Name)' is configured to forward messages to external recipients, which could allow data exfiltration." `
                        -Recommendation "Review this rule and confirm it's legitimate. If not, remove it immediately." `
                        -Data $rule
                }
            }
        }
        
        # Check for rules that modify message content
        $contentModifyingRules = $transportRules | Where-Object {
            $_.ApplyHtmlDisclaimerText -or 
            $_.ApplyHtmlDisclaimerLocation -or 
            $_.ApplyHtmlDisclaimerFallbackAction -or 
            $_.PrependSubject -or 
            $_.SetHeaderName
        }
        
        if ($contentModifyingRules) {
            foreach ($rule in $contentModifyingRules) {
                # Check for suspicious content modifications
                if ($rule.ApplyHtmlDisclaimerText -and (
                    $rule.ApplyHtmlDisclaimerText -like "*<script*" -or 
                    $rule.ApplyHtmlDisclaimerText -like "*javascript:*"
                )) {
                    $findings += Add-Finding -Category "TransportRules" -Title "Transport rule contains script payload" `
                        -Severity "High" `
                        -Description "Rule '$($rule.Name)' contains a script payload in the HTML disclaimer text, which could be used for malicious purposes." `
                        -Recommendation "Review this rule immediately and remove any unauthorized scripts." `
                        -Data $rule
                }
            }
        }
        
        # Check for recently created or modified rules
        $recentCutoff = (Get-Date).AddDays(-30)
        $recentlyModified = $transportRules | Where-Object { $_.WhenChanged -gt $recentCutoff }
        
        if ($recentlyModified) {
            foreach ($rule in $recentlyModified) {
                $findings += Add-Finding -Category "TransportRules" -Title "Recently modified transport rule" `
                    -Severity "Medium" `
                    -Description "Rule '$($rule.Name)' was modified on $($rule.WhenChanged). Recent modifications could indicate attacker activity." `
                    -Recommendation "Verify that the changes to this rule were authorized and legitimate." `
                    -Data $rule
            }
        }
        
        # Check for rules with obfuscated names
        $obfuscatedRules = $transportRules | Where-Object {
            $_.Name -match "^\s*$" -or 
            $_.Name -match "^[a-zA-Z0-9]{16,}$" -or
            $_.Name -match "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$" # GUID pattern
        }
        
        if ($obfuscatedRules) {
            foreach ($rule in $obfuscatedRules) {
                $findings += Add-Finding -Category "TransportRules" -Title "Transport rule with suspicious name" `
                    -Severity "Medium" `
                    -Description "Rule '$($rule.Name)' has a suspicious name pattern which could indicate an attempt to hide malicious activity." `
                    -Recommendation "Review this rule to confirm it's legitimate and consider renaming it appropriately." `
                    -Data $rule
            }
        }
        
        Write-Log -Message "Completed transport rule analysis. Found $($findings.Count) suspicious rules." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing transport rules: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "TransportRules" -Title "Error analyzing transport rules" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing transport rules: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of transport rules is recommended."
    }
    
    return $findings
}

function Invoke-MailboxForwardingCheck {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$ThrottleLimit = 10
    )
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing mailbox forwarding configurations" -Level Info
        
        # Get all mailboxes
        $mailboxes = Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward -ErrorAction Stop
        
        # Filter mailboxes with forwarding configured
        $forwardingMailboxes = $mailboxes | Where-Object {
            $_.ForwardingSmtpAddress -or $_.ForwardingAddress
        }
        
        if ($forwardingMailboxes) {
            # Get tenant domains to determine if forwarding is internal or external
            $tenantDomains = Get-AcceptedDomain | Select-Object -ExpandProperty DomainName
            
            foreach ($mailbox in $forwardingMailboxes) {
                $isExternal = $false
                $forwardingTarget = ""
                
                if ($mailbox.ForwardingSmtpAddress) {
                    # Extract email from SMTP:user@domain.com format
                    $forwardingTarget = $mailbox.ForwardingSmtpAddress -replace "^SMTP:", ""
                    $forwardingDomain = ($forwardingTarget -split "@")[1]
                    
                    $isExternal = $true
                    # Check if the domain is external to the tenant
                    foreach ($domain in $tenantDomains) {
                        if ($forwardingDomain -eq $domain) {
                            $isExternal = $false
                            break
                        }
                    }
                }
                elseif ($mailbox.ForwardingAddress) {
                    $forwardingTarget = $mailbox.ForwardingAddress
                    
                    # We need to check if this is a contact object with external email
                    try {
                        $contact = Get-MailContact -Identity $forwardingTarget -ErrorAction SilentlyContinue
                        if ($contact) {
                            $forwardingTarget = $contact.ExternalEmailAddress -replace "^SMTP:", ""
                            $forwardingDomain = ($forwardingTarget -split "@")[1]
                            
                            $isExternal = $true
                            # Check if the domain is external to the tenant
                            foreach ($domain in $tenantDomains) {
                                if ($forwardingDomain -eq $domain) {
                                    $isExternal = $false
                                    break
                                }
                            }
                        }
                    }
                    catch {
                        Write-Log -Message "Error retrieving contact information for $($mailbox.ForwardingAddress): $($_.Exception.Message)" -Level Warning
                    }
                }
                
                $severity = "Medium"
                if ($isExternal) {
                    $severity = "High"
                }
                
                $findings += Add-Finding -Category "MailboxForwarding" -Title "Mailbox has forwarding configured" `
                    -Severity $severity `
                    -Description "Mailbox '$($mailbox.UserPrincipalName)' is configured to forward messages to '$forwardingTarget'. $(if($isExternal){"This is an external recipient, which could allow data exfiltration."})" `
                    -Recommendation "Verify that this forwarding configuration is legitimate and required." `
                    -Data @{
                        Mailbox = $mailbox.UserPrincipalName
                        ForwardingTarget = $forwardingTarget
                        IsExternal = $isExternal
                        DeliverToMailboxAndForward = $mailbox.DeliverToMailboxAndForward
                    }
            }
        }
        
        Write-Log -Message "Completed mailbox forwarding analysis. Found $($findings.Count) forwarding configurations." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing mailbox forwarding: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "MailboxForwarding" -Title "Error analyzing mailbox forwarding" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing mailbox forwarding: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of mailbox forwarding is recommended."
    }
    
    return $findings
}

function Invoke-InboxRuleCheck {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$ThrottleLimit = 10
    )
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing inbox rules" -Level Info
        
        # Get all mailboxes
        $mailboxes = Get-EXOMailbox -ResultSize Unlimited -ErrorAction Stop
        
        # Tenant domains for external check
        $tenantDomains = Get-AcceptedDomain | Select-Object -ExpandProperty DomainName
        
        $scriptBlock = {
            param($Mailbox, $TenantDomains)
            
            $mailboxRules = @()
            
            try {
                # Get inbox rules for the mailbox
                $rules = Get-InboxRule -Mailbox $Mailbox.UserPrincipalName -ErrorAction Stop
                
                # Check for suspicious rules
                foreach ($rule in $rules) {
                    $isSuspicious = $false
                    $reasons = @()
                    $severity = "Low"
                    
                    # Check for forwarding actions
                    if ($rule.ForwardTo -or $rule.ForwardAsAttachmentTo -or $rule.RedirectTo) {
                        $isSuspicious = $true
                        
                        $targets = @()
                        if ($rule.ForwardTo) { $targets += $rule.ForwardTo }
                        if ($rule.ForwardAsAttachmentTo) { $targets += $rule.ForwardAsAttachmentTo }
                        if ($rule.RedirectTo) { $targets += $rule.RedirectTo }
                        
                        $externalTargets = @()
                        foreach ($target in $targets) {
                            # Extract email from format like "SMTP:user@domain.com"
                            $email = $target -replace "^.*:", ""
                            $domain = ($email -split "@")[1]
                            
                            $isExternal = $true
                            foreach ($tenantDomain in $TenantDomains) {
                                if ($domain -eq $tenantDomain) {
                                    $isExternal = $false
                                    break
                                }
                            }
                            
                            if ($isExternal) {
                                $externalTargets += $email
                            }
                        }
                        
                        if ($externalTargets.Count -gt 0) {
                            $reasons += "Forwards to external recipients: $($externalTargets -join ', ')"
                            $severity = "High"
                        }
                        else {
                            $reasons += "Forwards to internal recipients"
                        }
                    }
                    
                    # Check for delete actions
                    if ($rule.DeleteMessage -eq $true) {
                        $isSuspicious = $true
                        $reasons += "Deletes messages"
                    }
                    
                    # Check for moving to hidden folders
                    if ($rule.MoveToFolder -and ($rule.MoveToFolder -like "*/RSS*" -or $rule.MoveToFolder -like "*/Conversation History*" -or $rule.MoveToFolder -like "*/Sync Issues*")) {
                        $isSuspicious = $true
                        $reasons += "Moves messages to potentially hidden folder: $($rule.MoveToFolder)"
                        if ($severity -ne "High") { $severity = "Medium" }
                    }
                    
                    # Check for suspicious rule names
                    if ($rule.Name -match "^\s*$" -or $rule.Name -match "^[a-zA-Z0-9]{16,}$" -or $rule.Name -match "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$") {
                        $isSuspicious = $true
                        $reasons += "Suspicious rule name pattern"
                        if ($severity -ne "High") { $severity = "Medium" }
                    }
                    
                    # Check for suspicious conditions
                    if ($rule.Conditions -match "credit|password|credential|login|secure|bank|financial|urgent") {
                        $isSuspicious = $true
                        $reasons += "Targets sensitive keywords"
                        if ($severity -ne "High") { $severity = "Medium" }
                    }
                    
                    if ($isSuspicious) {
                        $mailboxRules += [PSCustomObject]@{
                            MailboxPrimary = $Mailbox.UserPrincipalName
                            MailboxAlias = $Mailbox.Alias
                            RuleName = $rule.Name
                            Enabled = $rule.Enabled
                            SuspiciousReasons = $reasons
                            Severity = $severity
                            RuleDetails = $rule
                            ForwardTargets = if ($rule.ForwardTo -or $rule.ForwardAsAttachmentTo -or $rule.RedirectTo) {
                                @($rule.ForwardTo) + @($rule.ForwardAsAttachmentTo) + @($rule.RedirectTo) | Where-Object { $_ }
                            } else { $null }
                        }
                    }
                }
            }
            catch {
                $mailboxRules += [PSCustomObject]@{
                    MailboxPrimary = $Mailbox.UserPrincipalName
                    MailboxAlias = $Mailbox.Alias
                    Error = $_.Exception.Message
                    Severity = "Medium"
                }
            }
            
            return $mailboxRules
        }
        
        # Process mailboxes with throttling
        $counter = 0
        $totalMailboxes = $mailboxes.Count
        $batchSize = [Math]::Min($ThrottleLimit, 10)  # Adjust based on service limits
        
        for ($i = 0; $i -lt $totalMailboxes; $i += $batchSize) {
            $batch = $mailboxes | Select-Object -Skip $i -First $batchSize
            
            $jobs = @()
            foreach ($mailbox in $batch) {
                $counter++
                Write-Progress -Activity "Analyzing inbox rules" -Status "Processing mailbox $counter of $totalMailboxes" -PercentComplete (($counter / $totalMailboxes) * 100)
                
                $jobs += Start-Job -ScriptBlock $scriptBlock -ArgumentList $mailbox, $tenantDomains
            }
            
            $results = $jobs | Wait-Job | Receive-Job
            $jobs | Remove-Job -Force
            
            # Process batch results
            foreach ($result in $results) {
                if ($result.Error) {
                    $findings += Add-Finding -Category "InboxRules" -Title "Error analyzing inbox rules" `
                        -Severity "Medium" `
                        -Description "An error occurred while analyzing inbox rules for mailbox '$($result.MailboxPrimary)': $($result.Error)" `
                        -Recommendation "Manual investigation of inbox rules for this mailbox is recommended."
                }
                elseif ($result) {
                    foreach ($rule in $result) {
                        $findings += Add-Finding -Category "InboxRules" -Title "Suspicious inbox rule detected" `
                            -Severity $rule.Severity `
                            -Description "Mailbox '$($rule.MailboxPrimary)' has a suspicious inbox rule '$($rule.RuleName)'. Reasons: $($rule.SuspiciousReasons -join '; ')" `
                            -Recommendation "Review this rule to confirm it's legitimate. If not, remove it immediately." `
                            -Data $rule
                    }
                }
            }
        }
        
        Write-Progress -Activity "Analyzing inbox rules" -Completed
        Write-Log -Message "Completed inbox rule analysis. Found $($findings.Count) suspicious rules." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing inbox rules: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "InboxRules" -Title "Error analyzing inbox rules" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing inbox rules: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of inbox rules is recommended."
    }
    
    return $findings
}

function Invoke-MailboxPermissionCheck {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$ThrottleLimit = 10
    )
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing mailbox permissions" -Level Info
        
        # Get all mailboxes
        $mailboxes = Get-EXOMailbox -ResultSize Unlimited -ErrorAction Stop
        
        # Get all users and groups for resolution
        Write-Log -Message "Getting all users and groups for identity resolution" -Level Info
        $allUsers = Get-User -ResultSize Unlimited -ErrorAction Stop
        $allGroups = Get-Group -ResultSize Unlimited -ErrorAction Stop
        
        # Tenant domains for external check
        $tenantDomains = Get-AcceptedDomain | Select-Object -ExpandProperty DomainName
        
        $scriptBlock = {
            param($Mailbox, $AllUsers, $AllGroups, $TenantDomains)
            
            $permissions = @()
            
            try {
                # Get full access permissions
                $fullAccess = Get-MailboxPermission -Identity $Mailbox.Identity -ErrorAction Stop | 
                    Where-Object { $_.AccessRights -contains "FullAccess" -and $_.IsInherited -eq $false -and $_.User -ne "NT AUTHORITY\SELF" }
                
                # Get Send As permissions
                $sendAs = Get-RecipientPermission -Identity $Mailbox.Identity -ErrorAction Stop | 
                    Where-Object { $_.AccessRights -contains "SendAs" -and $_.IsInherited -eq $false -and $_.Trustee -ne "NT AUTHORITY\SELF" }
                
                # Get Send on Behalf permissions
                $sendOnBehalf = $Mailbox.GrantSendOnBehalfTo
                
                # Process Full Access permissions
                foreach ($access in $fullAccess) {
                    $userType = "Internal"
                    $isSuspicious = $false
                    $reasons = @()
                    
                    # Try to resolve the identity
                    $identityResolved = $AllUsers | Where-Object { $_.Identity -eq $access.User -or $_.UserPrincipalName -eq $access.User }
                    
                    if (-not $identityResolved) {
                        $identityResolved = $AllGroups | Where-Object { $_.Identity -eq $access.User -or $_.Name -eq $access.User }
                    }
                    
                    # Check if it's potentially an external user
                    if ($access.User -like "*@*") {
                        $domain = ($access.User -split "@")[1]
                        $isExternal = $true
                        
                        foreach ($tenantDomain in $TenantDomains) {
                            if ($domain -eq $tenantDomain) {
                                $isExternal = $false
                                break
                            }
                        }
                        
                        if ($isExternal) {
                            $userType = "External"
                            $isSuspicious = $true
                            $reasons += "External user has full access to mailbox"
                        }
                    }
                    
                    # Check if it's a recently added permission
                    if ($access.WhenChanged -and (New-TimeSpan -Start $access.WhenChanged -End (Get-Date)).Days -lt 30) {
                        $isSuspicious = $true
                        $reasons += "Recently granted permission ($(Get-Date $access.WhenChanged -Format 'yyyy-MM-dd'))"
                    }
                    
                    $permissions += [PSCustomObject]@{
                        MailboxPrimary = $Mailbox.UserPrincipalName
                        MailboxAlias = $Mailbox.Alias
                        PermissionType = "FullAccess"
                        Identity = $access.User
                        IdentityType = $userType
                        GrantDate = $access.WhenChanged
                        IsSuspicious = $isSuspicious
                        Reasons = $reasons
                        AccessDetails = $access
                    }
                }
                
                # Process Send As permissions
                foreach ($access in $sendAs) {
                    $userType = "Internal"
                    $isSuspicious = $false
                    $reasons = @()
                    
                    # Try to resolve the identity
                    $identityResolved = $AllUsers | Where-Object { $_.Identity -eq $access.Trustee -or $_.UserPrincipalName -eq $access.Trustee }
                    
                    if (-not $identityResolved) {
                        $identityResolved = $AllGroups | Where-Object { $_.Identity -eq $access.Trustee -or $_.Name -eq $access.Trustee }
                    }
                    
                    # Check if it's potentially an external user
                    if ($access.Trustee -like "*@*") {
                        $domain = ($access.Trustee -split "@")[1]
                        $isExternal = $true
                        
                        foreach ($tenantDomain in $TenantDomains) {
                            if ($domain -eq $tenantDomain) {
                                $isExternal = $false
                                break
                            }
                        }
                        
                        if ($isExternal) {
                            $userType = "External"
                            $isSuspicious = $true
                            $reasons += "External user has send as permission for mailbox"
                        }
                    }
                    
                    # Check if it's a recently added permission
                    if ($access.WhenChanged -and (New-TimeSpan -Start $access.WhenChanged -End (Get-Date)).Days -lt 30) {
                        $isSuspicious = $true
                        $reasons += "Recently granted permission ($(Get-Date $access.WhenChanged -Format 'yyyy-MM-dd'))"
                    }
                    
                    $permissions += [PSCustomObject]@{
                        MailboxPrimary = $Mailbox.UserPrincipalName
                        MailboxAlias = $Mailbox.Alias
                        PermissionType = "SendAs"
                        Identity = $access.Trustee
                        IdentityType = $userType
                        GrantDate = $access.WhenChanged
                        IsSuspicious = $isSuspicious
                        Reasons = $reasons
                        AccessDetails = $access
                    }
                }
                
                # Process Send on Behalf permissions
                if ($sendOnBehalf) {
                    foreach ($identity in $sendOnBehalf) {
                        $userType = "Internal"
                        $isSuspicious = $false
                        $reasons = @()
                        
                        # Try to resolve the identity
                        $identityResolved = $AllUsers | Where-Object { $_.Identity -eq $identity -or $_.UserPrincipalName -eq $identity }
                        
                        if (-not $identityResolved) {
                            $identityResolved = $AllGroups | Where-Object { $_.Identity -eq $identity -or $_.Name -eq $identity }
                        }
                        
                        # Check if it's potentially an external user
                        if ($identity -like "*@*") {
                            $domain = ($identity -split "@")[1]
                            $isExternal = $true
                            
                            foreach ($tenantDomain in $TenantDomains) {
                                if ($domain -eq $tenantDomain) {
                                    $isExternal = $false
                                    break
                                }
                            }
                            
                            if ($isExternal) {
                                $userType = "External"
                                $isSuspicious = $true
                                $reasons += "External user has send on behalf permission for mailbox"
                            }
                        }
                        
                        $permissions += [PSCustomObject]@{
                            MailboxPrimary = $Mailbox.UserPrincipalName
                            MailboxAlias = $Mailbox.Alias
                            PermissionType = "SendOnBehalf"
                            Identity = $identity
                            IdentityType = $userType
                            IsSuspicious = $isSuspicious
                            Reasons = $reasons
                        }
                    }
                }
            }
            catch {
                $permissions += [PSCustomObject]@{
                    MailboxPrimary = $Mailbox.UserPrincipalName
                    MailboxAlias = $Mailbox.Alias
                    Error = $_.Exception.Message
                }
            }
            
            return $permissions
        }
        
        # Process mailboxes with throttling
        $counter = 0
        $totalMailboxes = $mailboxes.Count
        $batchSize = [Math]::Min($ThrottleLimit, 10)  # Adjust based on service limits
        
        for ($i = 0; $i -lt $totalMailboxes; $i += $batchSize) {
            $batch = $mailboxes | Select-Object -Skip $i -First $batchSize
            
            $jobs = @()
            foreach ($mailbox in $batch) {
                $counter++
                Write-Progress -Activity "Analyzing mailbox permissions" -Status "Processing mailbox $counter of $totalMailboxes" -PercentComplete (($counter / $totalMailboxes) * 100)
                
                $jobs += Start-Job -ScriptBlock $scriptBlock -ArgumentList $mailbox, $allUsers, $allGroups, $tenantDomains
            }
            
            $results = $jobs | Wait-Job | Receive-Job
            $jobs | Remove-Job -Force
            
            # Process batch results
            foreach ($result in $results) {
                if ($result.Error) {
                    $findings += Add-Finding -Category "MailboxPermissions" -Title "Error analyzing mailbox permissions" `
                        -Severity "Medium" `
                        -Description "An error occurred while analyzing permissions for mailbox '$($result.MailboxPrimary)': $($result.Error)" `
                        -Recommendation "Manual investigation of permissions for this mailbox is recommended."
                }
                elseif ($result) {
                    foreach ($permission in $result) {
                        if ($permission.IsSuspicious) {
                            $severity = "Medium"
                            if ($permission.IdentityType -eq "External") {
                                $severity = "High"
                            }
                            
                            $findings += Add-Finding -Category "MailboxPermissions" -Title "Suspicious mailbox permission detected" `
                                -Severity $severity `
                                -Description "Mailbox '$($permission.MailboxPrimary)' has a suspicious $($permission.PermissionType) permission granted to '$($permission.Identity)'. Reasons: $($permission.Reasons -join '; ')" `
                                -Recommendation "Review this permission to confirm it's legitimate. If not, remove it immediately." `
                                -Data $permission
                        }
                    }
                }
            }
        }
        
        Write-Progress -Activity "Analyzing mailbox permissions" -Completed
        Write-Log -Message "Completed mailbox permission analysis. Found $($findings.Count) suspicious permissions." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing mailbox permissions: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "MailboxPermissions" -Title "Error analyzing mailbox permissions" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing mailbox permissions: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of mailbox permissions is recommended."
    }
    
    return $findings
}

function Invoke-MailConnectorCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing mail connectors" -Level Info
        
        # Get all inbound and outbound connectors
        $inboundConnectors = Get-InboundConnector -ErrorAction Stop
        $outboundConnectors = Get-OutboundConnector -ErrorAction Stop
        
        # Check inbound connectors
        foreach ($connector in $inboundConnectors) {
            $isSuspicious = $false
            $reasons = @()
            
            # Check for connectors that bypass spam filtering
            if ($connector.SenderDomains -contains "*" -and $connector.ConnectorSource -eq "Default") {
                $isSuspicious = $true
                $reasons += "Accepts mail from all domains"
            }
            
            if ($connector.EFSkipLastIP -eq $true -or $connector.EFSkipIPs -contains "*") {
                $isSuspicious = $true
                $reasons += "Bypasses spam filtering for some or all IPs"
            }
            
            # Check for recently modified connectors
            $recentCutoff = (Get-Date).AddDays(-30)
            if ($connector.WhenChanged -gt $recentCutoff) {
                $isSuspicious = $true
                $reasons += "Recently modified ($(Get-Date $connector.WhenChanged -Format 'yyyy-MM-dd'))"
            }
            
            if ($isSuspicious) {
                $findings += Add-Finding -Category "MailConnectors" -Title "Suspicious inbound connector detected" `
                    -Severity "Medium" `
                    -Description "Inbound connector '$($connector.Name)' has suspicious configuration. Reasons: $($reasons -join '; ')" `
                    -Recommendation "Review this connector to confirm it's legitimate and properly configured." `
                    -Data $connector
            }
        }
        
        # Check outbound connectors
        foreach ($connector in $outboundConnectors) {
            $isSuspicious = $false
            $reasons = @()
            
            # Check for connectors with non-standard settings
            if ($connector.SmartHosts) {
                # Check for recently modified smart hosts
                $recentCutoff = (Get-Date).AddDays(-30)
                if ($connector.WhenChanged -gt $recentCutoff) {
                    $isSuspicious = $true
                    $reasons += "Recently modified with custom smart hosts ($(Get-Date $connector.WhenChanged -Format 'yyyy-MM-dd'))"
                }
                
                # Check for unusual smart host domains
                foreach ($smartHost in $connector.SmartHosts) {
                    if ($smartHost -notmatch "\.onmicrosoft\.com$|microsoft\.com$|office365\.com$") {
                        $isSuspicious = $true
                        $reasons += "Uses non-standard smart host: $smartHost"
                    }
                }
            }
            
            # Check for disabled TLS
            if ($connector.TlsSettings -eq "EncryptionDisabled") {
                $isSuspicious = $true
                $reasons += "TLS encryption is disabled"
            }
            
            # Check for connectors that route mail to all domains
            if ($connector.RecipientDomains -contains "*") {
                $isSuspicious = $true
                $reasons += "Routes mail for all recipient domains"
            }
            
            if ($isSuspicious) {
                $findings += Add-Finding -Category "MailConnectors" -Title "Suspicious outbound connector detected" `
                    -Severity "Medium" `
                    -Description "Outbound connector '$($connector.Name)' has suspicious configuration. Reasons: $($reasons -join '; ')" `
                    -Recommendation "Review this connector to confirm it's legitimate and properly configured." `
                    -Data $connector
            }
        }
        
        Write-Log -Message "Completed mail connector analysis. Found $($findings.Count) suspicious connectors." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing mail connectors: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "MailConnectors" -Title "Error analyzing mail connectors" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing mail connectors: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of mail connectors is recommended."
    }
    
    return $findings
}

function Invoke-JournalingRuleCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing journaling rules" -Level Info
        
        # Get all journaling rules
        $rules = Get-JournalRule -ErrorAction Stop
        
        if ($rules) {
            # Tenant domains for external check
            $tenantDomains = Get-AcceptedDomain | Select-Object -ExpandProperty DomainName
            
            foreach ($rule in $rules) {
                $isSuspicious = $false
                $reasons = @()
                $severity = "Medium"
                
                # Get journaling mailbox details
                $recipient = $rule.JournalEmailAddress
                $domain = ($recipient -split "@")[1]
                
                # Check if external
                $isExternal = $true
                foreach ($tenantDomain in $tenantDomains) {
                    if ($domain -eq $tenantDomain) {
                        $isExternal = $false
                        break
                    }
                }
                
                if ($isExternal) {
                    $isSuspicious = $true
                    $reasons += "Journals to external email address: $recipient"
                    $severity = "High"
                }
                
                # Check for recently created or modified rules
                $recentCutoff = (Get-Date).AddDays(-30)
                if ($rule.WhenChanged -gt $recentCutoff) {
                    $isSuspicious = $true
                    $reasons += "Recently modified ($(Get-Date $rule.WhenChanged -Format 'yyyy-MM-dd'))"
                }
                
                if ($isSuspicious) {
                    $findings += Add-Finding -Category "JournalingRules" -Title "Suspicious journaling rule detected" `
                        -Severity $severity `
                        -Description "Journaling rule '$($rule.Name)' has suspicious configuration. Reasons: $($reasons -join '; ')" `
                        -Recommendation "Review this journaling rule to confirm it's legitimate." `
                        -Data $rule
                }
                else {
                    # Add informational finding even if not suspicious
                    $findings += Add-Finding -Category "JournalingRules" -Title "Journaling rule detected" `
                        -Severity "Informational" `
                        -Description "Journaling rule '$($rule.Name)' is configured with recipient '$recipient'." `
                        -Recommendation "Verify that this journaling configuration is legitimate and required." `
                        -Data $rule
                }
            }
        }
        
        Write-Log -Message "Completed journaling rule analysis. Found $($findings.Count) journaling rules." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing journaling rules: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "JournalingRules" -Title "Error analyzing journaling rules" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing journaling rules: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of journaling rules is recommended."
    }
    
    return $findings
}

function Invoke-EmailSecurityCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing email security settings" -Level Info
        
        # Check for Defender for Office 365 (Safe Attachments, Safe Links, Anti-Phishing)
        $isDefenderEnabled = $false
        
        try {
            # Get Safe Attachment policies
            $safeAttachmentPolicies = Get-SafeAttachmentPolicy -ErrorAction Stop
            $isDefenderEnabled = $true
            
            foreach ($policy in $safeAttachmentPolicies) {
                $isSuspicious = $false
                $reasons = @()
                
                # Check for policies with non-blocking actions
                if ($policy.Action -eq "Allow" -or $policy.Action -eq "DynamicDelivery") {
                    $isSuspicious = $true
                    $reasons += "Uses '$($policy.Action)' action instead of 'Block'"
                }
                
                # Check for recently modified policies
                $recentCutoff = (Get-Date).AddDays(-30)
                if ($policy.WhenChanged -gt $recentCutoff) {
                    $isSuspicious = $true
                    $reasons += "Recently modified ($(Get-Date $policy.WhenChanged -Format 'yyyy-MM-dd'))"
                }
                
                if ($isSuspicious) {
                    $findings += Add-Finding -Category "EmailSecurity" -Title "Suspicious Safe Attachment policy detected" `
                        -Severity "Medium" `
                        -Description "Safe Attachment policy '$($policy.Name)' has suspicious configuration. Reasons: $($reasons -join '; ')" `
                        -Recommendation "Review this policy to confirm it's properly configured for your security requirements." `
                        -Data $policy
                }
            }
            
            # Get Safe Links policies
            $safeLinksPolices = Get-SafeLinksPolicy -ErrorAction Stop
            
            foreach ($policy in $safeLinksPolices) {
                $isSuspicious = $false
                $reasons = @()
                
                # Check for policies with tracking disabled
                if ($policy.TrackClicks -eq $false) {
                    $isSuspicious = $true
                    $reasons += "URL click tracking is disabled"
                }
                
                # Check for policies not scanning URLs
                if ($policy.IsEnabled -eq $false) {
                    $isSuspicious = $true
                    $reasons += "URL scanning is disabled"
                }
                
                # Check for policies allowing users to click through to original URL
                if ($policy.AllowClickThrough -eq $true) {
                    $isSuspicious = $true
                    $reasons += "Users can click through to the original URL"
                }
                
                # Check for recently modified policies
                $recentCutoff = (Get-Date).AddDays(-30)
                if ($policy.WhenChanged -gt $recentCutoff) {
                    $isSuspicious = $true
                    $reasons += "Recently modified ($(Get-Date $policy.WhenChanged -Format 'yyyy-MM-dd'))"
                }
                
                if ($isSuspicious) {
                    $findings += Add-Finding -Category "EmailSecurity" -Title "Suspicious Safe Links policy detected" `
                        -Severity "Medium" `
                        -Description "Safe Links policy '$($policy.Name)' has suspicious configuration. Reasons: $($reasons -join '; ')" `
                        -Recommendation "Review this policy to confirm it's properly configured for your security requirements." `
                        -Data $policy
                }
            }
            
            # Get Anti-Phishing policies
            $antiPhishingPolicies = Get-AntiPhishPolicy -ErrorAction Stop
            
            foreach ($policy in $antiPhishingPolicies) {
                $isSuspicious = $false
                $reasons = @()
                
                # Check for policies with impersonation protection disabled
                if ($policy.EnableTargetedUserProtection -eq $false) {
                    $isSuspicious = $true
                    $reasons += "Targeted user impersonation protection is disabled"
                }
                
                if ($policy.EnableOrganizationDomainsProtection -eq $false) {
                    $isSuspicious = $true
                    $reasons += "Organization domain impersonation protection is disabled"
                }
                
                if ($policy.EnableMailboxIntelligence -eq $false) {
                    $isSuspicious = $true
                    $reasons += "Mailbox intelligence is disabled"
                }
                
                # Check for recently modified policies
                $recentCutoff = (Get-Date).AddDays(-30)
                if ($policy.WhenChanged -gt $recentCutoff) {
                    $isSuspicious = $true
                    $reasons += "Recently modified ($(Get-Date $policy.WhenChanged -Format 'yyyy-MM-dd'))"
                }
                
                if ($isSuspicious) {
                    $findings += Add-Finding -Category "EmailSecurity" -Title "Suspicious Anti-Phishing policy detected" `
                        -Severity "Medium" `
                        -Description "Anti-Phishing policy '$($policy.Name)' has suspicious configuration. Reasons: $($reasons -join '; ')" `
                        -Recommendation "Review this policy to confirm it's properly configured for your security requirements." `
                        -Data $policy
                }
            }
        }
        catch {
            if ($_.Exception.Message -like "*isn't recognized as the name of a cmdlet*") {
                $findings += Add-Finding -Category "EmailSecurity" -Title "Defender for Office 365 not available" `
                    -Severity "Informational" `
                    -Description "Defender for Office 365 cmdlets are not available. This may indicate that Defender for Office 365 is not licensed or enabled for this tenant." `
                    -Recommendation "Consider implementing Defender for Office 365 for enhanced email security."
            }
            else {
                Write-Log -Message "Error checking Defender for Office 365 settings: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "EmailSecurity" -Title "Error checking Defender for Office 365 settings" `
                    -Severity "Medium" `
                    -Description "An error occurred while checking Defender for Office 365 settings: $($_.Exception.Message)" `
                    -Recommendation "Manual investigation of email security settings is recommended."
            }
        }
        
        # Check standard malware filter policies
        try {
            $malwarePolicies = Get-MalwareFilterPolicy -ErrorAction Stop
            
            foreach ($policy in $malwarePolicies) {
                $isSuspicious = $false
                $reasons = @()
                
                # Check for policies with disabled scanning
                if ($policy.Action -eq "Release") {
                    $isSuspicious = $true
                    $reasons += "Malware scanning action is set to 'Release' (allow) instead of 'Delete'"
                }
                
                # Check for disabled protections
                if ($policy.EnableFileFilter -eq $false) {
                    $isSuspicious = $true
                    $reasons += "Common attachment filtering is disabled"
                }
                
                # Check for recently modified policies
                $recentCutoff = (Get-Date).AddDays(-30)
                if ($policy.WhenChanged -gt $recentCutoff) {
                    $isSuspicious = $true
                    $reasons += "Recently modified ($(Get-Date $policy.WhenChanged -Format 'yyyy-MM-dd'))"
                }
                
                if ($isSuspicious) {
                    $findings += Add-Finding -Category "EmailSecurity" -Title "Suspicious Malware Filter policy detected" `
                        -Severity "High" `
                        -Description "Malware Filter policy '$($policy.Name)' has suspicious configuration. Reasons: $($reasons -join '; ')" `
                        -Recommendation "Review this policy to confirm it's properly configured for your security requirements." `
                        -Data $policy
                }
            }
        }
        catch {
            Write-Log -Message "Error checking malware filter policies: $($_.Exception.Message)" -Level Error
            $findings += Add-Finding -Category "EmailSecurity" -Title "Error checking malware filter policies" `
                -Severity "Medium" `
                -Description "An error occurred while checking malware filter policies: $($_.Exception.Message)" `
                -Recommendation "Manual investigation of malware filter policies is recommended."
        }
        
        # Check spam filter policies
        try {
            $spamPolicies = Get-HostedContentFilterPolicy -ErrorAction Stop
            
            foreach ($policy in $spamPolicies) {
                $isSuspicious = $false
                $reasons = @()
                
                # Check for high spam threshold
                if ([int]$policy.SpamThreshold -gt 7) {
                    $isSuspicious = $true
                    $reasons += "High spam threshold ($($policy.SpamThreshold)) may allow more spam"
                }
                
                # Check for high bulk threshold
                if ([int]$policy.BulkThreshold -gt 7) {
                    $isSuspicious = $true
                    $reasons += "High bulk threshold ($($policy.BulkThreshold)) may allow more bulk email"
                }
                
                # Check for allowing high confidence spam
                if ($policy.HighConfidenceSpamAction -ne "Quarantine" -and $policy.HighConfidenceSpamAction -ne "Delete") {
                    $isSuspicious = $true
                    $reasons += "High confidence spam action is set to '$($policy.HighConfidenceSpamAction)' instead of 'Quarantine' or 'Delete'"
                }
                
                # Check for recently modified policies
                $recentCutoff = (Get-Date).AddDays(-30)
                if ($policy.WhenChanged -gt $recentCutoff) {
                    $isSuspicious = $true
                    $reasons += "Recently modified ($(Get-Date $policy.WhenChanged -Format 'yyyy-MM-dd'))"
                }
                
                if ($isSuspicious) {
                    $findings += Add-Finding -Category "EmailSecurity" -Title "Suspicious Spam Filter policy detected" `
                        -Severity "Medium" `
                        -Description "Spam Filter policy '$($policy.Name)' has suspicious configuration. Reasons: $($reasons -join '; ')" `
                        -Recommendation "Review this policy to confirm it's properly configured for your security requirements." `
                        -Data $policy
                }
            }
        }
        catch {
            Write-Log -Message "Error checking spam filter policies: $($_.Exception.Message)" -Level Error
            $findings += Add-Finding -Category "EmailSecurity" -Title "Error checking spam filter policies" `
                -Severity "Medium" `
                -Description "An error occurred while checking spam filter policies: $($_.Exception.Message)" `
                -Recommendation "Manual investigation of spam filter policies is recommended."
        }
        
        Write-Log -Message "Completed email security analysis. Found $($findings.Count) potential issues." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing email security settings: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "EmailSecurity" -Title "Error analyzing email security settings" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing email security settings: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of email security settings is recommended."
    }
    
    return $findings
}

# Export the module function
Export-ModuleMember -Function Start-ExchangeOnlineForensics

<#
.SYNOPSIS
    Azure AD / Entra ID Core Identity Forensics Module for M365 Compromise Assessment
.DESCRIPTION
    This module performs detailed forensic analysis of Azure AD / Entra ID configurations
    to identify potential attacker persistence mechanisms following admin-level compromise.
.NOTES
    Author: Dragos Ruiu
    Version 2.0
    Requires: Microsoft.Graph PowerShell modules
    License: MIT
#>

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, 
#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users, Microsoft.Graph.Groups,
#Requires -Modules Microsoft.Graph.Applications

function Start-EntraIDCoreForensics {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$DetailedLogging,
        
        [Parameter()]
        [ValidateSet("All", "UserAccounts", "DirectoryRoles", "Applications", 
                     "OAuthGrants", "FederationSettings", "ConditionalAccess", "SignInAnalysis")]
        [string[]]$Checks = @("All"),
        
        [Parameter()]
        [int]$ThrottleLimit = 10,
        
        [Parameter()]
        [switch]$SkipExistingResults,
        
        [Parameter()]
        [int]$DaysToAnalyze = 30
    )
    
    begin {
        # Initialize logging
        $script:LogFile = Join-Path -Path $OutputPath -ChildPath "EntraIDCoreForensics_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $script:ResultPath = Join-Path -Path $OutputPath -ChildPath "Results"
        
        if (-not (Test-Path -Path $OutputPath)) {
            try {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created output directory: $OutputPath" -Level Info
            }
            catch {
                throw "Failed to create output directory: $($_.Exception.Message)"
            }
        }
        
        if (-not (Test-Path -Path $script:ResultPath)) {
            try {
                New-Item -Path $script:ResultPath -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created results directory: $script:ResultPath" -Level Info
            }
            catch {
                throw "Failed to create results directory: $($_.Exception.Message)"
            }
        }
        
        # Script-level variables
        $script:DetailedLogging = $DetailedLogging
        $script:AllFindings = @()
        $script:DaysToAnalyze = $DaysToAnalyze
        $script:AnalysisStartDate = (Get-Date).AddDays(-$DaysToAnalyze)
    }
    
    process {
        try {
            Write-Log -Message "Starting Azure AD / Entra ID Core Identity Forensics analysis" -Level Info
            
            # Connect to Microsoft Graph
            Connect-MgGraph
            
            # Determine which checks to run
            $checksToRun = @()
            if ($Checks -contains "All") {
                $checksToRun = @("UserAccounts", "DirectoryRoles", "Applications", 
                              "OAuthGrants", "FederationSettings", "ConditionalAccess", "SignInAnalysis")
            }
            else {
                $checksToRun = $Checks
            }
            
            # Run selected checks
            foreach ($check in $checksToRun) {
                $checkResultPath = Join-Path -Path $script:ResultPath -ChildPath "EntraID_$check.json"
                
                if ($SkipExistingResults -and (Test-Path -Path $checkResultPath)) {
                    Write-Log -Message "Skipping $check check as results already exist" -Level Info
                    continue
                }
                
                Write-Log -Message "Running $check check" -Level Info
                
                switch ($check) {
                    "UserAccounts" { 
                        $findings = Invoke-UserAccountCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "DirectoryRoles" { 
                        $findings = Invoke-DirectoryRoleCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "Applications" { 
                        $findings = Invoke-ApplicationCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "OAuthGrants" { 
                        $findings = Invoke-OAuthGrantCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "FederationSettings" { 
                        $findings = Invoke-FederationSettingCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "ConditionalAccess" { 
                        $findings = Invoke-ConditionalAccessCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "SignInAnalysis" { 
                        $findings = Invoke-SignInAnalysisCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                }
            }
            
            # Generate summary report
            $summaryPath = Join-Path -Path $OutputPath -ChildPath "EntraIDCoreForensics_Summary.json"
            Export-FindingsToJson -Findings $script:AllFindings -FilePath $summaryPath
            
            Write-Log -Message "Azure AD / Entra ID Core Identity Forensics analysis completed successfully" -Level Info
        }
        catch {
            Write-Log -Message "Error during Azure AD / Entra ID Core Identity Forensics analysis: $($_.Exception.Message)" -Level Error
            Write-Log -Message "Stack Trace: $($_.ScriptStackTrace)" -Level Error
            throw "Azure AD / Entra ID Core Identity Forensics analysis failed: $($_.Exception.Message)"
        }
        finally {
            # Disconnect from Microsoft Graph
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        }
    }
    
    end {
        Write-Log -Message "Azure AD / Entra ID Core Identity Forensics analysis finished" -Level Info
    }
}

function Connect-MgGraph {
    [CmdletBinding()]
    param()
    
    try {
        # Check if already connected
        $connected = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $connected) {
            Write-Log -Message "Connecting to Microsoft Graph" -Level Info
            
            # Define required scopes
            $scopes = @(
                "Directory.Read.All",
                "AuditLog.Read.All",
                "User.Read.All",
                "Application.Read.All",
                "Group.Read.All",
                "Policy.Read.All",
                "IdentityRiskyUser.Read.All"
            )
            
            # Connect with required scopes
            $null = Microsoft.Graph.Authentication\Connect-MgGraph -Scopes $scopes -ErrorAction Stop
            
            $context = Get-MgContext
            if (-not $context) {
                throw "Failed to establish Microsoft Graph connection"
            }
            
            Write-Log -Message "Successfully connected to Microsoft Graph for tenant: $($context.TenantId)" -Level Info
        }
        else {
            Write-Log -Message "Already connected to Microsoft Graph for tenant: $($connected.TenantId)" -Level Info
        }
    }
    catch {
        Write-Log -Message "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
        throw "Microsoft Graph connection failed. Please ensure you have the Microsoft.Graph PowerShell modules installed and appropriate permissions."
    }
}

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("Info", "Warning", "Error", "Debug")]
        [string]$Level = "Info"
    )
    
    # Only log debug messages if detailed logging is enabled
    if ($Level -eq "Debug" -and -not $script:DetailedLogging) {
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Output to console based on level
    switch ($Level) {
        "Info" { Write-Host $logMessage }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Debug" { Write-Host $logMessage -ForegroundColor Cyan }
    }
    
    # Write to log file
    Add-Content -Path $script:LogFile -Value $logMessage
}

function Export-FindingsToJson {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Findings,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        $Findings | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding utf8 -Force
        Write-Log -Message "Exported findings to $FilePath" -Level Info
        
        # Add to master findings list
        $script:AllFindings += $Findings
    }
    catch {
        Write-Log -Message "Error exporting findings to $FilePath : $($_.Exception.Message)" -Level Error
    }
}

function Add-Finding {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("High", "Medium", "Low", "Informational")]
        [string]$Severity,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter()]
        [string]$Recommendation,
        
        [Parameter()]
        [PSObject]$Data,
        
        [Parameter()]
        [DateTime]$Timestamp = (Get-Date)
    )
    
    $finding = [PSCustomObject]@{
        Category = $Category
        Title = $Title
        Severity = $Severity
        Description = $Description
        Recommendation = $Recommendation
        Data = $Data
        Timestamp = $Timestamp
        Id = [Guid]::NewGuid().ToString()
    }
    
    return $finding
}

function Invoke-UserAccountCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing user accounts" -Level Info
        
        # Get all users
        $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, UserType, CreatedDateTime, AccountEnabled, 
                                      AssignedLicenses, OnPremisesSyncEnabled, Mail, OtherMails, ProxyAddresses, 
                                      PasswordPolicies, CreatedDateTime, SignInActivity, IdentityInfo -ErrorAction Stop
        
        Write-Log -Message "Retrieved $($users.Count) user accounts" -Level Info
        
        # Check for recently created users
        $recentUsers = $users | Where-Object { $_.CreatedDateTime -ge $script:AnalysisStartDate }
        
        if ($recentUsers) {
            foreach ($user in $recentUsers) {
                $severity = "Medium"
                $isSuspicious = $false
                $reasons = @()
                
                # Check for naming patterns that could indicate suspicious accounts
                if ($user.DisplayName -match "^admin" -or 
                    $user.UserPrincipalName -match "^admin" -or
                    $user.DisplayName -match "svc" -or
                    $user.UserPrincipalName -match "svc" -or
                    $user.DisplayName -match "service" -or
                    $user.UserPrincipalName -match "service") {
                    $isSuspicious = $true
                    $reasons += "Account has suspicious naming pattern (admin/service)"
                    $severity = "High"
                }
                
                # Check for temporary or free email domains in proxy addresses or other mails
                $suspiciousEmailDomains = @("gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "protonmail.com", "mail.com", "temp-mail.org", "mailinator.com")
                $userEmails = @()
                
                if ($user.Mail) { $userEmails += $user.Mail }
                if ($user.OtherMails) { $userEmails += $user.OtherMails }
                if ($user.ProxyAddresses) { 
                    $userEmails += $user.ProxyAddresses | ForEach-Object { $_ -replace "SMTP:", "" }
                }
                
                $hasSuspiciousDomain = $false
                foreach ($email in $userEmails) {
                    $domain = ($email -split "@")[1]
                    if ($domain -in $suspiciousEmailDomains) {
                        $hasSuspiciousDomain = $true
                        $reasons += "Account uses suspicious email domain: $domain"
                        break
                    }
                }
                
                if ($hasSuspiciousDomain) {
                    $isSuspicious = $true
                    $severity = "Medium"
                }
                
                # Findings reporting
                if ($isSuspicious) {
                    $findings += Add-Finding -Category "UserAccounts" -Title "Suspicious recently created user account" `
                        -Severity $severity `
                        -Description "User account '$($user.UserPrincipalName)' was created on $(Get-Date $user.CreatedDateTime -Format 'yyyy-MM-dd') and has suspicious characteristics. Reasons: $($reasons -join '; ')" `
                        -Recommendation "Verify that this account was created legitimately and is required." `
                        -Data $user
                }
                else {
                    $findings += Add-Finding -Category "UserAccounts" -Title "Recently created user account" `
                        -Severity "Informational" `
                        -Description "User account '$($user.UserPrincipalName)' was created on $(Get-Date $user.CreatedDateTime -Format 'yyyy-MM-dd')." `
                        -Recommendation "Verify that this account was created legitimately." `
                        -Data $user
                }
            }
        }
        
        # Check for accounts with password never expires
        $passwordNeverExpiresUsers = $users | Where-Object { $_.PasswordPolicies -contains "DisablePasswordExpiration" }
        
        if ($passwordNeverExpiresUsers) {
            foreach ($user in $passwordNeverExpiresUsers) {
                # Only report on enabled accounts that aren't synced from on-premises
                if ($user.AccountEnabled -and (-not $user.OnPremisesSyncEnabled)) {
                    $findings += Add-Finding -Category "UserAccounts" -Title "User account with password never expires" `
                        -Severity "Low" `
                        -Description "User account '$($user.UserPrincipalName)' is configured with password never expires policy, which could be exploited for persistent access." `
                        -Recommendation "Configure password expiration for this account or verify that this exception is legitimate and documented." `
                        -Data $user
                }
            }
        }
        
        # Check for MFA status using the Microsoft Graph beta endpoint (requires appropriate permissions)
        try {
            # First check if we can access authentication methods (might require additional permissions)
            $testUser = $users | Select-Object -First 1
            $authMethods = Get-MgUserAuthenticationMethod -UserId $testUser.Id -ErrorAction Stop
            
            # Get users with privileged roles for MFA check
            $directoryRoles = Get-MgDirectoryRole -All -ExpandProperty Members -ErrorAction Stop
            $privilegedRoles = @("Global Administrator", "Privileged Role Administrator", "Exchange Administrator", "SharePoint Administrator", "User Administrator", "Application Administrator", "Security Administrator")
            
            $usersInPrivilegedRoles = @()
            
            foreach ($role in $directoryRoles) {
                if ($role.DisplayName -in $privilegedRoles -and $role.Members) {
                    $usersInPrivilegedRoles += $role.Members
                }
            }
            
            $uniquePrivilegedUserIds = $usersInPrivilegedRoles | Select-Object -ExpandProperty Id -Unique
            
            foreach ($userId in $uniquePrivilegedUserIds) {
                $authMethods = Get-MgUserAuthenticationMethod -UserId $userId -ErrorAction Stop
                $user = $users | Where-Object { $_.Id -eq $userId }
                
                if (-not $user) {
                    continue
                }
                
                # Check for MFA methods
                $hasMFA = $false
                $strongMFAMethods = $false
                
                foreach ($method in $authMethods) {
                    $methodType = $method.AdditionalProperties["@odata.type"]
                    
                    # Microsoft Authenticator, FIDO2, or Certificate
                    if ($methodType -match "microsoft.graph.microsoftAuthenticatorAuthenticationMethod|microsoft.graph.fido2AuthenticationMethod|microsoft.graph.certificateBasedAuthenticationMethod") {
                        $hasMFA = $true
                        $strongMFAMethods = $true
                        break
                    }
                    # Phone-based methods (SMS or Phone call)
                    elseif ($methodType -match "microsoft.graph.phoneAuthenticationMethod") {
                        $hasMFA = $true
                    }
                }
                
                if (-not $hasMFA) {
                    $findings += Add-Finding -Category "UserAccounts" -Title "Privileged account without MFA" `
                        -Severity "High" `
                        -Description "User account '$($user.UserPrincipalName)' has privileged roles but does not have MFA enabled, which is a significant security risk." `
                        -Recommendation "Configure MFA for this privileged account immediately." `
                        -Data $user
                }
                elseif (-not $strongMFAMethods) {
                    $findings += Add-Finding -Category "UserAccounts" -Title "Privileged account with weak MFA" `
                        -Severity "Medium" `
                        -Description "User account '$($user.UserPrincipalName)' has privileged roles but is using weaker MFA methods (like SMS), which could be bypassed." `
                        -Recommendation "Configure stronger MFA methods such as Microsoft Authenticator or FIDO2 security keys for this privileged account." `
                        -Data $user
                }
            }
        }
        catch {
            Write-Log -Message "Error checking MFA status: $($_.Exception.Message)" -Level Warning
            $findings += Add-Finding -Category "UserAccounts" -Title "Unable to check MFA status" `
                -Severity "Medium" `
                -Description "Unable to check MFA status for users. This might indicate insufficient permissions or that the required Microsoft Graph API is not available." `
                -Recommendation "Manually verify MFA status for privileged accounts or ensure appropriate permissions for the Microsoft Graph API."
        }
        
        # Check for guest users (this might need to be moved to a separate module)
        $guestUsers = $users | Where-Object { $_.UserType -eq "Guest" }
        
        if ($guestUsers) {
            # Report on guests created recently as informational
            $recentGuests = $guestUsers | Where-Object { $_.CreatedDateTime -ge $script:AnalysisStartDate }
            
            if ($recentGuests) {
                foreach ($guest in $recentGuests) {
                    $findings += Add-Finding -Category "UserAccounts" -Title "Recently created guest user" `
                        -Severity "Informational" `
                        -Description "Guest user '$($guest.UserPrincipalName)' was created on $(Get-Date $guest.CreatedDateTime -Format 'yyyy-MM-dd')." `
                        -Recommendation "Verify that this guest user was invited legitimately and has appropriate access." `
                        -Data $guest
                }
            }
        }
        
        Write-Log -Message "Completed user account analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing user accounts: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "UserAccounts" -Title "Error analyzing user accounts" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing user accounts: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of user accounts is recommended."
    }
    
    return $findings
}

function Invoke-DirectoryRoleCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing directory roles" -Level Info
        
        # Get all directory roles with members
        $roles = Get-MgDirectoryRole -All -ExpandProperty Members -ErrorAction Stop
        
        # Define highly privileged roles
        $highPrivilegeRoles = @(
            "Global Administrator",
            "Privileged Role Administrator",
            "User Administrator",
            "Directory Writers",
            "Exchange Administrator",
            "SharePoint Administrator",
            "Hybrid Identity Administrator",
            "Application Administrator",
            "Cloud Application Administrator",
            "Authentication Administrator",
            "Security Administrator"
        )
        
        # Get all directory role templates to check for custom roles
        $roleTemplates = Get-MgDirectoryRoleTemplate -All -ErrorAction Stop
        
        # Get all service principals to check if any have admin roles
        $servicePrincipals = Get-MgServicePrincipal -All -Property Id, AppId, DisplayName, AppRoleAssignmentRequired, AccountEnabled, ServicePrincipalType -ErrorAction Stop
        
        # Get all users for resolving IDs
        $users = Get-MgUser -All -Property Id, UserPrincipalName, UserType, DisplayName -ErrorAction Stop
        
        # Check for high privilege roles
        foreach ($role in $roles) {
            if ($role.DisplayName -in $highPrivilegeRoles) {
                if ($role.Members) {
                    foreach ($member in $role.Members) {
                        $isSuspicious = $false
                        $reasons = @()
                        $severity = "Informational"
                        
                        # Try to get the member object (could be a user or service principal)
                        $memberUser = $users | Where-Object { $_.Id -eq $member.Id }
                        $memberServicePrincipal = $null
                        
                        if (-not $memberUser) {
                            $memberServicePrincipal = $servicePrincipals | Where-Object { $_.Id -eq $member.Id }
                        }
                        
                        # Check if this is a service principal with an admin role (suspicious)
                        if ($memberServicePrincipal) {
                            $isSuspicious = $true
                            $severity = "High"
                            $reasons += "Service principal assigned to privileged directory role"
                            
                            $findings += Add-Finding -Category "DirectoryRoles" -Title "Service principal with privileged directory role" `
                                -Severity $severity `
                                -Description "Service principal '$($memberServicePrincipal.DisplayName)' is assigned to the highly privileged role '$($role.DisplayName)'. Reasons: $($reasons -join '; ')" `
                                -Recommendation "Verify that this service principal requires this level of privilege. If not, remove it from the role immediately." `
                                -Data @{
                                    RoleName = $role.DisplayName
                                    MemberType = "ServicePrincipal"
                                    MemberName = $memberServicePrincipal.DisplayName
                                    MemberId = $member.Id
                                    ServicePrincipalDetails = $memberServicePrincipal
                                }
                        }
                        # Check if this is a guest user with an admin role (highly suspicious)
                        elseif ($memberUser -and $memberUser.UserType -eq "Guest") {
                            $isSuspicious = $true
                            $severity = "High"
                            $reasons += "Guest user assigned to privileged directory role"
                            
                            $findings += Add-Finding -Category "DirectoryRoles" -Title "Guest user with privileged directory role" `
                                -Severity $severity `
                                -Description "Guest user '$($memberUser.UserPrincipalName)' is assigned to the highly privileged role '$($role.DisplayName)'. Reasons: $($reasons -join '; ')" `
                                -Recommendation "Remove the guest user from this privileged role immediately unless there is a documented business requirement." `
                                -Data @{
                                    RoleName = $role.DisplayName
                                    MemberType = "User"
                                    MemberName = $memberUser.DisplayName
                                    UserPrincipalName = $memberUser.UserPrincipalName
                                    UserType = $memberUser.UserType
                                    MemberId = $member.Id
                                }
                        }
                        # Regular user in admin role - informational
                        elseif ($memberUser) {
                            # For Global Administrator, always report
                            if ($role.DisplayName -eq "Global Administrator") {
                                $findings += Add-Finding -Category "DirectoryRoles" -Title "User assigned to Global Administrator role" `
                                    -Severity "Medium" `
                                    -Description "User '$($memberUser.UserPrincipalName)' is assigned to the Global Administrator role. This gives full control over the tenant." `
                                    -Recommendation "Verify that this user requires Global Administrator privileges. Follow the principle of least privilege." `
                                    -Data @{
                                        RoleName = $role.DisplayName
                                        MemberType = "User"
                                        MemberName = $memberUser.DisplayName
                                        UserPrincipalName = $memberUser.UserPrincipalName
                                        UserType = $memberUser.UserType
                                        MemberId = $member.Id
                                    }
                            }
                            else {
                                # Only report other roles if detailed logging is enabled
                                if ($script:DetailedLogging) {
                                    $findings += Add-Finding -Category "DirectoryRoles" -Title "User assigned to privileged directory role" `
                                        -Severity "Informational" `
                                        -Description "User '$($memberUser.UserPrincipalName)' is assigned to the privileged role '$($role.DisplayName)'." `
                                        -Recommendation "Verify that this user requires these privileges. Follow the principle of least privilege." `
                                        -Data @{
                                            RoleName = $role.DisplayName
                                            MemberType = "User"
                                            MemberName = $memberUser.DisplayName
                                            UserPrincipalName = $memberUser.UserPrincipalName
                                            UserType = $memberUser.UserType
                                            MemberId = $member.Id
                                        }
                                }
                            }
                        }
                        # Unknown member type (could be group or other object)
                        else {
                            $findings += Add-Finding -Category "DirectoryRoles" -Title "Unknown entity with privileged directory role" `
                                -Severity "Medium" `
                                -Description "An unknown entity with ID '$($member.Id)' is assigned to the privileged role '$($role.DisplayName)'. This could be a group or other directory object." `
                                -Recommendation "Investigate this entity to verify its legitimacy and requirement for privileged access." `
                                -Data @{
                                    RoleName = $role.DisplayName
                                    MemberType = "Unknown"
                                    MemberId = $member.Id
                                }
                        }
                    }
                }
            }
        }
        
        # Check for custom directory roles (if available in the tenant)
        # Custom directory roles are available in Azure AD Premium P1
        try {
            # First see if this tenant has any custom roles
            $customRoles = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop | 
                           Where-Object { $_.IsBuiltIn -eq $false }
            
            if ($customRoles) {
                foreach ($customRole in $customRoles) {
                    # Check if the custom role has privileged permissions
                    $hasPrivilegedPermissions = $false
                    $permissions = @()
                    
                    if ($customRole.RolePermissions) {
                        foreach ($permission in $customRole.RolePermissions) {
                            # Look for particularly sensitive permissions
                            $sensitiveActions = @(
                                "microsoft.directory/users/create",
                                "microsoft.directory/users/delete",
                                "microsoft.directory/users/basic/update",
                                "microsoft.directory/users/password/update",
                                "microsoft.directory/applications/create",
                                "microsoft.directory/applications/credentials/update",
                                "microsoft.directory/servicePrincipals/create",
                                "microsoft.directory/servicePrincipals/credentials/update",
                                "microsoft.directory/groups/create",
                                "microsoft.directory/groups/delete",
                                "microsoft.directory/roles/create",
                                "microsoft.directory/roles/delete",
                                "microsoft.directory/roleAssignments/create",
                                "microsoft.directory/roleAssignments/delete"
                            )
                            
                            foreach ($action in $permission.AllowedResourceActions) {
                                if ($action -in $sensitiveActions -or $action -like "microsoft.directory/*.*") {
                                    $hasPrivilegedPermissions = $true
                                    $permissions += $action
                                }
                            }
                        }
                    }
                    
                    if ($hasPrivilegedPermissions) {
                        $findings += Add-Finding -Category "DirectoryRoles" -Title "Custom directory role with privileged permissions" `
                            -Severity "Medium" `
                            -Description "Custom directory role '$($customRole.DisplayName)' has privileged permissions: $($permissions -join ', ')" `
                            -Recommendation "Review the permissions of this custom role to ensure they follow the principle of least privilege." `
                            -Data $customRole
                    }
                    
                    # Check if this custom role was created/modified recently
                    if ($customRole.CreatedDateTime -ge $script:AnalysisStartDate -or 
                        ($customRole.ModifiedDateTime -and $customRole.ModifiedDateTime -ge $script:AnalysisStartDate)) {
                        $findings += Add-Finding -Category "DirectoryRoles" -Title "Recently created or modified custom directory role" `
                            -Severity "Medium" `
                            -Description "Custom directory role '$($customRole.DisplayName)' was $(if($customRole.CreatedDateTime -ge $script:AnalysisStartDate){'created'}else{'modified'}) on $(Get-Date $(if($customRole.CreatedDateTime -ge $script:AnalysisStartDate){$customRole.CreatedDateTime}else{$customRole.ModifiedDateTime}) -Format 'yyyy-MM-dd'). Recent modifications to roles could indicate attacker activity." `
                            -Recommendation "Verify that the changes to this custom role were authorized and legitimate." `
                            -Data $customRole
                    }
                }
            }
        }
        catch {
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Not Found*") {
                Write-Log -Message "Custom directory roles might not be available in this tenant or the account lacks permissions" -Level Warning
            }
            else {
                Write-Log -Message "Error checking custom directory roles: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "DirectoryRoles" -Title "Error checking custom directory roles" `
                    -Severity "Low" `
                    -Description "An error occurred while checking custom directory roles: $($_.Exception.Message)" `
                    -Recommendation "Manual investigation of custom directory roles is recommended."
            }
        }
        
        Write-Log -Message "Completed directory role analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing directory roles: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "DirectoryRoles" -Title "Error analyzing directory roles" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing directory roles: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of directory roles is recommended."
    }
    
    return $findings
}

function Invoke-ApplicationCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing application registrations and service principals" -Level Info
        
        # Get all application registrations
        $applications = Get-MgApplication -All -Property Id, AppId, DisplayName, CreatedDateTime, SignInAudience, Web, Api, RequiredResourceAccess, KeyCredentials, PasswordCredentials -ErrorAction Stop
        
        # Get all service principals
        $servicePrincipals = Get-MgServicePrincipal -All -Property Id, AppId, DisplayName, AccountEnabled, CreatedDateTime, ServicePrincipalType, AppRoleAssignmentRequired, KeyCredentials, PasswordCredentials, AppRoles, Oauth2PermissionScopes -ErrorAction Stop
        
        # Check for recently created applications
        $recentApplications = $applications | Where-Object { $_.CreatedDateTime -ge $script:AnalysisStartDate }
        
        if ($recentApplications) {
            foreach ($app in $recentApplications) {
                $severity = "Medium"
                $isSuspicious = $false
                $reasons = @()
                
                # Check for high-risk API permissions
                $highRiskPermissions = @()
                if ($app.RequiredResourceAccess) {
                    foreach ($resource in $app.RequiredResourceAccess) {
                        foreach ($scope in $resource.ResourceAccess) {
                            # High-risk scopes list (not exhaustive)
                            $highRiskScopes = @(
                                "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9", # Application.ReadWrite.All
                                "78c8a3c8-a07e-4b9e-af1b-b5ccab50a175", # Directory.ReadWrite.All
                                "62a82d76-70ea-41e2-9197-370581804d09", # Group.ReadWrite.All
                                "5b567255-7703-4780-807c-7be8301ae99b", # Group.Read.All
                                "6918b873-d17a-4dc1-b314-35f528134491", # Mail.Read
                                "dbaae8cf-10b5-4b86-a4a1-f871c94c6695", # Mail.ReadWrite.All
                                "ef54d2bf-783f-4e0f-bca1-3210c0444d99", # User.ReadBasic.All
                                "df021288-bdef-4463-88db-98f22de89214", # User.Read.All
                                "741f803b-c850-494e-b5df-cde7c675a1ca", # User.ReadWrite.All
                                "230c1aed-a721-4c5d-9cb4-a90514e508ef", # Reports.Read.All
                                "c5366453-9fb0-48a5-a156-24f0c49a4b84", # AuditLog.Read.All
                                "14dad69e-099b-42c9-810b-d002981feec1"  # AuditLog.ReadWrite.All
                            )
                            
                            if ($scope.Id -in $highRiskScopes) {
                                $highRiskPermissions += $scope.Id
                                $isSuspicious = $true
                                $severity = "High"
                            }
                        }
                    }
                    
                    if ($highRiskPermissions.Count -gt 0) {
                        $reasons += "Application requests high-risk permissions"
                    }
                }
                
                # Check for multi-tenant apps with high-risk permissions
                if ($app.SignInAudience -eq "AzureADMultipleOrgs" -and $highRiskPermissions.Count -gt 0) {
                    $reasons += "Multi-tenant application with high-risk permissions"
                    $severity = "High"
                }
                
                # Check for app credentials
                $hasCredentials = $false
                $recentCredentials = $false
                
                # Check certificates
                if ($app.KeyCredentials) {
                    $hasCredentials = $true
                    foreach ($cert in $app.KeyCredentials) {
                        if ($cert.StartDateTime -ge $script:AnalysisStartDate) {
                            $recentCredentials = $true
                            $reasons += "Recently added certificate credential ($(Get-Date $cert.StartDateTime -Format 'yyyy-MM-dd'))"
                            break
                        }
                    }
                }
                
                # Check secrets
                if ($app.PasswordCredentials) {
                    $hasCredentials = $true
                    foreach ($secret in $app.PasswordCredentials) {
                        if ($secret.StartDateTime -ge $script:AnalysisStartDate) {
                            $recentCredentials = $true
                            $reasons += "Recently added secret credential ($(Get-Date $secret.StartDateTime -Format 'yyyy-MM-dd'))"
                            break
                        }
                    }
                }
                
                # Check for suspicious Redirect URIs
                $suspiciousRedirects = $false
                $suspiciousRedirectList = @()
                
                if ($app.Web -and $app.Web.RedirectUris) {
                    foreach ($uri in $app.Web.RedirectUris) {
                        # Check for potentially suspicious domains
                        if ($uri -like "*.herokuapp.com*" -or 
                            $uri -like "*.azurewebsites.net*" -or
                            $uri -like "*.000webhostapp.com*" -or
                            $uri -like "*.ngrok.io*" -or
                            $uri -like "*.firebaseapp.com*" -or
                            $uri -like "*.glitch.me*" -or
                            $uri -like "localhost*" -or
                            $uri -like "127.0.0.1*") {
                            $suspiciousRedirects = $true
                            $suspiciousRedirectList += $uri
                        }
                    }
                    
                    if ($suspiciousRedirects) {
                        $reasons += "Contains potentially suspicious redirect URIs: $($suspiciousRedirectList -join ', ')"
                        $isSuspicious = $true
                    }
                }
                
                # Create findings based on analysis
                if ($reasons.Count -gt 0) {
                    $findings += Add-Finding -Category "Applications" -Title "Suspicious recently created application" `
                        -Severity $severity `
                        -Description "Application '$($app.DisplayName)' (AppId: $($app.AppId)) was created on $(Get-Date $app.CreatedDateTime -Format 'yyyy-MM-dd') and has suspicious characteristics. Reasons: $($reasons -join '; ')" `
                        -Recommendation "Review this application to confirm it's legitimate. If not, remove it immediately and investigate for potential compromise." `
                        -Data $app
                }
                else {
                    $findings += Add-Finding -Category "Applications" -Title "Recently created application" `
                        -Severity "Informational" `
                        -Description "Application '$($app.DisplayName)' (AppId: $($app.AppId)) was created on $(Get-Date $app.CreatedDateTime -Format 'yyyy-MM-dd')." `
                        -Recommendation "Verify that this application was created legitimately." `
                        -Data $app
                }
            }
        }
        
        # Check for recently created service principals
        $recentServicePrincipals = $servicePrincipals | Where-Object { $_.CreatedDateTime -ge $script:AnalysisStartDate }
        
        if ($recentServicePrincipals) {
            foreach ($sp in $recentServicePrincipals) {
                $severity = "Medium"
                $isSuspicious = $false
                $reasons = @()
                
                # Check if this is an application SP or a managed identity
                $spType = if ($sp.ServicePrincipalType -eq "Application") { "application" } else { $sp.ServicePrincipalType.ToLower() }
                
                # Check if app assignment is not required (meaning any user can use it)
                if ($sp.AppRoleAssignmentRequired -eq $false -and $sp.ServicePrincipalType -eq "Application") {
                    $reasons += "Does not require user assignment (any user can consent)"
                    $isSuspicious = $true
                }
                
                # Check for app credentials
                $hasCredentials = $false
                $recentCredentials = $false
                
                # Check certificates
                if ($sp.KeyCredentials) {
                    $hasCredentials = $true
                    foreach ($cert in $sp.KeyCredentials) {
                        if ($cert.StartDateTime -ge $script:AnalysisStartDate) {
                            $recentCredentials = $true
                            $reasons += "Recently added certificate credential ($(Get-Date $cert.StartDateTime -Format 'yyyy-MM-dd'))"
                            break
                        }
                    }
                }
                
                # Check secrets
                if ($sp.PasswordCredentials) {
                    $hasCredentials = $true
                    foreach ($secret in $sp.PasswordCredentials) {
                        if ($secret.StartDateTime -ge $script:AnalysisStartDate) {
                            $recentCredentials = $true
                            $reasons += "Recently added secret credential ($(Get-Date $secret.StartDateTime -Format 'yyyy-MM-dd'))"
                            break
                        }
                    }
                }
                
                # Check for high-risk app roles
                if ($sp.AppRoles -and $sp.ServicePrincipalType -eq "Application") {
                    $highRiskRoles = $false
                    
                    foreach ($role in $sp.AppRoles) {
                        if ($role.IsEnabled -and $role.AllowedMemberTypes -contains "Application") {
                            $highRiskRoles = $true
                            $reasons += "Exposes app roles to other applications"
                            break
                        }
                    }
                }
                
                # Check for OAuth scopes with application consent
                if ($sp.Oauth2PermissionScopes -and $sp.ServicePrincipalType -eq "Application") {
                    $hasApplicationScopes = $false
                    
                    foreach ($scope in $sp.Oauth2PermissionScopes) {
                        if ($scope.IsEnabled -and $scope.Type -eq "Admin") {
                            $hasApplicationScopes = $true
                            $reasons += "Exposes admin-only OAuth scopes"
                            break
                        }
                    }
                }
                
                # Create findings based on analysis
                if ($reasons.Count -gt 0) {
                    $findings += Add-Finding -Category "Applications" -Title "Suspicious recently created service principal" `
                        -Severity $severity `
                        -Description "Service principal '$($sp.DisplayName)' (AppId: $($sp.AppId)) of type $spType was created on $(Get-Date $sp.CreatedDateTime -Format 'yyyy-MM-dd') and has suspicious characteristics. Reasons: $($reasons -join '; ')" `
                        -Recommendation "Review this service principal to confirm it's legitimate. If not, remove it immediately and investigate for potential compromise." `
                        -Data $sp
                }
                else {
                    $findings += Add-Finding -Category "Applications" -Title "Recently created service principal" `
                        -Severity "Informational" `
                        -Description "Service principal '$($sp.DisplayName)' (AppId: $($sp.AppId)) of type $spType was created on $(Get-Date $sp.CreatedDateTime -Format 'yyyy-MM-dd')." `
                        -Recommendation "Verify that this service principal was created legitimately." `
                        -Data $sp
                }
            }
        }
        
        # Check for expiring credentials to help prevent future issues
        $applications | ForEach-Object {
            $app = $_
            
            # Check certificate credentials
            if ($app.KeyCredentials) {
                foreach ($cert in $app.KeyCredentials) {
                    if ($cert.EndDateTime -le (Get-Date).AddDays(30)) {
                        $findings += Add-Finding -Category "Applications" -Title "Application with soon-expiring certificate" `
                            -Severity "Low" `
                            -Description "Application '$($app.DisplayName)' (AppId: $($app.AppId)) has a certificate that will expire on $(Get-Date $cert.EndDateTime -Format 'yyyy-MM-dd')." `
                            -Recommendation "Renew this certificate before it expires to prevent application disruption." `
                            -Data @{
                                Application = $app
                                ExpiringCertificate = $cert
                            }
                    }
                }
            }
            
            # Check password credentials
            if ($app.PasswordCredentials) {
                foreach ($cred in $app.PasswordCredentials) {
                    if ($cred.EndDateTime -le (Get-Date).AddDays(30)) {
                        $findings += Add-Finding -Category "Applications" -Title "Application with soon-expiring secret" `
                            -Severity "Low" `
                            -Description "Application '$($app.DisplayName)' (AppId: $($app.AppId)) has a secret that will expire on $(Get-Date $cred.EndDateTime -Format 'yyyy-MM-dd')." `
                            -Recommendation "Renew this secret before it expires to prevent application disruption." `
                            -Data @{
                                Application = $app
                                ExpiringSecret = $cred
                            }
                    }
                }
            }
        }
        
        # Do the same for service principals
        $servicePrincipals | ForEach-Object {
            $sp = $_
            
            # Check certificate credentials
            if ($sp.KeyCredentials) {
                foreach ($cert in $sp.KeyCredentials) {
                    if ($cert.EndDateTime -le (Get-Date).AddDays(30)) {
                        $findings += Add-Finding -Category "Applications" -Title "Service principal with soon-expiring certificate" `
                            -Severity "Low" `
                            -Description "Service principal '$($sp.DisplayName)' (AppId: $($sp.AppId)) has a certificate that will expire on $(Get-Date $cert.EndDateTime -Format 'yyyy-MM-dd')." `
                            -Recommendation "Renew this certificate before it expires to prevent service disruption." `
                            -Data @{
                                ServicePrincipal = $sp
                                ExpiringCertificate = $cert
                            }
                    }
                }
            }
            
            # Check password credentials
            if ($sp.PasswordCredentials) {
                foreach ($cred in $sp.PasswordCredentials) {
                    if ($cred.EndDateTime -le (Get-Date).AddDays(30)) {
                        $findings += Add-Finding -Category "Applications" -Title "Service principal with soon-expiring secret" `
                            -Severity "Low" `
                            -Description "Service principal '$($sp.DisplayName)' (AppId: $($sp.AppId)) has a secret that will expire on $(Get-Date $cred.EndDateTime -Format 'yyyy-MM-dd')." `
                            -Recommendation "Renew this secret before it expires to prevent service disruption." `
                            -Data @{
                                ServicePrincipal = $sp
                                ExpiringSecret = $cred
                            }
                    }
                }
            }
        }
        
        Write-Log -Message "Completed application and service principal analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing applications and service principals: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "Applications" -Title "Error analyzing applications and service principals" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing applications and service principals: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of applications and service principals is recommended."
    }
    
    return $findings
}

function Invoke-OAuthGrantCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing OAuth permission grants" -Level Info
        
        # Get OAuth2 permission grants (delegated permissions)
        $oAuth2PermissionGrants = Get-MgOauth2PermissionGrant -All -ErrorAction Stop
        
        # Get service principals for resolution
        $servicePrincipals = Get-MgServicePrincipal -All -Property Id, AppId, DisplayName, AppOwnerOrganizationId -ErrorAction Stop
        
        # Get app role assignments (application permissions)
        $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignedTo -All -ErrorAction Stop
        
        # Define high-risk scopes
        $highRiskScopes = @(
            "Directory.Read.All",
            "Directory.ReadWrite.All",
            "Group.Read.All",
            "Group.ReadWrite.All",
            "Mail.Read",
            "Mail.ReadWrite",
            "MailboxSettings.Read",
            "MailboxSettings.ReadWrite",
            "User.Read.All",
            "User.ReadWrite.All",
            "Files.Read.All",
            "Files.ReadWrite.All",
            "Sites.Read.All",
            "Sites.ReadWrite.All",
            "IdentityRiskyUser.Read.All",
            "AuditLog.Read.All",
            "Application.Read.All",
            "Application.ReadWrite.All"
        )
        
        # Get tenant ID
        $context = Get-MgContext
        $tenantId = $context.TenantId
        
        # Process delegated permission grants
        foreach ($grant in $oAuth2PermissionGrants) {
            $isSuspicious = $false
            $reasons = @()
            $severity = "Low"
            
            # Get client service principal
            $clientSp = $servicePrincipals | Where-Object { $_.Id -eq $grant.ClientId }
            if (-not $clientSp) {
                continue  # Skip if we can't find the service principal
            }
            
            # Get resource service principal
            $resourceSp = $servicePrincipals | Where-Object { $_.Id -eq $grant.ResourceId }
            if (-not $resourceSp) {
                continue  # Skip if we can't find the service principal
            }
            
            # Check if this is a multi-tenant app
            $isMultiTenant = $false
            if ($clientSp.AppOwnerOrganizationId -and $clientSp.AppOwnerOrganizationId -ne $tenantId) {
                $isMultiTenant = $true
            }
            
            # Parse scopes
            $scopes = $grant.Scope -split ' '
            $highRiskScopesFound = @()
            
            foreach ($scope in $scopes) {
                if ($highRiskScopes -contains $scope) {
                    $highRiskScopesFound += $scope
                }
            }
            
            if ($highRiskScopesFound.Count -gt 0) {
                $isSuspicious = $true
                $reasons += "Has high-risk permissions: $($highRiskScopesFound -join ', ')"
                $severity = "Medium"
                
                if ($isMultiTenant) {
                    $reasons += "Multi-tenant application with high-risk permissions"
                    $severity = "High"
                }
            }
            
            # Check for consent type
            if ($grant.ConsentType -eq "AllPrincipals") {
                $reasons += "Admin-consented for all users in the organization"
                $isSuspicious = $true
                
                if ($highRiskScopesFound.Count -gt 0) {
                    $severity = "High"
                }
            }
            
            # Check if recently created
            if ($grant.CreatedDateTime -ge $script:AnalysisStartDate) {
                $isSuspicious = $true
                $reasons += "Recently created ($(Get-Date $grant.CreatedDateTime -Format 'yyyy-MM-dd'))"
                
                # Increase severity if also has high-risk permissions
                if ($highRiskScopesFound.Count -gt 0) {
                    $severity = "High"
                }
            }
            
            if ($isSuspicious) {
                $findings += Add-Finding -Category "OAuthGrants" -Title "Suspicious OAuth permission grant" `
                    -Severity $severity `
                    -Description "OAuth permission grant for application '$($clientSp.DisplayName)' to '$($resourceSp.DisplayName)' has suspicious characteristics. Reasons: $($reasons -join '; ')" `
                    -Recommendation "Review this permission grant to confirm it's legitimate. If not, remove it immediately." `
                    -Data @{
                        Grant = $grant
                        ClientApplication = $clientSp
                        ResourceApplication = $resourceSp
                        Scopes = $scopes
                        HighRiskScopes = $highRiskScopesFound
                    }
            }
        }
        
        # Process application permissions (app role assignments)
        foreach ($assignment in $appRoleAssignments) {
            $isSuspicious = $false
            $reasons = @()
            $severity = "Low"
            
            # Get client service principal (the one that got the permission)
            $clientSp = $servicePrincipals | Where-Object { $_.Id -eq $assignment.PrincipalId }
            if (-not $clientSp) {
                continue  # Skip if we can't find the service principal
            }
            
            # Get resource service principal (the one that granted the permission)
            $resourceSp = $servicePrincipals | Where-Object { $_.Id -eq $assignment.ResourceId }
            if (-not $resourceSp) {
                continue  # Skip if we can't find the service principal
            }
            
            # Determine role name
            $roleName = $assignment.AppRoleId
            
            # Check if this is a multi-tenant app
            $isMultiTenant = $false
            if ($clientSp.AppOwnerOrganizationId -and $clientSp.AppOwnerOrganizationId -ne $tenantId) {
                $isMultiTenant = $true
                $reasons += "Multi-tenant application with application permissions"
                $isSuspicious = $true
                $severity = "Medium"
            }
            
            # Check high-risk permissions for specific resource service principals
            if ($resourceSp.AppId -eq "00000003-0000-0000-c000-000000000000") {  # Microsoft Graph
                # Known high-risk Microsoft Graph app roles
                $highRiskRoles = @(
                    "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30", # Application.Read.All
                    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9", # Application.ReadWrite.All
                    "19dbc75e-c2e2-444c-a770-ec69d8559fc7", # Directory.ReadWrite.All
                    "62a82d76-70ea-41e2-9197-370581804d09", # Group.ReadWrite.All
                    "5b567255-7703-4780-807c-7be8301ae99b", # Group.Read.All
                    "6918b873-d17a-4dc1-b314-35f528134491", # Mail.Read
                    "dbaae8cf-10b5-4b86-a4a1-f871c94c6695", # Mail.ReadWrite
                    "df021288-bdef-4463-88db-98f22de89214", # User.Read.All
                    "741f803b-c850-494e-b5df-cde7c675a1ca", # User.ReadWrite.All
                    "230c1aed-a721-4c5d-9cb4-a90514e508ef", # Reports.Read.All
                    "c5366453-9fb0-48a5-a156-24f0c49a4b84", # AuditLog.Read.All
                    "14dad69e-099b-42c9-810b-d002981feec1"  # AuditLog.ReadWrite.All
                )
                
                if ($assignment.AppRoleId -in $highRiskRoles) {
                    $isSuspicious = $true
                    $reasons += "Has high-risk Microsoft Graph application permission"
                    $severity = "High"
                }
            }
            
            # Check if recently created
            if ($assignment.CreatedDateTime -ge $script:AnalysisStartDate) {
                $isSuspicious = $true
                $reasons += "Recently created ($(Get-Date $assignment.CreatedDateTime -Format 'yyyy-MM-dd'))"
                
                # Increase severity if also has high-risk permissions
                if ($severity -eq "Medium") {
                    $severity = "High"
                }
            }
            
            if ($isSuspicious) {
                $findings += Add-Finding -Category "OAuthGrants" -Title "Suspicious application permission assignment" `
                    -Severity $severity `
                    -Description "Application permission assignment for service principal '$($clientSp.DisplayName)' to '$($resourceSp.DisplayName)' has suspicious characteristics. Reasons: $($reasons -join '; ')" `
                    -Recommendation "Review this permission assignment to confirm it's legitimate. If not, remove it immediately." `
                    -Data @{
                        Assignment = $assignment
                        ClientApplication = $clientSp
                        ResourceApplication = $resourceSp
                        AppRoleId = $assignment.AppRoleId
                    }
            }
        }
        
        Write-Log -Message "Completed OAuth permission grant analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing OAuth permission grants: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "OAuthGrants" -Title "Error analyzing OAuth permission grants" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing OAuth permission grants: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of OAuth permission grants is recommended."
    }
    
    return $findings
}

function Invoke-FederationSettingCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing federation settings" -Level Info
        
        # Get all domains
        $domains = Get-MgDomain -All -ErrorAction Stop
        
        # Check for federated domains
        $federatedDomains = $domains | Where-Object { $_.AuthenticationType -eq "Federated" }
        
        if ($federatedDomains) {
            foreach ($domain in $federatedDomains) {
                # Get federation configuration if possible
                try {
                    # This might need additional permissions or might not be available via Graph API
                    # Using msol for this is often easier but less future-proof
                    
                    # For demo purposes, we'll just log the domain information
                    $findings += Add-Finding -Category "FederationSettings" -Title "Federated domain detected" `
                        -Severity "Medium" `
                        -Description "Domain '$($domain.Id)' is configured for federated authentication. Federation configurations could be modified by attackers to maintain persistence." `
                        -Recommendation "Verify that the federation settings for this domain are legitimate and have not been tampered with." `
                        -Data $domain
                }
                catch {
                    $findings += Add-Finding -Category "FederationSettings" -Title "Unable to retrieve federation settings" `
                        -Severity "Medium" `
                        -Description "Domain '$($domain.Id)' is configured for federated authentication, but federation settings could not be retrieved. Error: $($_.Exception.Message)" `
                        -Recommendation "Manually check the federation settings for this domain to ensure they haven't been tampered with." `
                        -Data $domain
                }
            }
        }
        
        # Check for Certificate-Based Authentication (CBA) settings if available
        try {
            # This might need additional permissions or might not be available via Graph API
            # For demonstration purposes, note that this check would require appropriate Graph permissions
            
            # Placeholder for actual implementation
            Write-Log -Message "Certificate-Based Authentication (CBA) settings check would happen here if available" -Level Debug
        }
        catch {
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Not Found*") {
                Write-Log -Message "Certificate-Based Authentication settings check not available or requires additional permissions" -Level Warning
            }
            else {
                Write-Log -Message "Error checking Certificate-Based Authentication settings: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "FederationSettings" -Title "Error checking Certificate-Based Authentication settings" `
                    -Severity "Low" `
                    -Description "An error occurred while checking Certificate-Based Authentication settings: $($_.Exception.Message)" `
                    -Recommendation "Manual investigation of Certificate-Based Authentication settings is recommended."
            }
        }
        
        Write-Log -Message "Completed federation settings analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing federation settings: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "FederationSettings" -Title "Error analyzing federation settings" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing federation settings: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of federation settings is recommended."
    }
    
    return $findings
}

function Invoke-ConditionalAccessCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing conditional access policies" -Level Info
        
        # Get all conditional access policies
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        
        # Get named locations
        $namedLocations = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop
        
        # Check for recently modified or created policies
        $recentPolicies = $policies | Where-Object { $_.CreatedDateTime -ge $script:AnalysisStartDate -or $_.ModifiedDateTime -ge $script:AnalysisStartDate }
        
        if ($recentPolicies) {
            foreach ($policy in $recentPolicies) {
                $isSuspicious = $false
                $reasons = @()
                $severity = "Medium"
                
                # Check policy state
                if ($policy.State -eq "disabled") {
                    $isSuspicious = $true
                    $reasons += "Policy is disabled"
                }
                elseif ($policy.State -eq "enabledForReportingButNotEnforced") {
                    $isSuspicious = $true
                    $reasons += "Policy is in report-only mode"
                }
                
                # Check if recently created or modified
                if ($policy.CreatedDateTime -ge $script:AnalysisStartDate) {
                    $isSuspicious = $true
                    $reasons += "Recently created ($(Get-Date $policy.CreatedDateTime -Format 'yyyy-MM-dd'))"
                }
                elseif ($policy.ModifiedDateTime -ge $script:AnalysisStartDate) {
                    $isSuspicious = $true
                    $reasons += "Recently modified ($(Get-Date $policy.ModifiedDateTime -Format 'yyyy-MM-dd'))"
                }
                
                if ($isSuspicious) {
                    $findings += Add-Finding -Category "ConditionalAccess" -Title "Recently modified conditional access policy" `
                        -Severity $severity `
                        -Description "Conditional Access policy '$($policy.DisplayName)' has suspicious characteristics. Reasons: $($reasons -join '; ')" `
                        -Recommendation "Review this policy to confirm the changes are legitimate." `
                        -Data $policy
                }
            }
        }
        
        # Check for recently created or modified named locations
        $recentLocations = $namedLocations | Where-Object { $_.CreatedDateTime -ge $script:AnalysisStartDate -or $_.ModifiedDateTime -ge $script:AnalysisStartDate }
        
        if ($recentLocations) {
            foreach ($location in $recentLocations) {
                $isSuspicious = $false
                $reasons = @()
                $severity = "Medium"
                
                # Check if recently created or modified
                if ($location.CreatedDateTime -ge $script:AnalysisStartDate) {
                    $isSuspicious = $true
                    $reasons += "Recently created ($(Get-Date $location.CreatedDateTime -Format 'yyyy-MM-dd'))"
                }
                elseif ($location.ModifiedDateTime -ge $script:AnalysisStartDate) {
                    $isSuspicious = $true
                    $reasons += "Recently modified ($(Get-Date $location.ModifiedDateTime -Format 'yyyy-MM-dd'))"
                }
                
                # Check for suspicious IP ranges (this is a simple example, could be expanded)
                if ($location.AdditionalProperties["ipRanges"]) {
                    $ipRanges = $location.AdditionalProperties["ipRanges"]
                    $containsNonCorporateRanges = $false
                    
                    # List of potentially non-corporate ranges (simple example)
                    $nonCorporateRanges = @("0.0.0.0/0", "0.0.0.0/1", "0.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
                    
                    foreach ($range in $ipRanges) {
                        if ($range.cidrAddress -in $nonCorporateRanges) {
                            $containsNonCorporateRanges = $true
                            $reasons += "Contains overly broad IP range: $($range.cidrAddress)"
                            break
                        }
                    }
                    
                    if ($containsNonCorporateRanges) {
                        $isSuspicious = $true
                        $severity = "High"
                    }
                }
                
                if ($isSuspicious) {
                    $findings += Add-Finding -Category "ConditionalAccess" -Title "Recently modified named location" `
                        -Severity $severity `
                        -Description "Named location '$($location.DisplayName)' has suspicious characteristics. Reasons: $($reasons -join '; ')" `
                        -Recommendation "Review this named location to confirm the changes are legitimate." `
                        -Data $location
                }
            }
        }
        
        # Check for policies with overly broad exclusions
        foreach ($policy in $policies) {
            $isSuspicious = $false
            $reasons = @()
            $severity = "Medium"
            
            # Check for excluded users that might be privileged
            if ($policy.Conditions.Users.ExcludeUsers) {
                $excludedUserCount = $policy.Conditions.Users.ExcludeUsers.Count
                
                if ($excludedUserCount -gt 5) {
                    $isSuspicious = $true
                    $reasons += "Excludes a large number of users ($excludedUserCount)"
                }
                
                # If we could resolve these IDs to user objects, we could check if they're privileged
            }
            
            # Check for excluded groups
            if ($policy.Conditions.Users.ExcludeGroups) {
                $excludedGroupCount = $policy.Conditions.Users.ExcludeGroups.Count
                
                if ($excludedGroupCount -gt 2) {
                    $isSuspicious = $true
                    $reasons += "Excludes a large number of groups ($excludedGroupCount)"
                }
                
                # If we could resolve these IDs to group objects, we could check if they're admin groups
            }
            
            # Check for excluded roles
            if ($policy.Conditions.Users.ExcludeRoles) {
                $excludedRoleCount = $policy.Conditions.Users.ExcludeRoles.Count
                
                $isSuspicious = $true
                $reasons += "Excludes directory roles ($excludedRoleCount)"
                $severity = "High"  # This is very suspicious
            }
            
            # Check grant controls (look for weakened authentication)
            if ($policy.GrantControls) {
                $weakAuth = $false
                
                # Check for just one authentication factor
                if ($policy.GrantControls.AuthenticationStrength -and 
                    $policy.GrantControls.AuthenticationStrength.AllowedCombinations) {
                    $allowsPasswordOnly = $policy.GrantControls.AuthenticationStrength.AllowedCombinations -contains "password"
                    
                    if ($allowsPasswordOnly) {
                        $weakAuth = $true
                        $reasons += "Allows password-only authentication"
                    }
                }
                elseif ($policy.GrantControls.BuiltInControls -and 
                      (-not ($policy.GrantControls.BuiltInControls -contains "mfa"))) {
                    $weakAuth = $true
                    $reasons += "Does not require MFA"
                }
                
                if ($weakAuth) {
                    $isSuspicious = $true
                    $severity = "High"
                }
            }
            
            if ($isSuspicious) {
                $findings += Add-Finding -Category "ConditionalAccess" -Title "Suspicious conditional access policy configuration" `
                    -Severity $severity `
                    -Description "Conditional Access policy '$($policy.DisplayName)' has potentially suspicious configuration. Reasons: $($reasons -join '; ')" `
                    -Recommendation "Review this policy to confirm it's properly configured for your security requirements." `
                    -Data $policy
            }
        }
        
        Write-Log -Message "Completed conditional access policy analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing conditional access policies: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "ConditionalAccess" -Title "Error analyzing conditional access policies" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing conditional access policies: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of conditional access policies is recommended."
    }
    
    return $findings
}

function Invoke-SignInAnalysisCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing sign-in patterns" -Level Info
        
        # Define the lookback period
        $startDate = $script:AnalysisStartDate
        $endDate = Get-Date
        
        # Get sign-in logs
        # Note: This requires appropriate permissions and the AuditLog.Read.All scope
        try {
            # Check if we can access sign-in logs first
            $testSignIn = Get-MgAuditLogSignIn -Top 1 -ErrorAction Stop
            
            # Get sign-ins for the analysis period
            $filter = "createdDateTime ge $($startDate.ToString('yyyy-MM-ddTHH:mm:ssZ')) and createdDateTime le $($endDate.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
            $signIns = Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction Stop
            
            Write-Log -Message "Retrieved $($signIns.Count) sign-in records for analysis" -Level Info
            
            # Get directory roles for identifying privileged users
            $directoryRoles = Get-MgDirectoryRole -All -ExpandProperty Members -ErrorAction Stop
            $privilegedRoles = @("Global Administrator", "Privileged Role Administrator", "Exchange Administrator", "SharePoint Administrator", "User Administrator", "Application Administrator", "Security Administrator")
            
            $usersInPrivilegedRoles = @()
            
            foreach ($role in $directoryRoles) {
                if ($role.DisplayName -in $privilegedRoles -and $role.Members) {
                    $usersInPrivilegedRoles += $role.Members
                }
            }
            
            $privilegedUserIds = $usersInPrivilegedRoles | Select-Object -ExpandProperty Id -Unique
            
            # Analyze sign-ins for suspicious patterns
            # 1. Failed sign-ins followed by successful sign-ins (potential password spray/brute force)
            $userSignIns = $signIns | Group-Object -Property UserId
            
            foreach ($userGroup in $userSignIns) {
                $userId = $userGroup.Name
                $userSignInHistory = $userGroup.Group | Sort-Object CreatedDateTime
                
                # Analyze for potential brute force patterns
                $consecutiveFailures = 0
                $maxConsecutiveFailures = 0
                $hadFailuresThenSuccess = $false
                
                for ($i = 0; $i -lt $userSignInHistory.Count; $i++) {
                    $currentSignIn = $userSignInHistory[$i]
                    
                    if ($currentSignIn.Status.ErrorCode -ne 0) {
                        $consecutiveFailures++
                        
                        if ($consecutiveFailures > $maxConsecutiveFailures) {
                            $maxConsecutiveFailures = $consecutiveFailures
                        }
                    }
                    else {
                        # This is a successful sign-in
                        if ($consecutiveFailures -gt 0) {
                            $hadFailuresThenSuccess = $true
                        }
                        
                        $consecutiveFailures = 0
                    }
                }
                
                # Report suspicious pattern
                if ($hadFailuresThenSuccess -and $maxConsecutiveFailures -ge 3) {
                    $severity = "Medium"
                    
                    # Check if this is a privileged user
                    if ($userId -in $privilegedUserIds) {
                        $severity = "High"
                    }
                    
                    $findings += Add-Finding -Category "SignInAnalysis" -Title "Suspicious sign-in pattern detected" `
                        -Severity $severity `
                        -Description "User with ID '$userId' had $maxConsecutiveFailures consecutive failed sign-in attempts followed by a successful sign-in within the analysis period. This could indicate a brute force or password spray attack." `
                        -Recommendation "Investigate these sign-in attempts to determine if they are legitimate or indicate an attack." `
                        -Data @{
                            UserId = $userId
                            MaxConsecutiveFailures = $maxConsecutiveFailures
                            IsPrivilegedUser = $userId -in $privilegedUserIds
                            SignInHistory = $userSignInHistory
                        }
                }
            }
            
            # 2. Sign-ins from unusual locations for privileged users
            $privilegedUserSignIns = $signIns | Where-Object { $_.UserId -in $privilegedUserIds }
            
            if ($privilegedUserSignIns) {
                # Group by user to analyze patterns per user
                $privilegedUserGroups = $privilegedUserSignIns | Group-Object -Property UserId
                
                foreach ($userGroup in $privilegedUserGroups) {
                    $userId = $userGroup.Name
                    $userSignInHistory = $userGroup.Group
                    
                    # Extract unique locations (IP addresses, countries, etc.)
                    $ipAddresses = $userSignInHistory | ForEach-Object { $_.IpAddress } | Sort-Object -Unique
                    $countries = $userSignInHistory | ForEach-Object { $_.Location.CountryOrRegion } | Where-Object { $_ } | Sort-Object -Unique
                    
                    # Check for unusual location indicators
                    $hasMultipleCountries = $countries.Count -gt 1
                    $hasExcessiveIPs = $ipAddresses.Count -gt 5
                    
                    if ($hasMultipleCountries -or $hasExcessiveIPs) {
                        $reasons = @()
                        
                        if ($hasMultipleCountries) {
                            $reasons += "Sign-ins from multiple countries: $($countries -join ', ')"
                        }
                        
                        if ($hasExcessiveIPs) {
                            $reasons += "Sign-ins from an unusually high number of IP addresses ($($ipAddresses.Count))"
                        }
                        
                        $findings += Add-Finding -Category "SignInAnalysis" -Title "Privileged user with suspicious sign-in locations" `
                            -Severity "High" `
                            -Description "Privileged user with ID '$userId' has suspicious sign-in location patterns. Reasons: $($reasons -join '; ')" `
                            -Recommendation "Investigate these sign-in attempts to determine if they are legitimate or indicate an account compromise." `
                            -Data @{
                                UserId = $userId
                                IPAddresses = $ipAddresses
                                Countries = $countries
                                SignInHistory = $userSignInHistory
                            }
                    }
                }
            }
            
            # 3. Dormant privileged accounts with sudden activity
            # Get user accounts
            $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, CreatedDateTime, SignInActivity -ErrorAction Stop
            
            # Identify dormant privileged accounts that suddenly became active
            foreach ($userId in $privilegedUserIds) {
                $user = $users | Where-Object { $_.Id -eq $userId }
                
                if (-not $user) {
                    continue
                }
                
                # Check if the account was dormant and then became active
                if ($user.SignInActivity -and $user.SignInActivity.LastSignInDateTime) {
                    $lastSignInBefore = $user.SignInActivity.LastSignInDateTime
                    
                    # If the last sign-in was over 90 days ago, consider it dormant
                    if ($lastSignInBefore -lt $startDate.AddDays(-90)) {
                        $recentSignIns = $signIns | Where-Object { $_.UserId -eq $userId }
                        
                        if ($recentSignIns.Count -gt 0) {
                            $findings += Add-Finding -Category "SignInAnalysis" -Title "Dormant privileged account with recent activity" `
                                -Severity "High" `
                                -Description "Privileged account '$($user.UserPrincipalName)' was dormant (last sign-in over 90 days ago) but shows recent sign-in activity. This could indicate account takeover." `
                                -Recommendation "Investigate this account's recent activity to determine if it is legitimate or indicates an account compromise." `
                                -Data @{
                                    UserId = $userId
                                    UserPrincipalName = $user.UserPrincipalName
                                    LastSignInBefore = $lastSignInBefore
                                    RecentSignIns = $recentSignIns
                                }
                        }
                    }
                }
            }
        }
        catch {
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Not Found*") {
                Write-Log -Message "Sign-in log analysis not available or requires additional permissions" -Level Warning
                $findings += Add-Finding -Category "SignInAnalysis" -Title "Unable to analyze sign-in logs" `
                    -Severity "Medium" `
                    -Description "Sign-in log analysis is not available or requires additional permissions. Error: $($_.Exception.Message)" `
                    -Recommendation "Ensure the account used for analysis has the AuditLog.Read.All permission and try again, or perform manual sign-in log analysis."
            }
            else {
                Write-Log -Message "Error analyzing sign-in logs: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "SignInAnalysis" -Title "Error analyzing sign-in logs" `
                    -Severity "Medium" `
                    -Description "An error occurred while analyzing sign-in logs: $($_.Exception.Message)" `
                    -Recommendation "Investigate the error and perform manual sign-in log analysis."
            }
        }
        
        Write-Log -Message "Completed sign-in pattern analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing sign-in patterns: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "SignInAnalysis" -Title "Error analyzing sign-in patterns" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing sign-in patterns: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of sign-in patterns is recommended."
    }
    
    return $findings
}

# Export the module function
Export-ModuleMember -Function Start-EntraIDCoreForensics

<#
.SYNOPSIS
    Azure AD / Entra ID Advanced Forensics Module for M365 Compromise Assessment
.DESCRIPTION
    This module performs detailed forensic analysis of advanced Azure AD / Entra ID configurations
    to identify potential attacker persistence mechanisms following admin-level compromise.
    Focuses on Administrative Units, Partner Relationships, Device Registrations,
    Guest Access, Privileged Groups, and Cross-Tenant Synchronization.
.NOTES
    Author: Dragos Ruiu
    Version 2.0
    Requires: Microsoft Graph PowerShell modules
    License: MIT
#>

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement
#Requires -Modules Microsoft.Graph.Identity.Governance, Microsoft.Graph.Users, Microsoft.Graph.Groups
#Requires -Modules Microsoft.Graph.Beta.Identity.DirectoryManagement, Microsoft.Graph.DeviceManagement.Administration

function Start-EntraIDAdvancedForensics {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$DetailedLogging,
        
        [Parameter()]
        [ValidateSet("All", "AdminUnits", "PartnerRelationships", "DeviceRegistrations", 
                     "GuestAccess", "PrivilegedGroups", "CrossTenantSync")]
        [string[]]$Checks = @("All"),
        
        [Parameter()]
        [int]$ThrottleLimit = 10,
        
        [Parameter()]
        [switch]$SkipExistingResults,
        
        [Parameter()]
        [int]$DaysToAnalyze = 30
    )
    
    begin {
        # Initialize logging
        $script:LogFile = Join-Path -Path $OutputPath -ChildPath "EntraIDAdvancedForensics_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $script:ResultPath = Join-Path -Path $OutputPath -ChildPath "Results"
        
        if (-not (Test-Path -Path $OutputPath)) {
            try {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created output directory: $OutputPath" -Level Info
            }
            catch {
                throw "Failed to create output directory: $($_.Exception.Message)"
            }
        }
        
        if (-not (Test-Path -Path $script:ResultPath)) {
            try {
                New-Item -Path $script:ResultPath -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created results directory: $script:ResultPath" -Level Info
            }
            catch {
                throw "Failed to create results directory: $($_.Exception.Message)"
            }
        }
        
        # Script-level variables
        $script:DetailedLogging = $DetailedLogging
        $script:AllFindings = @()
        $script:DaysToAnalyze = $DaysToAnalyze
        $script:AnalysisStartDate = (Get-Date).AddDays(-$DaysToAnalyze)
        $script:LicenseInfo = $null
    }
    
    process {
        try {
            Write-Log -Message "Starting Azure AD / Entra ID Advanced Forensics analysis" -Level Info
            
            # Connect to Microsoft Graph
            Connect-MgGraph
            
            # Check tenant's license information for feature availability
            Get-TenantLicenseInfo
            
            # Determine which checks to run
            $checksToRun = @()
            if ($Checks -contains "All") {
                $checksToRun = @("AdminUnits", "PartnerRelationships", "DeviceRegistrations", 
                               "GuestAccess", "PrivilegedGroups", "CrossTenantSync")
            }
            else {
                $checksToRun = $Checks
            }
            
            # Run selected checks
            foreach ($check in $checksToRun) {
                $checkResultPath = Join-Path -Path $script:ResultPath -ChildPath "EntraIDAdvanced_$check.json"
                
                if ($SkipExistingResults -and (Test-Path -Path $checkResultPath)) {
                    Write-Log -Message "Skipping $check check as results already exist" -Level Info
                    continue
                }
                
                Write-Log -Message "Running $check check" -Level Info
                
                switch ($check) {
                    "AdminUnits" { 
                        $findings = Invoke-AdminUnitCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "PartnerRelationships" { 
                        $findings = Invoke-PartnerRelationshipCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "DeviceRegistrations" { 
                        $findings = Invoke-DeviceRegistrationCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "GuestAccess" { 
                        $findings = Invoke-GuestAccessCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "PrivilegedGroups" { 
                        $findings = Invoke-PrivilegedGroupCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "CrossTenantSync" { 
                        $findings = Invoke-CrossTenantSyncCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                }
            }
            
            # Generate summary report
            $summaryPath = Join-Path -Path $OutputPath -ChildPath "EntraIDAdvancedForensics_Summary.json"
            Export-FindingsToJson -Findings $script:AllFindings -FilePath $summaryPath
            
            Write-Log -Message "Azure AD / Entra ID Advanced Forensics analysis completed successfully" -Level Info
        }
        catch {
            Write-Log -Message "Error during Azure AD / Entra ID Advanced Forensics analysis: $($_.Exception.Message)" -Level Error
            Write-Log -Message "Stack Trace: $($_.ScriptStackTrace)" -Level Error
            throw "Azure AD / Entra ID Advanced Forensics analysis failed: $($_.Exception.Message)"
        }
        finally {
            # Disconnect from Microsoft Graph
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        }
    }
    
    end {
        Write-Log -Message "Azure AD / Entra ID Advanced Forensics analysis finished" -Level Info
    }
}

function Connect-MgGraph {
    [CmdletBinding()]
    param()
    
    try {
        # Check if already connected
        $connected = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $connected) {
            Write-Log -Message "Connecting to Microsoft Graph" -Level Info
            
            # Define required scopes
            $scopes = @(
                "Directory.Read.All",
                "User.Read.All",
                "Group.Read.All",
                "AdministrativeUnit.Read.All",
                "DeviceManagementManagedDevices.Read.All",
                "PrivilegedAccess.Read.AzureAD",
                "Organization.Read.All",
                "IdentityProvider.Read.All"
            )
            
            # Connect with required scopes
            $null = Microsoft.Graph.Authentication\Connect-MgGraph -Scopes $scopes -ErrorAction Stop
            
            $context = Get-MgContext
            if (-not $context) {
                throw "Failed to establish Microsoft Graph connection"
            }
            
            Write-Log -Message "Successfully connected to Microsoft Graph for tenant: $($context.TenantId)" -Level Info
        }
        else {
            Write-Log -Message "Already connected to Microsoft Graph for tenant: $($connected.TenantId)" -Level Info
        }
    }
    catch {
        Write-Log -Message "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
        throw "Microsoft Graph connection failed. Please ensure you have the Microsoft.Graph PowerShell modules installed and appropriate permissions."
    }
}

function Get-TenantLicenseInfo {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Message "Checking tenant license information" -Level Info
        
        $org = Get-MgOrganization
        if (-not $org) {
            Write-Log -Message "Unable to retrieve organization information" -Level Warning
            return
        }
        
        $subscriptions = Get-MgSubscribedSku
        if (-not $subscriptions) {
            Write-Log -Message "Unable to retrieve subscription information" -Level Warning
            return
        }
        
        # Check for Azure AD Premium licenses
        $aadP1Present = $false
        $aadP2Present = $false
        
        foreach ($sub in $subscriptions) {
            # Azure AD Premium P1 SKU
            if ($sub.SkuPartNumber -like "*AAD_PREMIUM*" -or 
                $sub.SkuPartNumber -like "*ENTERPRISE_MOBILITY*" -or 
                $sub.SkuPartNumber -like "*EMS*" -or 
                $sub.SkuPartNumber -like "*EMSPREMIUM*") {
                $aadP1Present = $true
            }
            
            # Azure AD Premium P2 SKU
            if ($sub.SkuPartNumber -like "*AAD_PREMIUM_P2*" -or 
                $sub.SkuPartNumber -like "*EMSPREMIUM*") {
                $aadP2Present = $true
            }
        }
        
        $script:LicenseInfo = [PSCustomObject]@{
            AadP1Present = $aadP1Present
            AadP2Present = $aadP2Present
            Subscriptions = $subscriptions
        }
        
        Write-Log -Message "Tenant license information: AAD P1: $aadP1Present, AAD P2: $aadP2Present" -Level Info
    }
    catch {
        Write-Log -Message "Error checking tenant license information: $($_.Exception.Message)" -Level Warning
    }
}

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("Info", "Warning", "Error", "Debug")]
        [string]$Level = "Info"
    )
    
    # Only log debug messages if detailed logging is enabled
    if ($Level -eq "Debug" -and -not $script:DetailedLogging) {
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Output to console based on level
    switch ($Level) {
        "Info" { Write-Host $logMessage }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Debug" { Write-Host $logMessage -ForegroundColor Cyan }
    }
    
    # Write to log file
    Add-Content -Path $script:LogFile -Value $logMessage
}

function Export-FindingsToJson {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Findings,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        $Findings | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding utf8 -Force
        Write-Log -Message "Exported findings to $FilePath" -Level Info
        
        # Add to master findings list
        $script:AllFindings += $Findings
    }
    catch {
        Write-Log -Message "Error exporting findings to $FilePath : $($_.Exception.Message)" -Level Error
    }
}

function Add-Finding {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("High", "Medium", "Low", "Informational")]
        [string]$Severity,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter()]
        [string]$Recommendation,
        
        [Parameter()]
        [PSObject]$Data,
        
        [Parameter()]
        [DateTime]$Timestamp = (Get-Date)
    )
    
    $finding = [PSCustomObject]@{
        Category = $Category
        Title = $Title
        Severity = $Severity
        Description = $Description
        Recommendation = $Recommendation
        Data = $Data
        Timestamp = $Timestamp
        Id = [Guid]::NewGuid().ToString()
    }
    
    return $finding
}

function Invoke-AdminUnitCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing administrative units" -Level Info
        
        # Check if Administrative Units are available (requires Azure AD Premium P1)
        if (-not $script:LicenseInfo.AadP1Present) {
            Write-Log -Message "Administrative Units feature requires Azure AD Premium P1, which may not be present in this tenant" -Level Warning
            $findings += Add-Finding -Category "AdminUnits" -Title "Administrative Units feature may not be available" `
                -Severity "Informational" `
                -Description "Administrative Units feature requires Azure AD Premium P1, which may not be present in this tenant." `
                -Recommendation "If you've purchased Azure AD Premium P1 licenses, ensure they are properly assigned."
            return $findings
        }
        
        # Get all administrative units
        $adminUnits = Get-MgBetaDirectoryAdministrativeUnit -All -ErrorAction Stop
        
        if (-not $adminUnits -or $adminUnits.Count -eq 0) {
            Write-Log -Message "No administrative units found in the tenant" -Level Info
            $findings += Add-Finding -Category "AdminUnits" -Title "No administrative units found" `
                -Severity "Informational" `
                -Description "No administrative units were found in the tenant." `
                -Recommendation "This is informational only. Administrative units are not being used for delegation."
            return $findings
        }
        
        Write-Log -Message "Found $($adminUnits.Count) administrative units" -Level Info
        
        # Get all directory roles
        $directoryRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        
        # Identify recently created or modified administrative units
        $recentAdminUnits = $adminUnits | Where-Object { 
            $_.CreatedDateTime -ge $script:AnalysisStartDate -or 
            ($_.AdditionalProperties.modifiedDateTime -and $_.AdditionalProperties.modifiedDateTime -ge $script:AnalysisStartDate) 
        }
        
        if ($recentAdminUnits) {
            foreach ($au in $recentAdminUnits) {
                $findings += Add-Finding -Category "AdminUnits" -Title "Recently created or modified administrative unit" `
                    -Severity "Medium" `
                    -Description "Administrative unit '$($au.DisplayName)' was recently created or modified. Administrative units can be used to segment administrative control." `
                    -Recommendation "Verify that this administrative unit was created or modified legitimately." `
                    -Data $au
                
                # Check for scoped role assignments in this AU
                try {
                    $scopedRoles = Get-MgBetaDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId $au.Id -ErrorAction Stop
                    
                    if ($scopedRoles) {
                        foreach ($scopedRole in $scopedRoles) {
                            # Get role information
                            $roleName = "Unknown Role"
                            $role = $directoryRoles | Where-Object { $_.Id -eq $scopedRole.RoleId }
                            if ($role) {
                                $roleName = $role.DisplayName
                            }
                            
                            $findings += Add-Finding -Category "AdminUnits" -Title "Scoped role assignment in administrative unit" `
                                -Severity "Medium" `
                                -Description "Administrative unit '$($au.DisplayName)' has a scoped role assignment for role '$roleName'. This grants administrative privileges limited to this administrative unit." `
                                -Recommendation "Verify that this scoped role assignment is legitimate and necessary." `
                                -Data @{
                                    AdministrativeUnit = $au
                                    ScopedRole = $scopedRole
                                    RoleName = $roleName
                                }
                        }
                    }
                }
                catch {
                    Write-Log -Message "Error retrieving scoped role members for administrative unit '$($au.DisplayName)': $($_.Exception.Message)" -Level Warning
                }
            }
        }
        
        # Check for administrative units with privileged scoped roles
        # Highly privileged roles that would be concerning if scoped to an AU
        $privilegedRoles = @(
            "Global Administrator",
            "Privileged Role Administrator",
            "User Administrator",
            "Directory Writers",
            "Exchange Administrator",
            "SharePoint Administrator",
            "Hybrid Identity Administrator",
            "Application Administrator"
        )
        
        foreach ($au in $adminUnits) {
            try {
                $scopedRoles = Get-MgBetaDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId $au.Id -ErrorAction Stop
                
                if ($scopedRoles) {
                    foreach ($scopedRole in $scopedRoles) {
                        # Get role information
                        $roleName = "Unknown Role"
                        $role = $directoryRoles | Where-Object { $_.Id -eq $scopedRole.RoleId }
                        if ($role) {
                            $roleName = $role.DisplayName
                        }
                        
                        # Check if this is a privileged role
                        if ($roleName -in $privilegedRoles) {
                            $findings += Add-Finding -Category "AdminUnits" -Title "Privileged role scoped to administrative unit" `
                                -Severity "High" `
                                -Description "Administrative unit '$($au.DisplayName)' has the privileged role '$roleName' scoped to it. This is a high-privilege role that could be misused." `
                                -Recommendation "Verify that this privileged scoped role assignment is legitimate, necessary, and assigned to trusted administrators." `
                                -Data @{
                                    AdministrativeUnit = $au
                                    ScopedRole = $scopedRole
                                    RoleName = $roleName
                                }
                        }
                    }
                }
            }
            catch {
                Write-Log -Message "Error retrieving scoped role members for administrative unit '$($au.DisplayName)': $($_.Exception.Message)" -Level Warning
            }
        }
        
        Write-Log -Message "Completed administrative unit analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing administrative units: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "AdminUnits" -Title "Error analyzing administrative units" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing administrative units: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of administrative units is recommended."
    }
    
    return $findings
}

function Invoke-PartnerRelationshipCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing partner relationships" -Level Info
        
        # Get partner contracts/relationships - modern GDAP (Granular Delegated Admin Privileges)
        try {
            $gdapRelationships = Get-MgContract -All -ErrorAction Stop
            
            if ($gdapRelationships -and $gdapRelationships.Count -gt 0) {
                Write-Log -Message "Found $($gdapRelationships.Count) GDAP relationships" -Level Info
                
                foreach ($relationship in $gdapRelationships) {
                    # Check if recently created
                    if ($relationship.DefaultDomainName -or $relationship.DisplayName) {
                        $partnerInfo = if ($relationship.DefaultDomainName) { $relationship.DefaultDomainName } else { $relationship.DisplayName }
                    }
                    else {
                        $partnerInfo = $relationship.Id
                    }
                    
                    $findings += Add-Finding -Category "PartnerRelationships" -Title "Partner relationship detected" `
                        -Severity "Medium" `
                        -Description "Partner relationship with '$partnerInfo' detected. Partner relationships grant external organizations administrative access to your tenant." `
                        -Recommendation "Verify that this partner relationship is legitimate and necessary. Review the roles granted to this partner." `
                        -Data $relationship
                    
                    # We would need to check the specific roles assigned to this partner
                    # This would require additional API calls or PowerShell cmdlets
                }
            }
            else {
                Write-Log -Message "No GDAP partner relationships found" -Level Info
            }
        }
        catch {
            Write-Log -Message "Error checking GDAP partner relationships: $($_.Exception.Message). This might require different permissions." -Level Warning
        }
        
        # Legacy Delegated Admin Privileges (DAP) - Check using older methods if needed
        try {
            # This command might not be available via Graph API
            # Using MSOnline for this would be more typical, but MsOnline is being deprecated
            Write-Log -Message "Legacy DAP partner relationship check would happen here if available" -Level Debug
        }
        catch {
            Write-Log -Message "Legacy DAP partner relationship check not available or requires different permissions" -Level Warning
        }
        
        # Additional check for recent role assignments to partners through PIM
        # This is more complex and might require Azure AD Premium P2
        if ($script:LicenseInfo.AadP2Present) {
            try {
                Write-Log -Message "PIM role assignment check for partners would happen here if available" -Level Debug
                # This would require additional code to check PIM role assignments specifically for partners
            }
            catch {
                Write-Log -Message "PIM role assignment check for partners not available or requires different permissions" -Level Warning
            }
        }
        
        Write-Log -Message "Completed partner relationship analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing partner relationships: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "PartnerRelationships" -Title "Error analyzing partner relationships" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing partner relationships: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of partner relationships is recommended."
    }
    
    return $findings
}

function Invoke-DeviceRegistrationCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing device registrations" -Level Info
        
        # Get all registered devices
        $devices = Get-MgDevice -All -ErrorAction Stop
        
        Write-Log -Message "Found $($devices.Count) registered devices" -Level Info
        
        # Get all users for resolving device owners
        $users = Get-MgUser -All -Property Id, UserPrincipalName, DisplayName -ErrorAction Stop
        
        # Get directory roles for identifying privileged users
        $directoryRoles = Get-MgDirectoryRole -All -ExpandProperty Members -ErrorAction Stop
        $privilegedRoles = @("Global Administrator", "Privileged Role Administrator", "Exchange Administrator", 
                            "SharePoint Administrator", "User Administrator", "Application Administrator", 
                            "Security Administrator", "Teams Administrator")
        
        $usersInPrivilegedRoles = @()
        
        foreach ($role in $directoryRoles) {
            if ($role.DisplayName -in $privilegedRoles -and $role.Members) {
                $usersInPrivilegedRoles += $role.Members
            }
        }
        
        $privilegedUserIds = $usersInPrivilegedRoles | Select-Object -ExpandProperty Id -Unique
        
        # Check for recently registered devices
        $recentDevices = $devices | Where-Object { $_.RegistrationDateTime -ge $script:AnalysisStartDate }
        
        if ($recentDevices) {
            Write-Log -Message "Found $($recentDevices.Count) recently registered devices" -Level Info
            
            foreach ($device in $recentDevices) {
                $deviceOwner = $null
                $isPrivilegedUserDevice = $false
                
                # Try to get device owner
                if ($device.RegisteredOwners) {
                    $ownerIds = $device.RegisteredOwners | ForEach-Object { $_.Id }
                    foreach ($ownerId in $ownerIds) {
                        $owner = $users | Where-Object { $_.Id -eq $ownerId }
                        if ($owner) {
                            $deviceOwner = $owner
                            
                            # Check if owner is a privileged user
                            if ($ownerId -in $privilegedUserIds) {
                                $isPrivilegedUserDevice = $true
                            }
                            
                            break
                        }
                    }
                }
                
                $severity = "Low"
                if ($isPrivilegedUserDevice) {
                    $severity = "Medium"
                }
                
                $ownerInfo = if ($deviceOwner) { $deviceOwner.UserPrincipalName } else { "Unknown" }
                
                $findings += Add-Finding -Category "DeviceRegistrations" -Title "Recently registered device" `
                    -Severity $severity `
                    -Description "Device '$($device.DisplayName)' (ID: $($device.Id)) was registered on $(Get-Date $device.RegistrationDateTime -Format 'yyyy-MM-dd') by user '$ownerInfo'$(if($isPrivilegedUserDevice){' who has privileged role assignments'})." `
                    -Recommendation "Verify that this device registration is legitimate, especially since $(if($isPrivilegedUserDevice){'it belongs to a privileged user and '})'it was registered recently." `
                    -Data @{
                        Device = $device
                        Owner = $deviceOwner
                        IsPrivilegedUserDevice = $isPrivilegedUserDevice
                    }
            }
        }
        
        # Check for devices with anomalous OS or device types
        $anomalousDevices = $devices | Where-Object { 
            ($_.OperatingSystem -like "*Linux*") -or 
            ($_.OperatingSystem -like "*Server*") -or
            ($_.OperatingSystemVersion -match "^[0-9.]+$" -and [version]$_.OperatingSystemVersion -lt [version]"10.0") -or
            ($_.DeviceId -and $_.DeviceId -ne $_.Id)
        }
        
        if ($anomalousDevices) {
            foreach ($device in $anomalousDevices) {
                $deviceOwner = $null
                $isPrivilegedUserDevice = $false
                $reasons = @()
                
                # Try to get device owner
                if ($device.RegisteredOwners) {
                    $ownerIds = $device.RegisteredOwners | ForEach-Object { $_.Id }
                    foreach ($ownerId in $ownerIds) {
                        $owner = $users | Where-Object { $_.Id -eq $ownerId }
                        if ($owner) {
                            $deviceOwner = $owner
                            
                            # Check if owner is a privileged user
                            if ($ownerId -in $privilegedUserIds) {
                                $isPrivilegedUserDevice = $true
                            }
                            
                            break
                        }
                    }
                }
                
                # Determine why this device is anomalous
                if ($device.OperatingSystem -like "*Linux*") {
                    $reasons += "Linux-based OS (unusual for corporate devices)"
                }
                if ($device.OperatingSystem -like "*Server*") {
                    $reasons += "Server OS (unusual for user devices)"
                }
                if ($device.OperatingSystemVersion -match "^[0-9.]+$" -and [version]$_.OperatingSystemVersion -lt [version]"10.0") {
                    $reasons += "Outdated OS version ($($device.OperatingSystemVersion))"
                }
                if ($device.DeviceId -and $device.DeviceId -ne $device.Id) {
                    $reasons += "Discrepancy between DeviceId and Id"
                }
                
                $severity = "Medium"
                if ($isPrivilegedUserDevice) {
                    $severity = "High"
                }
                
                $ownerInfo = if ($deviceOwner) { $deviceOwner.UserPrincipalName } else { "Unknown" }
                
                $findings += Add-Finding -Category "DeviceRegistrations" -Title "Anomalous device registration" `
                    -Severity $severity `
                    -Description "Device '$($device.DisplayName)' (ID: $($device.Id)) has anomalous characteristics: $($reasons -join '; '). Owner: '$ownerInfo'$(if($isPrivilegedUserDevice){' who has privileged role assignments'})." `
                    -Recommendation "Verify that this device registration is legitimate and meets security requirements." `
                    -Data @{
                        Device = $device
                        Owner = $deviceOwner
                        IsPrivilegedUserDevice = $isPrivilegedUserDevice
                        Reasons = $reasons
                    }
            }
        }
        
        # Try to check device compliance status if available
        try {
            $complianceInfo = $false
            
            # Try to get compliance information from Intune if available
            # This would require additional Microsoft Graph permissions and endpoints
            
            if (-not $complianceInfo) {
                Write-Log -Message "Device compliance information check would require Intune integration" -Level Debug
            }
        }
        catch {
            Write-Log -Message "Device compliance check not available or requires different permissions" -Level Warning
        }
        
        Write-Log -Message "Completed device registration analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing device registrations: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "DeviceRegistrations" -Title "Error analyzing device registrations" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing device registrations: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of device registrations is recommended."
    }
    
    return $findings
}

function Invoke-GuestAccessCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing guest access" -Level Info
        
        # Get all guest users
        $guestUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, UserType, CreatedDateTime, ExternalUserState, AccountEnabled, Mail, OtherMails -Filter "userType eq 'Guest'" -ErrorAction Stop
        
        Write-Log -Message "Found $($guestUsers.Count) guest users" -Level Info
        
        # Get all directory roles with members
        $directoryRoles = Get-MgDirectoryRole -All -ExpandProperty Members -ErrorAction Stop
        
        # Get B2B collaboration settings
        try {
            $b2bSettings = $null
            # There doesn't seem to be a direct Graph API for this yet - would use MSOnline traditionally
            # We'll simulate this information for now
            Write-Log -Message "B2B collaboration settings check would happen here if available via Graph" -Level Debug
        }
        catch {
            Write-Log -Message "B2B collaboration settings check not available or requires different permissions" -Level Warning
        }
        
        # Check for recently invited guests
        $recentGuests = $guestUsers | Where-Object { $_.CreatedDateTime -ge $script:AnalysisStartDate }
        
        if ($recentGuests) {
            foreach ($guest in $recentGuests) {
                $domain = ($guest.UserPrincipalName -split '#')[0] -split '@' | Select-Object -Last 1
                
                $findings += Add-Finding -Category "GuestAccess" -Title "Recently invited guest user" `
                    -Severity "Low" `
                    -Description "Guest user '$($guest.DisplayName)' (UPN: $($guest.UserPrincipalName)) from domain '$domain' was invited on $(Get-Date $guest.CreatedDateTime -Format 'yyyy-MM-dd')." `
                    -Recommendation "Verify that this guest invitation is legitimate and necessary for business purposes." `
                    -Data $guest
            }
        }
        
        # Check for guests with privileged roles (high risk)
        foreach ($role in $directoryRoles) {
            if ($role.Members) {
                foreach ($member in $role.Members) {
                    $guestInRole = $guestUsers | Where-Object { $_.Id -eq $member.Id }
                    
                    if ($guestInRole) {
                        $domain = ($guestInRole.UserPrincipalName -split '#')[0] -split '@' | Select-Object -Last 1
                        
                        $findings += Add-Finding -Category "GuestAccess" -Title "Guest user with privileged role" `
                            -Severity "High" `
                            -Description "Guest user '$($guestInRole.DisplayName)' (UPN: $($guestInRole.UserPrincipalName)) from domain '$domain' has been assigned the '$($role.DisplayName)' role. This is a significant security risk." `
                            -Recommendation "Remove this guest user from the privileged role immediately unless there is a documented business requirement." `
                            -Data @{
                                GuestUser = $guestInRole
                                Role = $role.DisplayName
                                RoleId = $role.Id
                            }
                    }
                }
            }
        }
        
        # Check for guest users in sensitive groups
        # This would require additional logic to identify sensitive groups
        
        # Check external collaboration settings if available
        if ($b2bSettings) {
            # Analysis would happen here based on retrieved settings
            Write-Log -Message "External collaboration settings analysis would happen here" -Level Debug
        }
        
        Write-Log -Message "Completed guest access analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing guest access: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "GuestAccess" -Title "Error analyzing guest access" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing guest access: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of guest access is recommended."
    }
    
    return $findings
}

function Invoke-PrivilegedGroupCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing privileged access groups" -Level Info
        
        # Get all directory roles
        $directoryRoles = Get-MgDirectoryRole -All -ExpandProperty Members -ErrorAction Stop
        
        # Get all groups
        $groups = Get-MgGroup -All -Property Id, DisplayName, Description, CreatedDateTime, MembershipRule, MembershipRuleProcessingState, SecurityEnabled, GroupTypes, IsAssignableToRole -ErrorAction Stop
        
        # Get directory role templates
        $roleTemplates = Get-MgDirectoryRoleTemplate -All -ErrorAction Stop
        
        # Identify role-assignable groups (groups that can be assigned to roles)
        $roleAssignableGroups = $groups | Where-Object { $_.IsAssignableToRole -eq $true }
        
        if ($roleAssignableGroups) {
            Write-Log -Message "Found $($roleAssignableGroups.Count) role-assignable groups" -Level Info
            
            foreach ($group in $roleAssignableGroups) {
                # Check if this group is recently created
                $isRecent = $group.CreatedDateTime -ge $script:AnalysisStartDate
                $severity = if ($isRecent) { "Medium" } else { "Low" }
                
                # Check if this group is actually assigned to any roles
                $assignedRoles = @()
                foreach ($role in $directoryRoles) {
                    if ($role.Members) {
                        $groupInRole = $role.Members | Where-Object { $_.Id -eq $group.Id }
                        if ($groupInRole) {
                            $assignedRoles += $role.DisplayName
                            $severity = "Medium"  # Increase severity if actually assigned to a role
                        }
                    }
                }
                
                $assignedRoleText = if ($assignedRoles.Count -gt 0) { 
                    " It is assigned to the following roles: $($assignedRoles -join ', ')." 
                } else { 
                    " It is not currently assigned to any roles." 
                }
                
                $findings += Add-Finding -Category "PrivilegedGroups" -Title "Role-assignable group detected" `
                    -Severity $severity `
                    -Description "Group '$($group.DisplayName)' is configured as role-assignable, meaning it can be assigned to directory roles.$assignedRoleText$(if($isRecent){' This group was recently created on ' + (Get-Date $group.CreatedDateTime -Format 'yyyy-MM-dd') + '.'})" `
                    -Recommendation "Verify that this role-assignable group is legitimate and its membership is properly restricted." `
                    -Data @{
                        Group = $group
                        AssignedRoles = $assignedRoles
                        IsRecent = $isRecent
                    }
                
                # Check dynamic group membership rules if present
                if ($group.GroupTypes -contains "DynamicMembership" -and $group.MembershipRule) {
                    $findings += Add-Finding -Category "PrivilegedGroups" -Title "Role-assignable group with dynamic membership" `
                        -Severity "Medium" `
                        -Description "Group '$($group.DisplayName)' is configured as role-assignable and uses a dynamic membership rule: '$($group.MembershipRule)'. Dynamic membership rules could be manipulated to gain privileged access." `
                        -Recommendation "Review the dynamic membership rule to ensure it cannot be exploited for privilege escalation." `
                        -Data @{
                            Group = $group
                            MembershipRule = $group.MembershipRule
                            AssignedRoles = $assignedRoles
                        }
                }
                
                # Check if the group has been recently modified - requires additional API calls
                try {
                    # Get recent group members - this could be extended further based on available APIs
                    $members = Get-MgGroupMember -GroupId $group.Id -ErrorAction Stop
                    
                    if ($members) {
                        $findings += Add-Finding -Category "PrivilegedGroups" -Title "Role-assignable group membership" `
                            -Severity "Informational" `
                            -Description "Group '$($group.DisplayName)' is configured as role-assignable and has $($members.Count) members. Changes to this group's membership directly affect administrative privileges." `
                            -Recommendation "Regularly audit the membership of this group to prevent unauthorized access to privileged roles." `
                            -Data @{
                                Group = $group
                                MemberCount = $members.Count
                                AssignedRoles = $assignedRoles
                            }
                    }
                }
                catch {
                    Write-Log -Message "Error retrieving members for group '$($group.DisplayName)': $($_.Exception.Message)" -Level Warning
                }
            }
        }
        else {
            Write-Log -Message "No role-assignable groups found" -Level Info
        }
        
        # Check PIM if available (requires Azure AD Premium P2)
        if ($script:LicenseInfo.AadP2Present) {
            try {
                # Check PIM-enabled roles and their group memberships
                # This would require additional API calls to the PIM endpoints
                Write-Log -Message "PIM-enabled role group check would happen here if available" -Level Debug
            }
            catch {
                Write-Log -Message "PIM-enabled role group check not available or requires different permissions" -Level Warning
            }
        }
        
        Write-Log -Message "Completed privileged access group analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing privileged access groups: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "PrivilegedGroups" -Title "Error analyzing privileged access groups" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing privileged access groups: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of privileged access groups is recommended."
    }
    
    return $findings
}

function Invoke-CrossTenantSyncCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing cross-tenant synchronization" -Level Info
        
        # Check for cross-tenant synchronization settings - using beta endpoints as this is newer
        try {
            # Inbound synchronization settings
            $inboundSettings = Get-MgBetaOrganizationInboundSetting -All -ErrorAction Stop
            
            if ($inboundSettings) {
                foreach ($setting in $inboundSettings) {
                    $findings += Add-Finding -Category "CrossTenantSync" -Title "Inbound cross-tenant synchronization configured" `
                        -Severity "Medium" `
                        -Description "Inbound cross-tenant synchronization is configured from tenant ID '$($setting.SourceTenantId)'. This allows another tenant to synchronize identities into your tenant." `
                        -Recommendation "Verify that this cross-tenant synchronization is legitimate and necessary for business purposes." `
                        -Data $setting
                }
            }
            
            # Outbound synchronization settings
            $outboundSettings = Get-MgBetaOrganizationOutboundSetting -All -ErrorAction Stop
            
            if ($outboundSettings) {
                foreach ($setting in $outboundSettings) {
                    $findings += Add-Finding -Category "CrossTenantSync" -Title "Outbound cross-tenant synchronization configured" `
                        -Severity "Medium" `
                        -Description "Outbound cross-tenant synchronization is configured to tenant ID '$($setting.TargetTenantId)'. This allows your tenant to synchronize identities to another tenant." `
                        -Recommendation "Verify that this cross-tenant synchronization is legitimate and necessary for business purposes." `
                        -Data $setting
                }
            }
            
            if (-not $inboundSettings -and -not $outboundSettings) {
                Write-Log -Message "No cross-tenant synchronization settings found" -Level Info
                $findings += Add-Finding -Category "CrossTenantSync" -Title "No cross-tenant synchronization configured" `
                    -Severity "Informational" `
                    -Description "No cross-tenant synchronization settings were found in the tenant." `
                    -Recommendation "This is informational only. Cross-tenant synchronization is not being used."
            }
        }
        catch {
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Not Found*") {
                Write-Log -Message "Cross-tenant synchronization settings check not available or requires different permissions" -Level Warning
                $findings += Add-Finding -Category "CrossTenantSync" -Title "Unable to check cross-tenant synchronization settings" `
                    -Severity "Low" `
                    -Description "Could not check cross-tenant synchronization settings. This might be due to insufficient permissions or the feature not being enabled." `
                    -Recommendation "Verify manually if cross-tenant synchronization is in use in your environment."
            }
            else {
                Write-Log -Message "Error checking cross-tenant synchronization settings: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "CrossTenantSync" -Title "Error checking cross-tenant synchronization settings" `
                    -Severity "Medium" `
                    -Description "An error occurred while checking cross-tenant synchronization settings: $($_.Exception.Message)" `
                    -Recommendation "Manual investigation of cross-tenant synchronization settings is recommended."
            }
        }
        
        Write-Log -Message "Completed cross-tenant synchronization analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing cross-tenant synchronization: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "CrossTenantSync" -Title "Error analyzing cross-tenant synchronization" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing cross-tenant synchronization: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of cross-tenant synchronization is recommended."
    }
    
    return $findings
}

# Export the module function
Export-ModuleMember -Function Start-EntraIDAdvancedForensics

<#
.SYNOPSIS
    SharePoint & OneDrive Forensics Module for M365 Compromise Assessment
.DESCRIPTION
    This module performs detailed forensic analysis of SharePoint Online and OneDrive for Business
    configurations to identify potential attacker persistence mechanisms following admin-level compromise.
.NOTES
    Author: Dragos Ruiu
    Version 2.0
    Requires: PnP.PowerShell module, SharePointOnline.CSOM
    License: MIT
#>

#Requires -Modules PnP.PowerShell

function Start-SharePointForensics {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantUrl,
        
        [Parameter()]
        [switch]$DetailedLogging,
        
        [Parameter()]
        [ValidateSet("All", "SiteAdmins", "ExternalSharing", "AddIns", "InformationBarriers", "SitePermissions")]
        [string[]]$Checks = @("All"),
        
        [Parameter()]
        [int]$ThrottleLimit = 10,
        
        [Parameter()]
        [switch]$SkipExistingResults,
        
        [Parameter()]
        [int]$DaysToAnalyze = 30,
        
        [Parameter()]
        [int]$MaxSitesToAnalyze = 100
    )
    
    begin {
        # Initialize logging
        $script:LogFile = Join-Path -Path $OutputPath -ChildPath "SharePointForensics_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $script:ResultPath = Join-Path -Path $OutputPath -ChildPath "Results"
        
        if (-not (Test-Path -Path $OutputPath)) {
            try {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created output directory: $OutputPath" -Level Info
            }
            catch {
                throw "Failed to create output directory: $($_.Exception.Message)"
            }
        }
        
        if (-not (Test-Path -Path $script:ResultPath)) {
            try {
                New-Item -Path $script:ResultPath -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created results directory: $script:ResultPath" -Level Info
            }
            catch {
                throw "Failed to create results directory: $($_.Exception.Message)"
            }
        }
        
        # Script-level variables
        $script:DetailedLogging = $DetailedLogging
        $script:AllFindings = @()
        $script:DaysToAnalyze = $DaysToAnalyze
        $script:AnalysisStartDate = (Get-Date).AddDays(-$DaysToAnalyze)
        $script:TenantUrl = $TenantUrl
        $script:AdminUrl = $TenantUrl -replace "\.sharepoint\.com", "-admin.sharepoint.com"
        $script:PnPConnection = $null
        $script:MaxSitesToAnalyze = $MaxSitesToAnalyze
    }
    
    process {
        try {
            Write-Log -Message "Starting SharePoint & OneDrive Forensics analysis for tenant $TenantUrl" -Level Info
            
            # Connect to SharePoint Online
            Connect-SharePointOnline
            
            # Determine which checks to run
            $checksToRun = @()
            if ($Checks -contains "All") {
                $checksToRun = @("SiteAdmins", "ExternalSharing", "AddIns", "InformationBarriers", "SitePermissions")
            }
            else {
                $checksToRun = $Checks
            }
            
            # Run selected checks
            foreach ($check in $checksToRun) {
                $checkResultPath = Join-Path -Path $script:ResultPath -ChildPath "SharePoint_$check.json"
                
                if ($SkipExistingResults -and (Test-Path -Path $checkResultPath)) {
                    Write-Log -Message "Skipping $check check as results already exist" -Level Info
                    continue
                }
                
                Write-Log -Message "Running $check check" -Level Info
                
                switch ($check) {
                    "SiteAdmins" { 
                        $findings = Invoke-SiteAdminCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "ExternalSharing" { 
                        $findings = Invoke-ExternalSharingCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "AddIns" { 
                        $findings = Invoke-AddInCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "InformationBarriers" { 
                        $findings = Invoke-InformationBarrierCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "SitePermissions" { 
                        $findings = Invoke-SitePermissionCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                }
            }
            
            # Generate summary report
            $summaryPath = Join-Path -Path $OutputPath -ChildPath "SharePointForensics_Summary.json"
            Export-FindingsToJson -Findings $script:AllFindings -FilePath $summaryPath
            
            Write-Log -Message "SharePoint & OneDrive Forensics analysis completed successfully" -Level Info
        }
        catch {
            Write-Log -Message "Error during SharePoint & OneDrive Forensics analysis: $($_.Exception.Message)" -Level Error
            Write-Log -Message "Stack Trace: $($_.ScriptStackTrace)" -Level Error
            throw "SharePoint & OneDrive Forensics analysis failed: $($_.Exception.Message)"
        }
    }
    
    end {
        # Disconnect from SharePoint Online
        Disconnect-PnPOnline -ErrorAction SilentlyContinue
        Write-Log -Message "SharePoint & OneDrive Forensics analysis finished" -Level Info
    }
}

function Connect-SharePointOnline {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Message "Connecting to SharePoint Online Admin center" -Level Info
        
        # Connect to SharePoint Admin Center
        $script:PnPConnection = Connect-PnPOnline -Url $script:AdminUrl -Interactive -ReturnConnection -ErrorAction Stop
        
        # Verify connection by getting tenant info
        $tenantSettings = Get-PnPTenant -ErrorAction Stop
        if (-not $tenantSettings) {
            throw "Failed to retrieve tenant settings - connection may not be valid"
        }
        
        Write-Log -Message "Successfully connected to SharePoint Online Admin center" -Level Info
        return $true
    }
    catch {
        Write-Log -Message "Failed to connect to SharePoint Online: $($_.Exception.Message)" -Level Error
        throw "SharePoint Online connection failed. Please ensure you have the PnP.PowerShell module installed and appropriate permissions."
    }
}

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("Info", "Warning", "Error", "Debug")]
        [string]$Level = "Info"
    )
    
    # Only log debug messages if detailed logging is enabled
    if ($Level -eq "Debug" -and -not $script:DetailedLogging) {
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Output to console based on level
    switch ($Level) {
        "Info" { Write-Host $logMessage }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Debug" { Write-Host $logMessage -ForegroundColor Cyan }
    }
    
    # Write to log file
    Add-Content -Path $script:LogFile -Value $logMessage
}

function Export-FindingsToJson {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Findings,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        $Findings | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding utf8 -Force
        Write-Log -Message "Exported findings to $FilePath" -Level Info
        
        # Add to master findings list
        $script:AllFindings += $Findings
    }
    catch {
        Write-Log -Message "Error exporting findings to $FilePath : $($_.Exception.Message)" -Level Error
    }
}

function Add-Finding {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("High", "Medium", "Low", "Informational")]
        [string]$Severity,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter()]
        [string]$Recommendation,
        
        [Parameter()]
        [PSObject]$Data,
        
        [Parameter()]
        [DateTime]$Timestamp = (Get-Date)
    )
    
    $finding = [PSCustomObject]@{
        Category = $Category
        Title = $Title
        Severity = $Severity
        Description = $Description
        Recommendation = $Recommendation
        Data = $Data
        Timestamp = $Timestamp
        Id = [Guid]::NewGuid().ToString()
    }
    
    return $finding
}

function Invoke-SiteAdminCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing site collection administrators" -Level Info
        
        # Get all site collections
        $siteCollections = Get-PnPTenantSite -Detailed -ErrorAction Stop
        
        if (-not $siteCollections -or $siteCollections.Count -eq 0) {
            Write-Log -Message "No site collections found" -Level Warning
            $findings += Add-Finding -Category "SiteAdmins" -Title "No site collections found" `
                -Severity "Low" `
                -Description "No site collections were found in the tenant. This is unusual and might indicate an issue with permissions or the tenant configuration." `
                -Recommendation "Verify that the account used for analysis has appropriate permissions to view site collections."
            return $findings
        }
        
        Write-Log -Message "Found $($siteCollections.Count) site collections" -Level Info
        
        # Limit the number of sites analyzed if there are too many
        if ($siteCollections.Count -gt $script:MaxSitesToAnalyze) {
            Write-Log -Message "Limiting analysis to $script:MaxSitesToAnalyze sites out of $($siteCollections.Count) total sites" -Level Warning
            
            # Prioritize critical sites first
            $prioritySites = $siteCollections | Where-Object { 
                $_.Url -like "*admin*" -or 
                $_.Url -like "*security*" -or 
                $_.Url -like "*compliance*" -or
                $_.Url -like "*finance*" -or
                $_.Url -like "*hr*" -or
                $_.Url -like "*legal*" -or
                $_.Title -like "*admin*" -or
                $_.Title -like "*security*" -or
                $_.Title -like "*compliance*" -or
                $_.Title -like "*finance*" -or
                $_.Title -like "*hr*" -or
                $_.Title -like "*legal*"
            }
            
            # Then include OneDrive sites if any are present
            $oneDriveSites = $siteCollections | Where-Object { $_.Template -eq "SPSPERS" }
            $priorityOneDriveSites = $oneDriveSites | Select-Object -First 10
            
            # Then include the most recently modified sites
            $recentSites = $siteCollections | 
                          Where-Object { $_ -notin $prioritySites -and $_ -notin $priorityOneDriveSites } | 
                          Sort-Object LastContentModifiedDate -Descending | 
                          Select-Object -First ($script:MaxSitesToAnalyze - $prioritySites.Count - $priorityOneDriveSites.Count)
            
            # Combine the prioritized sites
            $sitesToAnalyze = @($prioritySites) + @($priorityOneDriveSites) + @($recentSites) | Select-Object -First $script:MaxSitesToAnalyze
        }
        else {
            $sitesToAnalyze = $siteCollections
        }
        
        $counter = 0
        $totalSites = $sitesToAnalyze.Count
        
        foreach ($site in $sitesToAnalyze) {
            $counter++
            Write-Progress -Activity "Analyzing site collection administrators" -Status "Processing site $counter of $totalSites" -PercentComplete (($counter / $totalSites) * 100)
            
            try {
                # Connect to site collection
                $siteConnection = Connect-PnPOnline -Url $site.Url -Interactive -ReturnConnection -ErrorAction Stop
                
                # Get site admins
                $siteAdmins = Get-PnPSiteCollectionAdmin -Connection $siteConnection -ErrorAction Stop
                
                if ($siteAdmins -and $siteAdmins.Count -gt 0) {
                    
                    # Look for non-standard admin accounts or external users
                    foreach ($admin in $siteAdmins) {
                        $isSuspicious = $false
                        $reasons = @()
                        $severity = "Low"
                        
                        # Check if this is an external user (Guest)
                        if ($admin.Email -and $admin.Email -like "*#EXT#*") {
                            $isSuspicious = $true
                            $reasons += "External user with site collection admin privileges"
                            $severity = "High"
                        }
                        
                        # Check for generic or suspicious account names
                        if ($admin.Title -like "*admin*" -or 
                            $admin.Title -like "*svc*" -or 
                            $admin.Title -like "*service*" -or
                            $admin.LoginName -like "*admin*" -or
                            $admin.LoginName -like "*svc*" -or
                            $admin.LoginName -like "*service*") {
                            $isSuspicious = $true
                            $reasons += "Generic service account with site collection admin privileges"
                            
                            if ($severity -ne "High") {
                                $severity = "Medium"
                            }
                        }
                        
                        # Check for personal email domains if email is available
                        if ($admin.Email) {
                            $emailDomain = $admin.Email.Split('@')[1]
                            $personalDomains = @("gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "protonmail.com")
                            
                            if ($emailDomain -in $personalDomains) {
                                $isSuspicious = $true
                                $reasons += "Personal email domain ($emailDomain) with site collection admin privileges"
                                $severity = "High"
                            }
                        }
                        
                        if ($isSuspicious) {
                            $findings += Add-Finding -Category "SiteAdmins" -Title "Suspicious site collection admin detected" `
                                -Severity $severity `
                                -Description "User '$($admin.Title)' (Login: $($admin.LoginName)) has site collection administrator privileges on site '$($site.Url)'. Reasons: $($reasons -join '; ')" `
                                -Recommendation "Review this site collection administrator account to verify it's legitimate and required." `
                                -Data @{
                                    SiteUrl = $site.Url
                                    SiteTitle = $site.Title
                                    AdminName = $admin.Title
                                    AdminLogin = $admin.LoginName
                                    AdminEmail = $admin.Email
                                    Reasons = $reasons
                                }
                        }
                    }
                    
                    # Always report site collections with many admins (potential over-privileged)
                    if ($siteAdmins.Count -gt 5) {
                        $findings += Add-Finding -Category "SiteAdmins" -Title "Site collection with excessive administrators" `
                            -Severity "Medium" `
                            -Description "Site collection '$($site.Url)' has $($siteAdmins.Count) administrators, which exceeds the recommended maximum (5)." `
                            -Recommendation "Review the list of site collection administrators and remove unnecessary accounts to reduce the attack surface." `
                            -Data @{
                                SiteUrl = $site.Url
                                SiteTitle = $site.Title
                                AdminCount = $siteAdmins.Count
                                Admins = $siteAdmins | Select-Object Title, LoginName, Email
                            }
                    }
                }
                
                # Disconnect from site
                Disconnect-PnPOnline -Connection $siteConnection -ErrorAction SilentlyContinue
            }
            catch {
                Write-Log -Message "Error analyzing site collection administrators for site '$($site.Url)': $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "SiteAdmins" -Title "Error analyzing site collection administrators" `
                    -Severity "Low" `
                    -Description "An error occurred while analyzing site collection administrators for site '$($site.Url)': $($_.Exception.Message)" `
                    -Recommendation "Manually investigate site collection administrators for this site."
            }
        }
        
        Write-Progress -Activity "Analyzing site collection administrators" -Completed
        Write-Log -Message "Completed site collection administrator analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing site collection administrators: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "SiteAdmins" -Title "Error analyzing site collection administrators" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing site collection administrators: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of site collection administrators is recommended."
    }
    
    return $findings
}

function Invoke-ExternalSharingCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing external sharing settings" -Level Info
        
        # Get tenant-level sharing settings
        $tenantSettings = Get-PnPTenant -ErrorAction Stop
        
        # Check tenant-level external sharing settings
        if ($tenantSettings) {
            $sharingLevel = $tenantSettings.SharingCapability
            
            # Evaluate sharing level
            switch ($sharingLevel) {
                "ExternalUserAndGuestSharing" {
                    # Most permissive level - can share with anyone
                    $findings += Add-Finding -Category "ExternalSharing" -Title "Tenant allows sharing with anyone (most permissive)" `
                        -Severity "Medium" `
                        -Description "The tenant is configured to allow sharing with anyone, which is the most permissive setting." `
                        -Recommendation "Consider restricting sharing to only authenticated external users or disabling external sharing if not required." `
                        -Data @{
                            SharingCapability = $sharingLevel
                            TenantSettings = $tenantSettings
                        }
                }
                "ExternalUserSharingOnly" {
                    # Medium - requires authentication
                    $findings += Add-Finding -Category "ExternalSharing" -Title "Tenant allows sharing with authenticated external users" `
                        -Severity "Low" `
                        -Description "The tenant is configured to allow sharing with authenticated external users." `
                        -Recommendation "This is a reasonable setting if external collaboration is required. Consider periodic review of external shares." `
                        -Data @{
                            SharingCapability = $sharingLevel
                            TenantSettings = $tenantSettings
                        }
                }
                "Disabled" {
                    # Most restrictive - no external sharing
                    $findings += Add-Finding -Category "ExternalSharing" -Title "Tenant external sharing is disabled" `
                        -Severity "Informational" `
                        -Description "The tenant is configured to disable external sharing entirely." `
                        -Recommendation "This is the most restrictive setting. No action required unless external sharing is needed." `
                        -Data @{
                            SharingCapability = $sharingLevel
                            TenantSettings = $tenantSettings
                        }
                }
                default {
                    # Unknown or unexpected value
                    $findings += Add-Finding -Category "ExternalSharing" -Title "Tenant has unexpected sharing capability" `
                        -Severity "Medium" `
                        -Description "The tenant is configured with an unexpected sharing capability value: $sharingLevel." `
                        -Recommendation "Investigate this setting to ensure it meets security requirements." `
                        -Data @{
                            SharingCapability = $sharingLevel
                            TenantSettings = $tenantSettings
                        }
                }
            }
            
            # Check for recent changes to external sharing settings
            # This information might not be directly available via the API
            
            # Check for additional sharing settings at tenant level
            if ($tenantSettings.RequireAcceptingAccountMatchInvitedAccount -eq $false) {
                $findings += Add-Finding -Category "ExternalSharing" -Title "Account matching not required for external sharing" `
                    -Severity "Medium" `
                    -Description "The tenant is configured to not require that the accepting account matches the invited account for external sharing." `
                    -Recommendation "Consider enabling this setting to prevent sharing links from being forwarded to other users." `
                    -Data @{
                        RequireAcceptingAccountMatchInvitedAccount = $tenantSettings.RequireAcceptingAccountMatchInvitedAccount
                        TenantSettings = $tenantSettings
                    }
            }
            
            if ($tenantSettings.PreventExternalUsersFromResharing -eq $false) {
                $findings += Add-Finding -Category "ExternalSharing" -Title "External users can reshare content" `
                    -Severity "Medium" `
                    -Description "The tenant is configured to allow external users to reshare content, which could lead to uncontrolled sharing." `
                    -Recommendation "Consider preventing external users from resharing content to maintain better control over sharing." `
                    -Data @{
                        PreventExternalUsersFromResharing = $tenantSettings.PreventExternalUsersFromResharing
                        TenantSettings = $tenantSettings
                    }
            }
            
            if ($tenantSettings.SharingAllowedDomainList -or $tenantSettings.SharingBlockedDomainList) {
                # One of these should be set, not both
                if ($tenantSettings.SharingAllowedDomainList -and $tenantSettings.SharingBlockedDomainList) {
                    $findings += Add-Finding -Category "ExternalSharing" -Title "Both allowed and blocked domain lists are configured" `
                        -Severity "Low" `
                        -Description "The tenant has both allowed and blocked domain lists configured for external sharing, which might cause confusion." `
                        -Recommendation "Consider using either an allowed domain list or a blocked domain list, but not both." `
                        -Data @{
                            SharingAllowedDomainList = $tenantSettings.SharingAllowedDomainList
                            SharingBlockedDomainList = $tenantSettings.SharingBlockedDomainList
                            TenantSettings = $tenantSettings
                        }
                }
                
                # Just informational about what domains are allowed/blocked
                if ($tenantSettings.SharingAllowedDomainList) {
                    $findings += Add-Finding -Category "ExternalSharing" -Title "Sharing allowed only with specific domains" `
                        -Severity "Informational" `
                        -Description "The tenant is configured to allow sharing only with specific domains: $($tenantSettings.SharingAllowedDomainList)" `
                        -Recommendation "This is a restrictive setting. Verify that the allowed domains list includes all necessary collaboration partners." `
                        -Data @{
                            SharingAllowedDomainList = $tenantSettings.SharingAllowedDomainList
                            TenantSettings = $tenantSettings
                        }
                }
                
                if ($tenantSettings.SharingBlockedDomainList) {
                    $findings += Add-Finding -Category "ExternalSharing" -Title "Sharing blocked with specific domains" `
                        -Severity "Informational" `
                        -Description "The tenant is configured to block sharing with specific domains: $($tenantSettings.SharingBlockedDomainList)" `
                        -Recommendation "Verify that the blocked domains list is appropriate and up to date." `
                        -Data @{
                            SharingBlockedDomainList = $tenantSettings.SharingBlockedDomainList
                            TenantSettings = $tenantSettings
                        }
                }
            }
            else {
                # Neither list is set
                if ($sharingLevel -ne "Disabled") {
                    $findings += Add-Finding -Category "ExternalSharing" -Title "No domain restrictions for external sharing" `
                        -Severity "Low" `
                        -Description "The tenant does not have any domain restrictions configured for external sharing." `
                        -Recommendation "Consider implementing domain restrictions to limit external sharing to specific trusted domains." `
                        -Data @{
                            SharingAllowedDomainList = $tenantSettings.SharingAllowedDomainList
                            SharingBlockedDomainList = $tenantSettings.SharingBlockedDomainList
                            TenantSettings = $tenantSettings
                        }
                }
            }
        }
        
        # Get all site collections
        $siteCollections = Get-PnPTenantSite -Detailed -ErrorAction Stop
        
        if (-not $siteCollections -or $siteCollections.Count -eq 0) {
            Write-Log -Message "No site collections found" -Level Warning
            return $findings
        }
        
        # Limit the number of sites analyzed if there are too many
        if ($siteCollections.Count -gt $script:MaxSitesToAnalyze) {
            Write-Log -Message "Limiting analysis to $script:MaxSitesToAnalyze sites out of $($siteCollections.Count) total sites" -Level Warning
            
            # Prioritize sites with external sharing enabled
            $externalSharingSites = $siteCollections | Where-Object { $_.SharingCapability -ne "Disabled" }
            
            # Then include the most recently modified sites
            $recentSites = $siteCollections | 
                          Where-Object { $_ -notin $externalSharingSites } | 
                          Sort-Object LastContentModifiedDate -Descending | 
                          Select-Object -First ($script:MaxSitesToAnalyze - $externalSharingSites.Count)
            
            # Combine the prioritized sites
            $sitesToAnalyze = @($externalSharingSites) + @($recentSites) | Select-Object -First $script:MaxSitesToAnalyze
        }
        else {
            $sitesToAnalyze = $siteCollections
        }
        
        # Site-specific sharing settings
        $counter = 0
        $totalSites = $sitesToAnalyze.Count
        
        foreach ($site in $sitesToAnalyze) {
            $counter++
            Write-Progress -Activity "Analyzing site-level external sharing settings" -Status "Processing site $counter of $totalSites" -PercentComplete (($counter / $totalSites) * 100)
            
            try {
                # Check site-level sharing capability
                $siteSharingLevel = $site.SharingCapability
                
                # If site allows more sharing than tenant default, report it
                if (($sharingLevel -eq "Disabled" -and $siteSharingLevel -ne "Disabled") -or
                    ($sharingLevel -eq "ExternalUserSharingOnly" -and $siteSharingLevel -eq "ExternalUserAndGuestSharing")) {
                    
                    $findings += Add-Finding -Category "ExternalSharing" -Title "Site collection with elevated sharing capability" `
                        -Severity "Medium" `
                        -Description "Site collection '$($site.Url)' has a sharing capability ($siteSharingLevel) that is more permissive than the tenant default ($sharingLevel)." `
                        -Recommendation "Review this site collection to determine if elevated sharing capabilities are necessary. If not, adjust to match the tenant default." `
                        -Data @{
                            SiteUrl = $site.Url
                            SiteTitle = $site.Title
                            SiteSharingCapability = $siteSharingLevel
                            TenantSharingCapability = $sharingLevel
                        }
                }
                
                # Connect to site collection
                $siteConnection = Connect-PnPOnline -Url $site.Url -Interactive -ReturnConnection -ErrorAction Stop
                
                # Get site sharing information if available
                try {
                    # This might require additional permissions or API calls
                    # Check for anonymous sharing links
                    $webContext = Get-PnPContext
                    $web = Get-PnPWeb -Connection $siteConnection -ErrorAction Stop
                    
                    # Get sharing links information if available
                    try {
                        # This would need to be expanded based on available APIs
                        # For now, just a placeholder for what would be checked
                        Write-Log -Message "Detailed sharing links check for site '$($site.Url)' would happen here" -Level Debug
                    }
                    catch {
                        Write-Log -Message "Unable to check sharing links for site '$($site.Url)': $($_.Exception.Message)" -Level Warning
                    }
                }
                catch {
                    Write-Log -Message "Unable to get detailed sharing information for site '$($site.Url)': $($_.Exception.Message)" -Level Warning
                }
                
                # Disconnect from site
                Disconnect-PnPOnline -Connection $siteConnection -ErrorAction SilentlyContinue
            }
            catch {
                Write-Log -Message "Error analyzing external sharing for site '$($site.Url)': $($_.Exception.Message)" -Level Warning
            }
        }
        
        Write-Progress -Activity "Analyzing site-level external sharing settings" -Completed
        Write-Log -Message "Completed external sharing analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing external sharing settings: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "ExternalSharing" -Title "Error analyzing external sharing settings" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing external sharing settings: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of external sharing settings is recommended."
    }
    
    return $findings
}

function Invoke-AddInCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing SharePoint add-ins and SPFx solutions" -Level Info
        
        # Check for tenant-scoped add-ins first (these are the most concerning)
        try {
            # Get tenant app catalog
            $catalog = Get-PnPTenantAppCatalogUrl -ErrorAction Stop
            
            if ($catalog) {
                # Connect to app catalog
                $appCatalogConnection = Connect-PnPOnline -Url $catalog -Interactive -ReturnConnection -ErrorAction Stop
                
                # Get all apps in the catalog
                $apps = Get-PnPApp -Connection $appCatalogConnection -ErrorAction Stop
                
                if ($apps -and $apps.Count -gt 0) {
                    Write-Log -Message "Found $($apps.Count) apps in tenant app catalog" -Level Info
                    
                    foreach ($app in $apps) {
                        $isSuspicious = $false
                        $reasons = @()
                        $severity = "Low"
                        
                        # Check if app was recently deployed
                        if ($app.InstalledVersion) {
                            $findings += Add-Finding -Category "AddIns" -Title "Deployed app found in tenant app catalog" `
                                -Severity "Medium" `
                                -Description "App '$($app.Title)' (ID: $($app.Id)) is deployed in the tenant app catalog. SharePoint apps can have elevated permissions and execute custom code." `
                                -Recommendation "Verify that this app is legitimate and authorized. Review its permissions and functionality." `
                                -Data @{
                                    AppTitle = $app.Title
                                    AppId = $app.Id
                                    Developer = $app.Developer
                                    InstalledVersion = $app.InstalledVersion
                                    AppCatalogVersion = $app.AppCatalogVersion
                                }
                        }
                        else {
                            $findings += Add-Finding -Category "AddIns" -Title "App found in tenant app catalog" `
                                -Severity "Informational" `
                                -Description "App '$($app.Title)' (ID: $($app.Id)) is available in the tenant app catalog but not deployed." `
                                -Recommendation "This is informational only. The app is not currently deployed." `
                                -Data @{
                                    AppTitle = $app.Title
                                    AppId = $app.Id
                                    Developer = $app.Developer
                                    AppCatalogVersion = $app.AppCatalogVersion
                                }
                        }
                    }
                }
                else {
                    Write-Log -Message "No apps found in tenant app catalog" -Level Info
                }
                
                # Disconnect from app catalog
                Disconnect-PnPOnline -Connection $appCatalogConnection -ErrorAction SilentlyContinue
            }
            else {
                Write-Log -Message "No tenant app catalog found" -Level Info
            }
        }
        catch {
            Write-Log -Message "Error checking tenant app catalog: $($_.Exception.Message)" -Level Warning
            $findings += Add-Finding -Category "AddIns" -Title "Error checking tenant app catalog" `
                -Severity "Low" `
                -Description "An error occurred while checking the tenant app catalog: $($_.Exception.Message)" `
                -Recommendation "Manually investigate tenant-level apps and add-ins."
        }
        
        # Get all site collections
        $siteCollections = Get-PnPTenantSite -Detailed -ErrorAction Stop
        
        if (-not $siteCollections -or $siteCollections.Count -eq 0) {
            Write-Log -Message "No site collections found" -Level Warning
            return $findings
        }
        
        # Limit the number of sites analyzed if there are too many
        if ($siteCollections.Count -gt $script:MaxSitesToAnalyze) {
            Write-Log -Message "Limiting analysis to $script:MaxSitesToAnalyze sites out of $($siteCollections.Count) total sites" -Level Warning
            
            # Prioritize sites with most recent modifications
            $sitesToAnalyze = $siteCollections | Sort-Object LastContentModifiedDate -Descending | Select-Object -First $script:MaxSitesToAnalyze
        }
        else {
            $sitesToAnalyze = $siteCollections
        }
        
        # Check for site-level apps and add-ins
        $counter = 0
        $totalSites = $sitesToAnalyze.Count
        
        foreach ($site in $sitesToAnalyze) {
            $counter++
            Write-Progress -Activity "Analyzing site-level apps and add-ins" -Status "Processing site $counter of $totalSites" -PercentComplete (($counter / $totalSites) * 100)
            
            try {
                # Connect to site collection
                $siteConnection = Connect-PnPOnline -Url $site.Url -Interactive -ReturnConnection -ErrorAction Stop
                
                # Check for site-scoped apps
                $siteApps = Get-PnPApp -Connection $siteConnection -ErrorAction Stop
                
                if ($siteApps -and $siteApps.Count -gt 0) {
                    foreach ($app in $siteApps) {
                        if ($app.InstalledVersion) {
                            $findings += Add-Finding -Category "AddIns" -Title "Deployed app found in site collection" `
                                -Severity "Medium" `
                                -Description "App '$($app.Title)' (ID: $($app.Id)) is deployed in site collection '$($site.Url)'. SharePoint apps can have elevated permissions and execute custom code." `
                                -Recommendation "Verify that this app is legitimate and authorized. Review its permissions and functionality." `
                                -Data @{
                                    SiteUrl = $site.Url
                                    SiteTitle = $site.Title
                                    AppTitle = $app.Title
                                    AppId = $app.Id
                                    Developer = $app.Developer
                                    InstalledVersion = $app.InstalledVersion
                                    AppCatalogVersion = $app.AppCatalogVersion
                                }
                        }
                    }
                }
                
                # Check for add-ins (legacy app model)
                try {
                    $addins = Get-PnPAddIn -Connection $siteConnection -ErrorAction Stop
                    
                    if ($addins -and $addins.Count -gt 0) {
                        foreach ($addin in $addins) {
                            $findings += Add-Finding -Category "AddIns" -Title "SharePoint add-in found in site collection" `
                                -Severity "Medium" `
                                -Description "SharePoint add-in '$($addin.Title)' (ID: $($addin.Id)) is installed in site collection '$($site.Url)'. SharePoint add-ins can have elevated permissions." `
                                -Recommendation "Verify that this add-in is legitimate and authorized. Review its permissions and functionality." `
                                -Data @{
                                    SiteUrl = $site.Url
                                    SiteTitle = $site.Title
                                    AddInTitle = $addin.Title
                                    AddInId = $addin.Id
                                    Publisher = $addin.Publisher
                                    Status = $addin.Status
                                }
                        }
                    }
                }
                catch {
                    Write-Log -Message "Error checking add-ins for site '$($site.Url)': $($_.Exception.Message)" -Level Warning
                }
                
                # Disconnect from site
                Disconnect-PnPOnline -Connection $siteConnection -ErrorAction SilentlyContinue
            }
            catch {
                Write-Log -Message "Error analyzing site-level apps for site '$($site.Url)': $($_.Exception.Message)" -Level Warning
            }
        }
        
        Write-Progress -Activity "Analyzing site-level apps and add-ins" -Completed
        Write-Log -Message "Completed add-in and app analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing SharePoint add-ins and SPFx solutions: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "AddIns" -Title "Error analyzing SharePoint add-ins and SPFx solutions" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing SharePoint add-ins and SPFx solutions: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of SharePoint add-ins and SPFx solutions is recommended."
    }
    
    return $findings
}

function Invoke-InformationBarrierCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing information barrier policies" -Level Info
        
        # Information Barriers require E5 licensing or specific compliance add-ons
        # First, check if the feature is available in the tenant
        
        $ibAvailable = $false
        
        try {
            # This is a placeholder for checking if Information Barriers are available
            # In practice, this would involve checking specific PowerShell modules or endpoints
            
            Write-Log -Message "Information Barriers feature verification would happen here" -Level Debug
            
            # For the purpose of this script, let's assume IB is not available
            $ibAvailable = $false
            
            if (-not $ibAvailable) {
                $findings += Add-Finding -Category "InformationBarriers" -Title "Information Barriers feature may not be available" `
                    -Severity "Informational" `
                    -Description "Information Barriers feature typically requires Microsoft 365 E5 or specific compliance add-ons, which may not be present in this tenant." `
                    -Recommendation "If you've purchased the necessary licenses, ensure they are properly assigned. If not, this feature is not available for analysis."
                
                Write-Log -Message "Information Barriers feature may not be available in this tenant" -Level Info
                return $findings
            }
        }
        catch {
            Write-Log -Message "Error checking Information Barriers availability: $($_.Exception.Message)" -Level Warning
            $findings += Add-Finding -Category "InformationBarriers" -Title "Unable to check Information Barriers availability" `
                -Severity "Low" `
                -Description "Unable to determine if Information Barriers feature is available in this tenant: $($_.Exception.Message)" `
                -Recommendation "Verify manually if Information Barriers are being used in your environment."
            
            return $findings
        }
        
        # If IB is available, check for policy configurations
        if ($ibAvailable) {
            # This block would contain the actual IB policy checks
            # Since IB requires specific PowerShell modules and permissions, this is a placeholder
            
            Write-Log -Message "Information Barriers policy analysis would happen here" -Level Debug
        }
        
        Write-Log -Message "Completed information barrier policy analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing information barrier policies: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "InformationBarriers" -Title "Error analyzing information barrier policies" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing information barrier policies: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of information barrier policies is recommended."
    }
    
    return $findings
}

function Invoke-SitePermissionCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing site permissions" -Level Info
        
        # Get all site collections
        $siteCollections = Get-PnPTenantSite -Detailed -ErrorAction Stop
        
        if (-not $siteCollections -or $siteCollections.Count -eq 0) {
            Write-Log -Message "No site collections found" -Level Warning
            return $findings
        }
        
        # Limit the number of sites analyzed if there are too many
        if ($siteCollections.Count -gt $script:MaxSitesToAnalyze) {
            Write-Log -Message "Limiting analysis to $script:MaxSitesToAnalyze sites out of $($siteCollections.Count) total sites" -Level Warning
            
            # Prioritize critical sites first
            $prioritySites = $siteCollections | Where-Object { 
                $_.Url -like "*admin*" -or 
                $_.Url -like "*security*" -or 
                $_.Url -like "*compliance*" -or
                $_.Url -like "*finance*" -or
                $_.Url -like "*hr*" -or
                $_.Url -like "*legal*" -or
                $_.Title -like "*admin*" -or
                $_.Title -like "*security*" -or
                $_.Title -like "*compliance*" -or
                $_.Title -like "*finance*" -or
                $_.Title -like "*hr*" -or
                $_.Title -like "*legal*"
            }
            
            # Then include the most recently modified sites
            $recentSites = $siteCollections | 
                          Where-Object { $_ -notin $prioritySites } | 
                          Sort-Object LastContentModifiedDate -Descending | 
                          Select-Object -First ($script:MaxSitesToAnalyze - $prioritySites.Count)
            
            # Combine the prioritized sites
            $sitesToAnalyze = @($prioritySites) + @($recentSites) | Select-Object -First $script:MaxSitesToAnalyze
        }
        else {
            $sitesToAnalyze = $siteCollections
        }
        
        $counter = 0
        $totalSites = $sitesToAnalyze.Count
        
        foreach ($site in $sitesToAnalyze) {
            $counter++
            Write-Progress -Activity "Analyzing site permissions" -Status "Processing site $counter of $totalSites" -PercentComplete (($counter / $totalSites) * 100)
            
            try {
                # Connect to site collection
                $siteConnection = Connect-PnPOnline -Url $site.Url -Interactive -ReturnConnection -ErrorAction Stop
                
                # Get site users and permissions
                $siteUsers = Get-PnPUser -Connection $siteConnection -ErrorAction Stop
                
                # Filter to users with direct permissions (not through groups)
                $usersWithDirectPermissions = $siteUsers | Where-Object { $_.IsSiteAdmin -or $_.HasUniqueRoleAssignments }
                
                if ($usersWithDirectPermissions -and $usersWithDirectPermissions.Count -gt 0) {
                    foreach ($user in $usersWithDirectPermissions) {
                        $isSuspicious = $false
                        $reasons = @()
                        $severity = "Low"
                        
                        # Check if this is an external user
                        if ($user.LoginName -like "*#ext#*" -or $user.Email -like "*#EXT#*") {
                            $isSuspicious = $true
                            $reasons += "External user with direct permissions"
                            $severity = "Medium"
                            
                            # If they're also a site admin, that's worse
                            if ($user.IsSiteAdmin) {
                                $reasons += "External user is also a site administrator"
                                $severity = "High"
                            }
                        }
                        
                        # Check for generic or suspicious account names
                        if ($user.Title -like "*admin*" -or 
                            $user.Title -like "*svc*" -or 
                            $user.Title -like "*service*" -or
                            $user.LoginName -like "*admin*" -or
                            $user.LoginName -like "*svc*" -or
                            $user.LoginName -like "*service*") {
                            $isSuspicious = $true
                            $reasons += "Generic service account with direct permissions"
                            
                            if ($severity -ne "High") {
                                $severity = "Medium"
                            }
                        }
                        
                        # Report suspicious users
                        if ($isSuspicious) {
                            $findings += Add-Finding -Category "SitePermissions" -Title "Suspicious user with direct permissions" `
                                -Severity $severity `
                                -Description "User '$($user.Title)' (Login: $($user.LoginName)) has direct permissions on site '$($site.Url)'. Reasons: $($reasons -join '; ')" `
                                -Recommendation "Review this user's permissions to verify they are legitimate and required." `
                                -Data @{
                                    SiteUrl = $site.Url
                                    SiteTitle = $site.Title
                                    UserName = $user.Title
                                    UserLogin = $user.LoginName
                                    UserEmail = $user.Email
                                    IsSiteAdmin = $user.IsSiteAdmin
                                    HasUniqueRoleAssignments = $user.HasUniqueRoleAssignments
                                    Reasons = $reasons
                                }
                        }
                        # Always report site admins
                        elseif ($user.IsSiteAdmin) {
                            $findings += Add-Finding -Category "SitePermissions" -Title "User with site administrator privileges" `
                                -Severity "Informational" `
                                -Description "User '$($user.Title)' (Login: $($user.LoginName)) has site administrator privileges on site '$($site.Url)'." `
                                -Recommendation "Verify that this user requires site administrator privileges." `
                                -Data @{
                                    SiteUrl = $site.Url
                                    SiteTitle = $site.Title
                                    UserName = $user.Title
                                    UserLogin = $user.LoginName
                                    UserEmail = $user.Email
                                    IsSiteAdmin = $user.IsSiteAdmin
                                }
                        }
                    }
                }
                
                # Check broken inheritance at the site level
                try {
                    $web = Get-PnPWeb -Includes HasUniqueRoleAssignments -Connection $siteConnection -ErrorAction Stop
                    
                    if ($web.HasUniqueRoleAssignments) {
                        # Get the permission levels assigned
                        $roleAssignments = Get-PnPRoleAssignment -Connection $siteConnection -ErrorAction Stop
                        
                        # Look for potentially concerning assignments
                        foreach ($assignment in $roleAssignments) {
                            $isSuspicious = $false
                            $reasons = @()
                            $severity = "Low"
                            
                            # Check for "Everyone" or "Everyone except external users" with high permissions
                            if ($assignment.PrincipalName -eq "Everyone" -or $assignment.PrincipalName -eq "Everyone except external users") {
                                $isSuspicious = $true
                                $reasons += "Broad group ($($assignment.PrincipalName)) with permissions"
                                
                                # Check permission level - Full Control or Design are concerning
                                if ($assignment.RoleDefinitionName -like "*Full Control*" -or 
                                    $assignment.RoleDefinitionName -like "*Design*" -or
                                    $assignment.RoleDefinitionName -like "*Edit*") {
                                    $reasons += "High permission level ($($assignment.RoleDefinitionName))"
                                    $severity = "High"
                                }
                                else {
                                    $severity = "Medium"
                                }
                            }
                            
                            # Report suspicious role assignments
                            if ($isSuspicious) {
                                $findings += Add-Finding -Category "SitePermissions" -Title "Suspicious site-level role assignment" `
                                    -Severity $severity `
                                    -Description "Site '$($site.Url)' has a potentially risky role assignment. Principal: '$($assignment.PrincipalName)', Role: '$($assignment.RoleDefinitionName)'. Reasons: $($reasons -join '; ')" `
                                    -Recommendation "Review this role assignment to verify it is legitimate and required." `
                                    -Data @{
                                        SiteUrl = $site.Url
                                        SiteTitle = $site.Title
                                        PrincipalName = $assignment.PrincipalName
                                        PrincipalType = $assignment.PrincipalType
                                        RoleDefinitionName = $assignment.RoleDefinitionName
                                        Reasons = $reasons
                                    }
                            }
                        }
                    }
                }
                catch {
                    Write-Log -Message "Error checking role assignments for site '$($site.Url)': $($_.Exception.Message)" -Level Warning
                }
                
                # Disconnect from site
                Disconnect-PnPOnline -Connection $siteConnection -ErrorAction SilentlyContinue
            }
            catch {
                Write-Log -Message "Error analyzing permissions for site '$($site.Url)': $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "SitePermissions" -Title "Error analyzing site permissions" `
                    -Severity "Low" `
                    -Description "An error occurred while analyzing permissions for site '$($site.Url)': $($_.Exception.Message)" `
                    -Recommendation "Manually investigate permissions for this site."
            }
        }
        
        Write-Progress -Activity "Analyzing site permissions" -Completed
        Write-Log -Message "Completed site permission analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing site permissions: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "SitePermissions" -Title "Error analyzing site permissions" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing site permissions: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of site permissions is recommended."
    }
    
    return $findings
}

# Export the module function
Export-ModuleMember -Function Start-SharePointForensics

<#
.SYNOPSIS
    Teams & Collaboration Forensics Module for M365 Compromise Assessment
.DESCRIPTION
    This module performs detailed forensic analysis of Microsoft Teams and related collaboration tools
    to identify potential attacker persistence mechanisms following admin-level compromise.
.NOTES
    Author: Dragos Ruiu
    Version 2.0
    Requires: MicrosoftTeams PowerShell module
    License: MIT
#>

#Requires -Modules MicrosoftTeams

function Start-TeamsForensics {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$DetailedLogging,
        
        [Parameter()]
        [ValidateSet("All", "ExternalAccess", "TeamOwnership", "TeamsApps", "PrivateChannels")]
        [string[]]$Checks = @("All"),
        
        [Parameter()]
        [int]$ThrottleLimit = 10,
        
        [Parameter()]
        [switch]$SkipExistingResults,
        
        [Parameter()]
        [int]$DaysToAnalyze = 30,
        
        [Parameter()]
        [int]$MaxTeamsToAnalyze = 100
    )
    
    begin {
        # Initialize logging
        $script:LogFile = Join-Path -Path $OutputPath -ChildPath "TeamsForensics_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $script:ResultPath = Join-Path -Path $OutputPath -ChildPath "Results"
        
        if (-not (Test-Path -Path $OutputPath)) {
            try {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created output directory: $OutputPath" -Level Info
            }
            catch {
                throw "Failed to create output directory: $($_.Exception.Message)"
            }
        }
        
        if (-not (Test-Path -Path $script:ResultPath)) {
            try {
                New-Item -Path $script:ResultPath -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created results directory: $script:ResultPath" -Level Info
            }
            catch {
                throw "Failed to create results directory: $($_.Exception.Message)"
            }
        }
        
        # Script-level variables
        $script:DetailedLogging = $DetailedLogging
        $script:AllFindings = @()
        $script:DaysToAnalyze = $DaysToAnalyze
        $script:AnalysisStartDate = (Get-Date).AddDays(-$DaysToAnalyze)
        $script:MaxTeamsToAnalyze = $MaxTeamsToAnalyze
    }
    
    process {
        try {
            Write-Log -Message "Starting Teams & Collaboration Forensics analysis" -Level Info
            
            # Connect to Microsoft Teams
            Connect-MicrosoftTeams
            
            # Determine which checks to run
            $checksToRun = @()
            if ($Checks -contains "All") {
                $checksToRun = @("ExternalAccess", "TeamOwnership", "TeamsApps", "PrivateChannels")
            }
            else {
                $checksToRun = $Checks
            }
            
            # Run selected checks
            foreach ($check in $checksToRun) {
                $checkResultPath = Join-Path -Path $script:ResultPath -ChildPath "Teams_$check.json"
                
                if ($SkipExistingResults -and (Test-Path -Path $checkResultPath)) {
                    Write-Log -Message "Skipping $check check as results already exist" -Level Info
                    continue
                }
                
                Write-Log -Message "Running $check check" -Level Info
                
                switch ($check) {
                    "ExternalAccess" { 
                        $findings = Invoke-ExternalAccessCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "TeamOwnership" { 
                        $findings = Invoke-TeamOwnershipCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "TeamsApps" { 
                        $findings = Invoke-TeamsAppCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "PrivateChannels" { 
                        $findings = Invoke-PrivateChannelCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                }
            }
            
            # Generate summary report
            $summaryPath = Join-Path -Path $OutputPath -ChildPath "TeamsForensics_Summary.json"
            Export-FindingsToJson -Findings $script:AllFindings -FilePath $summaryPath
            
            Write-Log -Message "Teams & Collaboration Forensics analysis completed successfully" -Level Info
        }
        catch {
            Write-Log -Message "Error during Teams & Collaboration Forensics analysis: $($_.Exception.Message)" -Level Error
            Write-Log -Message "Stack Trace: $($_.ScriptStackTrace)" -Level Error
            throw "Teams & Collaboration Forensics analysis failed: $($_.Exception.Message)"
        }
    }
    
    end {
        # Disconnect from Microsoft Teams
        Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
        Write-Log -Message "Teams & Collaboration Forensics analysis finished" -Level Info
    }
}

function Connect-MicrosoftTeams {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Message "Connecting to Microsoft Teams" -Level Info
        
        # Check if we're already connected
        $connected = Get-CsTenant -ErrorAction SilentlyContinue
        
        if (-not $connected) {
            # Connect to Teams
            $null = Connect-MicrosoftTeams -ErrorAction Stop
            
            # Verify connection
            $tenant = Get-CsTenant -ErrorAction Stop
            if (-not $tenant) {
                throw "Failed to connect to Microsoft Teams"
            }
            
            Write-Log -Message "Successfully connected to Microsoft Teams for tenant: $($tenant.DisplayName)" -Level Info
        }
        else {
            Write-Log -Message "Already connected to Microsoft Teams" -Level Info
        }
        
        return $true
    }
    catch {
        Write-Log -Message "Failed to connect to Microsoft Teams: $($_.Exception.Message)" -Level Error
        throw "Microsoft Teams connection failed. Please ensure you have the MicrosoftTeams module installed and appropriate permissions."
    }
}

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("Info", "Warning", "Error", "Debug")]
        [string]$Level = "Info"
    )
    
    # Only log debug messages if detailed logging is enabled
    if ($Level -eq "Debug" -and -not $script:DetailedLogging) {
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Output to console based on level
    switch ($Level) {
        "Info" { Write-Host $logMessage }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Debug" { Write-Host $logMessage -ForegroundColor Cyan }
    }
    
    # Write to log file
    Add-Content -Path $script:LogFile -Value $logMessage
}

function Export-FindingsToJson {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Findings,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        $Findings | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding utf8 -Force
        Write-Log -Message "Exported findings to $FilePath" -Level Info
        
        # Add to master findings list
        $script:AllFindings += $Findings
    }
    catch {
        Write-Log -Message "Error exporting findings to $FilePath : $($_.Exception.Message)" -Level Error
    }
}

function Add-Finding {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("High", "Medium", "Low", "Informational")]
        [string]$Severity,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter()]
        [string]$Recommendation,
        
        [Parameter()]
        [PSObject]$Data,
        
        [Parameter()]
        [DateTime]$Timestamp = (Get-Date)
    )
    
    $finding = [PSCustomObject]@{
        Category = $Category
        Title = $Title
        Severity = $Severity
        Description = $Description
        Recommendation = $Recommendation
        Data = $Data
        Timestamp = $Timestamp
        Id = [Guid]::NewGuid().ToString()
    }
    
    return $finding
}

function Invoke-ExternalAccessCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing Teams external access settings" -Level Info
        
        # Get tenant-level federation configuration
        $federationConfig = Get-CsTenantFederationConfiguration -ErrorAction Stop
        
        if ($federationConfig) {
            # Check for open federation settings
            if ($federationConfig.AllowFederatedUsers -eq $true) {
                $findings += Add-Finding -Category "ExternalAccess" -Title "Federation with external Teams organizations is enabled" `
                    -Severity "Low" `
                    -Description "Federation with external Teams organizations is enabled, allowing users to communicate with external Teams users." `
                    -Recommendation "This is generally a standard configuration. Consider implementing domain allow/block lists if you want more restrictive control." `
                    -Data $federationConfig
                
                # Check for open federation (allowed domains = any)
                if ($federationConfig.AllowedDomains.AllowedDomain -eq $null -and 
                    $federationConfig.BlockedDomains.BlockedDomain -eq $null) {
                    $findings += Add-Finding -Category "ExternalAccess" -Title "Federation allowed with all external domains" `
                        -Severity "Medium" `
                        -Description "Federation is enabled without any domain restrictions, allowing users to communicate with any external Teams organization." `
                        -Recommendation "Consider implementing domain allow/block lists to restrict federation to specific trusted partners." `
                        -Data $federationConfig
                }
                
                # Check blocked domains
                if ($federationConfig.BlockedDomains.BlockedDomain -ne $null) {
                    $findings += Add-Finding -Category "ExternalAccess" -Title "Federation blocked with specific domains" `
                        -Severity "Informational" `
                        -Description "Federation is blocked with the following domains: $($federationConfig.BlockedDomains.BlockedDomain | ForEach-Object { $_.Domain } | Join-String -Separator ', ')" `
                        -Recommendation "Review the blocked domain list to ensure it is up to date and meets your security requirements." `
                        -Data @{
                            BlockedDomains = $federationConfig.BlockedDomains.BlockedDomain | ForEach-Object { $_.Domain }
                            FederationConfig = $federationConfig
                        }
                }
                
                # Check allowed domains
                if ($federationConfig.AllowedDomains.AllowedDomain -ne $null) {
                    $findings += Add-Finding -Category "ExternalAccess" -Title "Federation restricted to specific allowed domains" `
                        -Severity "Informational" `
                        -Description "Federation is restricted to the following allowed domains: $($federationConfig.AllowedDomains.AllowedDomain | ForEach-Object { $_.Domain } | Join-String -Separator ', ')" `
                        -Recommendation "Review the allowed domain list to ensure it only includes trusted partners." `
                        -Data @{
                            AllowedDomains = $federationConfig.AllowedDomains.AllowedDomain | ForEach-Object { $_.Domain }
                            FederationConfig = $federationConfig
                        }
                }
            }
            else {
                $findings += Add-Finding -Category "ExternalAccess" -Title "Federation with external Teams organizations is disabled" `
                    -Severity "Informational" `
                    -Description "Federation with external Teams organizations is disabled, preventing users from communicating with external Teams users." `
                    -Recommendation "This is a restrictive configuration. No action required unless external collaboration is needed." `
                    -Data $federationConfig
            }
            
            # Check for public cloud federation (consumer Skype)
            if ($federationConfig.AllowPublicUsers -eq $true) {
                $findings += Add-Finding -Category "ExternalAccess" -Title "Federation with Skype consumer users is enabled" `
                    -Severity "Medium" `
                    -Description "Federation with Skype consumer users is enabled, allowing users to communicate with consumer Skype accounts." `
                    -Recommendation "Consider disabling Skype consumer federation if not explicitly required for business purposes." `
                    -Data $federationConfig
            }
        }
        
        # Get tenant-level guest access configuration
        $teamsGuestConfig = Get-CsTeamsGuestMeetingConfiguration -ErrorAction Stop
        $teamsGuestCallingConfig = Get-CsTeamsGuestCallingConfiguration -ErrorAction Stop
        $teamsGuestMessagingConfig = Get-CsTeamsGuestMessagingConfiguration -ErrorAction Stop
        
        # Check guest meeting access
        if ($teamsGuestConfig) {
            if ($teamsGuestConfig.AllowMeetingSchedule -eq $true) {
                $findings += Add-Finding -Category "ExternalAccess" -Title "Guest users can schedule meetings" `
                    -Severity "Medium" `
                    -Description "Guest users are allowed to schedule meetings, which could be used for data sharing or social engineering." `
                    -Recommendation "Consider disabling meeting scheduling for guest users if not explicitly required." `
                    -Data $teamsGuestConfig
            }
            
            if ($teamsGuestConfig.AllowIPVideo -eq $true) {
                $findings += Add-Finding -Category "ExternalAccess" -Title "Guest users can use video in meetings" `
                    -Severity "Low" `
                    -Description "Guest users are allowed to use video in meetings." `
                    -Recommendation "Consider disabling video for guest users if not explicitly required." `
                    -Data $teamsGuestConfig
            }
        }
        
        # Check guest calling access
        if ($teamsGuestCallingConfig) {
            if ($teamsGuestCallingConfig.AllowPrivateCalling -eq $true) {
                $findings += Add-Finding -Category "ExternalAccess" -Title "Guest users can make private calls" `
                    -Severity "Medium" `
                    -Description "Guest users are allowed to make private calls, which could be used for data exfiltration or social engineering." `
                    -Recommendation "Consider disabling private calling for guest users if not explicitly required." `
                    -Data $teamsGuestCallingConfig
            }
        }
        
        # Check guest messaging access
        if ($teamsGuestMessagingConfig) {
            if ($teamsGuestMessagingConfig.AllowUserEditMessage -eq $true) {
                $findings += Add-Finding -Category "ExternalAccess" -Title "Guest users can edit messages" `
                    -Severity "Low" `
                    -Description "Guest users are allowed to edit messages they have sent." `
                    -Recommendation "Consider disabling message editing for guest users to maintain message integrity." `
                    -Data $teamsGuestMessagingConfig
            }
            
            if ($teamsGuestMessagingConfig.AllowUserDeleteMessage -eq $true) {
                $findings += Add-Finding -Category "ExternalAccess" -Title "Guest users can delete messages" `
                    -Severity "Low" `
                    -Description "Guest users are allowed to delete messages they have sent, which could be used to remove evidence of malicious activity." `
                    -Recommendation "Consider disabling message deletion for guest users to maintain an audit trail." `
                    -Data $teamsGuestMessagingConfig
            }
            
            if ($teamsGuestMessagingConfig.AllowGiphy -eq $true) {
                $findings += Add-Finding -Category "ExternalAccess" -Title "Guest users can use Giphy" `
                    -Severity "Low" `
                    -Description "Guest users are allowed to use Giphy in conversations." `
                    -Recommendation "Consider disabling Giphy for guest users to reduce potential attack vectors." `
                    -Data $teamsGuestMessagingConfig
            }
        }
        
        # Get Teams external access policy
        $externalAccessPolicy = Get-CsExternalAccessPolicy -ErrorAction Stop
        
        if ($externalAccessPolicy) {
            # Check for custom external access policies
            $nonDefaultPolicies = $externalAccessPolicy | Where-Object { $_.Identity -ne "Global" }
            
            if ($nonDefaultPolicies) {
                foreach ($policy in $nonDefaultPolicies) {
                    $findings += Add-Finding -Category "ExternalAccess" -Title "Custom external access policy detected" `
                        -Severity "Medium" `
                        -Description "Custom external access policy '$($policy.Identity)' detected. Custom policies could be used to bypass global settings for specific users." `
                        -Recommendation "Review this custom policy to ensure it meets security requirements and is assigned to appropriate users." `
                        -Data $policy
                }
            }
        }
        
        Write-Log -Message "Completed Teams external access analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing Teams external access settings: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "ExternalAccess" -Title "Error analyzing Teams external access settings" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing Teams external access settings: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of Teams external access settings is recommended."
    }
    
    return $findings
}

function Invoke-TeamOwnershipCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing Teams ownership and membership" -Level Info
        
        # Get all teams
        $teams = Get-Team -ErrorAction Stop
        
        if (-not $teams -or $teams.Count -eq 0) {
            Write-Log -Message "No teams found" -Level Warning
            $findings += Add-Finding -Category "TeamOwnership" -Title "No teams found" `
                -Severity "Low" `
                -Description "No Microsoft Teams teams were found in the tenant. This is unusual and might indicate an issue with permissions or the tenant configuration." `
                -Recommendation "Verify that the account used for analysis has appropriate permissions to view teams."
            return $findings
        }
        
        Write-Log -Message "Found $($teams.Count) teams" -Level Info
        
        # Limit the number of teams analyzed if there are too many
        if ($teams.Count -gt $script:MaxTeamsToAnalyze) {
            Write-Log -Message "Limiting analysis to $script:MaxTeamsToAnalyze teams out of $($teams.Count) total teams" -Level Warning
            
            # Prioritize teams with sensitive names first
            $priorityTeams = $teams | Where-Object { 
                $_.DisplayName -like "*admin*" -or 
                $_.DisplayName -like "*security*" -or 
                $_.DisplayName -like "*compliance*" -or
                $_.DisplayName -like "*finance*" -or
                $_.DisplayName -like "*hr*" -or
                $_.DisplayName -like "*legal*" -or
                $_.DisplayName -like "*confidential*" -or
                $_.DisplayName -like "*sensitive*" -or
                $_.DisplayName -like "*restricted*"
            }
            
            # Then include teams with external members
            $teamsWithExternalMembers = $teams | Where-Object { $_.AllowGuestEnabled -eq $true }
            
            # Then include the remaining teams up to the limit
            $remainingTeams = $teams | 
                            Where-Object { $_ -notin $priorityTeams -and $_ -notin $teamsWithExternalMembers } | 
                            Select-Object -First ($script:MaxTeamsToAnalyze - $priorityTeams.Count - $teamsWithExternalMembers.Count)
            
            # Combine the prioritized teams
            $teamsToAnalyze = @($priorityTeams) + @($teamsWithExternalMembers) + @($remainingTeams) | 
                             Select-Object -First $script:MaxTeamsToAnalyze
        }
        else {
            $teamsToAnalyze = $teams
        }
        
        $counter = 0
        $totalTeams = $teamsToAnalyze.Count
        
        foreach ($team in $teamsToAnalyze) {
            $counter++
            Write-Progress -Activity "Analyzing Teams ownership and membership" -Status "Processing team $counter of $totalTeams" -PercentComplete (($counter / $totalTeams) * 100)
            
            try {
                # Get team owners
                $owners = Get-TeamUser -GroupId $team.GroupId -Role Owner -ErrorAction Stop
                
                # Get team members
                $members = Get-TeamUser -GroupId $team.GroupId -Role Member -ErrorAction Stop
                
                # Get team guests
                $guests = Get-TeamUser -GroupId $team.GroupId -Role Guest -ErrorAction Stop
                
                # Check ownership issues
                if (-not $owners -or $owners.Count -eq 0) {
                    $findings += Add-Finding -Category "TeamOwnership" -Title "Team without any owners" `
                        -Severity "High" `
                        -Description "Team '$($team.DisplayName)' (ID: $($team.GroupId)) does not have any owners, which is a significant administrative issue." `
                        -Recommendation "Assign at least one owner to this team immediately to ensure proper administration." `
                        -Data @{
                            TeamName = $team.DisplayName
                            TeamId = $team.GroupId
                            Visibility = $team.Visibility
                        }
                }
                elseif ($owners.Count -eq 1) {
                    $findings += Add-Finding -Category "TeamOwnership" -Title "Team with single owner" `
                        -Severity "Medium" `
                        -Description "Team '$($team.DisplayName)' (ID: $($team.GroupId)) has only one owner ($($owners[0].User)), which creates a single point of failure." `
                        -Recommendation "Assign at least one additional owner to this team to ensure continuity of administration." `
                        -Data @{
                            TeamName = $team.DisplayName
                            TeamId = $team.GroupId
                            Visibility = $team.Visibility
                            Owner = $owners[0].User
                        }
                }
                
                # Check for external guest owners (very unusual and suspicious)
                $externalOwners = $owners | Where-Object { $_.User -like "*#EXT#*" }
                
                if ($externalOwners -and $externalOwners.Count -gt 0) {
                    foreach ($extOwner in $externalOwners) {
                        $findings += Add-Finding -Category "TeamOwnership" -Title "External user as team owner" `
                            -Severity "High" `
                            -Description "Team '$($team.DisplayName)' (ID: $($team.GroupId)) has an external user '$($extOwner.User)' as an owner, which is highly unusual and a potential security risk." `
                            -Recommendation "Remove external user from owner role immediately and investigate why this was configured." `
                            -Data @{
                                TeamName = $team.DisplayName
                                TeamId = $team.GroupId
                                Visibility = $team.Visibility
                                ExternalOwner = $extOwner.User
                            }
                    }
                }
                
                # Check for sensitive teams with external guests
                if ($guests -and $guests.Count -gt 0) {
                    $isSensitiveTeam = $team.DisplayName -like "*admin*" -or 
                                    $team.DisplayName -like "*security*" -or 
                                    $team.DisplayName -like "*compliance*" -or
                                    $team.DisplayName -like "*finance*" -or
                                    $team.DisplayName -like "*hr*" -or
                                    $team.DisplayName -like "*legal*" -or
                                    $team.DisplayName -like "*confidential*" -or
                                    $team.DisplayName -like "*sensitive*" -or
                                    $team.DisplayName -like "*restricted*"
                    
                    if ($isSensitiveTeam) {
                        $findings += Add-Finding -Category "TeamOwnership" -Title "Sensitive team with external guests" `
                            -Severity "High" `
                            -Description "Team '$($team.DisplayName)' (ID: $($team.GroupId)) appears to contain sensitive information based on its name and has $($guests.Count) external guest users." `
                            -Recommendation "Review all guest users in this sensitive team and remove any that are not explicitly required." `
                            -Data @{
                                TeamName = $team.DisplayName
                                TeamId = $team.GroupId
                                Visibility = $team.Visibility
                                GuestCount = $guests.Count
                                Guests = $guests | ForEach-Object { $_.User }
                            }
                    }
                    else {
                        # Normal team with guests - just informational
                        $findings += Add-Finding -Category "TeamOwnership" -Title "Team with external guests" `
                            -Severity "Informational" `
                            -Description "Team '$($team.DisplayName)' (ID: $($team.GroupId)) has $($guests.Count) external guest users." `
                            -Recommendation "Review guest users periodically to ensure they still require access." `
                            -Data @{
                                TeamName = $team.DisplayName
                                TeamId = $team.GroupId
                                Visibility = $team.Visibility
                                GuestCount = $guests.Count
                                Guests = $guests | ForEach-Object { $_.User }
                            }
                    }
                }
                
                # Check for teams with abnormal guest:member ratios (more guests than members)
                if ($guests -and $members -and $guests.Count > $members.Count) {
                    $findings += Add-Finding -Category "TeamOwnership" -Title "Team with more guests than members" `
                        -Severity "Medium" `
                        -Description "Team '$($team.DisplayName)' (ID: $($team.GroupId)) has more external guests ($($guests.Count)) than internal members ($($members.Count)), which is unusual." `
                        -Recommendation "Review guest users to ensure they all require access and consider if this team should be restructured." `
                        -Data @{
                            TeamName = $team.DisplayName
                            TeamId = $team.GroupId
                            Visibility = $team.Visibility
                            GuestCount = $guests.Count
                            MemberCount = $members.Count
                            Guests = $guests | ForEach-Object { $_.User }
                            Members = $members | ForEach-Object { $_.User }
                        }
                }
            }
            catch {
                Write-Log -Message "Error analyzing team '$($team.DisplayName)': $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "TeamOwnership" -Title "Error analyzing team" `
                    -Severity "Low" `
                    -Description "An error occurred while analyzing team '$($team.DisplayName)' (ID: $($team.GroupId)): $($_.Exception.Message)" `
                    -Recommendation "Manually investigate this team's ownership and membership." `
                    -Data @{
                        TeamName = $team.DisplayName
                        TeamId = $team.GroupId
                        Error = $_.Exception.Message
                    }
            }
        }
        
        Write-Progress -Activity "Analyzing Teams ownership and membership" -Completed
        Write-Log -Message "Completed Teams ownership and membership analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing Teams ownership and membership: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "TeamOwnership" -Title "Error analyzing Teams ownership and membership" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing Teams ownership and membership: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of Teams ownership and membership is recommended."
    }
    
    return $findings
}

function Invoke-TeamsAppCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing Teams apps and permissions" -Level Info
        
        # Get tenant app policy
        $appSetupPolicy = Get-CsTeamsAppSetupPolicy -ErrorAction Stop
        
        if ($appSetupPolicy) {
            # Check for custom app policies with potentially risky settings
            $nonDefaultPolicies = $appSetupPolicy | Where-Object { $_.Identity -ne "Global" }
            
            if ($nonDefaultPolicies) {
                foreach ($policy in $nonDefaultPolicies) {
                    $isSuspicious = $false
                    $reasons = @()
                    $severity = "Low"
                    
                    if ($policy.AllowSideLoading -eq $true) {
                        $isSuspicious = $true
                        $reasons += "Allows sideloading of custom apps"
                        $severity = "Medium"
                    }
                    
                    if ($policy.AllowUserPinning -eq $true) {
                        $isSuspicious = $true
                        $reasons += "Allows users to pin apps"
                    }
                    
                    if ($isSuspicious) {
                        $findings += Add-Finding -Category "TeamsApps" -Title "Custom Teams app setup policy with potentially risky settings" `
                            -Severity $severity `
                            -Description "Custom Teams app setup policy '$($policy.Identity)' has potentially risky settings. Reasons: $($reasons -join '; ')" `
                            -Recommendation "Review this custom policy to ensure it meets security requirements and verify which users it's assigned to." `
                            -Data $policy
                    }
                }
            }
            
            # Check global policy
            $globalPolicy = $appSetupPolicy | Where-Object { $_.Identity -eq "Global" }
            
            if ($globalPolicy -and $globalPolicy.AllowSideLoading -eq $true) {
                $findings += Add-Finding -Category "TeamsApps" -Title "Global Teams app setup policy allows sideloading" `
                    -Severity "Medium" `
                    -Description "The global Teams app setup policy allows sideloading of custom apps, which could be used to deploy unauthorized or malicious apps." `
                    -Recommendation "Consider disabling sideloading in the global policy and only enabling it in specific policies assigned to developers or administrators." `
                    -Data $globalPolicy
            }
        }
        
        # Get app permission policy
        $appPermissionPolicy = Get-CsTeamsAppPermissionPolicy -ErrorAction Stop
        
        if ($appPermissionPolicy) {
            # Check for custom app permission policies with potentially risky settings
            $nonDefaultPolicies = $appPermissionPolicy | Where-Object { $_.Identity -ne "Global" }
            
            if ($nonDefaultPolicies) {
                foreach ($policy in $nonDefaultPolicies) {
                    $isSuspicious = $false
                    $reasons = @()
                    $severity = "Low"
                    
                    if ($policy.GlobalCatalogAppsType -eq "Allow") {
                        # This is normal, but just note it
                        $isSuspicious = $true
                        $reasons += "Allows all global catalog apps"
                    }
                    
                    if ($policy.PrivateCatalogAppsType -eq "Allow") {
                        $isSuspicious = $true
                        $reasons += "Allows all private catalog apps"
                        $severity = "Medium"
                    }
                    
                    if ($policy.OrgCatalogAppsType -eq "Allow") {
                        $isSuspicious = $true
                        $reasons += "Allows all organization catalog apps"
                    }
                    
                    if ($policy.SideLoadedAppsType -eq "Allow") {
                        $isSuspicious = $true
                        $reasons += "Allows all sideloaded apps"
                        $severity = "Medium"
                    }
                    
                    if ($isSuspicious) {
                        $findings += Add-Finding -Category "TeamsApps" -Title "Custom Teams app permission policy with potentially risky settings" `
                            -Severity $severity `
                            -Description "Custom Teams app permission policy '$($policy.Identity)' has potentially risky settings. Reasons: $($reasons -join '; ')" `
                            -Recommendation "Review this custom policy to ensure it meets security requirements and verify which users it's assigned to." `
                            -Data $policy
                    }
                }
            }
            
            # Check global policy
            $globalPolicy = $appPermissionPolicy | Where-Object { $_.Identity -eq "Global" }
            
            if ($globalPolicy) {
                $riskReasons = @()
                
                if ($globalPolicy.PrivateCatalogAppsType -eq "Allow") {
                    $riskReasons += "Allows all private catalog apps"
                }
                
                if ($globalPolicy.SideLoadedAppsType -eq "Allow") {
                    $riskReasons += "Allows all sideloaded apps"
                }
                
                if ($riskReasons.Count -gt 0) {
                    $findings += Add-Finding -Category "TeamsApps" -Title "Global Teams app permission policy with potentially risky settings" `
                        -Severity "Medium" `
                        -Description "The global Teams app permission policy has potentially risky settings. Reasons: $($riskReasons -join '; ')" `
                        -Recommendation "Consider restricting private catalog and sideloaded apps in the global policy to reduce potential attack surface." `
                        -Data $globalPolicy
                }
            }
        }
        
        # Get custom Teams apps
        try {
            # Get Teams apps
            $teamsApps = Get-TeamsApp -ErrorAction Stop
            
            if ($teamsApps) {
                # Filter to custom and third-party apps
                $customApps = $teamsApps | Where-Object { $_.DistributionMethod -ne "store" }
                
                if ($customApps) {
                    foreach ($app in $customApps) {
                        $findings += Add-Finding -Category "TeamsApps" -Title "Custom Teams app detected" `
                            -Severity "Medium" `
                            -Description "Custom Teams app '$($app.DisplayName)' (ID: $($app.Id)) is deployed with distribution method '$($app.DistributionMethod)'." `
                            -Recommendation "Verify that this app is legitimate, authorized, and required. Review its permissions and functionality." `
                            -Data $app
                    }
                }
            }
        }
        catch {
            Write-Log -Message "Error retrieving Teams apps: $($_.Exception.Message)" -Level Warning
            $findings += Add-Finding -Category "TeamsApps" -Title "Error retrieving Teams apps" `
                -Severity "Low" `
                -Description "An error occurred while retrieving Teams apps: $($_.Exception.Message)" `
                -Recommendation "Manually investigate Teams apps for any unauthorized or suspicious apps."
        }
        
        Write-Log -Message "Completed Teams apps and permissions analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing Teams apps and permissions: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "TeamsApps" -Title "Error analyzing Teams apps and permissions" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing Teams apps and permissions: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of Teams apps and permissions is recommended."
    }
    
    return $findings
}

function Invoke-PrivateChannelCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing Teams private channels" -Level Info
        
        # Get all teams
        $teams = Get-Team -ErrorAction Stop
        
        if (-not $teams -or $teams.Count -eq 0) {
            Write-Log -Message "No teams found" -Level Warning
            return $findings
        }
        
        # Limit the number of teams analyzed if there are too many
        if ($teams.Count -gt $script:MaxTeamsToAnalyze) {
            Write-Log -Message "Limiting analysis to $script:MaxTeamsToAnalyze teams out of $($teams.Count) total teams" -Level Warning
            
            # Prioritize teams with sensitive names first
            $priorityTeams = $teams | Where-Object { 
                $_.DisplayName -like "*admin*" -or 
                $_.DisplayName -like "*security*" -or 
                $_.DisplayName -like "*compliance*" -or
                $_.DisplayName -like "*finance*" -or
                $_.DisplayName -like "*hr*" -or
                $_.DisplayName -like "*legal*" -or
                $_.DisplayName -like "*confidential*" -or
                $_.DisplayName -like "*sensitive*" -or
                $_.DisplayName -like "*restricted*"
            }
            
            # Then include the remaining teams up to the limit
            $remainingTeams = $teams | 
                            Where-Object { $_ -notin $priorityTeams } | 
                            Select-Object -First ($script:MaxTeamsToAnalyze - $priorityTeams.Count)
            
            # Combine the prioritized teams
            $teamsToAnalyze = @($priorityTeams) + @($remainingTeams) | 
                             Select-Object -First $script:MaxTeamsToAnalyze
        }
        else {
            $teamsToAnalyze = $teams
        }
        
        $counter = 0
        $totalTeams = $teamsToAnalyze.Count
        
        foreach ($team in $teamsToAnalyze) {
            $counter++
            Write-Progress -Activity "Analyzing Teams private channels" -Status "Processing team $counter of $totalTeams" -PercentComplete (($counter / $totalTeams) * 100)
            
            try {
                # Get channels for this team
                $channels = Get-TeamChannel -GroupId $team.GroupId -ErrorAction Stop
                
                if ($channels) {
                    # Filter to private channels
                    $privateChannels = $channels | Where-Object { $_.MembershipType -eq "Private" }
                    
                    if ($privateChannels) {
                        # Check each private channel
                        foreach ($channel in $privateChannels) {
                            try {
                                # Get channel members
                                $channelUsers = Get-TeamChannelUser -GroupId $team.GroupId -DisplayName $channel.DisplayName -ErrorAction Stop
                                
                                if ($channelUsers) {
                                    # Filter to owners
                                    $channelOwners = $channelUsers | Where-Object { $_.Role -eq "Owner" }
                                    
                                    # Check if there are no owners
                                    if (-not $channelOwners -or $channelOwners.Count -eq 0) {
                                        $findings += Add-Finding -Category "PrivateChannels" -Title "Private channel without owners" `
                                            -Severity "High" `
                                            -Description "Private channel '$($channel.DisplayName)' in team '$($team.DisplayName)' does not have any owners, which is a significant administrative issue." `
                                            -Recommendation "Assign at least one owner to this private channel immediately to ensure proper administration." `
                                            -Data @{
                                                TeamName = $team.DisplayName
                                                TeamId = $team.GroupId
                                                ChannelName = $channel.DisplayName
                                                ChannelId = $channel.Id
                                            }
                                    }
                                    elseif ($channelOwners.Count -eq 1) {
                                        $findings += Add-Finding -Category "PrivateChannels" -Title "Private channel with single owner" `
                                            -Severity "Medium" `
                                            -Description "Private channel '$($channel.DisplayName)' in team '$($team.DisplayName)' has only one owner ($($channelOwners[0].User)), which creates a single point of failure." `
                                            -Recommendation "Assign at least one additional owner to this private channel to ensure continuity of administration." `
                                            -Data @{
                                                TeamName = $team.DisplayName
                                                TeamId = $team.GroupId
                                                ChannelName = $channel.DisplayName
                                                ChannelId = $channel.Id
                                                Owner = $channelOwners[0].User
                                            }
                                    }
                                    
                                    # Filter to guests
                                    $channelGuests = $channelUsers | Where-Object { $_.User -like "*#EXT#*" }
                                    
                                    if ($channelGuests -and $channelGuests.Count -gt 0) {
                                        # Check for sensitive channel names with guests
                                        $isSensitiveChannel = $channel.DisplayName -like "*admin*" -or 
                                                            $channel.DisplayName -like "*security*" -or 
                                                            $channel.DisplayName -like "*compliance*" -or
                                                            $channel.DisplayName -like "*finance*" -or
                                                            $channel.DisplayName -like "*hr*" -or
                                                            $channel.DisplayName -like "*legal*" -or
                                                            $channel.DisplayName -like "*confidential*" -or
                                                            $channel.DisplayName -like "*sensitive*" -or
                                                            $channel.DisplayName -like "*restricted*"
                                        
                                        if ($isSensitiveChannel) {
                                            $findings += Add-Finding -Category "PrivateChannels" -Title "Sensitive private channel with external guests" `
                                                -Severity "High" `
                                                -Description "Private channel '$($channel.DisplayName)' in team '$($team.DisplayName)' appears to contain sensitive information based on its name and has $($channelGuests.Count) external guest users." `
                                                -Recommendation "Review all guest users in this sensitive private channel and remove any that are not explicitly required." `
                                                -Data @{
                                                    TeamName = $team.DisplayName
                                                    TeamId = $team.GroupId
                                                    ChannelName = $channel.DisplayName
                                                    ChannelId = $channel.Id
                                                    GuestCount = $channelGuests.Count
                                                    Guests = $channelGuests | ForEach-Object { $_.User }
                                                }
                                        }
                                        
                                        # Check for guest owners (very suspicious)
                                        $guestOwners = $channelUsers | Where-Object { $_.User -like "*#EXT#*" -and $_.Role -eq "Owner" }
                                        
                                        if ($guestOwners -and $guestOwners.Count -gt 0) {
                                            foreach ($guestOwner in $guestOwners) {
                                                $findings += Add-Finding -Category "PrivateChannels" -Title "External guest as private channel owner" `
                                                    -Severity "High" `
                                                    -Description "Private channel '$($channel.DisplayName)' in team '$($team.DisplayName)' has an external user '$($guestOwner.User)' as an owner, which is highly unusual and a potential security risk." `
                                                    -Recommendation "Remove external user from owner role immediately and investigate why this was configured." `
                                                    -Data @{
                                                        TeamName = $team.DisplayName
                                                        TeamId = $team.GroupId
                                                        ChannelName = $channel.DisplayName
                                                        ChannelId = $channel.Id
                                                        ExternalOwner = $guestOwner.User
                                                    }
                                            }
                                        }
                                    }
                                }
                            }
                            catch {
                                Write-Log -Message "Error analyzing private channel '$($channel.DisplayName)' in team '$($team.DisplayName)': $($_.Exception.Message)" -Level Warning
                            }
                        }
                    }
                }
            }
            catch {
                Write-Log -Message "Error retrieving channels for team '$($team.DisplayName)': $($_.Exception.Message)" -Level Warning
            }
        }
        
        Write-Progress -Activity "Analyzing Teams private channels" -Completed
        Write-Log -Message "Completed Teams private channels analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing Teams private channels: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "PrivateChannels" -Title "Error analyzing Teams private channels" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing Teams private channels: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of Teams private channels is recommended."
    }
    
    return $findings
}

# Export the module function
Export-ModuleMember -Function Start-TeamsForensics

<#
.SYNOPSIS
    Power Platform Forensics Module for M365 Compromise Assessment
.DESCRIPTION
    This module performs detailed forensic analysis of Power Platform components
    (Power Automate flows, Power Apps, Dataverse, custom connectors) to identify
    potential attacker persistence mechanisms following admin-level compromise.
.NOTES
    Author: Dragos Ruiu
    Version 2.0
    Requires: Microsoft.PowerApps.PowerShell, Microsoft.PowerApps.Administration.PowerShell
    License: MIT
#>

#Requires -Modules Microsoft.PowerApps.PowerShell, Microsoft.PowerApps.Administration.PowerShell

function Start-PowerPlatformForensics {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$DetailedLogging,
        
        [Parameter()]
        [ValidateSet("All", "PowerAutomateFlows", "PowerApps", "CustomConnectors", 
                     "DataverseRoles", "DataLossPrevention")]
        [string[]]$Checks = @("All"),
        
        [Parameter()]
        [int]$ThrottleLimit = 10,
        
        [Parameter()]
        [switch]$SkipExistingResults,
        
        [Parameter()]
        [int]$DaysToAnalyze = 30,
        
        [Parameter()]
        [int]$MaxItemsToAnalyze = 100
    )
    
    begin {
        # Initialize logging
        $script:LogFile = Join-Path -Path $OutputPath -ChildPath "PowerPlatformForensics_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $script:ResultPath = Join-Path -Path $OutputPath -ChildPath "Results"
        
        if (-not (Test-Path -Path $OutputPath)) {
            try {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created output directory: $OutputPath" -Level Info
            }
            catch {
                throw "Failed to create output directory: $($_.Exception.Message)"
            }
        }
        
        if (-not (Test-Path -Path $script:ResultPath)) {
            try {
                New-Item -Path $script:ResultPath -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created results directory: $script:ResultPath" -Level Info
            }
            catch {
                throw "Failed to create results directory: $($_.Exception.Message)"
            }
        }
        
        # Script-level variables
        $script:DetailedLogging = $DetailedLogging
        $script:AllFindings = @()
        $script:DaysToAnalyze = $DaysToAnalyze
        $script:AnalysisStartDate = (Get-Date).AddDays(-$DaysToAnalyze)
        $script:MaxItemsToAnalyze = $MaxItemsToAnalyze
        $script:EnvironmentCache = @{}
        $script:ConnectorCache = @{}
    }
    
    process {
        try {
            Write-Log -Message "Starting Power Platform Forensics analysis" -Level Info
            
            # Connect to Power Platform
            Connect-PowerPlatform
            
            # Determine which checks to run
            $checksToRun = @()
            if ($Checks -contains "All") {
                $checksToRun = @("PowerAutomateFlows", "PowerApps", "CustomConnectors", 
                              "DataverseRoles", "DataLossPrevention")
            }
            else {
                $checksToRun = $Checks
            }
            
            # Run selected checks
            foreach ($check in $checksToRun) {
                $checkResultPath = Join-Path -Path $script:ResultPath -ChildPath "PowerPlatform_$check.json"
                
                if ($SkipExistingResults -and (Test-Path -Path $checkResultPath)) {
                    Write-Log -Message "Skipping $check check as results already exist" -Level Info
                    continue
                }
                
                Write-Log -Message "Running $check check" -Level Info
                
                switch ($check) {
                    "PowerAutomateFlows" { 
                        $findings = Invoke-PowerAutomateFlowCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "PowerApps" { 
                        $findings = Invoke-PowerAppsCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "CustomConnectors" { 
                        $findings = Invoke-CustomConnectorCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "DataverseRoles" { 
                        $findings = Invoke-DataverseRoleCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "DataLossPrevention" { 
                        $findings = Invoke-DataLossPreventionCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                }
            }
            
            # Generate summary report
            $summaryPath = Join-Path -Path $OutputPath -ChildPath "PowerPlatformForensics_Summary.json"
            Export-FindingsToJson -Findings $script:AllFindings -FilePath $summaryPath
            
            Write-Log -Message "Power Platform Forensics analysis completed successfully" -Level Info
        }
        catch {
            Write-Log -Message "Error during Power Platform Forensics analysis: $($_.Exception.Message)" -Level Error
            Write-Log -Message "Stack Trace: $($_.ScriptStackTrace)" -Level Error
            throw "Power Platform Forensics analysis failed: $($_.Exception.Message)"
        }
    }
    
    end {
        # Disconnect (no explicit disconnect cmdlet in Power Platform modules)
        Write-Log -Message "Power Platform Forensics analysis finished" -Level Info
    }
}

function Connect-PowerPlatform {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Message "Connecting to Power Platform" -Level Info
        
        # Check if we're already connected
        $environments = $null
        try {
            $environments = Get-AdminPowerAppEnvironment -ErrorAction Stop
        }
        catch {
            # Not connected or missing permissions
        }
        
        if (-not $environments) {
            # Connect to Power Apps Admin API
            Add-PowerAppsAccount -ErrorAction Stop
            
            # Verify connection
            $environments = Get-AdminPowerAppEnvironment -ErrorAction Stop
            if (-not $environments) {
                throw "Failed to connect to Power Platform"
            }
            
            # Cache available environments
            $script:EnvironmentCache = @{}
            foreach ($env in $environments) {
                $script:EnvironmentCache[$env.EnvironmentName] = $env
            }
            
            Write-Log -Message "Successfully connected to Power Platform. Found $($environments.Count) environments." -Level Info
        }
        else {
            # Already connected - just cache environments if not already done
            if ($script:EnvironmentCache.Count -eq 0) {
                foreach ($env in $environments) {
                    $script:EnvironmentCache[$env.EnvironmentName] = $env
                }
            }
            
            Write-Log -Message "Already connected to Power Platform" -Level Info
        }
        
        return $true
    }
    catch {
        Write-Log -Message "Failed to connect to Power Platform: $($_.Exception.Message)" -Level Error
        throw "Power Platform connection failed. Please ensure you have the Microsoft.PowerApps.PowerShell and Microsoft.PowerApps.Administration.PowerShell modules installed and appropriate permissions."
    }
}

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("Info", "Warning", "Error", "Debug")]
        [string]$Level = "Info"
    )
    
    # Only log debug messages if detailed logging is enabled
    if ($Level -eq "Debug" -and -not $script:DetailedLogging) {
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Output to console based on level
    switch ($Level) {
        "Info" { Write-Host $logMessage }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Debug" { Write-Host $logMessage -ForegroundColor Cyan }
    }
    
    # Write to log file
    Add-Content -Path $script:LogFile -Value $logMessage
}

function Export-FindingsToJson {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Findings,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        $Findings | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding utf8 -Force
        Write-Log -Message "Exported findings to $FilePath" -Level Info
        
        # Add to master findings list
        $script:AllFindings += $Findings
    }
    catch {
        Write-Log -Message "Error exporting findings to $FilePath : $($_.Exception.Message)" -Level Error
    }
}

function Add-Finding {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("High", "Medium", "Low", "Informational")]
        [string]$Severity,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter()]
        [string]$Recommendation,
        
        [Parameter()]
        [PSObject]$Data,
        
        [Parameter()]
        [DateTime]$Timestamp = (Get-Date)
    )
    
    $finding = [PSCustomObject]@{
        Category = $Category
        Title = $Title
        Severity = $Severity
        Description = $Description
        Recommendation = $Recommendation
        Data = $Data
        Timestamp = $Timestamp
        Id = [Guid]::NewGuid().ToString()
    }
    
    return $finding
}

function Invoke-PowerAutomateFlowCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing Power Automate flows" -Level Info
        
        # Get all environments
        $environments = Get-AdminPowerAppEnvironment -ErrorAction Stop
        
        if (-not $environments -or $environments.Count -eq 0) {
            Write-Log -Message "No Power Platform environments found" -Level Warning
            $findings += Add-Finding -Category "PowerAutomateFlows" -Title "No Power Platform environments found" `
                -Severity "Low" `
                -Description "No Power Platform environments were found in the tenant. This is unusual and might indicate an issue with permissions or the tenant configuration." `
                -Recommendation "Verify that the account used for analysis has appropriate permissions to view Power Platform environments."
            return $findings
        }
        
        Write-Log -Message "Found $($environments.Count) Power Platform environments" -Level Info
        
        # Load connector information for reference
        try {
            $connectors = Get-AdminPowerAppConnector -ErrorAction Stop
            
            # Cache connector details for later reference
            foreach ($connector in $connectors) {
                $script:ConnectorCache[$connector.ConnectorName] = $connector
            }
            
            Write-Log -Message "Cached information for $($connectors.Count) connectors" -Level Info
        }
        catch {
            Write-Log -Message "Error retrieving connector information: $($_.Exception.Message)" -Level Warning
        }
        
        # Define high-risk connectors
        $highRiskConnectors = @(
            "microsoftflowforadmins",
            "office365users",
            "office365groups",
            "azuread",
            "mscrm",
            "sharepoint",
            "excelonlinebusiness",
            "onedriveforbusiness",
            "outlook",
            "teams",
            "powerplatformforadmins",
            "flow",
            "powerapps",
            "azureautomation",
            "azureloganalytics",
            "azureresourcemanager",
            "azurecognitiveservices",
            "keyvault",
            "http",
            "webhook",
            "ftp",
            "azureblobstorage",
            "azuredatalakestorage",
            "azurefunctions"
        )
        
        # Define suspicious trigger types
        $suspiciousTriggers = @(
            "HttpWebhook",
            "HttpTrigger",
            "Request",
            "ApiConnection",
            "ApiManagementOperation",
            "Button",
            "Manual"
        )
        
        # Process each environment
        foreach ($environment in $environments) {
            try {
                # Get flows in this environment
                $flows = Get-AdminFlow -EnvironmentName $environment.EnvironmentName -ErrorAction Stop
                
                if ($flows -and $flows.Count -gt 0) {
                    Write-Log -Message "Found $($flows.Count) flows in environment $($environment.DisplayName)" -Level Info
                    
                    # Limit analysis if too many flows
                    if ($flows.Count -gt $script:MaxItemsToAnalyze) {
                        Write-Log -Message "Limiting analysis to $script:MaxItemsToAnalyze flows out of $($flows.Count) total flows in environment $($environment.DisplayName)" -Level Warning
                        
                        # Prioritize based on creation date (most recent first)
                        $flowsToAnalyze = $flows | Sort-Object CreatedTime -Descending | Select-Object -First $script:MaxItemsToAnalyze
                    }
                    else {
                        $flowsToAnalyze = $flows
                    }
                    
                    # Analyze each flow
                    foreach ($flow in $flowsToAnalyze) {
                        try {
                            # Get detailed flow information
                            $flowDetails = Get-AdminFlow -FlowName $flow.FlowName -EnvironmentName $environment.EnvironmentName -ErrorAction Stop
                            
                            if ($flowDetails) {
                                $isSuspicious = $false
                                $reasons = @()
                                $severity = "Low"
                                
                                # Check if flow was recently created
                                if ($flowDetails.CreatedTime -ge $script:AnalysisStartDate) {
                                    $isSuspicious = $true
                                    $reasons += "Recently created ($(Get-Date $flowDetails.CreatedTime -Format 'yyyy-MM-dd'))"
                                }
                                
                                # Check if flow was recently modified
                                if ($flowDetails.LastModifiedTime -ge $script:AnalysisStartDate) {
                                    $isSuspicious = $true
                                    $reasons += "Recently modified ($(Get-Date $flowDetails.LastModifiedTime -Format 'yyyy-MM-dd'))"
                                }
                                
                                # Check display name for suspicious patterns
                                if ($flowDetails.DisplayName -match "^[a-zA-Z0-9]{16,}$" -or 
                                    $flowDetails.DisplayName -match "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$" -or
                                    [string]::IsNullOrWhiteSpace($flowDetails.DisplayName)) {
                                    $isSuspicious = $true
                                    $reasons += "Suspicious name pattern (random or GUID-like)"
                                    $severity = "Medium"
                                }
                                
                                # Check trigger type
                                if ($flowDetails.Triggers -and $flowDetails.Triggers.Count -gt 0) {
                                    foreach ($trigger in $flowDetails.Triggers) {
                                        $triggerType = $trigger.Type
                                        if ($triggerType -in $suspiciousTriggers) {
                                            $isSuspicious = $true
                                            $reasons += "Uses potentially risky trigger type: $triggerType"
                                            
                                            if ($triggerType -in @("HttpWebhook", "HttpTrigger", "Request")) {
                                                $severity = "High"
                                            }
                                        }
                                    }
                                }
                                
                                # Check connections used
                                if ($flowDetails.Connections -and $flowDetails.Connections.Count -gt 0) {
                                    $highRiskConnectionsUsed = @()
                                    foreach ($connection in $flowDetails.Connections) {
                                        if ($connection.ConnectorName -in $highRiskConnectors) {
                                            $highRiskConnectionsUsed += $connection.ConnectorName
                                        }
                                    }
                                    
                                    if ($highRiskConnectionsUsed.Count -gt 0) {
                                        $isSuspicious = $true
                                        $reasons += "Uses high-risk connectors: $($highRiskConnectionsUsed -join ', ')"
                                        
                                        if ($severity -ne "High") {
                                            $severity = "Medium"
                                        }
                                    }
                                    
                                    # Check for combinations of certain connectors that together could be extra risky
                                    $hasOffice365Connector = $highRiskConnectionsUsed -contains "office365users" -or 
                                                          $highRiskConnectionsUsed -contains "office365groups" -or
                                                          $highRiskConnectionsUsed -contains "outlook" -or
                                                          $highRiskConnectionsUsed -contains "sharepoint"
                                    
                                    $hasExternalConnector = $highRiskConnectionsUsed -contains "http" -or 
                                                         $highRiskConnectionsUsed -contains "webhook" -or
                                                         $highRiskConnectionsUsed -contains "ftp"
                                    
                                    if ($hasOffice365Connector -and $hasExternalConnector) {
                                        $reasons += "Combines Office 365 connectors with external connectors (potential data exfiltration)"
                                        $severity = "High"
                                    }
                                }
                                
                                # Report suspicious flows
                                if ($isSuspicious) {
                                    $findings += Add-Finding -Category "PowerAutomateFlows" -Title "Suspicious Power Automate flow detected" `
                                        -Severity $severity `
                                        -Description "Flow '$($flowDetails.DisplayName)' (ID: $($flowDetails.FlowName)) in environment '$($environment.DisplayName)' has suspicious characteristics. Reasons: $($reasons -join '; ')" `
                                        -Recommendation "Review this flow to verify it is legitimate, necessary, and appropriately secured." `
                                        -Data @{
                                            FlowName = $flowDetails.DisplayName
                                            FlowId = $flowDetails.FlowName
                                            State = $flowDetails.Statuses.Status
                                            EnvironmentName = $environment.DisplayName
                                            EnvironmentId = $environment.EnvironmentName
                                            CreatedBy = $flowDetails.CreatedBy.UserDisplayName
                                            CreatedTime = $flowDetails.CreatedTime
                                            LastModifiedTime = $flowDetails.LastModifiedTime
                                            Triggers = $flowDetails.Triggers | Select-Object Type, Kind
                                            Connections = $flowDetails.Connections | Select-Object ConnectorName, ConnectionName
                                            Reasons = $reasons
                                        }
                                }
                            }
                        }
                        catch {
                            Write-Log -Message "Error analyzing flow '$($flow.DisplayName)' in environment '$($environment.DisplayName)': $($_.Exception.Message)" -Level Warning
                        }
                    }
                }
                else {
                    Write-Log -Message "No flows found in environment $($environment.DisplayName)" -Level Info
                }
            }
            catch {
                Write-Log -Message "Error retrieving flows from environment '$($environment.DisplayName)': $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "PowerAutomateFlows" -Title "Error retrieving flows" `
                    -Severity "Low" `
                    -Description "An error occurred while retrieving flows from environment '$($environment.DisplayName)': $($_.Exception.Message)" `
                    -Recommendation "Manually investigate flows in this environment."
            }
        }
        
        Write-Log -Message "Completed Power Automate flow analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing Power Automate flows: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "PowerAutomateFlows" -Title "Error analyzing Power Automate flows" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing Power Automate flows: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of Power Automate flows is recommended."
    }
    
    return $findings
}

function Invoke-PowerAppsCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing Power Apps applications" -Level Info
        
        # Get all environments
        $environments = Get-AdminPowerAppEnvironment -ErrorAction Stop
        
        if (-not $environments -or $environments.Count -eq 0) {
            Write-Log -Message "No Power Platform environments found" -Level Warning
            return $findings
        }
        
        # Process each environment
        foreach ($environment in $environments) {
            try {
                # Get apps in this environment
                $apps = Get-AdminPowerApp -EnvironmentName $environment.EnvironmentName -ErrorAction Stop
                
                if ($apps -and $apps.Count -gt 0) {
                    Write-Log -Message "Found $($apps.Count) apps in environment $($environment.DisplayName)" -Level Info
                    
                    # Limit analysis if too many apps
                    if ($apps.Count -gt $script:MaxItemsToAnalyze) {
                        Write-Log -Message "Limiting analysis to $script:MaxItemsToAnalyze apps out of $($apps.Count) total apps in environment $($environment.DisplayName)" -Level Warning
                        
                        # Prioritize based on creation date (most recent first)
                        $appsToAnalyze = $apps | Sort-Object CreatedTime -Descending | Select-Object -First $script:MaxItemsToAnalyze
                    }
                    else {
                        $appsToAnalyze = $apps
                    }
                    
                    # Define high-risk connectors (same as for flows)
                    $highRiskConnectors = @(
                        "microsoftflowforadmins",
                        "office365users",
                        "office365groups",
                        "azuread",
                        "mscrm",
                        "sharepoint",
                        "excelonlinebusiness",
                        "onedriveforbusiness",
                        "outlook",
                        "teams",
                        "powerplatformforadmins",
                        "flow",
                        "powerapps",
                        "azureautomation",
                        "azureloganalytics",
                        "azureresourcemanager",
                        "azurecognitiveservices",
                        "keyvault",
                        "http",
                        "webhook",
                        "ftp",
                        "azureblobstorage",
                        "azuredatalakestorage",
                        "azurefunctions"
                    )
                    
                    # Analyze each app
                    foreach ($app in $appsToAnalyze) {
                        try {
                            # Get detailed app information
                            $appDetails = Get-AdminPowerApp -AppName $app.AppName -EnvironmentName $environment.EnvironmentName -ErrorAction Stop
                            
                            if ($appDetails) {
                                $isSuspicious = $false
                                $reasons = @()
                                $severity = "Low"
                                
                                # Check if app was recently created
                                if ($appDetails.CreatedTime -ge $script:AnalysisStartDate) {
                                    $isSuspicious = $true
                                    $reasons += "Recently created ($(Get-Date $appDetails.CreatedTime -Format 'yyyy-MM-dd'))"
                                }
                                
                                # Check if app was recently modified
                                if ($appDetails.LastModifiedTime -ge $script:AnalysisStartDate) {
                                    $isSuspicious = $true
                                    $reasons += "Recently modified ($(Get-Date $appDetails.LastModifiedTime -Format 'yyyy-MM-dd'))"
                                }
                                
                                # Check display name for suspicious patterns
                                if ($appDetails.DisplayName -match "^[a-zA-Z0-9]{16,}$" -or 
                                    $appDetails.DisplayName -match "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$" -or
                                    [string]::IsNullOrWhiteSpace($appDetails.DisplayName)) {
                                    $isSuspicious = $true
                                    $reasons += "Suspicious name pattern (random or GUID-like)"
                                    $severity = "Medium"
                                }
                                
                                # Check connections used
                                if ($appDetails.Connections -and $appDetails.Connections.Count -gt 0) {
                                    $highRiskConnectionsUsed = @()
                                    foreach ($connection in $appDetails.Connections) {
                                        if ($connection.ConnectorName -in $highRiskConnectors) {
                                            $highRiskConnectionsUsed += $connection.ConnectorName
                                        }
                                    }
                                    
                                    if ($highRiskConnectionsUsed.Count -gt 0) {
                                        $isSuspicious = $true
                                        $reasons += "Uses high-risk connectors: $($highRiskConnectionsUsed -join ', ')"
                                        
                                        if ($severity -ne "High") {
                                            $severity = "Medium"
                                        }
                                    }
                                    
                                    # Check for combinations of certain connectors that together could be extra risky
                                    $hasOffice365Connector = $highRiskConnectionsUsed -contains "office365users" -or 
                                                          $highRiskConnectionsUsed -contains "office365groups" -or
                                                          $highRiskConnectionsUsed -contains "outlook" -or
                                                          $highRiskConnectionsUsed -contains "sharepoint"
                                    
                                    $hasExternalConnector = $highRiskConnectionsUsed -contains "http" -or 
                                                         $highRiskConnectionsUsed -contains "webhook" -or
                                                         $highRiskConnectionsUsed -contains "ftp"
                                    
                                    if ($hasOffice365Connector -and $hasExternalConnector) {
                                        $reasons += "Combines Office 365 connectors with external connectors (potential data exfiltration)"
                                        $severity = "High"
                                    }
                                }
                                
                                # Check sharing settings - broadly shared apps with high-risk connectors are concerning
                                if ($appDetails.UserSharing -ne "NotShared") {
                                    if ($highRiskConnectionsUsed -and $highRiskConnectionsUsed.Count -gt 0) {
                                        $isSuspicious = $true
                                        $reasons += "Broadly shared app with high-risk connectors"
                                        
                                        if ($severity -ne "High") {
                                            $severity = "Medium"
                                        }
                                    }
                                }
                                
                                # Report suspicious apps
                                if ($isSuspicious) {
                                    $findings += Add-Finding -Category "PowerApps" -Title "Suspicious Power App detected" `
                                        -Severity $severity `
                                        -Description "App '$($appDetails.DisplayName)' (ID: $($appDetails.AppName)) in environment '$($environment.DisplayName)' has suspicious characteristics. Reasons: $($reasons -join '; ')" `
                                        -Recommendation "Review this app to verify it is legitimate, necessary, and appropriately secured." `
                                        -Data @{
                                            AppName = $appDetails.DisplayName
                                            AppId = $appDetails.AppName
                                            EnvironmentName = $environment.DisplayName
                                            EnvironmentId = $environment.EnvironmentName
                                            CreatedBy = $appDetails.Owner.displayName
                                            CreatedTime = $appDetails.CreatedTime
                                            LastModifiedTime = $appDetails.LastModifiedTime
                                            Connections = $appDetails.Connections | Select-Object ConnectorName, ConnectionName
                                            UserSharing = $appDetails.UserSharing
                                            Reasons = $reasons
                                        }
                                }
                            }
                        }
                        catch {
                            Write-Log -Message "Error analyzing app '$($app.DisplayName)' in environment '$($environment.DisplayName)': $($_.Exception.Message)" -Level Warning
                        }
                    }
                }
                else {
                    Write-Log -Message "No apps found in environment $($environment.DisplayName)" -Level Info
                }
            }
            catch {
                Write-Log -Message "Error retrieving apps from environment '$($environment.DisplayName)': $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "PowerApps" -Title "Error retrieving apps" `
                    -Severity "Low" `
                    -Description "An error occurred while retrieving apps from environment '$($environment.DisplayName)': $($_.Exception.Message)" `
                    -Recommendation "Manually investigate apps in this environment."
            }
        }
        
        Write-Log -Message "Completed Power Apps analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing Power Apps: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "PowerApps" -Title "Error analyzing Power Apps" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing Power Apps: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of Power Apps is recommended."
    }
    
    return $findings
}

function Invoke-CustomConnectorCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing custom connectors" -Level Info
        
        # Get all environments
        $environments = Get-AdminPowerAppEnvironment -ErrorAction Stop
        
        if (-not $environments -or $environments.Count -eq 0) {
            Write-Log -Message "No Power Platform environments found" -Level Warning
            return $findings
        }
        
        # Process each environment
        foreach ($environment in $environments) {
            try {
                # Get custom connectors in this environment
                $customConnectors = Get-AdminPowerAppConnector -EnvironmentName $environment.EnvironmentName | 
                                  Where-Object { $_.ConnectorType -eq "Custom" }
                
                if ($customConnectors -and $customConnectors.Count -gt 0) {
                    Write-Log -Message "Found $($customConnectors.Count) custom connectors in environment $($environment.DisplayName)" -Level Info
                    
                    # Analyze each custom connector
                    foreach ($connector in $customConnectors) {
                        try {
                            $isSuspicious = $false
                            $reasons = @()
                            $severity = "Medium"  # Custom connectors always start at Medium severity
                            
                            # Custom connectors are always somewhat suspicious since they can connect to arbitrary endpoints
                            $isSuspicious = $true
                            $reasons += "Custom connector can connect to external services"
                            
                            # Check if connector was recently created
                            if ($connector.CreatedTime -ge $script:AnalysisStartDate) {
                                $reasons += "Recently created ($(Get-Date $connector.CreatedTime -Format 'yyyy-MM-dd'))"
                            }
                            
                            # Check the endpoint URL if available
                            $endpointUrl = ""
                            if ($connector.ApiDefinitions -and $connector.ApiDefinitions.Properties -and $connector.ApiDefinitions.Properties.Host) {
                                $endpointUrl = $connector.ApiDefinitions.Properties.Host
                                
                                # Check for suspicious domains or IP addresses
                                if ($endpointUrl -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" -or  # IP address
                                    $endpointUrl -match "\.ngrok\.io$" -or  # Temporary tunnel services
                                    $endpointUrl -match "\.serveo\.net$" -or
                                    $endpointUrl -match "\.localtunnel\.me$" -or
                                    $endpointUrl -match "\.loca\.lt$" -or
                                    $endpointUrl -match "localhost" -or
                                    $endpointUrl -match "^[a-f0-9]{16,}\..*" -or  # Random subdomain
                                    $endpointUrl -match "^(?:ftp|sftp|ftps)://") {  # FTP services
                                    $reasons += "Connects to potentially suspicious endpoint: $endpointUrl"
                                    $severity = "High"
                                }
                            }
                            
                            # Report all custom connectors
                            $findings += Add-Finding -Category "CustomConnectors" -Title "Custom connector detected" `
                                -Severity $severity `
                                -Description "Custom connector '$($connector.DisplayName)' (ID: $($connector.ConnectorName)) in environment '$($environment.DisplayName)' could be used to connect to external services. Reasons: $($reasons -join '; ')" `
                                -Recommendation "Review this custom connector to verify it is legitimate, necessary, and connects to trusted endpoints." `
                                -Data @{
                                    ConnectorName = $connector.DisplayName
                                    ConnectorId = $connector.ConnectorName
                                    EnvironmentName = $environment.DisplayName
                                    EnvironmentId = $environment.EnvironmentName
                                    CreatedBy = $connector.CreatedBy.displayName
                                    CreatedTime = $connector.CreatedTime
                                    EndpointUrl = $endpointUrl
                                    Reasons = $reasons
                                }
                        }
                        catch {
                            Write-Log -Message "Error analyzing custom connector '$($connector.DisplayName)' in environment '$($environment.DisplayName)': $($_.Exception.Message)" -Level Warning
                        }
                    }
                }
                else {
                    Write-Log -Message "No custom connectors found in environment $($environment.DisplayName)" -Level Info
                }
            }
            catch {
                Write-Log -Message "Error retrieving custom connectors from environment '$($environment.DisplayName)': $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "CustomConnectors" -Title "Error retrieving custom connectors" `
                    -Severity "Low" `
                    -Description "An error occurred while retrieving custom connectors from environment '$($environment.DisplayName)': $($_.Exception.Message)" `
                    -Recommendation "Manually investigate custom connectors in this environment."
            }
        }
        
        Write-Log -Message "Completed custom connector analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing custom connectors: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "CustomConnectors" -Title "Error analyzing custom connectors" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing custom connectors: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of custom connectors is recommended."
    }
    
    return $findings
}

function Invoke-DataverseRoleCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing Dataverse security roles" -Level Info
        
        # Get all environments
        $environments = Get-AdminPowerAppEnvironment -ErrorAction Stop
        
        if (-not $environments -or $environments.Count -eq 0) {
            Write-Log -Message "No Power Platform environments found" -Level Warning
            return $findings
        }
        
        # Check for Dataverse environments (those with a database)
        $dataverseEnvironments = $environments | Where-Object { $_.EnvironmentType -eq "Sandbox" -or $_.EnvironmentType -eq "Production" }
        
        if (-not $dataverseEnvironments -or $dataverseEnvironments.Count -eq 0) {
            Write-Log -Message "No Dataverse environments found" -Level Info
            $findings += Add-Finding -Category "DataverseRoles" -Title "No Dataverse environments found" `
                -Severity "Informational" `
                -Description "No Dataverse environments were found in the tenant. This check is only applicable to environments with Dataverse databases." `
                -Recommendation "No action required. If you have Dataverse environments, verify that the account used for analysis has appropriate permissions."
            return $findings
        }
        
        # Note: Full security role analysis requires additional PowerShell modules or direct API calls
        # This is a simplified version that looks for admin and environment maker role assignments
        # For a complete analysis, consider using the Microsoft.Xrm.Data.PowerShell module
        
        # Look for environment admin assignments
        foreach ($environment in $dataverseEnvironments) {
            try {
                # Get environment roles
                $roles = Get-AdminPowerAppEnvironmentRoleAssignment -EnvironmentName $environment.EnvironmentName -ErrorAction Stop
                
                if ($roles -and $roles.Count -gt 0) {
                    # Filter to admin roles
                    $adminRoles = $roles | Where-Object { 
                        $_.RoleName -eq "EnvironmentAdmin" -or 
                        $_.RoleName -eq "SystemAdministrator" -or
                        $_.RoleName -eq "SystemCustomizer"
                    }
                    
                    foreach ($role in $adminRoles) {
                        $isSuspicious = $false
                        $reasons = @()
                        $severity = "Medium"
                        
                        # Check if recently assigned
                        # Note: Role assignment doesn't typically have creation date in the API
                        # This would need to be enhanced with audit log analysis
                        
                        # Check if assigned to suspicious principal
                        if ($role.PrincipalType -eq "Tenant") {
                            $isSuspicious = $true
                            $reasons += "Role assigned at tenant level (potentially overly broad)"
                            $severity = "High"
                        }
                        elseif ($role.PrincipalType -eq "Group") {
                            $isSuspicious = $true
                            $reasons += "Role assigned to a group (potentially overly broad)"
                        }
                        
                        # All admin role assignments are worth reporting
                        $findings += Add-Finding -Category "DataverseRoles" -Title "Dataverse administrative role assignment" `
                            -Severity $severity `
                            -Description "Role '$($role.RoleName)' is assigned to principal '$($role.PrincipalDisplayName)' (Type: $($role.PrincipalType)) in environment '$($environment.DisplayName)'. $($if ($reasons.Count -gt 0) { "Reasons for concern: $($reasons -join '; ')" } else { "Administrative roles provide significant control over the environment." })" `
                            -Recommendation "Review this role assignment to verify it is legitimate and necessary." `
                            -Data @{
                                EnvironmentName = $environment.DisplayName
                                EnvironmentId = $environment.EnvironmentName
                                RoleName = $role.RoleName
                                PrincipalDisplayName = $role.PrincipalDisplayName
                                PrincipalId = $role.PrincipalId
                                PrincipalType = $role.PrincipalType
                                Reasons = $reasons
                            }
                    }
                }
            }
            catch {
                Write-Log -Message "Error retrieving role assignments from environment '$($environment.DisplayName)': $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "DataverseRoles" -Title "Error retrieving Dataverse role assignments" `
                    -Severity "Low" `
                    -Description "An error occurred while retrieving role assignments from environment '$($environment.DisplayName)': $($_.Exception.Message)" `
                    -Recommendation "Manually investigate Dataverse security roles in this environment."
            }
        }
        
        Write-Log -Message "Completed Dataverse security role analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing Dataverse security roles: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "DataverseRoles" -Title "Error analyzing Dataverse security roles" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing Dataverse security roles: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of Dataverse security roles is recommended."
    }
    
    return $findings
}

function Invoke-DataLossPreventionCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing Data Loss Prevention policies" -Level Info
        
        # Get DLP policies
        $dlpPolicies = Get-AdminDlpPolicy -ErrorAction Stop
        
        if (-not $dlpPolicies -or $dlpPolicies.Count -eq 0) {
            Write-Log -Message "No Data Loss Prevention policies found" -Level Warning
            $findings += Add-Finding -Category "DataLossPrevention" -Title "No Data Loss Prevention policies found" `
                -Severity "Medium" `
                -Description "No Data Loss Prevention (DLP) policies were found in the tenant. DLP policies help prevent data exfiltration by controlling which connectors can be used together." `
                -Recommendation "Consider implementing DLP policies to prevent sensitive data from being shared with unauthorized external services."
            return $findings
        }
        
        # Define business and non-business connectors that should not mix
        $sensitiveBusinessConnectors = @(
            "office365users",
            "office365groups",
            "sharepoint",
            "onedriveforbusiness",
            "microsoftteams",
            "outlook",
            "excel",
            "azuread",
            "mscrm",
            "dynamics365"
        )
        
        $highRiskNonBusinessConnectors = @(
            "http",
            "webhook",
            "ftp",
            "sftp",
            "smtp",
            "twitter",
            "facebook",
            "dropbox",
            "box",
            "azureblobstorage",
            "azuredatalakestorage"
        )
        
        # Analyze each policy
        foreach ($policy in $dlpPolicies) {
            try {
                $isSuspicious = $false
                $reasons = @()
                $severity = "Low"
                
                # Check if policy was recently created or modified
                # Note: This information might not be directly available via the API
                
                # Check connector groups
                $businessGroupConnectors = @()
                $nonBusinessGroupConnectors = @()
                
                foreach ($group in $policy.Connectors) {
                    if ($group.Classification -eq "Business") {
                        $businessGroupConnectors += $group.Name
                    }
                    elseif ($group.Classification -eq "NonBusiness") {
                        $nonBusinessGroupConnectors += $group.Name
                    }
                }
                
                # Check for sensitive business connectors in non-business group
                $misclassifiedBusinessConnectors = $sensitiveBusinessConnectors | Where-Object { $_ -in $nonBusinessGroupConnectors }
                
                if ($misclassifiedBusinessConnectors -and $misclassifiedBusinessConnectors.Count -gt 0) {
                    $isSuspicious = $true
                    $reasons += "Sensitive business connectors ($($misclassifiedBusinessConnectors -join ', ')) are classified as non-business"
                    $severity = "High"
                }
                
                # Check for high-risk non-business connectors in business group
                $misclassifiedNonBusinessConnectors = $highRiskNonBusinessConnectors | Where-Object { $_ -in $businessGroupConnectors }
                
                if ($misclassifiedNonBusinessConnectors -and $misclassifiedNonBusinessConnectors.Count -gt 0) {
                    $isSuspicious = $true
                    $reasons += "High-risk non-business connectors ($($misclassifiedNonBusinessConnectors -join ', ')) are classified as business"
                    $severity = "High"
                }
                
                # Check if sensitive business and high-risk non-business connectors are in the same group
                $businessAndNonBusinessMixed = $false
                foreach ($group in $policy.Connectors) {
                    $groupConnectors = $group.Name
                    $hasSensitiveBusiness = $sensitiveBusinessConnectors | Where-Object { $_ -in $groupConnectors }
                    $hasHighRiskNonBusiness = $highRiskNonBusinessConnectors | Where-Object { $_ -in $groupConnectors }
                    
                    if ($hasSensitiveBusiness -and $hasHighRiskNonBusiness) {
                        $businessAndNonBusinessMixed = $true
                        break
                    }
                }
                
                if ($businessAndNonBusinessMixed) {
                    $isSuspicious = $true
                    $reasons += "Sensitive business connectors and high-risk non-business connectors are in the same group, allowing potential data exfiltration"
                    $severity = "High"
                }
                
                # Check environments
                $appliesDefault = $policy.DefaultConnectorPolicy -ne "NoConnectorsAllowed"
                
                # Report suspicious policies
                if ($isSuspicious) {
                    $findings += Add-Finding -Category "DataLossPrevention" -Title "Suspicious Data Loss Prevention policy" `
                        -Severity $severity `
                        -Description "DLP policy '$($policy.DisplayName)' (Type: $($policy.PolicyType)) has suspicious characteristics. Reasons: $($reasons -join '; ')" `
                        -Recommendation "Review this DLP policy to ensure it properly protects sensitive data from being exfiltrated to unauthorized external services." `
                        -Data @{
                            PolicyName = $policy.DisplayName
                            PolicyType = $policy.PolicyType
                            DefaultConnectorPolicy = $policy.DefaultConnectorPolicy
                            AppliesDefault = $appliesDefault
                            BusinessConnectors = $businessGroupConnectors
                            NonBusinessConnectors = $nonBusinessGroupConnectors
                            Reasons = $reasons
                        }
                }
                else {
                    # Report informational for all policies
                    $findings += Add-Finding -Category "DataLossPrevention" -Title "Data Loss Prevention policy" `
                        -Severity "Informational" `
                        -Description "DLP policy '$($policy.DisplayName)' (Type: $($policy.PolicyType)) defines connector classifications for data loss prevention." `
                        -Recommendation "Regularly review DLP policies to ensure they meet security requirements." `
                        -Data @{
                            PolicyName = $policy.DisplayName
                            PolicyType = $policy.PolicyType
                            DefaultConnectorPolicy = $policy.DefaultConnectorPolicy
                            AppliesDefault = $appliesDefault
                            BusinessConnectors = $businessGroupConnectors
                            NonBusinessConnectors = $nonBusinessGroupConnectors
                        }
                }
            }
            catch {
                Write-Log -Message "Error analyzing DLP policy '$($policy.DisplayName)': $($_.Exception.Message)" -Level Warning
            }
        }
        
        Write-Log -Message "Completed Data Loss Prevention policy analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing Data Loss Prevention policies: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "DataLossPrevention" -Title "Error analyzing Data Loss Prevention policies" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing Data Loss Prevention policies: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of Data Loss Prevention policies is recommended."
    }
    
    return $findings
}

# Export the module function
Export-ModuleMember -Function Start-PowerPlatformForensics

<#
.SYNOPSIS
    Cross-Service & Azure Integration Forensics Module for M365 Compromise Assessment
.DESCRIPTION
    This module performs detailed forensic analysis of cross-service integrations and
    Azure services connected to M365 to identify potential attacker persistence mechanisms
    following admin-level compromise.
.NOTES
    Author: Dragos Ruiu
    Version 2.0
    Requires: Az modules, Microsoft.Graph.Authentication, other service-specific modules
    License: MIT
#>

#Requires -Modules Az.Accounts, Az.Automation, Az.Resources, Microsoft.Graph.Authentication

function Start-CrossServiceForensics {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$DetailedLogging,
        
        [Parameter()]
        [ValidateSet("All", "AzureAutomation", "GraphSubscriptions", "AppProxy", 
                     "SecureScore", "ApiPermissions", "CustomEndpoints", "DlpPolicies", 
                     "AuditLogs", "SiemIntegration", "KeyVault")]
        [string[]]$Checks = @("All"),
        
        [Parameter()]
        [switch]$SkipExistingResults,
        
        [Parameter()]
        [int]$DaysToAnalyze = 30
    )
    
    begin {
        # Initialize logging
        $script:LogFile = Join-Path -Path $OutputPath -ChildPath "CrossServiceForensics_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $script:ResultPath = Join-Path -Path $OutputPath -ChildPath "Results"
        
        if (-not (Test-Path -Path $OutputPath)) {
            try {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created output directory: $OutputPath" -Level Info
            }
            catch {
                throw "Failed to create output directory: $($_.Exception.Message)"
            }
        }
        
        if (-not (Test-Path -Path $script:ResultPath)) {
            try {
                New-Item -Path $script:ResultPath -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created results directory: $script:ResultPath" -Level Info
            }
            catch {
                throw "Failed to create results directory: $($_.Exception.Message)"
            }
        }
        
        # Script-level variables
        $script:DetailedLogging = $DetailedLogging
        $script:AllFindings = @()
        $script:DaysToAnalyze = $DaysToAnalyze
        $script:AnalysisStartDate = (Get-Date).AddDays(-$DaysToAnalyze)
        $script:AzureConnected = $false
        $script:GraphConnected = $false
    }
    
    process {
        try {
            Write-Log -Message "Starting Cross-Service & Azure Integration Forensics analysis" -Level Info
            
            # Determine which checks to run
            $checksToRun = @()
            if ($Checks -contains "All") {
                $checksToRun = @("AzureAutomation", "GraphSubscriptions", "AppProxy", 
                               "SecureScore", "ApiPermissions", "CustomEndpoints", "DlpPolicies", 
                               "AuditLogs", "SiemIntegration", "KeyVault")
            }
            else {
                $checksToRun = $Checks
            }
            
            # Run selected checks
            foreach ($check in $checksToRun) {
                $checkResultPath = Join-Path -Path $script:ResultPath -ChildPath "CrossService_$check.json"
                
                if ($SkipExistingResults -and (Test-Path -Path $checkResultPath)) {
                    Write-Log -Message "Skipping $check check as results already exist" -Level Info
                    continue
                }
                
                Write-Log -Message "Running $check check" -Level Info
                
                switch ($check) {
                    "AzureAutomation" { 
                        $findings = Invoke-AzureAutomationCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "GraphSubscriptions" { 
                        $findings = Invoke-GraphSubscriptionCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "AppProxy" { 
                        $findings = Invoke-AppProxyCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "SecureScore" { 
                        $findings = Invoke-SecureScoreCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "ApiPermissions" { 
                        $findings = Invoke-ApiPermissionCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "CustomEndpoints" { 
                        $findings = Invoke-CustomEndpointCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "DlpPolicies" { 
                        $findings = Invoke-DlpPolicyCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "AuditLogs" { 
                        $findings = Invoke-AuditLogCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "SiemIntegration" { 
                        $findings = Invoke-SiemIntegrationCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                    "KeyVault" { 
                        $findings = Invoke-KeyVaultCheck
                        Export-FindingsToJson -Findings $findings -FilePath $checkResultPath
                    }
                }
            }
            
            # Generate summary report
            $summaryPath = Join-Path -Path $OutputPath -ChildPath "CrossServiceForensics_Summary.json"
            Export-FindingsToJson -Findings $script:AllFindings -FilePath $summaryPath
            
            Write-Log -Message "Cross-Service & Azure Integration Forensics analysis completed successfully" -Level Info
        }
        catch {
            Write-Log -Message "Error during Cross-Service & Azure Integration Forensics analysis: $($_.Exception.Message)" -Level Error
            Write-Log -Message "Stack Trace: $($_.ScriptStackTrace)" -Level Error
            throw "Cross-Service & Azure Integration Forensics analysis failed: $($_.Exception.Message)"
        }
        finally {
            # Disconnect from services
            if ($script:AzureConnected) {
                Disconnect-AzAccount -ErrorAction SilentlyContinue
            }
            
            if ($script:GraphConnected) {
                Disconnect-MgGraph -ErrorAction SilentlyContinue
            }
        }
    }
    
    end {
        Write-Log -Message "Cross-Service & Azure Integration Forensics analysis finished" -Level Info
    }
}

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("Info", "Warning", "Error", "Debug")]
        [string]$Level = "Info"
    )
    
    # Only log debug messages if detailed logging is enabled
    if ($Level -eq "Debug" -and -not $script:DetailedLogging) {
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Output to console based on level
    switch ($Level) {
        "Info" { Write-Host $logMessage }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Debug" { Write-Host $logMessage -ForegroundColor Cyan }
    }
    
    # Write to log file
    Add-Content -Path $script:LogFile -Value $logMessage
}

function Export-FindingsToJson {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Findings,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        $Findings | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding utf8 -Force
        Write-Log -Message "Exported findings to $FilePath" -Level Info
        
        # Add to master findings list
        $script:AllFindings += $Findings
    }
    catch {
        Write-Log -Message "Error exporting findings to $FilePath : $($_.Exception.Message)" -Level Error
    }
}

function Add-Finding {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("High", "Medium", "Low", "Informational")]
        [string]$Severity,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter()]
        [string]$Recommendation,
        
        [Parameter()]
        [PSObject]$Data,
        
        [Parameter()]
        [DateTime]$Timestamp = (Get-Date)
    )
    
    $finding = [PSCustomObject]@{
        Category = $Category
        Title = $Title
        Severity = $Severity
        Description = $Description
        Recommendation = $Recommendation
        Data = $Data
        Timestamp = $Timestamp
        Id = [Guid]::NewGuid().ToString()
    }
    
    return $finding
}

function Invoke-AzureAutomationCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing Azure Automation accounts and runbooks" -Level Info
        
        # Connect to Azure if not already connected
        if (-not $script:AzureConnected) {
            try {
                # Check if already connected
                $context = Get-AzContext -ErrorAction SilentlyContinue
                
                if (-not $context) {
                    # Connect interactively
                    Connect-AzAccount -ErrorAction Stop
                }
                
                $script:AzureConnected = $true
                Write-Log -Message "Successfully connected to Azure" -Level Info
            }
            catch {
                Write-Log -Message "Failed to connect to Azure: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "AzureAutomation" -Title "Failed to connect to Azure" `
                    -Severity "Medium" `
                    -Description "Failed to connect to Azure to check Automation accounts: $($_.Exception.Message)" `
                    -Recommendation "Verify Azure access permissions and manually investigate Automation accounts."
                return $findings
            }
        }
        
        # Get all Azure subscriptions
        $subscriptions = Get-AzSubscription -ErrorAction Stop
        
        if (-not $subscriptions -or $subscriptions.Count -eq 0) {
            Write-Log -Message "No Azure subscriptions found" -Level Warning
            $findings += Add-Finding -Category "AzureAutomation" -Title "No Azure subscriptions found" `
                -Severity "Low" `
                -Description "No Azure subscriptions were found. Either no subscriptions exist or the account does not have access to any subscriptions." `
                -Recommendation "Verify Azure access permissions and manually investigate Automation accounts if subscriptions should exist."
            return $findings
        }
        
        Write-Log -Message "Found $($subscriptions.Count) Azure subscriptions" -Level Info
        
        # Process each subscription
        foreach ($subscription in $subscriptions) {
            try {
                # Set the current subscription context
                Set-AzContext -Subscription $subscription.Id -ErrorAction Stop | Out-Null
                
                Write-Log -Message "Checking subscription: $($subscription.Name) ($($subscription.Id))" -Level Info
                
                # Get Automation accounts in the subscription
                $automationAccounts = Get-AzAutomationAccount -ErrorAction Stop
                
                if ($automationAccounts -and $automationAccounts.Count -gt 0) {
                    Write-Log -Message "Found $($automationAccounts.Count) Automation accounts in subscription $($subscription.Name)" -Level Info
                    
                    # Analyze each Automation account
                    foreach ($account in $automationAccounts) {
                        try {
                            # Get runbooks in the Automation account
                            $runbooks = Get-AzAutomationRunbook -AutomationAccountName $account.AutomationAccountName -ResourceGroupName $account.ResourceGroupName -ErrorAction Stop
                            
                            if ($runbooks -and $runbooks.Count -gt 0) {
                                Write-Log -Message "Found $($runbooks.Count) runbooks in Automation account $($account.AutomationAccountName)" -Level Info
                                
                                # Check for recently created or modified runbooks
                                $recentRunbooks = $runbooks | Where-Object { 
                                    $_.LastModifiedTime -ge $script:AnalysisStartDate -or 
                                    $_.CreationTime -ge $script:AnalysisStartDate 
                                }
                                
                                if ($recentRunbooks -and $recentRunbooks.Count -gt 0) {
                                    foreach ($runbook in $recentRunbooks) {
                                        $eventType = if ($runbook.CreationTime -ge $script:AnalysisStartDate) { "Created" } else { "Modified" }
                                        $eventDate = if ($runbook.CreationTime -ge $script:AnalysisStartDate) { $runbook.CreationTime } else { $runbook.LastModifiedTime }
                                        
                                        # Determine severity based on runbook type
                                        $severity = switch ($runbook.RunbookType) {
                                            "PowerShell" { "High" }
                                            "PowerShellWorkflow" { "High" }
                                            "Python" { "High" }
                                            default { "Medium" }
                                        }
                                        
                                        $findings += Add-Finding -Category "AzureAutomation" -Title "Recently $eventType Azure Automation runbook" `
                                            -Severity $severity `
                                            -Description "Runbook '$($runbook.Name)' of type '$($runbook.RunbookType)' in Automation account '$($account.AutomationAccountName)' was $($eventType.ToLower()) on $(Get-Date $eventDate -Format 'yyyy-MM-dd'). Automation runbooks can be used to perform administrative actions on Azure and Microsoft 365 resources." `
                                            -Recommendation "Review this runbook's content and execution history to verify it is legitimate and performing expected actions." `
                                            -Data @{
                                                SubscriptionId = $subscription.Id
                                                SubscriptionName = $subscription.Name
                                                AutomationAccountName = $account.AutomationAccountName
                                                ResourceGroupName = $account.ResourceGroupName
                                                RunbookName = $runbook.Name
                                                RunbookType = $runbook.RunbookType
                                                State = $runbook.State
                                                CreationTime = $runbook.CreationTime
                                                LastModifiedTime = $runbook.LastModifiedTime
                                                EventType = $eventType
                                            }
                                        
                                        # Get runbook content for further analysis
                                        try {
                                            $content = Export-AzAutomationRunbook -AutomationAccountName $account.AutomationAccountName `
                                                -ResourceGroupName $account.ResourceGroupName `
                                                -Name $runbook.Name `
                                                -OutputFolder (Join-Path -Path $env:TEMP -ChildPath ([Guid]::NewGuid().ToString())) `
                                                -ErrorAction Stop
                                            
                                            if ($content) {
                                                # Simple content analysis for suspicious patterns
                                                $content = Get-Content -Path $content -Raw -ErrorAction SilentlyContinue
                                                
                                                if ($content) {
                                                    $suspiciousPatterns = @(
                                                        'Invoke-Expression', 'IEX',
                                                        'Net.WebClient', 'DownloadString',
                                                        'DownloadFile', 'Start-BitsTransfer',
                                                        'ConvertFrom-Base64', 'FromBase64String',
                                                        'SecretManagement', 'KeyVault', 'Secret',
                                                        'Add-MsolRoleMember', 'New-MsolUser',
                                                        'Add-AzRoleAssignment', 'Connect-MgGraph',
                                                        'Connect-AzAccount', 'Connect-MsolService',
                                                        'Invoke-WebRequest', 'New-Service',
                                                        'Start-Process', 'Start-Job',
                                                        'Hidden', 'Encoded'
                                                    )
                                                    
                                                    $matchedPatterns = @()
                                                    foreach ($pattern in $suspiciousPatterns) {
                                                        if ($content -match $pattern) {
                                                            $matchedPatterns += $pattern
                                                        }
                                                    }
                                                    
                                                    if ($matchedPatterns.Count -gt 0) {
                                                        $findings += Add-Finding -Category "AzureAutomation" -Title "Suspicious code patterns in Automation runbook" `
                                                            -Severity "High" `
                                                            -Description "Runbook '$($runbook.Name)' in Automation account '$($account.AutomationAccountName)' contains potentially suspicious code patterns: $($matchedPatterns -join ', '). These patterns may indicate malicious activity." `
                                                            -Recommendation "Carefully review this runbook's code to verify it is not performing unauthorized or malicious actions." `
                                                            -Data @{
                                                                SubscriptionId = $subscription.Id
                                                                SubscriptionName = $subscription.Name
                                                                AutomationAccountName = $account.AutomationAccountName
                                                                ResourceGroupName = $account.ResourceGroupName
                                                                RunbookName = $runbook.Name
                                                                RunbookType = $runbook.RunbookType
                                                                SuspiciousPatterns = $matchedPatterns
                                                                # Don't include the full content as it might be sensitive
                                                            }
                                                    }
                                                }
                                            }
                                        }
                                        catch {
                                            Write-Log -Message "Error analyzing content of runbook '$($runbook.Name)': $($_.Exception.Message)" -Level Warning
                                        }
                                    }
                                }
                                
                                # Check for webhooks associated with runbooks
                                foreach ($runbook in $runbooks) {
                                    try {
                                        $webhooks = Get-AzAutomationWebhook -AutomationAccountName $account.AutomationAccountName `
                                            -ResourceGroupName $account.ResourceGroupName `
                                            -RunbookName $runbook.Name `
                                            -ErrorAction Stop
                                        
                                        if ($webhooks -and $webhooks.Count -gt 0) {
                                            # Check for active webhooks
                                            $activeWebhooks = $webhooks | Where-Object { $_.IsEnabled -eq $true }
                                            
                                            if ($activeWebhooks -and $activeWebhooks.Count -gt 0) {
                                                foreach ($webhook in $activeWebhooks) {
                                                    # Determine if the webhook was recently created
                                                    $isRecent = $webhook.CreationTime -ge $script:AnalysisStartDate
                                                    $severity = if ($isRecent) { "High" } else { "Medium" }
                                                    
                                                    $findings += Add-Finding -Category "AzureAutomation" -Title "Active webhook for Automation runbook" `
                                                        -Severity $severity `
                                                        -Description "Runbook '$($runbook.Name)' in Automation account '$($account.AutomationAccountName)' has an active webhook '$($webhook.Name)' created on $(Get-Date $webhook.CreationTime -Format 'yyyy-MM-dd'). Webhooks allow anonymous triggering of runbooks from external sources." `
                                                        -Recommendation "Verify that this webhook is legitimate and secured appropriately. Consider implementing additional authentication mechanisms if possible." `
                                                        -Data @{
                                                            SubscriptionId = $subscription.Id
                                                            SubscriptionName = $subscription.Name
                                                            AutomationAccountName = $account.AutomationAccountName
                                                            ResourceGroupName = $account.ResourceGroupName
                                                            RunbookName = $runbook.Name
                                                            WebhookName = $webhook.Name
                                                            IsEnabled = $webhook.IsEnabled
                                                            CreationTime = $webhook.CreationTime
                                                            ExpiryTime = $webhook.ExpiryTime
                                                            LastInvokedTime = $webhook.LastInvokedTime
                                                            IsRecent = $isRecent
                                                        }
                                                }
                                            }
                                        }
                                    }
                                    catch {
                                        Write-Log -Message "Error checking webhooks for runbook '$($runbook.Name)': $($_.Exception.Message)" -Level Warning
                                    }
                                }
                            }
                            
                            # Check Automation account credentials and connections
                            try {
                                # Get credentials
                                $credentials = Get-AzAutomationCredential -AutomationAccountName $account.AutomationAccountName `
                                    -ResourceGroupName $account.ResourceGroupName `
                                    -ErrorAction Stop
                                
                                if ($credentials -and $credentials.Count -gt 0) {
                                    # Check for recently created credentials
                                    $recentCredentials = $credentials | Where-Object { $_.CreationTime -ge $script:AnalysisStartDate }
                                    
                                    if ($recentCredentials -and $recentCredentials.Count -gt 0) {
                                        foreach ($credential in $recentCredentials) {
                                            $findings += Add-Finding -Category "AzureAutomation" -Title "Recently created Automation credential" `
                                                -Severity "Medium" `
                                                -Description "Credential '$($credential.Name)' in Automation account '$($account.AutomationAccountName)' was created on $(Get-Date $credential.CreationTime -Format 'yyyy-MM-dd'). Automation credentials can be used by runbooks to authenticate to other services." `
                                                -Recommendation "Verify that this credential is legitimate and necessary for authorized automation tasks." `
                                                -Data @{
                                                    SubscriptionId = $subscription.Id
                                                    SubscriptionName = $subscription.Name
                                                    AutomationAccountName = $account.AutomationAccountName
                                                    ResourceGroupName = $account.ResourceGroupName
                                                    CredentialName = $credential.Name
                                                    CreationTime = $credential.CreationTime
                                                    LastModifiedTime = $credential.LastModifiedTime
                                                    UserName = $credential.UserName
                                                }
                                        }
                                    }
                                }
                            }
                            catch {
                                Write-Log -Message "Error checking credentials in Automation account '$($account.AutomationAccountName)': $($_.Exception.Message)" -Level Warning
                            }
                            
                            # Check Run As accounts (service principals)
                            try {
                                $certificates = Get-AzAutomationCertificate -AutomationAccountName $account.AutomationAccountName `
                                    -ResourceGroupName $account.ResourceGroupName `
                                    -ErrorAction Stop
                                
                                if ($certificates -and $certificates.Count -gt 0) {
                                    $runAsCertificates = $certificates | Where-Object { $_.Name -like "*RunAs*" }
                                    
                                    if ($runAsCertificates -and $runAsCertificates.Count -gt 0) {
                                        foreach ($cert in $runAsCertificates) {
                                            $findings += Add-Finding -Category "AzureAutomation" -Title "Automation Run As account certificate" `
                                                -Severity "Medium" `
                                                -Description "Certificate '$($cert.Name)' in Automation account '$($account.AutomationAccountName)' appears to be a Run As account certificate created on $(Get-Date $cert.CreationTime -Format 'yyyy-MM-dd'). Run As accounts are service principals that can be used by runbooks to authenticate to Azure." `
                                                -Recommendation "Verify that this Run As account is legitimate and has appropriate permissions (principle of least privilege)." `
                                                -Data @{
                                                    SubscriptionId = $subscription.Id
                                                    SubscriptionName = $subscription.Name
                                                    AutomationAccountName = $account.AutomationAccountName
                                                    ResourceGroupName = $account.ResourceGroupName
                                                    CertificateName = $cert.Name
                                                    CreationTime = $cert.CreationTime
                                                    LastModifiedTime = $cert.LastModifiedTime
                                                    ExpiryTime = $cert.ExpiryTime
                                                }
                                        }
                                    }
                                }
                            }
                            catch {
                                Write-Log -Message "Error checking certificates in Automation account '$($account.AutomationAccountName)': $($_.Exception.Message)" -Level Warning
                            }
                        }
                        catch {
                            Write-Log -Message "Error analyzing Automation account '$($account.AutomationAccountName)': $($_.Exception.Message)" -Level Warning
                            $findings += Add-Finding -Category "AzureAutomation" -Title "Error analyzing Automation account" `
                                -Severity "Low" `
                                -Description "An error occurred while analyzing Automation account '$($account.AutomationAccountName)' in subscription '$($subscription.Name)': $($_.Exception.Message)" `
                                -Recommendation "Manually investigate this Automation account for suspicious runbooks, webhooks, or credentials."
                        }
                    }
                }
                else {
                    Write-Log -Message "No Automation accounts found in subscription $($subscription.Name)" -Level Info
                }
            }
            catch {
                Write-Log -Message "Error checking subscription '$($subscription.Name)': $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "AzureAutomation" -Title "Error checking subscription" `
                    -Severity "Low" `
                    -Description "An error occurred while checking subscription '$($subscription.Name)' for Automation accounts: $($_.Exception.Message)" `
                    -Recommendation "Verify access permissions and manually investigate Automation accounts in this subscription."
            }
        }
        
        Write-Log -Message "Completed Azure Automation analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing Azure Automation accounts and runbooks: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "AzureAutomation" -Title "Error analyzing Azure Automation accounts and runbooks" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing Azure Automation accounts and runbooks: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of Azure Automation accounts and runbooks is recommended."
    }
    
    return $findings
}

function Invoke-GraphSubscriptionCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing Microsoft Graph API subscriptions" -Level Info
        
        # Connect to Microsoft Graph if not already connected
        if (-not $script:GraphConnected) {
            try {
                # Check if already connected
                $context = Get-MgContext -ErrorAction SilentlyContinue
                
                if (-not $context) {
                    # Connect with required scopes
                    $scopes = @(
                        "Directory.Read.All",
                        "Application.Read.All"
                    )
                    
                    Connect-MgGraph -Scopes $scopes -ErrorAction Stop
                }
                
                $context = Get-MgContext
                if (-not $context) {
                    throw "Failed to establish Microsoft Graph connection"
                }
                
                $script:GraphConnected = $true
                Write-Log -Message "Successfully connected to Microsoft Graph" -Level Info
            }
            catch {
                Write-Log -Message "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "GraphSubscriptions" -Title "Failed to connect to Microsoft Graph" `
                    -Severity "Medium" `
                    -Description "Failed to connect to Microsoft Graph to check API subscriptions: $($_.Exception.Message)" `
                    -Recommendation "Verify Graph API permissions and manually investigate Graph API subscriptions."
                return $findings
            }
        }
        
        # Check if we can access the subscriptions
        try {
            # Graph API subscriptions can be accessed through the beta endpoint
            # This requires specialized permissions and might not be available in all contexts
            $subscriptions = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/subscriptions' -ErrorAction Stop
            
            if ($subscriptions -and $subscriptions.value) {
                Write-Log -Message "Found $($subscriptions.value.Count) Graph API subscriptions" -Level Info
                
                foreach ($subscription in $subscriptions.value) {
                    $isSuspicious = $false
                    $reasons = @()
                    $severity = "Medium"
                    
                    # Check if recently created
                    if ($subscription.createdDateTime -and [DateTime]$subscription.createdDateTime -ge $script:AnalysisStartDate) {
                        $isSuspicious = $true
                        $reasons += "Recently created ($(Get-Date ([DateTime]$subscription.createdDateTime) -Format 'yyyy-MM-dd'))"
                    }
                    
                    # Check notification URL for suspicious patterns
                    if ($subscription.notificationUrl) {
                        $url = $subscription.notificationUrl
                        
                        # Check for suspicious URLs
                        if ($url -match "ngrok\.io" -or 
                            $url -match "tunnel\.me" -or 
                            $url -match "serveo\.net" -or
                            $url -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" -or  # IP address
                            $url -match "^https?://[a-z0-9]{16,}\..*" -or  # Random subdomain
                            $url -match "\.onion\.") {  # Tor network
                            $isSuspicious = $true
                            $reasons += "Suspicious notification URL: $url"
                            $severity = "High"
                        }
                    }
                    
                    # Check resource types being monitored
                    if ($subscription.resource) {
                        $resource = $subscription.resource
                        
                        # High-risk resources to monitor
                        $highRiskResources = @(
                            "users", "groups", "directoryRoles", "roleManagement",
                            "servicePrincipals", "applications", "devices", "auditLogs"
                        )
                        
                        foreach ($highRiskResource in $highRiskResources) {
                            if ($resource -like "*/$highRiskResource*") {
                                $isSuspicious = $true
                                $reasons += "Monitors sensitive resource: $highRiskResource"
                                
                                if ($highRiskResource -in @("users", "directoryRoles", "roleManagement")) {
                                    $severity = "High"
                                }
                            }
                        }
                    }
                    
                    # Check for application owner
                    $appId = $subscription.applicationId
                    if ($appId) {
                        try {
                            $app = Get-MgApplication -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
                            if ($app) {
                                $appName = $app.DisplayName
                                
                                # Further investigation of the app could be done here
                            }
                            else {
                                $appName = "Unknown application"
                                $isSuspicious = $true
                                $reasons += "Application not found in directory"
                                $severity = "High"
                            }
                        }
                        catch {
                            $appName = "Error retrieving application"
                            Write-Log -Message "Error retrieving application info for $appId: $($_.Exception.Message)" -Level Warning
                        }
                    }
                    else {
                        $appName = "No application ID"
                    }
                    
                    # Report findings
                    $finding = Add-Finding -Category "GraphSubscriptions" -Title "Graph API subscription detected" `
                        -Severity $severity `
                        -Description "Microsoft Graph API subscription '$($subscription.id)' for resource '$($subscription.resource)' sends notifications to '$($subscription.notificationUrl)'. Created by application '$appName'. $($if ($reasons.Count -gt 0) { "Suspicious characteristics: $($reasons -join '; ')" })" `
                        -Recommendation "Review this Graph API subscription to verify it is legitimate and necessary. If unknown, consider removing it immediately." `
                        -Data @{
                            SubscriptionId = $subscription.id
                            Resource = $subscription.resource
                            NotificationUrl = $subscription.notificationUrl
                            ApplicationId = $subscription.applicationId
                            ApplicationName = $appName
                            CreatedDateTime = $subscription.createdDateTime
                            ExpirationDateTime = $subscription.expirationDateTime
                            IsSuspicious = $isSuspicious
                            Reasons = $reasons
                        }
                    
                    $findings += $finding
                }
            }
            else {
                Write-Log -Message "No Graph API subscriptions found" -Level Info
                $findings += Add-Finding -Category "GraphSubscriptions" -Title "No Graph API subscriptions found" `
                    -Severity "Informational" `
                    -Description "No Microsoft Graph API subscriptions were found in the tenant." `
                    -Recommendation "This is informational only. Graph API subscriptions are used by applications to receive notifications about changes to resources."
            }
        }
        catch {
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Permission*") {
                Write-Log -Message "Insufficient permissions to access Graph API subscriptions: $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "GraphSubscriptions" -Title "Insufficient permissions to access Graph API subscriptions" `
                    -Severity "Medium" `
                    -Description "Unable to check Microsoft Graph API subscriptions due to insufficient permissions: $($_.Exception.Message)" `
                    -Recommendation "Review Graph API permissions or use an account with higher privileges to check for suspicious subscriptions."
            }
            else {
                Write-Log -Message "Error checking Graph API subscriptions: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "GraphSubscriptions" -Title "Error checking Graph API subscriptions" `
                    -Severity "Medium" `
                    -Description "An error occurred while checking Microsoft Graph API subscriptions: $($_.Exception.Message)" `
                    -Recommendation "Manual investigation of Graph API subscriptions is recommended."
            }
        }
        
        Write-Log -Message "Completed Graph API subscription analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing Microsoft Graph API subscriptions: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "GraphSubscriptions" -Title "Error analyzing Microsoft Graph API subscriptions" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing Microsoft Graph API subscriptions: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of Microsoft Graph API subscriptions is recommended."
    }
    
    return $findings
}

function Invoke-AppProxyCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing Azure AD Application Proxy configurations" -Level Info
        
        # Connect to Microsoft Graph if not already connected
        if (-not $script:GraphConnected) {
            try {
                # Check if already connected
                $context = Get-MgContext -ErrorAction SilentlyContinue
                
                if (-not $context) {
                    # Connect with required scopes
                    $scopes = @(
                        "Directory.Read.All",
                        "Application.Read.All"
                    )
                    
                    Connect-MgGraph -Scopes $scopes -ErrorAction Stop
                }
                
                $context = Get-MgContext
                if (-not $context) {
                    throw "Failed to establish Microsoft Graph connection"
                }
                
                $script:GraphConnected = $true
                Write-Log -Message "Successfully connected to Microsoft Graph" -Level Info
            }
            catch {
                Write-Log -Message "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "AppProxy" -Title "Failed to connect to Microsoft Graph" `
                    -Severity "Medium" `
                    -Description "Failed to connect to Microsoft Graph to check Application Proxy configurations: $($_.Exception.Message)" `
                    -Recommendation "Verify Graph API permissions and manually investigate Application Proxy configurations."
                return $findings
            }
        }
        
        # Get all service principals and filter for Application Proxy apps
        try {
            $servicePrincipals = Get-MgServicePrincipal -All -Filter "tags/any(t:t eq 'WindowsAzureActiveDirectoryOnPremApp')" -ErrorAction Stop
            
            if ($servicePrincipals -and $servicePrincipals.Count -gt 0) {
                Write-Log -Message "Found $($servicePrincipals.Count) Application Proxy applications" -Level Info
                
                foreach ($sp in $servicePrincipals) {
                    $isSuspicious = $false
                    $reasons = @()
                    $severity = "Medium"  # Start with medium for all App Proxy apps
                    
                    # Check if recently created
                    if ($sp.CreatedDateTime -ge $script:AnalysisStartDate) {
                        $isSuspicious = $true
                        $reasons += "Recently created ($(Get-Date $sp.CreatedDateTime -Format 'yyyy-MM-dd'))"
                    }
                    
                    # Get app proxy specific configuration
                    try {
                        $appProxyConfig = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($sp.Id)/appProxyApplication" -ErrorAction Stop
                        
                        if ($appProxyConfig) {
                            # Check pre-authentication type
                            if ($appProxyConfig.prerequiredApplicationProtocols -eq "none") {
                                $isSuspicious = $true
                                $reasons += "No pre-authentication configured"
                                $severity = "High"
                            }
                            elseif ($appProxyConfig.prerequiredApplicationProtocols -eq "passthrough") {
                                $isSuspicious = $true
                                $reasons += "Passthrough authentication configured"
                                $severity = "High"
                            }
                            
                            # Check internal URL for sensitive resources
                            if ($appProxyConfig.internalUrl) {
                                $internalUrl = $appProxyConfig.internalUrl.ToLower()
                                
                                $sensitivePatterns = @(
                                    "admin", "adfs", "exchange", "sql", "rdweb", "rdp", "gateway", 
                                    "console", "manage", "vpn", "login", "portal", "control", 
                                    "ssh", "database", "hr", "finance", "accounting"
                                )
                                
                                foreach ($pattern in $sensitivePatterns) {
                                    if ($internalUrl -like "*$pattern*") {
                                        $isSuspicious = $true
                                        $reasons += "Internal URL contains sensitive pattern: $pattern"
                                        
                                        if ($pattern -in @("admin", "adfs", "sql", "console", "manage")) {
                                            $severity = "High"
                                        }
                                        
                                        break
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-Log -Message "Error retrieving Application Proxy configuration for $($sp.DisplayName): $($_.Exception.Message)" -Level Warning
                    }
                    
                    # Check for external URL that may indicate sensitive exposure
                    $externalUrl = if ($appProxyConfig -and $appProxyConfig.externalUrl) { 
                        $appProxyConfig.externalUrl 
                    } 
                    else { 
                        "Unknown" 
                    }
                    
                    $internalUrl = if ($appProxyConfig -and $appProxyConfig.internalUrl) { 
                        $appProxyConfig.internalUrl 
                    } 
                    else { 
                        "Unknown" 
                    }
                    
                    $preAuth = if ($appProxyConfig -and $appProxyConfig.prerequiredApplicationProtocols) { 
                        $appProxyConfig.prerequiredApplicationProtocols 
                    } 
                    else { 
                        "Unknown" 
                    }
                    
                    $findings += Add-Finding -Category "AppProxy" -Title "Application Proxy application detected" `
                        -Severity $severity `
                        -Description "Azure AD Application Proxy application '$($sp.DisplayName)' (ID: $($sp.Id)) publishes internal application '$internalUrl' to external URL '$externalUrl'. Pre-authentication: $preAuth. $($if ($reasons.Count -gt 0) { "Suspicious characteristics: $($reasons -join '; ')" })" `
                        -Recommendation "Review this Application Proxy configuration to verify it is legitimate, necessary, and properly secured. Ensure pre-authentication is enabled for all but the most exceptional cases." `
                        -Data @{
                            AppDisplayName = $sp.DisplayName
                            AppId = $sp.Id
                            InternalUrl = $internalUrl
                            ExternalUrl = $externalUrl
                            PreAuthentication = $preAuth
                            CreatedDateTime = $sp.CreatedDateTime
                            IsSuspicious = $isSuspicious
                            Reasons = $reasons
                        }
                }
            }
            else {
                Write-Log -Message "No Application Proxy applications found" -Level Info
                $findings += Add-Finding -Category "AppProxy" -Title "No Application Proxy applications found" `
                    -Severity "Informational" `
                    -Description "No Azure AD Application Proxy applications were found in the tenant." `
                    -Recommendation "This is informational only. Application Proxy is used to publish internal applications for external access."
            }
        }
        catch {
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Permission*") {
                Write-Log -Message "Insufficient permissions to access Application Proxy configurations: $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "AppProxy" -Title "Insufficient permissions to access Application Proxy configurations" `
                    -Severity "Medium" `
                    -Description "Unable to check Azure AD Application Proxy configurations due to insufficient permissions: $($_.Exception.Message)" `
                    -Recommendation "Review Graph API permissions or use an account with higher privileges to check for suspicious Application Proxy configurations."
            }
            else {
                Write-Log -Message "Error checking Application Proxy configurations: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "AppProxy" -Title "Error checking Application Proxy configurations" `
                    -Severity "Medium" `
                    -Description "An error occurred while checking Azure AD Application Proxy configurations: $($_.Exception.Message)" `
                    -Recommendation "Manual investigation of Application Proxy configurations is recommended."
            }
        }
        
        Write-Log -Message "Completed Application Proxy configuration analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing Azure AD Application Proxy configurations: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "AppProxy" -Title "Error analyzing Azure AD Application Proxy configurations" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing Azure AD Application Proxy configurations: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of Azure AD Application Proxy configurations is recommended."
    }
    
    return $findings
}

function Invoke-SecureScoreCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing Microsoft Secure Score" -Level Info
        
        # Connect to Microsoft Graph if not already connected
        if (-not $script:GraphConnected) {
            try {
                # Check if already connected
                $context = Get-MgContext -ErrorAction SilentlyContinue
                
                if (-not $context) {
                    # Connect with required scopes
                    $scopes = @(
                        "Directory.Read.All",
                        "SecurityEvents.Read.All"
                    )
                    
                    Connect-MgGraph -Scopes $scopes -ErrorAction Stop
                }
                
                $context = Get-MgContext
                if (-not $context) {
                    throw "Failed to establish Microsoft Graph connection"
                }
                
                $script:GraphConnected = $true
                Write-Log -Message "Successfully connected to Microsoft Graph" -Level Info
            }
            catch {
                Write-Log -Message "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "SecureScore" -Title "Failed to connect to Microsoft Graph" `
                    -Severity "Medium" `
                    -Description "Failed to connect to Microsoft Graph to check Secure Score: $($_.Exception.Message)" `
                    -Recommendation "Verify Graph API permissions and manually investigate Secure Score."
                return $findings
            }
        }
        
        # Get current secure score
        try {
            $secureScore = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/security/secureScores?$top=1' -ErrorAction Stop
            
            if ($secureScore -and $secureScore.value -and $secureScore.value.Count -gt 0) {
                $currentScore = $secureScore.value[0]
                
                # Get historical data for comparison
                $historicalScores = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/security/secureScores?$top=90' -ErrorAction Stop
                
                if ($historicalScores -and $historicalScores.value -and $historicalScores.value.Count -gt 1) {
                    # Sort by date descending (most recent first)
                    $sortedScores = $historicalScores.value | 
                                  Sort-Object @{Expression = { [DateTime]$_.createdDateTime }; Descending = $true }
                    
                    # Get score from 30 days ago (or closest available)
                    $thirtyDaysAgo = (Get-Date).AddDays(-30)
                    $previousScore = $null
                    
                    foreach ($score in $sortedScores) {
                        $scoreDate = [DateTime]$score.createdDateTime
                        if ($scoreDate -lt $thirtyDaysAgo) {
                            $previousScore = $score
                            break
                        }
                    }
                    
                    # If we couldn't find a score 30 days ago, use the oldest available score
                    if (-not $previousScore -and $sortedScores.Count -gt 1) {
                        $previousScore = $sortedScores | 
                                      Sort-Object @{Expression = { [DateTime]$_.createdDateTime }; Descending = $false } | 
                                      Select-Object -First 1
                    }
                    
                    # Compare scores
                    if ($previousScore) {
                        $currentScoreValue = $currentScore.currentScore
                        $previousScoreValue = $previousScore.currentScore
                        $scoreDifference = $currentScoreValue - $previousScoreValue
                        
                        # Report significant decreases in score
                        if ($scoreDifference -lt -5) {
                            $findings += Add-Finding -Category "SecureScore" -Title "Significant decrease in Secure Score" `
                                -Severity "High" `
                                -Description "Microsoft Secure Score has decreased by $([Math]::Abs($scoreDifference)) points from $previousScoreValue to $currentScoreValue since $(Get-Date ([DateTime]$previousScore.createdDateTime) -Format 'yyyy-MM-dd'). This could indicate security controls have been disabled or weakened." `
                                -Recommendation "Review the Secure Score recommendations and changes made to security settings in the environment." `
                                -Data @{
                                    CurrentScore = $currentScoreValue
                                    PreviousScore = $previousScoreValue
                                    Difference = $scoreDifference
                                    CurrentDate = $currentScore.createdDateTime
                                    PreviousDate = $previousScore.createdDateTime
                                }
                        }
                        elseif ($scoreDifference -lt 0) {
                            $findings += Add-Finding -Category "SecureScore" -Title "Decrease in Secure Score" `
                                -Severity "Medium" `
                                -Description "Microsoft Secure Score has decreased by $([Math]::Abs($scoreDifference)) points from $previousScoreValue to $currentScoreValue since $(Get-Date ([DateTime]$previousScore.createdDateTime) -Format 'yyyy-MM-dd'). This might indicate security controls have been modified." `
                                -Recommendation "Review the Secure Score recommendations and changes made to security settings in the environment." `
                                -Data @{
                                    CurrentScore = $currentScoreValue
                                    PreviousScore = $previousScoreValue
                                    Difference = $scoreDifference
                                    CurrentDate = $currentScore.createdDateTime
                                    PreviousDate = $previousScore.createdDateTime
                                }
                        }
                        else {
                            $findings += Add-Finding -Category "SecureScore" -Title "No decrease in Secure Score" `
                                -Severity "Informational" `
                                -Description "Microsoft Secure Score is $currentScoreValue as of $(Get-Date ([DateTime]$currentScore.createdDateTime) -Format 'yyyy-MM-dd'), compared to $previousScoreValue on $(Get-Date ([DateTime]$previousScore.createdDateTime) -Format 'yyyy-MM-dd'). No significant decrease detected." `
                                -Recommendation "Continue monitoring Secure Score for changes." `
                                -Data @{
                                    CurrentScore = $currentScoreValue
                                    PreviousScore = $previousScoreValue
                                    Difference = $scoreDifference
                                    CurrentDate = $currentScore.createdDateTime
                                    PreviousDate = $previousScore.createdDateTime
                                }
                        }
                    }
                    else {
                        $findings += Add-Finding -Category "SecureScore" -Title "Insufficient historical Secure Score data" `
                            -Severity "Informational" `
                            -Description "Microsoft Secure Score is currently $($currentScore.currentScore), but insufficient historical data is available for comparison." `
                            -Recommendation "Continue monitoring Secure Score for changes." `
                            -Data @{
                                CurrentScore = $currentScore.currentScore
                                CurrentDate = $currentScore.createdDateTime
                            }
                    }
                }
                else {
                    $findings += Add-Finding -Category "SecureScore" -Title "Insufficient historical Secure Score data" `
                        -Severity "Informational" `
                        -Description "Microsoft Secure Score is currently $($currentScore.currentScore), but insufficient historical data is available for comparison." `
                        -Recommendation "Continue monitoring Secure Score for changes." `
                        -Data @{
                            CurrentScore = $currentScore.currentScore
                            CurrentDate = $currentScore.createdDateTime
                        }
                }
                
                # Get score controls
                try {
                    $scoreControls = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/security/secureScoreControls' -ErrorAction Stop
                    
                    if ($scoreControls -and $scoreControls.value) {
                        # Check for disabled controls that were previously enabled
                        $disabledControls = $scoreControls.value | Where-Object { $_.state -eq "Disabled" }
                        
                        if ($disabledControls -and $disabledControls.Count -gt 0) {
                            foreach ($control in $disabledControls) {
                                $findings += Add-Finding -Category "SecureScore" -Title "Disabled Secure Score control" `
                                    -Severity "Medium" `
                                    -Description "Secure Score control '$($control.title)' is currently disabled. This control could provide $($control.maxScore) points to your overall score." `
                                    -Recommendation "Review this control and consider enabling it to improve security posture." `
                                    -Data @{
                                        ControlName = $control.title
                                        ControlId = $control.id
                                        State = $control.state
                                        MaxScore = $control.maxScore
                                        Description = $control.description
                                    }
                            }
                        }
                        
                        # Check for critical controls with low implementation
                        $criticalControls = $scoreControls.value | Where-Object { 
                            $_.maxScore -ge 10 -and 
                            $_.implementationStatus -eq "thirdParty" -eq $false -and
                            $_.state -ne "Disabled"
                        }
                        
                        if ($criticalControls -and $criticalControls.Count -gt 0) {
                            foreach ($control in $criticalControls) {
                                if ($control.implementationStatus -eq "none" -or $control.percentageComplete -lt 50) {
                                    $findings += Add-Finding -Category "SecureScore" -Title "Critical Secure Score control not fully implemented" `
                                        -Severity "Medium" `
                                        -Description "Critical Secure Score control '$($control.title)' is not fully implemented ($(if($control.percentageComplete){"$($control.percentageComplete)%"}else{"0%"}) complete). This control could provide $($control.maxScore) points to your overall score." `
                                        -Recommendation "Review this control and consider implementing it to improve security posture." `
                                        -Data @{
                                            ControlName = $control.title
                                            ControlId = $control.id
                                            State = $control.state
                                            MaxScore = $control.maxScore
                                            PercentageComplete = $control.percentageComplete
                                            ImplementationStatus = $control.implementationStatus
                                            Description = $control.description
                                        }
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Log -Message "Error retrieving Secure Score controls: $($_.Exception.Message)" -Level Warning
                }
            }
            else {
                Write-Log -Message "No Secure Score data found" -Level Warning
                $findings += Add-Finding -Category "SecureScore" -Title "No Secure Score data found" `
                    -Severity "Low" `
                    -Description "No Microsoft Secure Score data was found. This could indicate a new tenant or an issue with the Secure Score service." `
                    -Recommendation "Verify that Secure Score is properly configured for your tenant."
            }
        }
        catch {
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Permission*") {
                Write-Log -Message "Insufficient permissions to access Secure Score: $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "SecureScore" -Title "Insufficient permissions to access Secure Score" `
                    -Severity "Medium" `
                    -Description "Unable to check Microsoft Secure Score due to insufficient permissions: $($_.Exception.Message)" `
                    -Recommendation "Review Graph API permissions or use an account with higher privileges to check Secure Score."
            }
            else {
                Write-Log -Message "Error checking Secure Score: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "SecureScore" -Title "Error checking Secure Score" `
                    -Severity "Medium" `
                    -Description "An error occurred while checking Microsoft Secure Score: $($_.Exception.Message)" `
                    -Recommendation "Manual investigation of Secure Score is recommended."
            }
        }
        
        Write-Log -Message "Completed Secure Score analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing Microsoft Secure Score: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "SecureScore" -Title "Error analyzing Microsoft Secure Score" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing Microsoft Secure Score: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of Microsoft Secure Score is recommended."
    }
    
    return $findings
}

function Invoke-ApiPermissionCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing API permission changes" -Level Info
        
        # Connect to Microsoft Graph if not already connected
        if (-not $script:GraphConnected) {
            try {
                # Check if already connected
                $context = Get-MgContext -ErrorAction SilentlyContinue
                
                if (-not $context) {
                    # Connect with required scopes
                    $scopes = @(
                        "Directory.Read.All",
                        "Application.Read.All",
                        "AuditLog.Read.All"
                    )
                    
                    Connect-MgGraph -Scopes $scopes -ErrorAction Stop
                }
                
                $context = Get-MgContext
                if (-not $context) {
                    throw "Failed to establish Microsoft Graph connection"
                }
                
                $script:GraphConnected = $true
                Write-Log -Message "Successfully connected to Microsoft Graph" -Level Info
            }
            catch {
                Write-Log -Message "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "ApiPermissions" -Title "Failed to connect to Microsoft Graph" `
                    -Severity "Medium" `
                    -Description "Failed to connect to Microsoft Graph to check API permission changes: $($_.Exception.Message)" `
                    -Recommendation "Verify Graph API permissions and manually investigate API permission changes."
                return $findings
            }
        }
        
        # Check audit logs for admin consent events
        try {
            # Construct filter for audit logs
            $startDate = $script:AnalysisStartDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
            $endDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
            $filter = "activityDateTime ge $startDate and activityDateTime le $endDate and (category eq 'ApplicationManagement' or category eq 'DelegatedPermissionGrant')"
            
            $auditLogs = Get-MgAuditLogDirectoryAudit -Filter $filter -All -ErrorAction Stop
            
            if ($auditLogs -and $auditLogs.Count -gt 0) {
                Write-Log -Message "Found $($auditLogs.Count) application management audit events" -Level Info
                
                # Filter for admin consent events
                $adminConsentEvents = $auditLogs | Where-Object { 
                    $_.ActivityDisplayName -like "*consent*" -or 
                    $_.ActivityDisplayName -like "*grant*" -or
                    $_.ActivityDisplayName -like "*permission*" -or
                    $_.ActivityDisplayName -like "*add service principal*" -or
                    $_.Category -eq "DelegatedPermissionGrant"
                }
                
                if ($adminConsentEvents -and $adminConsentEvents.Count -gt 0) {
                    Write-Log -Message "Found $($adminConsentEvents.Count) admin consent-related events" -Level Info
                    
                    foreach ($event in $adminConsentEvents) {
                        $isSuspicious = $false
                        $reasons = @()
                        $severity = "Medium"
                        
                        # Get app and permission details from the event
                        $appName = "Unknown"
                        $appId = "Unknown"
                        $permissions = @()
                        $initiatedBy = "Unknown"
                        
                        # Extract information from the event
                        if ($event.InitiatedBy -and $event.InitiatedBy.User) {
                            $initiatedBy = $event.InitiatedBy.User.UserPrincipalName
                        }
                        elseif ($event.InitiatedBy -and $event.InitiatedBy.App) {
                            $initiatedBy = $event.InitiatedBy.App.DisplayName
                            
                            # Application-initiated consent is unusual
                            $isSuspicious = $true
                            $reasons += "Consent initiated by an application"
                        }
                        
                        # Parse event properties
                        if ($event.TargetResources) {
                            foreach ($resource in $event.TargetResources) {
                                if ($resource.Type -eq "Application" -or $resource.Type -eq "ServicePrincipal") {
                                    $appName = $resource.DisplayName
                                    $appId = $resource.Id
                                }
                                
                                # Try to extract permissions from modified properties
                                if ($resource.ModifiedProperties) {
                                    foreach ($prop in $resource.ModifiedProperties) {
                                        if ($prop.DisplayName -like "*Permission*" -or $prop.DisplayName -like "*OAuth*" -or $prop.DisplayName -like "*Scope*") {
                                            $permissions += $prop.NewValue
                                        }
                                    }
                                }
                            }
                        }
                        
                        # Check if high-risk permissions were granted
                        $highRiskPermissions = @(
                            "Directory.Read", "Directory.ReadWrite", "Directory.AccessAsUser",
                            "Group.Read", "Group.ReadWrite",
                            "Mail.Read", "Mail.ReadWrite",
                            "Files.Read", "Files.ReadWrite",
                            "User.Read.All", "User.ReadWrite.All",
                            "Sites.Read.All", "Sites.ReadWrite.All",
                            "MailboxSettings", "Calendars",
                            "Contacts", "Notes", "full_access_as_app",
                            "Directory.Read.All", "Directory.ReadWrite.All"
                        )
                        
                        $hasHighRiskPermissions = $false
                        foreach ($perm in $permissions) {
                            foreach ($highRiskPerm in $highRiskPermissions) {
                                if ($perm -like "*$highRiskPerm*") {
                                    $hasHighRiskPermissions = $true
                                    $reasons += "High-risk permission granted: $highRiskPerm"
                                    $severity = "High"
                                    break
                                }
                            }
                            
                            if ($hasHighRiskPermissions) {
                                break
                            }
                        }
                        
                        # Report findings
                        $findings += Add-Finding -Category "ApiPermissions" -Title "API permission consent detected" `
                            -Severity $severity `
                            -Description "API permission consent was granted to application '$appName' (ID: $appId) by '$initiatedBy' on $(Get-Date $event.ActivityDateTime -Format 'yyyy-MM-dd'). $($if ($reasons.Count -gt 0) { "Suspicious characteristics: $($reasons -join '; ')" })" `
                            -Recommendation "Review this consent action to verify it was legitimate and the permissions granted are appropriate for the application's intended use." `
                            -Data @{
                                ApplicationName = $appName
                                ApplicationId = $appId
                                InitiatedBy = $initiatedBy
                                ActivityDateTime = $event.ActivityDateTime
                                ActivityDisplayName = $event.ActivityDisplayName
                                Permissions = $permissions
                                IsSuspicious = $isSuspicious
                                Reasons = $reasons
                            }
                    }
                }
                else {
                    Write-Log -Message "No admin consent events found during the analysis period" -Level Info
                    $findings += Add-Finding -Category "ApiPermissions" -Title "No admin consent events found" `
                        -Severity "Informational" `
                        -Description "No API permission consent events were found during the analysis period (last $script:DaysToAnalyze days)." `
                        -Recommendation "Continue monitoring for unauthorized API permission changes."
                }
            }
            else {
                Write-Log -Message "No application management audit events found during the analysis period" -Level Info
                $findings += Add-Finding -Category "ApiPermissions" -Title "No application management audit events found" `
                    -Severity "Informational" `
                    -Description "No application management audit events were found during the analysis period (last $script:DaysToAnalyze days)." `
                    -Recommendation "Continue monitoring for unauthorized API permission changes."
            }
        }
        catch {
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Permission*") {
                Write-Log -Message "Insufficient permissions to access audit logs: $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "ApiPermissions" -Title "Insufficient permissions to access audit logs" `
                    -Severity "Medium" `
                    -Description "Unable to check API permission changes in audit logs due to insufficient permissions: $($_.Exception.Message)" `
                    -Recommendation "Review Graph API permissions or use an account with higher privileges to check for API permission changes."
            }
            else {
                Write-Log -Message "Error checking audit logs for API permission changes: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "ApiPermissions" -Title "Error checking audit logs for API permission changes" `
                    -Severity "Medium" `
                    -Description "An error occurred while checking audit logs for API permission changes: $($_.Exception.Message)" `
                    -Recommendation "Manual investigation of API permission changes is recommended."
            }
        }
        
        # Check for current high-risk delegated and application permissions
        try {
            # Get all service principals
            $servicePrincipals = Get-MgServicePrincipal -All -ErrorAction Stop
            
            if ($servicePrincipals -and $servicePrincipals.Count -gt 0) {
                Write-Log -Message "Found $($servicePrincipals.Count) service principals" -Level Info
                
                # Get all OAuth2 permission grants (delegated permissions)
                $oauth2PermissionGrants = Get-MgOauth2PermissionGrant -All -ErrorAction Stop
                
                if ($oauth2PermissionGrants -and $oauth2PermissionGrants.Count -gt 0) {
                    Write-Log -Message "Found $($oauth2PermissionGrants.Count) OAuth2 permission grants" -Level Info
                    
                    # Group by client ID
                    $permissionsByClientId = $oauth2PermissionGrants | Group-Object -Property ClientId
                    
                    foreach ($clientGroup in $permissionsByClientId) {
                        $clientId = $clientGroup.Name
                        
                        # Get the service principal for this client
                        $sp = $servicePrincipals | Where-Object { $_.Id -eq $clientId }
                        
                        if ($sp) {
                            $clientName = $sp.DisplayName
                            
                            # Check for high-risk scopes
                            $highRiskScopes = @()
                            $adminConsented = $false
                            
                            foreach ($grant in $clientGroup.Group) {
                                # Check if admin consented
                                if ($grant.ConsentType -eq "AllPrincipals") {
                                    $adminConsented = $true
                                }
                                
                                $scopes = $grant.Scope -split " "
                                
                                foreach ($scope in $scopes) {
                                    # Check against list of high-risk scopes
                                    switch -Wildcard ($scope) {
                                        "Directory.Read.All" { $highRiskScopes += $scope }
                                        "Directory.ReadWrite.All" { $highRiskScopes += $scope }
                                        "Group.Read.All" { $highRiskScopes += $scope }
                                        "Group.ReadWrite.All" { $highRiskScopes += $scope }
                                        "Mail.Read" { $highRiskScopes += $scope }
                                        "Mail.ReadWrite" { $highRiskScopes += $scope }
                                        "Mail.Send" { $highRiskScopes += $scope }
                                        "Files.Read.All" { $highRiskScopes += $scope }
                                        "Files.ReadWrite.All" { $highRiskScopes += $scope }
                                        "User.Read.All" { $highRiskScopes += $scope }
                                        "User.ReadWrite.All" { $highRiskScopes += $scope }
                                        "Sites.Read.All" { $highRiskScopes += $scope }
                                        "Sites.ReadWrite.All" { $highRiskScopes += $scope }
                                        "*FullAccess*" { $highRiskScopes += $scope }
                                        "*full_access*" { $highRiskScopes += $scope }
                                    }
                                }
                            }
                            
                            # Report if high-risk scopes found
                            if ($highRiskScopes.Count -gt 0) {
                                $severity = if ($adminConsented) { "High" } else { "Medium" }
                                
                                $findings += Add-Finding -Category "ApiPermissions" -Title "Application with high-risk delegated permissions" `
                                    -Severity $severity `
                                    -Description "Application '$clientName' (ID: $clientId) has been granted high-risk delegated permissions: $($highRiskScopes -join ', '). $(if($adminConsented){"These permissions were admin-consented."})" `
                                    -Recommendation "Review this application to verify these permissions are necessary and appropriate. Consider revoking permissions if not explicitly required." `
                                    -Data @{
                                        ApplicationName = $clientName
                                        ApplicationId = $clientId
                                        HighRiskScopes = $highRiskScopes
                                        AdminConsented = $adminConsented
                                    }
                            }
                        }
                    }
                }
                
                # Get app role assignments (application permissions)
                $appRoleAssignments = @()
                $counter = 0
                $totalSPs = $servicePrincipals.Count
                
                # Process in batches to avoid throttling
                foreach ($sp in $servicePrincipals) {
                    $counter++
                    if ($counter % 50 -eq 0) {
                        Write-Log -Message "Processing service principal $counter of $totalSPs" -Level Debug
                    }
                    
                    try {
                        $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction Stop
                        if ($assignments) {
                            $appRoleAssignments += $assignments
                        }
                    }
                    catch {
                        Write-Log -Message "Error getting app role assignments for service principal $($sp.DisplayName): $($_.Exception.Message)" -Level Warning
                    }
                }
                
                if ($appRoleAssignments -and $appRoleAssignments.Count -gt 0) {
                    Write-Log -Message "Found $($appRoleAssignments.Count) app role assignments" -Level Info
                    
                    # Group by principal ID
                    $assignmentsByPrincipalId = $appRoleAssignments | Group-Object -Property PrincipalId
                    
                    foreach ($principalGroup in $assignmentsByPrincipalId) {
                        $principalId = $principalGroup.Name
                        
                        # Get the service principal for this principal
                        $sp = $servicePrincipals | Where-Object { $_.Id -eq $principalId }
                        
                        if ($sp) {
                            $principalName = $sp.DisplayName
                            
                            # Check for high-risk app roles
                            $highRiskRoles = @()
                            
                            foreach ($assignment in $principalGroup.Group) {
                                # Try to get resource name
                                $resource = $servicePrincipals | Where-Object { $_.Id -eq $assignment.ResourceId }
                                $resourceName = if ($resource) { $resource.DisplayName } else { "Unknown" }
                                
                                # Microsoft Graph app roles of concern
                                if ($resource -and $resource.AppId -eq "00000003-0000-0000-c000-000000000000") {  # Microsoft Graph
                                    switch ($assignment.AppRoleId) {
                                        "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30" { $highRiskRoles += "Application.Read.All" }
                                        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" { $highRiskRoles += "Application.ReadWrite.All" }
                                        "19dbc75e-c2e2-444c-a770-ec69d8559fc7" { $highRiskRoles += "Directory.ReadWrite.All" }
                                        "246dd0d5-5bd0-4def-940b-0421030a5b68" { $highRiskRoles += "Directory.Read.All" }
                                        "62a82d76-70ea-41e2-9197-370581804d09" { $highRiskRoles += "Group.ReadWrite.All" }
                                        "5b567255-7703-4780-807c-7be8301ae99b" { $highRiskRoles += "Group.Read.All" }
                                        "6918b873-d17a-4dc1-b314-35f528134491" { $highRiskRoles += "Mail.Read" }
                                        "dbaae8cf-10b5-4b86-a4a1-f871c94c6695" { $highRiskRoles += "Mail.ReadWrite" }
                                        "b633e1c5-b582-4048-a93e-9f11b44c7e96" { $highRiskRoles += "Mail.Send" }
                                        "df021288-bdef-4463-88db-98f22de89214" { $highRiskRoles += "User.Read.All" }
                                        "741f803b-c850-494e-b5df-cde7c675a1ca" { $highRiskRoles += "User.ReadWrite.All" }
                                    }
                                }
                                else {
                                    # Non-Graph roles that are typically risky
                                    $highRiskRoles += "$resourceName:$($assignment.AppRoleId)"
                                }
                            }
                            
                            # Report if high-risk roles found
                            if ($highRiskRoles.Count -gt 0) {
                                $findings += Add-Finding -Category "ApiPermissions" -Title "Application with high-risk application permissions" `
                                    -Severity "High" `
                                    -Description "Application '$principalName' (ID: $principalId) has been granted high-risk application permissions: $($highRiskRoles -join ', '). These permissions allow the application to act independently of users." `
                                    -Recommendation "Review this application to verify these permissions are necessary and appropriate. Consider revoking permissions if not explicitly required." `
                                    -Data @{
                                        ApplicationName = $principalName
                                        ApplicationId = $principalId
                                        HighRiskRoles = $highRiskRoles
                                    }
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Log -Message "Error checking current API permissions: $($_.Exception.Message)" -Level Error
            $findings += Add-Finding -Category "ApiPermissions" -Title "Error checking current API permissions" `
                -Severity "Medium" `
                -Description "An error occurred while checking current API permissions: $($_.Exception.Message)" `
                -Recommendation "Manual investigation of API permissions is recommended."
        }
        
        Write-Log -Message "Completed API permission change analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing API permission changes: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "ApiPermissions" -Title "Error analyzing API permission changes" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing API permission changes: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of API permission changes is recommended."
    }
    
    return $findings
}

function Invoke-CustomEndpointCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing custom integration endpoints" -Level Info
        
        # Connect to required services
        $needsMicrosoftTeams = $true
        $needsSharePointPnP = $true
        
        # Try to connect to Microsoft Teams if needed
        if ($needsMicrosoftTeams) {
            try {
                # Check if already connected
                $teamsConnected = $false
                try {
                    $teamsConnected = Get-CsTenant -ErrorAction SilentlyContinue
                }
                catch {
                    # Not connected
                }
                
                if (-not $teamsConnected) {
                    if (Get-Module -ListAvailable -Name MicrosoftTeams) {
                        Import-Module MicrosoftTeams -ErrorAction Stop
                        Connect-MicrosoftTeams -ErrorAction Stop
                        $teamsConnected = $true
                        Write-Log -Message "Successfully connected to Microsoft Teams" -Level Info
                    }
                    else {
                        Write-Log -Message "MicrosoftTeams module not available" -Level Warning
                        $teamsConnected = $false
                    }
                }
                else {
                    Write-Log -Message "Already connected to Microsoft Teams" -Level Info
                }
            }
            catch {
                Write-Log -Message "Failed to connect to Microsoft Teams: $($_.Exception.Message)" -Level Warning
                $teamsConnected = $false
            }
        }
        
        # Try to connect to SharePoint PnP if needed
        if ($needsSharePointPnP) {
            try {
                # Check if already connected
                $pnpConnected = $false
                try {
                    $pnpConnected = Get-PnPContext -ErrorAction SilentlyContinue
                }
                catch {
                    # Not connected
                }
                
                if (-not $pnpConnected) {
                    if (Get-Module -ListAvailable -Name PnP.PowerShell) {
                        Import-Module PnP.PowerShell -ErrorAction Stop
                        # This requires tenant admin URL
                        $tenantName = (Get-MgOrganization).VerifiedDomains | Where-Object { $_.IsInitial -eq $true } | Select-Object -ExpandProperty Name
                        if ($tenantName) {
                            $adminUrl = "https://$($tenantName.Split('.')[0])-admin.sharepoint.com"
                            $pnpConnection = Connect-PnPOnline -Url $adminUrl -Interactive -ReturnConnection -ErrorAction Stop
                            $pnpConnected = $true
                            Write-Log -Message "Successfully connected to SharePoint PnP" -Level Info
                        }
                        else {
                            Write-Log -Message "Could not determine tenant admin URL for SharePoint" -Level Warning
                            $pnpConnected = $false
                        }
                    }
                    else {
                        Write-Log -Message "PnP.PowerShell module not available" -Level Warning
                        $pnpConnected = $false
                    }
                }
                else {
                    Write-Log -Message "Already connected to SharePoint PnP" -Level Info
                }
            }
            catch {
                Write-Log -Message "Failed to connect to SharePoint PnP: $($_.Exception.Message)" -Level Warning
                $pnpConnected = $false
            }
        }
        
        # Check for Teams webhooks
        if ($teamsConnected) {
            try {
                Write-Log -Message "Checking for Microsoft Teams webhooks" -Level Info
                
                # Get all teams
                $teams = Get-Team -ErrorAction Stop
                
                if ($teams -and $teams.Count -gt 0) {
                    Write-Log -Message "Found $($teams.Count) teams" -Level Info
                    
                    # Limit to 100 teams to avoid excessive processing
                    $teamsToCheck = $teams | Select-Object -First 100
                    
                    foreach ($team in $teamsToCheck) {
                        try {
                            # Get channels for this team
                            $channels = Get-TeamChannel -GroupId $team.GroupId -ErrorAction Stop
                            
                            if ($channels) {
                                foreach ($channel in $channels) {
                                    try {
                                        # Get connectors for this channel
                                        $connectors = Get-TeamChannelConnector -GroupId $team.GroupId -ChannelId $channel.Id -ErrorAction Stop
                                        
                                        if ($connectors) {
                                            # Filter for webhook connectors
                                            $webhookConnectors = $connectors | Where-Object { $_.ConnectorType -eq "Incoming Webhook" }
                                            
                                            if ($webhookConnectors -and $webhookConnectors.Count -gt 0) {
                                                foreach ($webhook in $webhookConnectors) {
                                                    $findings += Add-Finding -Category "CustomEndpoints" -Title "Teams incoming webhook detected" `
                                                        -Severity "Medium" `
                                                        -Description "Microsoft Teams incoming webhook '$($webhook.Name)' found in team '$($team.DisplayName)', channel '$($channel.DisplayName)'. Incoming webhooks can be used to post messages to Teams from external systems." `
                                                        -Recommendation "Review this webhook to verify it is legitimate and used for authorized purposes." `
                                                        -Data @{
                                                            TeamName = $team.DisplayName
                                                            TeamId = $team.GroupId
                                                            ChannelName = $channel.DisplayName
                                                            ChannelId = $channel.Id
                                                            WebhookName = $webhook.Name
                                                            WebhookId = $webhook.Id
                                                        }
                                                }
                                            }
                                        }
                                    }
                                    catch {
                                        Write-Log -Message "Error retrieving connectors for team '$($team.DisplayName)', channel '$($channel.DisplayName)': $($_.Exception.Message)" -Level Warning
                                    }
                                }
                            }
                        }
                        catch {
                            Write-Log -Message "Error retrieving channels for team '$($team.DisplayName)': $($_.Exception.Message)" -Level Warning
                        }
                    }
                }
                else {
                    Write-Log -Message "No teams found" -Level Info
                }
            }
            catch {
                Write-Log -Message "Error checking Teams webhooks: $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "CustomEndpoints" -Title "Error checking Teams webhooks" `
                    -Severity "Low" `
                    -Description "An error occurred while checking Microsoft Teams webhooks: $($_.Exception.Message)" `
                    -Recommendation "Manual investigation of Teams webhooks is recommended."
            }
        }
        
        # Check for SharePoint webhooks
        if ($pnpConnected) {
            try {
                Write-Log -Message "Checking for SharePoint webhooks" -Level Info
                
                # Get all site collections
                $siteCollections = Get-PnPTenantSite -ErrorAction Stop
                
                if ($siteCollections -and $siteCollections.Count -gt 0) {
                    Write-Log -Message "Found $($siteCollections.Count) site collections" -Level Info
                    
                    # Limit to 20 most recently modified sites to avoid excessive processing
                    $sitesToCheck = $siteCollections | Sort-Object LastContentModifiedDate -Descending | Select-Object -First 20
                    
                    foreach ($site in $sitesToCheck) {
                        try {
                            # Connect to site
                            $siteConnection = Connect-PnPOnline -Url $site.Url -Interactive -ReturnConnection -ErrorAction Stop
                            
                            # Get all lists
                            $lists = Get-PnPList -Connection $siteConnection -ErrorAction Stop
                            
                            if ($lists) {
                                foreach ($list in $lists) {
                                    try {
                                        # Get webhooks for this list
                                        $webhooks = Get-PnPWebhookSubscriptions -List $list.Title -Connection $siteConnection -ErrorAction Stop
                                        
                                        if ($webhooks -and $webhooks.Count -gt 0) {
                                            foreach ($webhook in $webhooks) {
                                                $isSuspicious = $false
                                                $reasons = @()
                                                $severity = "Medium"
                                                
                                                # Check notification URL for suspicious patterns
                                                $url = $webhook.NotificationUrl
                                                
                                                # Check for suspicious URLs
                                                if ($url -match "ngrok\.io" -or 
                                                    $url -match "tunnel\.me" -or 
                                                    $url -match "serveo\.net" -or
                                                    $url -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" -or  # IP address
                                                    $url -match "^https?://[a-z0-9]{16,}\..*" -or  # Random subdomain
                                                    $url -match "\.onion\.") {  # Tor network
                                                    $isSuspicious = $true
                                                    $reasons += "Suspicious notification URL: $url"
                                                    $severity = "High"
                                                }
                                                
                                                # Report finding
                                                $findings += Add-Finding -Category "CustomEndpoints" -Title "SharePoint webhook detected" `
                                                    -Severity $severity `
                                                    -Description "SharePoint webhook found in site '$($site.Url)', list '$($list.Title)'. The webhook sends notifications to '$($webhook.NotificationUrl)'. $($if ($reasons.Count -gt 0) { "Suspicious characteristics: $($reasons -join '; ')" })" `
                                                    -Recommendation "Review this webhook to verify it is legitimate and used for authorized purposes." `
                                                    -Data @{
                                                        SiteUrl = $site.Url
                                                        ListTitle = $list.Title
                                                        WebhookId = $webhook.Id
                                                        NotificationUrl = $webhook.NotificationUrl
                                                        ExpirationDateTime = $webhook.ExpirationDateTime
                                                        IsSuspicious = $isSuspicious
                                                        Reasons = $reasons
                                                    }
                                            }
                                        }
                                    }
                                    catch {
                                        Write-Log -Message "Error retrieving webhooks for list '$($list.Title)' in site '$($site.Url)': $($_.Exception.Message)" -Level Warning
                                    }
                                }
                            }
                            
                            # Disconnect from site
                            Disconnect-PnPOnline -Connection $siteConnection -ErrorAction SilentlyContinue
                        }
                        catch {
                            Write-Log -Message "Error connecting to site '$($site.Url)': $($_.Exception.Message)" -Level Warning
                        }
                    }
                }
                else {
                    Write-Log -Message "No site collections found" -Level Info
                }
            }
            catch {
                Write-Log -Message "Error checking SharePoint webhooks: $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "CustomEndpoints" -Title "Error checking SharePoint webhooks" `
                    -Severity "Low" `
                    -Description "An error occurred while checking SharePoint webhooks: $($_.Exception.Message)" `
                    -Recommendation "Manual investigation of SharePoint webhooks is recommended."
            }
        }
        
        # Disconnect from services
        if ($teamsConnected) {
            Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
        }
        
        Write-Log -Message "Completed custom integration endpoint analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing custom integration endpoints: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "CustomEndpoints" -Title "Error analyzing custom integration endpoints" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing custom integration endpoints: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of custom integration endpoints is recommended."
    }
    
    return $findings
}

function Invoke-DlpPolicyCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing Data Loss Prevention policies" -Level Info
        
        # Connect to Microsoft Graph if not already connected
        if (-not $script:GraphConnected) {
            try {
                # Check if already connected
                $context = Get-MgContext -ErrorAction SilentlyContinue
                
                if (-not $context) {
                    # Connect with required scopes
                    $scopes = @(
                        "Directory.Read.All",
                        "Policy.Read.All"
                    )
                    
                    Connect-MgGraph -Scopes $scopes -ErrorAction Stop
                }
                
                $context = Get-MgContext
                if (-not $context) {
                    throw "Failed to establish Microsoft Graph connection"
                }
                
                $script:GraphConnected = $true
                Write-Log -Message "Successfully connected to Microsoft Graph" -Level Info
            }
            catch {
                Write-Log -Message "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "DlpPolicies" -Title "Failed to connect to Microsoft Graph" `
                    -Severity "Medium" `
                    -Description "Failed to connect to Microsoft Graph to check DLP policies: $($_.Exception.Message)" `
                    -Recommendation "Verify Graph API permissions and manually investigate DLP policies."
                return $findings
            }
        }
        
        # Check for DLP policy changes in audit logs
        try {
            # Construct filter for audit logs
            $startDate = $script:AnalysisStartDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
            $endDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
            $filter = "activityDateTime ge $startDate and activityDateTime le $endDate and (category eq 'DataLossPrevention')"
            
            $auditLogs = Get-MgAuditLogDirectoryAudit -Filter $filter -All -ErrorAction Stop
            
            if ($auditLogs -and $auditLogs.Count -gt 0) {
                Write-Log -Message "Found $($auditLogs.Count) DLP-related audit events" -Level Info
                
                foreach ($event in $auditLogs) {
                    $isSuspicious = $false
                    $reasons = @()
                    $severity = "Medium"
                    
                    # Look for policy disabling or modifications
                    if ($event.ActivityDisplayName -like "*Delete*" -or 
                        $event.ActivityDisplayName -like "*Remove*") {
                        $isSuspicious = $true
                        $reasons += "DLP policy or rule was deleted"
                        $severity = "High"
                    }
                    elseif ($event.ActivityDisplayName -like "*Update*" -or 
                           $event.ActivityDisplayName -like "*Modify*") {
                        $isSuspicious = $true
                        $reasons += "DLP policy or rule was modified"
                        
                        # Check modified properties for suspicious changes
                        if ($event.TargetResources -and $event.TargetResources.ModifiedProperties) {
                            foreach ($prop in $event.TargetResources.ModifiedProperties) {
                                if ($prop.DisplayName -like "*Enabled*" -and $prop.OldValue -like "*True*" -and $prop.NewValue -like "*False*") {
                                    $reasons += "Policy or rule was disabled"
                                    $severity = "High"
                                }
                                elseif ($prop.DisplayName -like "*Action*" -and 
                                      ($prop.OldValue -like "*Block*" -or $prop.OldValue -like "*Restrict*") -and 
                                      ($prop.NewValue -like "*Allow*" -or $prop.NewValue -like "*Audit*")) {
                                    $reasons += "Policy action changed from blocking to non-blocking"
                                    $severity = "High"
                                }
                            }
                        }
                    }
                    
                    # Get initiator information
                    $initiatedBy = "Unknown"
                    if ($event.InitiatedBy -and $event.InitiatedBy.User) {
                        $initiatedBy = $event.InitiatedBy.User.UserPrincipalName
                    }
                    elseif ($event.InitiatedBy -and $event.InitiatedBy.App) {
                        $initiatedBy = $event.InitiatedBy.App.DisplayName
                        
                        # Application-initiated changes are unusual
                        $isSuspicious = $true
                        $reasons += "DLP change initiated by an application"
                    }
                    
                    # Only report suspicious events or policy deletions
                    if ($isSuspicious) {
                        $findings += Add-Finding -Category "DlpPolicies" -Title "DLP policy modification detected" `
                            -Severity $severity `
                            -Description "DLP policy change detected: $($event.ActivityDisplayName) performed by '$initiatedBy' on $(Get-Date $event.ActivityDateTime -Format 'yyyy-MM-dd'). $($if ($reasons.Count -gt 0) { "Suspicious characteristics: $($reasons -join '; ')" })" `
                            -Recommendation "Review this DLP policy change to verify it was legitimate and authorized." `
                            -Data @{
                                ActivityDisplayName = $event.ActivityDisplayName
                                InitiatedBy = $initiatedBy
                                ActivityDateTime = $event.ActivityDateTime
                                Reasons = $reasons
                                TargetResources = $event.TargetResources | 
                                                Select-Object Type, Id, DisplayName,
                                                @{Name = "ModifiedProperties"; Expression = {
                                                    $_.ModifiedProperties | Select-Object DisplayName, OldValue, NewValue
                                                }}
                            }
                    }
                }
                
                if ($findings.Count -eq 0) {
                    $findings += Add-Finding -Category "DlpPolicies" -Title "DLP changes detected but none appear suspicious" `
                        -Severity "Informational" `
                        -Description "DLP policy changes were detected during the analysis period (last $script:DaysToAnalyze days), but none appear suspicious." `
                        -Recommendation "Continue monitoring for unauthorized DLP policy changes."
                }
            }
            else {
                Write-Log -Message "No DLP-related audit events found during the analysis period" -Level Info
                $findings += Add-Finding -Category "DlpPolicies" -Title "No DLP policy changes found" `
                    -Severity "Informational" `
                    -Description "No DLP policy changes were found during the analysis period (last $script:DaysToAnalyze days)." `
                    -Recommendation "Continue monitoring for unauthorized DLP policy changes."
            }
        }
        catch {
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Permission*") {
                Write-Log -Message "Insufficient permissions to access audit logs for DLP changes: $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "DlpPolicies" -Title "Insufficient permissions to check DLP policy changes" `
                    -Severity "Medium" `
                    -Description "Unable to check DLP policy changes in audit logs due to insufficient permissions: $($_.Exception.Message)" `
                    -Recommendation "Review Graph API permissions or use an account with higher privileges to check for DLP policy changes."
            }
            else {
                Write-Log -Message "Error checking audit logs for DLP policy changes: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "DlpPolicies" -Title "Error checking DLP policy changes" `
                    -Severity "Medium" `
                    -Description "An error occurred while checking audit logs for DLP policy changes: $($_.Exception.Message)" `
                    -Recommendation "Manual investigation of DLP policies is recommended."
            }
        }
        
        Write-Log -Message "Completed DLP policy analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing DLP policies: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "DlpPolicies" -Title "Error analyzing DLP policies" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing DLP policies: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of DLP policies is recommended."
    }
    
    return $findings
}

function Invoke-AuditLogCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing audit log settings" -Level Info
        
        # Connect to Microsoft Graph if not already connected
        if (-not $script:GraphConnected) {
            try {
                # Check if already connected
                $context = Get-MgContext -ErrorAction SilentlyContinue
                
                if (-not $context) {
                    # Connect with required scopes
                    $scopes = @(
                        "Directory.Read.All",
                        "Policy.Read.All"
                    )
                    
                    Connect-MgGraph -Scopes $scopes -ErrorAction Stop
                }
                
                $context = Get-MgContext
                if (-not $context) {
                    throw "Failed to establish Microsoft Graph connection"
                }
                
                $script:GraphConnected = $true
                Write-Log -Message "Successfully connected to Microsoft Graph" -Level Info
            }
            catch {
                Write-Log -Message "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "AuditLogs" -Title "Failed to connect to Microsoft Graph" `
                    -Severity "Medium" `
                    -Description "Failed to connect to Microsoft Graph to check audit log settings: $($_.Exception.Message)" `
                    -Recommendation "Verify Graph API permissions and manually investigate audit log settings."
                return $findings
            }
        }
        
        # Check for audit log policy changes
        try {
            # Construct filter for audit logs
            $startDate = $script:AnalysisStartDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
            $endDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
            $filter = "activityDateTime ge $startDate and activityDateTime le $endDate and (category eq 'Policy' or activityDisplayName eq 'Update policy' or activityDisplayName eq 'Update settings')"
            
            $auditLogs = Get-MgAuditLogDirectoryAudit -Filter $filter -All -ErrorAction Stop
            
            if ($auditLogs -and $auditLogs.Count -gt 0) {
                Write-Log -Message "Found $($auditLogs.Count) policy-related audit events" -Level Info
                
                # Filter for audit log policy changes
                $auditPolicyChanges = $auditLogs | Where-Object {
                    $_.ActivityDisplayName -like "*audit*" -or
                    ($_.TargetResources -and ($_.TargetResources.DisplayName -like "*audit*" -or $_.TargetResources.Type -like "*audit*"))
                }
                
                if ($auditPolicyChanges -and $auditPolicyChanges.Count -gt 0) {
                    Write-Log -Message "Found $($auditPolicyChanges.Count) audit policy-related events" -Level Info
                    
                    foreach ($event in $auditPolicyChanges) {
                        $isSuspicious = $false
                        $reasons = @()
                        $severity = "Medium"
                        
                        # Look for policy disabling or retention reductions
                        if ($event.TargetResources -and $event.TargetResources.ModifiedProperties) {
                            foreach ($prop in $event.TargetResources.ModifiedProperties) {
                                if ($prop.DisplayName -like "*Enabled*" -and $prop.OldValue -like "*True*" -and $prop.NewValue -like "*False*") {
                                    $isSuspicious = $true
                                    $reasons += "Audit logging was disabled"
                                    $severity = "High"
                                }
                                elseif ($prop.DisplayName -like "*Retention*" -or $prop.DisplayName -like "*Duration*") {
                                    # Try to parse old and new values to compare
                                    $oldValue = 0
                                    $newValue = 0
                                    
                                    try {
                                        # Extract numbers
                                        $oldValue = [int]($prop.OldValue -replace "[^0-9]", "")
                                        $newValue = [int]($prop.NewValue -replace "[^0-9]", "")
                                    }
                                    catch {
                                        # Continue if parsing fails
                                    }
                                    
                                    if ($oldValue -gt $newValue -and $newValue -gt 0) {
                                        $isSuspicious = $true
                                        $reasons += "Audit log retention was reduced from $oldValue to $newValue"
                                        $severity = "High"
                                    }
                                }
                            }
                        }
                        
                        # Get initiator information
                        $initiatedBy = "Unknown"
                        if ($event.InitiatedBy -and $event.InitiatedBy.User) {
                            $initiatedBy = $event.InitiatedBy.User.UserPrincipalName
                        }
                        elseif ($event.InitiatedBy -and $event.InitiatedBy.App) {
                            $initiatedBy = $event.InitiatedBy.App.DisplayName
                            
                            # Application-initiated changes are unusual
                            $isSuspicious = $true
                            $reasons += "Audit policy change initiated by an application"
                        }
                        
                        # Report suspicious events
                        if ($isSuspicious) {
                            $findings += Add-Finding -Category "AuditLogs" -Title "Suspicious audit log policy change detected" `
                                -Severity $severity `
                                -Description "Audit log policy change detected: $($event.ActivityDisplayName) performed by '$initiatedBy' on $(Get-Date $event.ActivityDateTime -Format 'yyyy-MM-dd'). Suspicious characteristics: $($reasons -join '; ')" `
                                -Recommendation "Review this audit log policy change to verify it was legitimate and authorized. Consider re-enabling audit logging or increasing retention periods if they were reduced." `
                                -Data @{
                                    ActivityDisplayName = $event.ActivityDisplayName
                                    InitiatedBy = $initiatedBy
                                    ActivityDateTime = $event.ActivityDateTime
                                    Reasons = $reasons
                                    TargetResources = $event.TargetResources | 
                                                    Select-Object Type, Id, DisplayName,
                                                    @{Name = "ModifiedProperties"; Expression = {
                                                        $_.ModifiedProperties | Select-Object DisplayName, OldValue, NewValue
                                                    }}
                                }
                        }
                    }
                }
            }
            
            if ($findings.Count -eq 0) {
                $findings += Add-Finding -Category "AuditLogs" -Title "No suspicious audit log policy changes found" `
                    -Severity "Informational" `
                    -Description "No suspicious audit log policy changes were found during the analysis period (last $script:DaysToAnalyze days)." `
                    -Recommendation "Continue monitoring for unauthorized audit log policy changes."
            }
        }
        catch {
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Permission*") {
                Write-Log -Message "Insufficient permissions to access audit logs for policy changes: $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "AuditLogs" -Title "Insufficient permissions to check audit log policy changes" `
                    -Severity "Medium" `
                    -Description "Unable to check audit log policy changes due to insufficient permissions: $($_.Exception.Message)" `
                    -Recommendation "Review Graph API permissions or use an account with higher privileges to check for audit log policy changes."
            }
            else {
                Write-Log -Message "Error checking audit logs for policy changes: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "AuditLogs" -Title "Error checking audit log policy changes" `
                    -Severity "Medium" `
                    -Description "An error occurred while checking audit logs for policy changes: $($_.Exception.Message)" `
                    -Recommendation "Manual investigation of audit log policies is recommended."
            }
        }
        
        # Check current audit log settings
        try {
            # This may need to be adjusted based on available API endpoints
            # For now, we'll use Exchange Online audit log configuration
            
            # Most accurate way would be to use Exchange Online PowerShell
            if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
                try {
                    # Check if already connected
                    $exchangeConnected = $false
                    try {
                        $exchangeConnected = Get-OrganizationConfig -ErrorAction SilentlyContinue
                    }
                    catch {
                        # Not connected
                    }
                    
                    if (-not $exchangeConnected) {
                        Import-Module ExchangeOnlineManagement -ErrorAction Stop
                        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
                        $exchangeConnected = $true
                        Write-Log -Message "Successfully connected to Exchange Online" -Level Info
                    }
                    else {
                        Write-Log -Message "Already connected to Exchange Online" -Level Info
                    }
                    
                    # Check unified audit log status
                    $adminAuditLogConfig = Get-AdminAuditLogConfig -ErrorAction Stop
                    
                    if ($adminAuditLogConfig -and $adminAuditLogConfig.UnifiedAuditLogIngestionEnabled -eq $false) {
                        $findings += Add-Finding -Category "AuditLogs" -Title "Unified audit logging is disabled" `
                            -Severity "High" `
                            -Description "Unified audit logging is currently disabled in the tenant. This prevents the recording of user and admin activities across Microsoft 365 services." `
                            -Recommendation "Enable unified audit logging immediately to ensure proper security monitoring and forensic capabilities." `
                            -Data $adminAuditLogConfig
                    }
                    else {
                        $findings += Add-Finding -Category "AuditLogs" -Title "Unified audit logging is enabled" `
                            -Severity "Informational" `
                            -Description "Unified audit logging is currently enabled in the tenant. This is the recommended configuration." `
                            -Recommendation "Continue monitoring audit log settings for any unauthorized changes." `
                            -Data $adminAuditLogConfig
                    }
                    
                    # Disconnect Exchange Online if we connected in this function
                    if ($exchangeConnected) {
                        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    Write-Log -Message "Error checking Exchange Online audit log settings: $($_.Exception.Message)" -Level Warning
                    $findings += Add-Finding -Category "AuditLogs" -Title "Error checking Exchange Online audit log settings" `
                        -Severity "Medium" `
                        -Description "An error occurred while checking Exchange Online audit log settings: $($_.Exception.Message)" `
                        -Recommendation "Manual investigation of audit log settings is recommended."
                }
            }
            else {
                Write-Log -Message "ExchangeOnlineManagement module not available" -Level Warning
                $findings += Add-Finding -Category "AuditLogs" -Title "Unable to check Exchange Online audit log settings" `
                    -Severity "Medium" `
                    -Description "Unable to check Exchange Online audit log settings because the ExchangeOnlineManagement module is not available." `
                    -Recommendation "Install the ExchangeOnlineManagement module and run this check again, or manually verify audit log settings."
            }
        }
        catch {
            Write-Log -Message "Error checking current audit log settings: $($_.Exception.Message)" -Level Error
            $findings += Add-Finding -Category "AuditLogs" -Title "Error checking current audit log settings" `
                -Severity "Medium" `
                -Description "An error occurred while checking current audit log settings: $($_.Exception.Message)" `
                -Recommendation "Manual investigation of audit log settings is recommended."
        }
        
        Write-Log -Message "Completed audit log setting analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing audit log settings: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "AuditLogs" -Title "Error analyzing audit log settings" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing audit log settings: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of audit log settings is recommended."
    }
    
    return $findings
}

function Invoke-SiemIntegrationCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing SIEM integration status" -Level Info
        
        # Connect to Azure if not already connected
        if (-not $script:AzureConnected) {
            try {
                # Check if already connected
                $context = Get-AzContext -ErrorAction SilentlyContinue
                
                if (-not $context) {
                    # Connect interactively
                    Connect-AzAccount -ErrorAction Stop
                }
                
                $script:AzureConnected = $true
                Write-Log -Message "Successfully connected to Azure" -Level Info
            }
            catch {
                Write-Log -Message "Failed to connect to Azure: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "SiemIntegration" -Title "Failed to connect to Azure" `
                    -Severity "Medium" `
                    -Description "Failed to connect to Azure to check SIEM integration status: $($_.Exception.Message)" `
                    -Recommendation "Verify Azure access permissions and manually investigate SIEM integration status."
                return $findings
            }
        }
        
        # Check for Azure Sentinel workspaces
        try {
            # Get all Azure subscriptions
            $subscriptions = Get-AzSubscription -ErrorAction Stop
            
            if (-not $subscriptions -or $subscriptions.Count -eq 0) {
                Write-Log -Message "No Azure subscriptions found" -Level Warning
                $findings += Add-Finding -Category "SiemIntegration" -Title "No Azure subscriptions found" `
                    -Severity "Low" `
                    -Description "No Azure subscriptions were found. Either no subscriptions exist or the account does not have access to any subscriptions." `
                    -Recommendation "Verify Azure access permissions and manually investigate SIEM integration status if subscriptions should exist."
                return $findings
            }
            
            $sentinelWorkspacesFound = $false
            
            # Process each subscription
            foreach ($subscription in $subscriptions) {
                try {
                    # Set the current subscription context
                    Set-AzContext -Subscription $subscription.Id -ErrorAction Stop | Out-Null
                    
                    Write-Log -Message "Checking subscription: $($subscription.Name) ($($subscription.Id))" -Level Info
                    
                    # Check for Log Analytics workspaces
                    $workspaces = Get-AzOperationalInsightsWorkspace -ErrorAction Stop
                    
                    if ($workspaces -and $workspaces.Count -gt 0) {
                        Write-Log -Message "Found $($workspaces.Count) Log Analytics workspaces in subscription $($subscription.Name)" -Level Info
                        
                        # Check for Sentinel solutions
                        foreach ($workspace in $workspaces) {
                            try {
                                # For Sentinel, we need to check for the Sentinel solution
                                # This can be done by checking resources or solutions
                                $isSentinelWorkspace = $false
                                
                                try {
                                    # Check for Sentinel solution (depends on Az.SecurityInsights)
                                    if (Get-Module -ListAvailable -Name Az.SecurityInsights) {
                                        Import-Module Az.SecurityInsights -ErrorAction Stop
                                        $sentinel = Get-AzSecurityInsightsSetting -WorkspaceId $workspace.ResourceId -ErrorAction SilentlyContinue
                                        if ($sentinel) {
                                            $isSentinelWorkspace = $true
                                        }
                                    }
                                    else {
                                        # Alternative check for Sentinel solution
                                        $solutions = Get-AzOperationalInsightsIntelligencePack -ResourceGroupName $workspace.ResourceGroupName -WorkspaceName $workspace.Name -ErrorAction SilentlyContinue
                                        
                                        if ($solutions -and ($solutions.Name -contains "SecurityInsights" -or $solutions.Name -contains "Sentinel")) {
                                            $isSentinelWorkspace = $true
                                        }
                                    }
                                }
                                catch {
                                    # If solution check fails, try to check for data connectors or analytics rules
                                    Write-Log -Message "Error checking for Sentinel solution in workspace $($workspace.Name): $($_.Exception.Message)" -Level Warning
                                }
                                
                                if ($isSentinelWorkspace) {
                                    $sentinelWorkspacesFound = $true
                                    
                                    # Check for M365 data connectors
                                    $m365ConnectorsFound = $false
                                    
                                    try {
                                        # This requires Az.SecurityInsights module or direct API calls
                                        if (Get-Module -ListAvailable -Name Az.SecurityInsights) {
                                            # Get data connectors
                                            $dataConnectors = Get-AzSecurityInsightsDataConnector -ResourceGroupName $workspace.ResourceGroupName -WorkspaceName $workspace.Name -ErrorAction SilentlyContinue
                                            
                                            if ($dataConnectors) {
                                                $m365Connectors = $dataConnectors | Where-Object { 
                                                    $_.Kind -like "*Office365*" -or 
                                                    $_.Kind -like "*MicrosoftThreatProtection*" -or 
                                                    $_.Kind -like "*AzureActiveDirectory*" 
                                                }
                                                
                                                if ($m365Connectors -and $m365Connectors.Count -gt 0) {
                                                    $m365ConnectorsFound = $true
                                                    
                                                    # Check for disabled connectors
                                                    $disabledConnectors = $m365Connectors | Where-Object { -not $_.DataTypes.State -contains "Enabled" }
                                                    
                                                    if ($disabledConnectors -and $disabledConnectors.Count -gt 0) {
                                                        foreach ($connector in $disabledConnectors) {
                                                            $findings += Add-Finding -Category "SiemIntegration" -Title "Disabled Microsoft 365 data connector in Sentinel" `
                                                                -Severity "High" `
                                                                -Description "Microsoft 365 data connector '$($connector.Name)' is disabled in Sentinel workspace '$($workspace.Name)'. This prevents security events from being collected and analyzed." `
                                                                -Recommendation "Review and re-enable this connector to ensure proper security monitoring." `
                                                                -Data @{
                                                                    SubscriptionId = $subscription.Id
                                                                    SubscriptionName = $subscription.Name
                                                                    WorkspaceName = $workspace.Name
                                                                    ResourceGroupName = $workspace.ResourceGroupName
                                                                    ConnectorName = $connector.Name
                                                                    ConnectorKind = $connector.Kind
                                                                    DataTypes = $connector.DataTypes
                                                                }
                                                        }
                                                    }
                                                    else {
                                                        $findings += Add-Finding -Category "SiemIntegration" -Title "Active Microsoft 365 data connectors in Sentinel" `
                                                            -Severity "Informational" `
                                                            -Description "Microsoft 365 data connectors are enabled in Sentinel workspace '$($workspace.Name)'." `
                                                            -Recommendation "Continue monitoring the status of these connectors to ensure they remain active." `
                                                            -Data @{
                                                                SubscriptionId = $subscription.Id
                                                                SubscriptionName = $subscription.Name
                                                                WorkspaceName = $workspace.Name
                                                                ResourceGroupName = $workspace.ResourceGroupName
                                                                Connectors = $m365Connectors | ForEach-Object { @{
                                                                    Name = $_.Name
                                                                    Kind = $_.Kind
                                                                    DataTypes = $_.DataTypes
                                                                }}
                                                            }
                                                    }
                                                }
                                            }
                                        }
                                        else {
                                            Write-Log -Message "Az.SecurityInsights module not available, can't check data connectors" -Level Warning
                                        }
                                    }
                                    catch {
                                        Write-Log -Message "Error checking data connectors in workspace $($workspace.Name): $($_.Exception.Message)" -Level Warning
                                    }
                                    
                                    if (-not $m365ConnectorsFound) {
                                        $findings += Add-Finding -Category "SiemIntegration" -Title "No Microsoft 365 data connectors found in Sentinel" `
                                            -Severity "Medium" `
                                            -Description "No Microsoft 365 data connectors were found in Sentinel workspace '$($workspace.Name)'. This may indicate that Microsoft 365 security events are not being collected for analysis." `
                                            -Recommendation "Consider adding Microsoft 365 data connectors to this Sentinel workspace for better security monitoring." `
                                            -Data @{
                                                SubscriptionId = $subscription.Id
                                                SubscriptionName = $subscription.Name
                                                WorkspaceName = $workspace.Name
                                                ResourceGroupName = $workspace.ResourceGroupName
                                            }
                                    }
                                }
                            }
                            catch {
                                Write-Log -Message "Error checking workspace $($workspace.Name) for Sentinel: $($_.Exception.Message)" -Level Warning
                            }
                        }
                    }
                    else {
                        Write-Log -Message "No Log Analytics workspaces found in subscription $($subscription.Name)" -Level Info
                    }
                }
                catch {
                    Write-Log -Message "Error checking subscription $($subscription.Name): $($_.Exception.Message)" -Level Warning
                    $findings += Add-Finding -Category "SiemIntegration" -Title "Error checking subscription for SIEM integration" `
                        -Severity "Low" `
                        -Description "An error occurred while checking subscription '$($subscription.Name)' for SIEM integration: $($_.Exception.Message)" `
                        -Recommendation "Verify access permissions and manually investigate SIEM integration in this subscription."
                }
            }
            
            if (-not $sentinelWorkspacesFound) {
                $findings += Add-Finding -Category "SiemIntegration" -Title "No Azure Sentinel workspaces found" `
                    -Severity "Medium" `
                    -Description "No Azure Sentinel workspaces were found across all accessible subscriptions. This may indicate that Microsoft 365 security events are not being collected for analysis." `
                    -Recommendation "Consider implementing Azure Sentinel or another SIEM solution to collect and analyze Microsoft 365 security events."
            }
        }
        catch {
            Write-Log -Message "Error checking Azure Sentinel workspaces: $($_.Exception.Message)" -Level Error
            $findings += Add-Finding -Category "SiemIntegration" -Title "Error checking Azure Sentinel workspaces" `
                -Severity "Medium" `
                -Description "An error occurred while checking Azure Sentinel workspaces: $($_.Exception.Message)" `
                -Recommendation "Manual investigation of SIEM integration status is recommended."
        }
        
        # Check for other SIEM integrations
        # This would require checking for API connectors, event hub exports, etc.
        # For now, we'll focus on Azure Sentinel as it's the most common SIEM for M365
        
        Write-Log -Message "Completed SIEM integration analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing SIEM integration status: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "SiemIntegration" -Title "Error analyzing SIEM integration status" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing SIEM integration status: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of SIEM integration status is recommended."
    }
    
    return $findings
}

function Invoke-KeyVaultCheck {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    try {
        Write-Log -Message "Analyzing Azure Key Vault access policies" -Level Info
        
        # Connect to Azure if not already connected
        if (-not $script:AzureConnected) {
            try {
                # Check if already connected
                $context = Get-AzContext -ErrorAction SilentlyContinue
                
                if (-not $context) {
                    # Connect interactively
                    Connect-AzAccount -ErrorAction Stop
                }
                
                $script:AzureConnected = $true
                Write-Log -Message "Successfully connected to Azure" -Level Info
            }
            catch {
                Write-Log -Message "Failed to connect to Azure: $($_.Exception.Message)" -Level Error
                $findings += Add-Finding -Category "KeyVault" -Title "Failed to connect to Azure" `
                    -Severity "Medium" `
                    -Description "Failed to connect to Azure to check Key Vault access policies: $($_.Exception.Message)" `
                    -Recommendation "Verify Azure access permissions and manually investigate Key Vault access policies."
                return $findings
            }
        }
        
        # Get all Azure subscriptions
        $subscriptions = Get-AzSubscription -ErrorAction Stop
        
        if (-not $subscriptions -or $subscriptions.Count -eq 0) {
            Write-Log -Message "No Azure subscriptions found" -Level Warning
            $findings += Add-Finding -Category "KeyVault" -Title "No Azure subscriptions found" `
                -Severity "Low" `
                -Description "No Azure subscriptions were found. Either no subscriptions exist or the account does not have access to any subscriptions." `
                -Recommendation "Verify Azure access permissions and manually investigate Key Vault access policies if subscriptions should exist."
            return $findings
        }
        
        # Process each subscription
        foreach ($subscription in $subscriptions) {
            try {
                # Set the current subscription context
                Set-AzContext -Subscription $subscription.Id -ErrorAction Stop | Out-Null
                
                Write-Log -Message "Checking subscription: $($subscription.Name) ($($subscription.Id))" -Level Info
                
                # Get all Key Vaults
                $keyVaults = Get-AzKeyVault -ErrorAction Stop
                
                if ($keyVaults -and $keyVaults.Count -gt 0) {
                    Write-Log -Message "Found $($keyVaults.Count) Key Vaults in subscription $($subscription.Name)" -Level Info
                    
                    # Check each Key Vault
                    foreach ($vault in $keyVaults) {
                        try {
                            # Get detailed vault information
                            $vaultDetail = Get-AzKeyVault -VaultName $vault.VaultName -ErrorAction Stop
                            
                            # Get access policies
                            $accessPolicies = $vaultDetail.AccessPolicies
                            
                            if ($accessPolicies -and $accessPolicies.Count -gt 0) {
                                # Check for recently modified access policies
                                # Note: We don't have direct access to when policies were modified
                                # We'd need to check the audit logs for this
 # Look for overly permissive policies
                                $highPrivilegePolicies = $accessPolicies | Where-Object {
                                    # Check if all permissions or many high-risk permissions are granted
                                    ($_.PermissionsToSecrets -contains "All" -or $_.PermissionsToSecrets.Count -gt 5) -or
                                    ($_.PermissionsToKeys -contains "All" -or $_.PermissionsToKeys.Count -gt 5) -or
                                    ($_.PermissionsToCertificates -contains "All" -or $_.PermissionsToCertificates.Count -gt 5)
                                }
                                
                                if ($highPrivilegePolicies -and $highPrivilegePolicies.Count -gt 0) {
                                    foreach ($policy in $highPrivilegePolicies) {
                                        # Try to resolve object ID to a name
                                        $objectName = "Unknown"
                                        $objectType = "Unknown"
                                        
                                        try {
                                            # Check if this is a service principal
                                            $sp = Get-AzADServicePrincipal -ObjectId $policy.ObjectId -ErrorAction SilentlyContinue
                                            if ($sp) {
                                                $objectName = $sp.DisplayName
                                                $objectType = "ServicePrincipal"
                                            }
                                            else {
                                                # Check if this is a user
                                                $user = Get-AzADUser -ObjectId $policy.ObjectId -ErrorAction SilentlyContinue
                                                if ($user) {
                                                    $objectName = $user.DisplayName
                                                    $objectType = "User"
                                                }
                                                else {
                                                    # Check if this is a group
                                                    $group = Get-AzADGroup -ObjectId $policy.ObjectId -ErrorAction SilentlyContinue
                                                    if ($group) {
                                                        $objectName = $group.DisplayName
                                                        $objectType = "Group"
                                                    }
                                                }
                                            }
                                        }
                                        catch {
                                            Write-Log -Message "Error resolving object ID $($policy.ObjectId): $($_.Exception.Message)" -Level Warning
                                        }
                                        
                                        $findings += Add-Finding -Category "KeyVault" -Title "High-privilege Key Vault access policy detected" `
                                            -Severity "Medium" `
                                            -Description "Entity '$objectName' ($objectType) has high-privilege access to Key Vault '$($vault.VaultName)'. This includes broad permissions to secrets, keys, or certificates." `
                                            -Recommendation "Review this access policy to ensure it follows the principle of least privilege and is assigned to a trusted entity." `
                                            -Data @{
                                                SubscriptionId = $subscription.Id
                                                SubscriptionName = $subscription.Name
                                                VaultName = $vault.VaultName
                                                ResourceGroupName = $vault.ResourceGroupName
                                                ObjectId = $policy.ObjectId
                                                ObjectName = $objectName
                                                ObjectType = $objectType
                                                PermissionsToSecrets = $policy.PermissionsToSecrets
                                                PermissionsToKeys = $policy.PermissionsToKeys
                                                PermissionsToCertificates = $policy.PermissionsToCertificates
                                            }
                                    }
                                }
                                
                                # Check for service principals with access
                                $servicePrincipalPolicies = @()
                                
                                foreach ($policy in $accessPolicies) {
                                    try {
                                        $sp = Get-AzADServicePrincipal -ObjectId $policy.ObjectId -ErrorAction SilentlyContinue
                                        if ($sp) {
                                            $servicePrincipalPolicies += @{
                                                Policy = $policy
                                                ServicePrincipal = $sp
                                            }
                                        }
                                    }
                                    catch {
                                        # Continue if we can't resolve
                                    }
                                }
                                
                                if ($servicePrincipalPolicies -and $servicePrincipalPolicies.Count -gt 0) {
                                    foreach ($spPolicy in $servicePrincipalPolicies) {
                                        $policy = $spPolicy.Policy
                                        $sp = $spPolicy.ServicePrincipal
                                        
                                        # Determine if this is a recently created service principal
                                        $isRecent = $false
                                        if ($sp.CreatedOn -and $sp.CreatedOn -ge $script:AnalysisStartDate) {
                                            $isRecent = $true
                                        }
                                        
                                        # Determine severity based on permissions and recency
                                        $severity = "Low"
                                        if ($isRecent) {
                                            $severity = "Medium"
                                        }
                                        
                                        if (($policy.PermissionsToSecrets -contains "All" -or $policy.PermissionsToSecrets -contains "Set") -or
                                            ($policy.PermissionsToKeys -contains "All" -or $policy.PermissionsToKeys -contains "Create") -or
                                            ($policy.PermissionsToCertificates -contains "All" -or $policy.PermissionsToCertificates -contains "Create")) {
                                            if ($isRecent) {
                                                $severity = "High"
                                            }
                                            else {
                                                $severity = "Medium"
                                            }
                                        }
                                        
                                        $findings += Add-Finding -Category "KeyVault" -Title "Service principal with Key Vault access" `
                                            -Severity $severity `
                                            -Description "Service principal '$($sp.DisplayName)' has access to Key Vault '$($vault.VaultName)'. $(if($isRecent){"This service principal was recently created."})" `
                                            -Recommendation "Verify that this service principal requires access to the Key Vault and that the permissions granted follow the principle of least privilege." `
                                            -Data @{
                                                SubscriptionId = $subscription.Id
                                                SubscriptionName = $subscription.Name
                                                VaultName = $vault.VaultName
                                                ResourceGroupName = $vault.ResourceGroupName
                                                ServicePrincipalId = $sp.Id
                                                ServicePrincipalName = $sp.DisplayName
                                                IsRecent = $isRecent
                                                CreatedOn = $sp.CreatedOn
                                                PermissionsToSecrets = $policy.PermissionsToSecrets
                                                PermissionsToKeys = $policy.PermissionsToKeys
                                                PermissionsToCertificates = $policy.PermissionsToCertificates
                                            }
                                    }
                                }
                            }
                            
                            # Check for recent key and secret access (requires key vault diagnostics logs)
                            try {
                                # This would typically involve checking Azure Monitor logs
                                # For now, we'll note that this check would be valuable but requires additional setup
                                
                                Write-Log -Message "Detailed Key Vault access history check would be performed here if diagnostics are enabled" -Level Debug
                            }
                            catch {
                                Write-Log -Message "Error checking Key Vault access history: $($_.Exception.Message)" -Level Warning
                            }
                        }
                        catch {
                            Write-Log -Message "Error analyzing Key Vault '$($vault.VaultName)': $($_.Exception.Message)" -Level Warning
                            $findings += Add-Finding -Category "KeyVault" -Title "Error analyzing Key Vault" `
                                -Severity "Low" `
                                -Description "An error occurred while analyzing Key Vault '$($vault.VaultName)': $($_.Exception.Message)" `
                                -Recommendation "Manually investigate this Key Vault's access policies and activity."
                        }
                    }
                }
                else {
                    Write-Log -Message "No Key Vaults found in subscription $($subscription.Name)" -Level Info
                }
            }
            catch {
                Write-Log -Message "Error checking subscription '$($subscription.Name)': $($_.Exception.Message)" -Level Warning
                $findings += Add-Finding -Category "KeyVault" -Title "Error checking subscription for Key Vaults" `
                    -Severity "Low" `
                    -Description "An error occurred while checking subscription '$($subscription.Name)' for Key Vaults: $($_.Exception.Message)" `
                    -Recommendation "Verify access permissions and manually investigate Key Vaults in this subscription."
            }
        }
        
        if ($findings.Count -eq 0) {
            $findings += Add-Finding -Category "KeyVault" -Title "No suspicious Key Vault access policies found" `
                -Severity "Informational" `
                -Description "No suspicious Key Vault access policies were found across all accessible subscriptions." `
                -Recommendation "Continue monitoring Key Vault access policies for unauthorized changes."
        }
        
        Write-Log -Message "Completed Key Vault access policy analysis. Found $($findings.Count) findings." -Level Info
    }
    catch {
        Write-Log -Message "Error analyzing Key Vault access policies: $($_.Exception.Message)" -Level Error
        $findings += Add-Finding -Category "KeyVault" -Title "Error analyzing Key Vault access policies" `
            -Severity "Medium" `
            -Description "An error occurred while analyzing Key Vault access policies: $($_.Exception.Message)" `
            -Recommendation "Manual investigation of Key Vault access policies is recommended."
    }
    
    return $findings
}

# Export the module function
Export-ModuleMember -Function Start-CrossServiceForensics

<#
.SYNOPSIS
    Unified Reporting & Analysis Module for M365 Compromise Assessment
.DESCRIPTION
    This module consolidates findings from all other forensic modules,
    performs cross-module correlation, risk scoring, timeline analysis,
    and generates comprehensive reports.
.NOTES
    Author: Dragos Ruiu
    Version 2.0
    Requires: Common PowerShell modules
    License: MIT
#>

function Start-UnifiedAnalysis {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$InputPath,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,
        
        [Parameter()]
        [ValidateSet("All", "Json", "Html", "Csv", "Excel", "Timeline")]
        [string[]]$ReportTypes = @("All"),
        
        [Parameter()]
        [switch]$DetailedLogging,
        
        [Parameter()]
        [ValidateRange(1, 100)]
        [int]$TopFindings = 20,
        
        [Parameter()]
        [ValidateSet("Severity", "Category", "Timestamp")]
        [string]$PrimarySortField = "Severity",
        
        [Parameter()]
        [ValidateSet("Severity", "Category", "Timestamp")]
        [string]$SecondarySortField = "Timestamp",
        
        [Parameter()]
        [switch]$IncludeInformational,
        
        [Parameter()]
        [switch]$IncludeRawFindings
    )
    
    begin {
        # Initialize logging
        $script:LogFile = Join-Path -Path $OutputPath -ChildPath "UnifiedAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        
        if (-not (Test-Path -Path $OutputPath)) {
            try {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created output directory: $OutputPath" -Level Info
            }
            catch {
                throw "Failed to create output directory: $($_.Exception.Message)"
            }
        }
        
        # Script-level variables
        $script:DetailedLogging = $DetailedLogging
        $script:AllFindings = @()
        $script:CategoryFindings = @{}
        $script:SeverityFindings = @{
            "High" = @()
            "Medium" = @()
            "Low" = @()
            "Informational" = @()
        }
        $script:Timeline = @()
        $script:RiskScores = @{}
        $script:RiskSummary = @()
        $script:RecommendationSummary = @()
        $script:SeverityWeights = @{
            "High" = 100
            "Medium" = 50
            "Low" = 10
            "Informational" = 0
        }
    }
    
    process {
        try {
            Write-Log -Message "Starting Unified Reporting & Analysis" -Level Info
            
            # Load all findings from input path
            $loadedFindings = Import-Findings -InputPath $InputPath
            
            if ($loadedFindings.Count -eq 0) {
                Write-Log -Message "No findings were loaded from the input path" -Level Warning
                throw "No findings were loaded from the input path. Please verify that the input path contains valid finding JSON files."
            }
            
            # Process and categorize findings
            Process-Findings -Findings $loadedFindings
            
            # Generate risk scores
            Calculate-RiskScores
            
            # Create summary reports
            Create-SummaryReports
            
            # Generate requested report types
            $reportTypesToGenerate = @()
            if ($ReportTypes -contains "All") {
                $reportTypesToGenerate = @("Json", "Html", "Csv", "Excel", "Timeline")
            }
            else {
                $reportTypesToGenerate = $ReportTypes
            }
            
            foreach ($reportType in $reportTypesToGenerate) {
                switch ($reportType) {
                    "Json" { Export-JsonReport }
                    "Html" { Export-HtmlReport }
                    "Csv" { Export-CsvReport }
                    "Excel" { Export-ExcelReport }
                    "Timeline" { Export-TimelineReport }
                }
            }
            
            Write-Log -Message "Unified Reporting & Analysis completed successfully" -Level Info
        }
        catch {
            Write-Log -Message "Error during Unified Reporting & Analysis: $($_.Exception.Message)" -Level Error
            Write-Log -Message "Stack Trace: $($_.ScriptStackTrace)" -Level Error
            throw "Unified Reporting & Analysis failed: $($_.Exception.Message)"
        }
    }
    
    end {
        Write-Log -Message "Unified Reporting & Analysis finished" -Level Info
    }
}

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("Info", "Warning", "Error", "Debug")]
        [string]$Level = "Info"
    )
    
    # Only log debug messages if detailed logging is enabled
    if ($Level -eq "Debug" -and -not $script:DetailedLogging) {
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Output to console based on level
    switch ($Level) {
        "Info" { Write-Host $logMessage }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Debug" { Write-Host $logMessage -ForegroundColor Cyan }
    }
    
    # Write to log file
    Add-Content -Path $script:LogFile -Value $logMessage
}

function Import-Findings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputPath
    )
    
    $allFindings = @()
    
    try {
        # Check if input path exists
        if (-not (Test-Path -Path $InputPath)) {
            Write-Log -Message "Input path does not exist: $InputPath" -Level Error
            throw "Input path does not exist: $InputPath"
        }
        
        # Find all JSON files in the input path (including subdirectories)
        $jsonFiles = Get-ChildItem -Path $InputPath -Filter "*.json" -Recurse
        
        Write-Log -Message "Found $($jsonFiles.Count) JSON files in the input path" -Level Info
        
        foreach ($file in $jsonFiles) {
            try {
                $content = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
                
                if ([string]::IsNullOrWhiteSpace($content)) {
                    Write-Log -Message "File is empty: $($file.FullName)" -Level Warning
                    continue
                }
                
                $findings = ConvertFrom-Json -InputObject $content -ErrorAction Stop
                
                # Handle both array and single object returns
                if ($findings -is [array]) {
                    $allFindings += $findings
                }
                else {
                    $allFindings += @($findings)
                }
                
                Write-Log -Message "Loaded $($findings.Count) findings from $($file.Name)" -Level Info
            }
            catch {
                Write-Log -Message "Error processing file $($file.FullName): $($_.Exception.Message)" -Level Warning
            }
        }
        
        # Deduplicate findings based on Id
        $uniqueFindings = $allFindings | Group-Object -Property Id | ForEach-Object { $_.Group[0] }
        
        Write-Log -Message "Loaded $($uniqueFindings.Count) unique findings from $($jsonFiles.Count) files" -Level Info
        
        return $uniqueFindings
    }
    catch {
        Write-Log -Message "Error importing findings: $($_.Exception.Message)" -Level Error
        throw "Failed to import findings: $($_.Exception.Message)"
    }
}

function Process-Findings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Findings
    )
    
    try {
        Write-Log -Message "Processing $($Findings.Count) findings" -Level Info
        
        # Store all findings
        $script:AllFindings = $Findings
        
        # Categorize findings
        foreach ($finding in $Findings) {
            # Ensure finding has all required properties
            if (-not $finding.Category -or -not $finding.Severity -or -not $finding.Title) {
                Write-Log -Message "Finding missing required properties: $($finding | ConvertTo-Json -Compress)" -Level Warning
                continue
            }
            
            # Filter out informational findings if not requested
            if (-not $IncludeInformational -and $finding.Severity -eq "Informational") {
                continue
            }
            
            # Group by category
            if (-not $script:CategoryFindings.ContainsKey($finding.Category)) {
                $script:CategoryFindings[$finding.Category] = @()
            }
            $script:CategoryFindings[$finding.Category] += $finding
            
            # Group by severity
            if ($script:SeverityFindings.ContainsKey($finding.Severity)) {
                $script:SeverityFindings[$finding.Severity] += $finding
            }
            
            # Add to timeline
            if ($finding.Timestamp) {
                $script:Timeline += $finding
            }
        }
        
        # Sort the timeline by timestamp
        $script:Timeline = $script:Timeline | Sort-Object -Property Timestamp
        
        Write-Log -Message "Finding counts by severity: High=$($script:SeverityFindings['High'].Count), Medium=$($script:SeverityFindings['Medium'].Count), Low=$($script:SeverityFindings['Low'].Count), Informational=$($script:SeverityFindings['Informational'].Count)" -Level Info
        
        # Log category breakdowns
        foreach ($category in $script:CategoryFindings.Keys) {
            Write-Log -Message "Category '$category': $($script:CategoryFindings[$category].Count) findings" -Level Debug
        }
    }
    catch {
        Write-Log -Message "Error processing findings: $($_.Exception.Message)" -Level Error
        throw "Failed to process findings: $($_.Exception.Message)"
    }
}

function Calculate-RiskScores {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Message "Calculating risk scores" -Level Info
        
        # Calculate overall risk score
        $totalScore = 0
        $totalWeight = 0
        
        foreach ($severity in $script:SeverityWeights.Keys) {
            $count = $script:SeverityFindings[$severity].Count
            $weight = $script:SeverityWeights[$severity]
            
            $totalScore += $count * $weight
            if ($count -gt 0) {
                $totalWeight += $weight
            }
        }
        
        $overallRiskScore = if ($totalWeight -gt 0) { [Math]::Round(($totalScore / $totalWeight) * 10) } else { 0 }
        
        $script:RiskScores["Overall"] = @{
            Score = $overallRiskScore
            Category = "Overall"
            HighCount = $script:SeverityFindings["High"].Count
            MediumCount = $script:SeverityFindings["Medium"].Count
            LowCount = $script:SeverityFindings["Low"].Count
            Findings = $script:AllFindings.Count
            RiskLevel = Get-RiskLevel -Score $overallRiskScore
        }
        
        Write-Log -Message "Overall risk score: $overallRiskScore ($($script:RiskScores["Overall"].RiskLevel))" -Level Info
        
        # Calculate category risk scores
        foreach ($category in $script:CategoryFindings.Keys) {
            $categoryFindings = $script:CategoryFindings[$category]
            $totalCategoryScore = 0
            $totalCategoryWeight = 0
            
            $highCount = ($categoryFindings | Where-Object { $_.Severity -eq "High" }).Count
            $mediumCount = ($categoryFindings | Where-Object { $_.Severity -eq "Medium" }).Count
            $lowCount = ($categoryFindings | Where-Object { $_.Severity -eq "Low" }).Count
            
            $totalCategoryScore += $highCount * $script:SeverityWeights["High"]
            $totalCategoryScore += $mediumCount * $script:SeverityWeights["Medium"]
            $totalCategoryScore += $lowCount * $script:SeverityWeights["Low"]
            
            if ($highCount -gt 0) { $totalCategoryWeight += $script:SeverityWeights["High"] }
            if ($mediumCount -gt 0) { $totalCategoryWeight += $script:SeverityWeights["Medium"] }
            if ($lowCount -gt 0) { $totalCategoryWeight += $script:SeverityWeights["Low"] }
            
            $categoryRiskScore = if ($totalCategoryWeight -gt 0) { [Math]::Round(($totalCategoryScore / $totalCategoryWeight) * 10) } else { 0 }
            
            $script:RiskScores[$category] = @{
                Score = $categoryRiskScore
                Category = $category
                HighCount = $highCount
                MediumCount = $mediumCount
                LowCount = $lowCount
                Findings = $categoryFindings.Count
                RiskLevel = Get-RiskLevel -Score $categoryRiskScore
            }
            
            Write-Log -Message "Risk score for category '$category': $categoryRiskScore ($($script:RiskScores[$category].RiskLevel))" -Level Debug
        }
        
        # Create risk summary for reporting
        $script:RiskSummary = $script:RiskScores.Keys | ForEach-Object {
            $script:RiskScores[$_]
        } | Sort-Object -Property Score -Descending
    }
    catch {
        Write-Log -Message "Error calculating risk scores: $($_.Exception.Message)" -Level Error
        throw "Failed to calculate risk scores: $($_.Exception.Message)"
    }
}

function Get-RiskLevel {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int]$Score
    )
    
    switch ($Score) {
        { $_ -ge 7 } { return "Critical" }
        { $_ -ge 5 } { return "High" }
        { $_ -ge 3 } { return "Medium" }
        { $_ -ge 1 } { return "Low" }
        default { return "None" }
    }
}

function Create-SummaryReports {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Message "Creating summary reports" -Level Info
        
        # Create top findings summary
        $topFindings = @()
        
        # Use primary and secondary sort fields
        switch ($PrimarySortField) {
            "Severity" {
                $primarySort = @{
                    Expression = {
                        switch ($_.Severity) {
                            "High" { 3 }
                            "Medium" { 2 }
                            "Low" { 1 }
                            "Informational" { 0 }
                            default { -1 }
                        }
                    }
                    Descending = $true
                }
            }
            "Category" {
                $primarySort = @{
                    Expression = { $_.Category }
                    Descending = $false
                }
            }
            "Timestamp" {
                $primarySort = @{
                    Expression = { $_.Timestamp }
                    Descending = $true
                }
            }
        }
        
        switch ($SecondarySortField) {
            "Severity" {
                $secondarySort = @{
                    Expression = {
                        switch ($_.Severity) {
                            "High" { 3 }
                            "Medium" { 2 }
                            "Low" { 1 }
                            "Informational" { 0 }
                            default { -1 }
                        }
                    }
                    Descending = $true
                }
            }
            "Category" {
                $secondarySort = @{
                    Expression = { $_.Category }
                    Descending = $false
                }
            }
            "Timestamp" {
                $secondarySort = @{
                    Expression = { $_.Timestamp }
                    Descending = $true
                }
            }
        }
        
        # Filter out informational findings if not requested
        $findingsToSort = if ($IncludeInformational) {
            $script:AllFindings
        }
        else {
            $script:AllFindings | Where-Object { $_.Severity -ne "Informational" }
        }
        
        # Apply sorting
        $sortedFindings = $findingsToSort | Sort-Object -Property $primarySort, $secondarySort
        
        # Take top N findings
        $topFindings = $sortedFindings | Select-Object -First $TopFindings
        
        # Group recommendations by frequency
        $recommendationFrequency = @{}
        foreach ($finding in $script:AllFindings) {
            if (-not [string]::IsNullOrWhiteSpace($finding.Recommendation)) {
                if (-not $recommendationFrequency.ContainsKey($finding.Recommendation)) {
                    $recommendationFrequency[$finding.Recommendation] = @{
                        Recommendation = $finding.Recommendation
                        Count = 0
                        HighCount = 0
                        MediumCount = 0
                        LowCount = 0
                        Categories = @{}
                    }
                }
                
                $recommendationFrequency[$finding.Recommendation].Count++
                
                switch ($finding.Severity) {
                    "High" { $recommendationFrequency[$finding.Recommendation].HighCount++ }
                    "Medium" { $recommendationFrequency[$finding.Recommendation].MediumCount++ }
                    "Low" { $recommendationFrequency[$finding.Recommendation].LowCount++ }
                }
                
                if (-not $recommendationFrequency[$finding.Recommendation].Categories.ContainsKey($finding.Category)) {
                    $recommendationFrequency[$finding.Recommendation].Categories[$finding.Category] = 0
                }
                $recommendationFrequency[$finding.Recommendation].Categories[$finding.Category]++
            }
        }
        
        # Sort recommendations by impact (weighted by severity)
        $script:RecommendationSummary = $recommendationFrequency.Values | ForEach-Object {
            $impact = ($_.HighCount * 10) + ($_.MediumCount * 5) + ($_.LowCount * 1)
            
            [PSCustomObject]@{
                Recommendation = $_.Recommendation
                Impact = $impact
                Count = $_.Count
                HighCount = $_.HighCount
                MediumCount = $_.MediumCount
                LowCount = $_.LowCount
                Categories = ($_.Categories.Keys | ForEach-Object { "$_($($_.Categories[$_]))" }) -join ", "
            }
        } | Sort-Object -Property Impact -Descending
    }
    catch {
        Write-Log -Message "Error creating summary reports: $($_.Exception.Message)" -Level Error
        throw "Failed to create summary reports: $($_.Exception.Message)"
    }
}

function Export-JsonReport {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Message "Exporting JSON report" -Level Info
        
        $reportFilePath = Join-Path -Path $OutputPath -ChildPath "UnifiedReport.json"
        
        $report = @{
            GeneratedAt = Get-Date
            OverallRiskScore = $script:RiskScores["Overall"]
            CategoryRiskScores = ($script:RiskScores.Keys | Where-Object { $_ -ne "Overall" } | ForEach-Object { $script:RiskScores[$_] })
            HighSeverityCount = $script:SeverityFindings["High"].Count
            MediumSeverityCount = $script:SeverityFindings["Medium"].Count
            LowSeverityCount = $script:SeverityFindings["Low"].Count
            InformationalCount = $script:SeverityFindings["Informational"].Count
            TopFindings = $topFindings
            TopRecommendations = $script:RecommendationSummary | Select-Object -First 10
            FindingsByCategory = $script:CategoryFindings
            AllFindings = if ($IncludeRawFindings) { $script:AllFindings } else { $null }
        }
        
        $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportFilePath -Encoding utf8 -Force
        
        Write-Log -Message "JSON report exported to $reportFilePath" -Level Info
    }
    catch {
        Write-Log -Message "Error exporting JSON report: $($_.Exception.Message)" -Level Error
    }
}

function Export-HtmlReport {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Message "Exporting HTML report" -Level Info
        
        $reportFilePath = Join-Path -Path $OutputPath -ChildPath "UnifiedReport.html"
        
        # Define HTML template with CSS styling
        $htmlTemplate = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>M365 Forensics Unified Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3, h4 {
            color: #0078d4;
        }
        .header {
            border-bottom: 2px solid #0078d4;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .summary-box {
            background-color: #f0f0f0;
            border-left: 4px solid #0078d4;
            padding: 15px;
            margin-bottom: 20px;
        }
        .risk-critical {
            background-color: #d13438;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
        }
        .risk-high {
            background-color: #ff8c00;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
        }
        .risk-medium {
            background-color: #ffd700;
            color: black;
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
        }
        .risk-low {
            background-color: #107c10;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
        }
        .risk-none {
            background-color: #ababab;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
        }
        .severity-high {
            background-color: #d13438;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.8em;
        }
        .severity-medium {
            background-color: #ff8c00;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.8em;
        }
        .severity-low {
            background-color: #ffd700;
            color: black;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.8em;
        }
        .severity-informational {
            background-color: #ababab;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.8em;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
        }
        th {
            background-color: #f2f2f2;
            text-align: left;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #f0f0f0;
        }
        .chart-container {
            width: 100%;
            max-width: 600px;
            margin: 20px 0;
        }
        .recommendation {
            background-color: #e6f2ff;
            border-left: 4px solid #0078d4;
            padding: 10px 15px;
            margin-bottom: 10px;
        }
        .filters {
            margin-bottom: 20px;
        }
        .expandable {
            cursor: pointer;
        }
        .expandable-content {
            display: none;
            padding: 10px;
            background-color: #f9f9f9;
            border: 1px solid #ddd;
            margin-top: 5px;
        }
    </style>
    <script>
        window.onload = function() {
            // Add click handlers for expandable sections
            var expandables = document.getElementsByClassName('expandable');
            for (var i = 0; i < expandables.length; i++) {
                expandables[i].addEventListener('click', function() {
                    var content = this.nextElementSibling;
                    if (content.style.display === 'block') {
                        content.style.display = 'none';
                    } else {
                        content.style.display = 'block';
                    }
                });
            }
        };
    </script>
</head>
<body>
    <div class="header">
        <h1>Microsoft 365 Forensics Unified Report</h1>
        <p>Generated: {0}</p>
    </div>

    <h2>Executive Summary</h2>
    <div class="summary-box">
        <h3>Overall Risk Assessment: <span class="risk-{1}">{2}</span></h3>
        <p>Score: {3}/10</p>
        <p>This assessment found {4} High severity, {5} Medium severity, and {6} Low severity findings across {7} categories.</p>
    </div>

    <h2>Risk Assessment by Category</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Risk Level</th>
            <th>Risk Score</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
            <th>Total Findings</th>
        </tr>
        {8}
    </table>

    <h2>Top Recommendations</h2>
    {9}

    <h2>Top {10} Findings</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Category</th>
            <th>Title</th>
            <th>Description</th>
        </tr>
        {11}
    </table>

    <h2>Findings by Category</h2>
    {12}

    <div class="footer">
        <p>&copy; {13} M365 Forensics</p>
    </div>
</body>
</html>
"@
        
        # Format date
        $formattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Format risk level
        $riskLevel = $script:RiskScores["Overall"].RiskLevel.ToLower()
        
        # Format risk assessment by category table rows
        $categoryRows = ""
        foreach ($category in ($script:RiskScores.Keys | Where-Object { $_ -ne "Overall" } | Sort-Object)) {
            $risk = $script:RiskScores[$category]
            $categoryRows += "<tr><td>$($category)</td><td><span class='risk-$($risk.RiskLevel.ToLower())'>$($risk.RiskLevel)</span></td><td>$($risk.Score)/10</td><td>$($risk.HighCount)</td><td>$($risk.MediumCount)</td><td>$($risk.LowCount)</td><td>$($risk.Findings)</td></tr>"
        }
        
        # Format recommendations
        $recommendations = ""
        for ($i = 0; $i -lt [Math]::Min($script:RecommendationSummary.Count, 10); $i++) {
            $rec = $script:RecommendationSummary[$i]
            $recommendations += "<div class='recommendation'><p><strong>$($i+1). $($rec.Recommendation)</strong></p><p>Impact: $($rec.Impact), Affects: $($rec.Count) findings ($($rec.HighCount) High, $($rec.MediumCount) Medium, $($rec.LowCount) Low)</p></div>"
        }
        
        # Format top findings table rows
        $findingRows = ""
        for ($i = 0; $i -lt [Math]::Min($topFindings.Count, $TopFindings); $i++) {
            $finding = $topFindings[$i]
            $findingRows += "<tr><td><span class='severity-$($finding.Severity.ToLower())'>$($finding.Severity)</span></td><td>$($finding.Category)</td><td>$($finding.Title)</td><td>$($finding.Description)</td></tr>"
        }
        
        # Format findings by category
        $categoryFindings = ""
        foreach ($category in $script:CategoryFindings.Keys | Sort-Object) {
            $findings = $script:CategoryFindings[$category]
            $categoryFindings += "<h3 class='expandable'>$category ($($findings.Count) findings)</h3>"
            $categoryFindings += "<div class='expandable-content'>"
            $categoryFindings += "<table>"
            $categoryFindings += "<tr><th>Severity</th><th>Title</th><th>Description</th></tr>"
            
            foreach ($finding in ($findings | Sort-Object -Property @{Expression={
                switch ($_.Severity) {
                    "High" { 3 }
                    "Medium" { 2 }
                    "Low" { 1 }
                    "Informational" { 0 }
                    default { -1 }
                }
            }; Descending = $true})) {
                $categoryFindings += "<tr><td><span class='severity-$($finding.Severity.ToLower())'>$($finding.Severity)</span></td><td>$($finding.Title)</td><td>$($finding.Description)</td></tr>"
            }
            
            $categoryFindings += "</table>"
            $categoryFindings += "</div>"
        }
        
        # Fill in template
        $htmlContent = $htmlTemplate -f `
            $formattedDate, `
            $riskLevel, `
            $script:RiskScores["Overall"].RiskLevel, `
            $script:RiskScores["Overall"].Score, `
            $script:SeverityFindings["High"].Count, `
            $script:SeverityFindings["Medium"].Count, `
            $script:SeverityFindings["Low"].Count, `
            $script:CategoryFindings.Count, `
            $categoryRows, `
            $recommendations, `
            $TopFindings, `
            $findingRows, `
            $categoryFindings, `
            (Get-Date).Year
        
        # Save to file
        $htmlContent | Out-File -FilePath $reportFilePath -Encoding utf8 -Force
        
        Write-Log -Message "HTML report exported to $reportFilePath" -Level Info
    }
    catch {
        Write-Log -Message "Error exporting HTML report: $($_.Exception.Message)" -Level Error
    }
}

function Export-CsvReport {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Message "Exporting CSV report" -Level Info
        
        $reportFilePath = Join-Path -Path $OutputPath -ChildPath "UnifiedReport.csv"
        
        # Create CSV-friendly objects
        $csvFindings = $script:AllFindings | ForEach-Object {
            [PSCustomObject]@{
                Category = $_.Category
                Severity = $_.Severity
                Title = $_.Title
                Description = $_.Description
                Recommendation = $_.Recommendation
                Timestamp = if ($_.Timestamp) { Get-Date $_.Timestamp -Format "yyyy-MM-dd HH:mm:ss" } else { "" }
                Risk = Get-RiskLevel -Score ($script:SeverityWeights[$_.Severity] / 10)
            }
        }
        
        # Export to CSV
        $csvFindings | Export-Csv -Path $reportFilePath -NoTypeInformation -Encoding UTF8
        
        Write-Log -Message "CSV report exported to $reportFilePath" -Level Info
        
        # Also export risk summary
        $riskSummaryPath = Join-Path -Path $OutputPath -ChildPath "RiskSummary.csv"
        
        $riskSummary = $script:RiskSummary | ForEach-Object {
            [PSCustomObject]@{
                Category = $_.Category
                RiskLevel = $_.RiskLevel
                RiskScore = $_.Score
                HighFindings = $_.HighCount
                MediumFindings = $_.MediumCount
                LowFindings = $_.LowCount
                TotalFindings = $_.Findings
            }
        }
        
        $riskSummary | Export-Csv -Path $riskSummaryPath -NoTypeInformation -Encoding UTF8
        
        Write-Log -Message "Risk summary CSV exported to $riskSummaryPath" -Level Info
        
        # Export recommendations summary
        $recommendationsPath = Join-Path -Path $OutputPath -ChildPath "Recommendations.csv"
        
        $script:RecommendationSummary | Export-Csv -Path $recommendationsPath -NoTypeInformation -Encoding UTF8
        
        Write-Log -Message "Recommendations CSV exported to $recommendationsPath" -Level Info
    }
    catch {
        Write-Log -Message "Error exporting CSV report: $($_.Exception.Message)" -Level Error
    }
}

function Export-ExcelReport {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Message "Checking for Excel module" -Level Info
        
        # Check if ImportExcel module is available
        if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
            Write-Log -Message "ImportExcel module not found. Excel report cannot be generated." -Level Warning
            Write-Log -Message "You can install the module with: Install-Module -Name ImportExcel -Scope CurrentUser" -Level Warning
            return
        }
        
        Import-Module ImportExcel
        
        Write-Log -Message "Exporting Excel report" -Level Info
        
        $reportFilePath = Join-Path -Path $OutputPath -ChildPath "UnifiedReport.xlsx"
        
        # Create Excel package
        $excelPackage = New-Object OfficeOpenXml.ExcelPackage
        
        # Create Summary worksheet
        $summaryWorksheet = $excelPackage.Workbook.Worksheets.Add("Summary")
        
        # Add summary information
        $summaryWorksheet.Cells[1, 1].Value = "Microsoft 365 Forensics - Unified Report"
        $summaryWorksheet.Cells[1, 1].Style.Font.Size = 16
        $summaryWorksheet.Cells[1, 1].Style.Font.Bold = $true
        
        $summaryWorksheet.Cells[2, 1].Value = "Generated: " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        
        $summaryWorksheet.Cells[4, 1].Value = "Overall Risk Score:"
        $summaryWorksheet.Cells[4, 2].Value = $script:RiskScores["Overall"].Score
        $summaryWorksheet.Cells[4, 3].Value = $script:RiskScores["Overall"].RiskLevel
        
        $summaryWorksheet.Cells[5, 1].Value = "High Severity Findings:"
        $summaryWorksheet.Cells[5, 2].Value = $script:SeverityFindings["High"].Count
        
        $summaryWorksheet.Cells[6, 1].Value = "Medium Severity Findings:"
        $summaryWorksheet.Cells[6, 2].Value = $script:SeverityFindings["Medium"].Count
        
        $summaryWorksheet.Cells[7, 1].Value = "Low Severity Findings:"
        $summaryWorksheet.Cells[7, 2].Value = $script:SeverityFindings["Low"].Count
        
        $summaryWorksheet.Cells[8, 1].Value = "Informational Findings:"
        $summaryWorksheet.Cells[8, 2].Value = $script:SeverityFindings["Informational"].Count
        
        $summaryWorksheet.Cells[9, 1].Value = "Total Categories:"
        $summaryWorksheet.Cells[9, 2].Value = $script:CategoryFindings.Count
        
        # Format summary cells
        $summaryWorksheet.Cells["A1:D9"].AutoFitColumns()
        
        # Create Risk Scores worksheet
        $riskWorksheet = $excelPackage.Workbook.Worksheets.Add("Risk Scores")
        
        # Add headers
        $riskWorksheet.Cells[1, 1].Value = "Category"
        $riskWorksheet.Cells[1, 2].Value = "Risk Level"
        $riskWorksheet.Cells[1, 3].Value = "Risk Score"
        $riskWorksheet.Cells[1, 4].Value = "High"
        $riskWorksheet.Cells[1, 5].Value = "Medium"
        $riskWorksheet.Cells[1, 6].Value = "Low"
        $riskWorksheet.Cells[1, 7].Value = "Total Findings"
        
        # Format headers
        $headerRange = "A1:G1"
        $riskWorksheet.Cells[$headerRange].Style.Font.Bold = $true
        $riskWorksheet.Cells[$headerRange].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $riskWorksheet.Cells[$headerRange].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGray)
        
        # Add data
        $row = 2
        foreach ($category in $script:RiskSummary) {
            $riskWorksheet.Cells[$row, 1].Value = $category.Category
            $riskWorksheet.Cells[$row, 2].Value = $category.RiskLevel
            $riskWorksheet.Cells[$row, 3].Value = $category.Score
            $riskWorksheet.Cells[$row, 4].Value = $category.HighCount
            $riskWorksheet.Cells[$row, 5].Value = $category.MediumCount
            $riskWorksheet.Cells[$row, 6].Value = $category.LowCount
            $riskWorksheet.Cells[$row, 7].Value = $category.Findings
            $row++
        }
        
        # Format risk scores
        $riskWorksheet.Cells["A1:G$($row-1)"].AutoFitColumns()
        
        # Create Recommendations worksheet
        $recommendationsWorksheet = $excelPackage.Workbook.Worksheets.Add("Recommendations")
        
        # Add headers
        $recommendationsWorksheet.Cells[1, 1].Value = "Recommendation"
        $recommendationsWorksheet.Cells[1, 2].Value = "Impact"
        $recommendationsWorksheet.Cells[1, 3].Value = "Total Findings"
        $recommendationsWorksheet.Cells[1, 4].Value = "High"
        $recommendationsWorksheet.Cells[1, 5].Value = "Medium"
        $recommendationsWorksheet.Cells[1, 6].Value = "Low"
        $recommendationsWorksheet.Cells[1, 7].Value = "Categories"
        
        # Format headers
        $headerRange = "A1:G1"
        $recommendationsWorksheet.Cells[$headerRange].Style.Font.Bold = $true
        $recommendationsWorksheet.Cells[$headerRange].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $recommendationsWorksheet.Cells[$headerRange].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGray)
        
        # Add data
        $row = 2
        foreach ($rec in $script:RecommendationSummary) {
            $recommendationsWorksheet.Cells[$row, 1].Value = $rec.Recommendation
            $recommendationsWorksheet.Cells[$row, 2].Value = $rec.Impact
            $recommendationsWorksheet.Cells[$row, 3].Value = $rec.Count
            $recommendationsWorksheet.Cells[$row, 4].Value = $rec.HighCount
            $recommendationsWorksheet.Cells[$row, 5].Value = $rec.MediumCount
            $recommendationsWorksheet.Cells[$row, 6].Value = $rec.LowCount
            $recommendationsWorksheet.Cells[$row, 7].Value = $rec.Categories
            $row++
        }
        
        # Format recommendations
        $recommendationsWorksheet.Cells["A1:G$($row-1)"].AutoFitColumns()
        
        # Create All Findings worksheet
        $findingsWorksheet = $excelPackage.Workbook.Worksheets.Add("All Findings")
        
        # Add headers
        $findingsWorksheet.Cells[1, 1].Value = "Category"
        $findingsWorksheet.Cells[1, 2].Value = "Severity"
        $findingsWorksheet.Cells[1, 3].Value = "Title"
        $findingsWorksheet.Cells[1, 4].Value = "Description"
        $findingsWorksheet.Cells[1, 5].Value = "Recommendation"
        $findingsWorksheet.Cells[1, 6].Value = "Timestamp"
        
        # Format headers
        $headerRange = "A1:F1"
        $findingsWorksheet.Cells[$headerRange].Style.Font.Bold = $true
        $findingsWorksheet.Cells[$headerRange].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $findingsWorksheet.Cells[$headerRange].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGray)
        
        # Add data
        $row = 2
        foreach ($finding in $script:AllFindings) {
            $findingsWorksheet.Cells[$row, 1].Value = $finding.Category
            $findingsWorksheet.Cells[$row, 2].Value = $finding.Severity
            $findingsWorksheet.Cells[$row, 3].Value = $finding.Title
            $findingsWorksheet.Cells[$row, 4].Value = $finding.Description
            $findingsWorksheet.Cells[$row, 5].Value = $finding.Recommendation
            $findingsWorksheet.Cells[$row, 6].Value = if ($finding.Timestamp) { Get-Date $finding.Timestamp -Format "yyyy-MM-dd HH:mm:ss" } else { "" }
            
            # Color code severity
            $colorCell = $findingsWorksheet.Cells[$row, 2]
            switch ($finding.Severity) {
                "High" { $colorCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(209, 52, 56)) } # Red
                "Medium" { $colorCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(255, 140, 0)) } # Orange
                "Low" { $colorCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(255, 215, 0)) } # Yellow
                "Informational" { $colorCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGray) } # Gray
            }
            $colorCell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $colorCell.Style.Font.Color.SetColor([System.Drawing.Color]::White)
            
            $row++
        }
        
        # Format findings
        $findingsWorksheet.Cells["A1:F$($row-1)"].AutoFitColumns()
        
        # Save Excel package
        $excelPackage.SaveAs($reportFilePath)
        $excelPackage.Dispose()
        
        Write-Log -Message "Excel report exported to $reportFilePath" -Level Info
    }
    catch {
        Write-Log -Message "Error exporting Excel report: $($_.Exception.Message)" -Level Error
    }
}

function Export-TimelineReport {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Message "Exporting Timeline report" -Level Info
        
        $reportFilePath = Join-Path -Path $OutputPath -ChildPath "Timeline.csv"
        
        # Format timeline events
        $timelineEvents = $script:Timeline | ForEach-Object {
            [PSCustomObject]@{
                Timestamp = if ($_.Timestamp) { Get-Date $_.Timestamp -Format "yyyy-MM-dd HH:mm:ss" } else { "" }
                Category = $_.Category
                Severity = $_.Severity
                Title = $_.Title
                Description = $_.Description
            }
        } | Sort-Object -Property Timestamp
        
        # Export to CSV
        $timelineEvents | Export-Csv -Path $reportFilePath -NoTypeInformation -Encoding UTF8
        
        Write-Log -Message "Timeline report exported to $reportFilePath" -Level Info
        
        # Create a more detailed HTML timeline
        $htmlTimelineFilePath = Join-Path -Path $OutputPath -ChildPath "Timeline.html"
        
        # HTML template for timeline
        $htmlTemplate = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>M365 Forensics Timeline</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #0078d4;
        }
        .header {
            border-bottom: 2px solid #0078d4;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .timeline {
            position: relative;
            max-width: 1200px;
            margin: 0 auto;
        }
        .timeline::after {
            content: '';
            position: absolute;
            width: 6px;
            background-color: #0078d4;
            top: 0;
            bottom: 0;
            left: 50px;
            margin-left: -3px;
        }
        .container {
            padding: 10px 40px;
            position: relative;
            background-color: inherit;
            width: 90%;
            margin-left: 60px;
            margin-bottom: 20px;
        }
        .container::after {
            content: '';
            position: absolute;
            width: 20px;
            height: 20px;
            right: 100%;
            background-color: white;
            border: 4px solid #0078d4;
            top: 15px;
            border-radius: 50%;
            z-index: 1;
            margin-right: -10px;
        }
        .high {
            border-left: 4px solid #d13438;
        }
        .medium {
            border-left: 4px solid #ff8c00;
        }
        .low {
            border-left: 4px solid #ffd700;
        }
        .informational {
            border-left: 4px solid #ababab;
        }
        .high::after {
            border-color: #d13438;
        }
        .medium::after {
            border-color: #ff8c00;
        }
        .low::after {
            border-color: #ffd700;
        }
        .informational::after {
            border-color: #ababab;
        }
        .content {
            padding: 15px;
            background-color: white;
            position: relative;
            border-radius: 6px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .severity-high {
            background-color: #d13438;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.8em;
        }
        .severity-medium {
            background-color: #ff8c00;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.8em;
        }
        .severity-low {
            background-color: #ffd700;
            color: black;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.8em;
        }
        .severity-informational {
            background-color: #ababab;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.8em;
        }
        .date {
            font-weight: bold;
            color: #0078d4;
        }
        .category {
            font-style: italic;
            color: #666;
        }
        h3 {
            margin-top: 0;
        }
        .filters {
            margin-bottom: 20px;
        }
    </style>
    <script>
        function filterTimeline() {
            var severityFilter = document.getElementById('severity-filter').value;
            var categoryFilter = document.getElementById('category-filter').value;
            
            var containers = document.getElementsByClassName('container');
            
            for (var i = 0; i < containers.length; i++) {
                var container = containers[i];
                var severity = container.getAttribute('data-severity').toLowerCase();
                var category = container.getAttribute('data-category');
                
                var matchesSeverity = severityFilter === 'all' || severity === severityFilter;
                var matchesCategory = categoryFilter === 'all' || category === categoryFilter;
                
                if (matchesSeverity && matchesCategory) {
                    container.style.display = '';
                } else {
                    container.style.display = 'none';
                }
            }
        }
        
        window.onload = function() {
            // Populate category filter
            var categories = [];
            var containers = document.getElementsByClassName('container');
            
            for (var i = 0; i < containers.length; i++) {
                var category = containers[i].getAttribute('data-category');
                if (categories.indexOf(category) === -1) {
                    categories.push(category);
                }
            }
            
            var categoryFilter = document.getElementById('category-filter');
            categories.sort().forEach(function(category) {
                var option = document.createElement('option');
                option.value = category;
                option.textContent = category;
                categoryFilter.appendChild(option);
            });
        };
    </script>
</head>
<body>
    <div class="header">
        <h1>Microsoft 365 Forensics Timeline</h1>
        <p>Generated: {0}</p>
    </div>
    
    <div class="filters">
        <label for="severity-filter">Filter by Severity:</label>
        <select id="severity-filter" onchange="filterTimeline()">
            <option value="all">All</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="informational">Informational</option>
        </select>
        
        <label for="category-filter" style="margin-left: 20px;">Filter by Category:</label>
        <select id="category-filter" onchange="filterTimeline()">
            <option value="all">All</option>
            <!-- Categories will be populated by JavaScript -->
        </select>
    </div>
    
    <div class="timeline">
        {1}
    </div>
    
    <div class="footer">
        <p>&copy; {2} M365 Forensics</p>
    </div>
</body>
</html>
"@
        
        # Format date
        $formattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Format timeline events for HTML
        $timelineHtml = ""
        $prevDate = $null
        
        foreach ($event in $timelineEvents) {
            # Check if we have a new date
            $currentDate = $null
            if ($event.Timestamp) {
                $currentDate = [DateTime]::ParseExact($event.Timestamp, "yyyy-MM-dd HH:mm:ss", $null).ToString("yyyy-MM-dd")
            }
            
            # Add date header if new day
            if ($currentDate -ne $prevDate) {
                $timelineHtml += "<h2>$currentDate</h2>"
                $prevDate = $currentDate
            }
            
            # Format event
            $timeClass = $event.Severity.ToLower()
            $timelineHtml += "<div class='container $timeClass' data-severity='$($event.Severity)' data-category='$($event.Category)'>"
            $timelineHtml += "<div class='content'>"
            $timelineHtml += "<span class='date'>$($event.Timestamp)</span> - <span class='category'>$($event.Category)</span> - <span class='severity-$($timeClass)'>$($event.Severity)</span>"
            $timelineHtml += "<h3>$($event.Title)</h3>"
            $timelineHtml += "<p>$($event.Description)</p>"
            $timelineHtml += "</div></div>"
        }
        
        # Fill in template
        $htmlContent = $htmlTemplate -f $formattedDate, $timelineHtml, (Get-Date).Year
        
        # Save to file
        $htmlContent | Out-File -FilePath $htmlTimelineFilePath -Encoding utf8 -Force
        
        Write-Log -Message "HTML Timeline exported to $htmlTimelineFilePath" -Level Info
    }
    catch {
        Write-Log -Message "Error exporting Timeline report: $($_.Exception.Message)" -Level Error
    }
}

# Export the module function
Export-ModuleMember -Function Start-UnifiedAnalysis







