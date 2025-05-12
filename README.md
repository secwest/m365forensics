# Microsoft 365 Post-Admin-Compromise Forensics Framework

Author: Dragos Ruiu - May 11 2025

## Overview

This PowerShell code represents an analysis framework designed specifically for Microsoft 365 environments. It's primarily focused on detecting potential attacker persistence mechanisms following an admin-level compromise. The framework consists of multiple specialized modules that analyze various M365 services, identify suspicious configurations, and generate detailed reports. These checks are designed to be run with a minimum of an E3 M365 subscription level.

## Purpose

After an admin-level compromise in Microsoft 365, attackers often establish persistence mechanisms to maintain access even after the initial breach is discovered. This framework helps security teams:

- Systematically scan all major M365 services for suspicious configurations
- Identify potential backdoors and persistence mechanisms
- Generate comprehensive reports for remediation
- Create timelines of suspicious activities

## Framework Components

The framework consists of the following modules:

- Exchange Online Forensics - Analyzes mailbox forwarding, transport rules, and permissions
- Entra ID Core Forensics - Examines directory roles, applications, and federation settings
- Entra ID Advanced Forensics - Examines administrative units, partner relationships, device registrations
- SharePoint Forensics - Analyzes site permissions, add-ins, and external sharing
- Teams Forensics - Examines external access, app permissions, and channel settings
- Power Platform Forensics - Analyzes flows, apps, custom connectors, and data policies
- Cross-Service Forensics - Examines Azure integration, API permissions, and SIEM connections
- Unified Analysis - Consolidates findings, generates risk scores, and creates reports

## Forensic Checks by Category

### Exchange Online Checks

- **OutboundSpam**: Identify suspicious outbound spam filter policies that might allow data exfiltration
- **RemoteDomains**: Detect wildcards or auto-forwarding configurations in remote domains
- **TransportRules**: Identify rules that forward, redirect, or modify messages to external domains
- **MailboxForwarding**: Detect mailboxes configured to forward to external recipients
- **InboxRules**: Identify suspicious inbox rules that may forward, delete, or hide emails
- **MailboxPermissions**: Detect unusual permissions granted to mailboxes, especially for external users
- **MailConnectors**: Analyze mail connectors for suspicious configurations and bypasses
- **JournalingRules**: Identify journaling rules that could be used for data exfiltration
- **EmailSecurity**: Check for disabled security features or suspicious configurations

### Entra ID Core Checks

- **UserAccounts**: Identify recently created accounts, suspicious naming patterns, and disabled MFA
- **DirectoryRoles**: Detect unusual role assignments, especially for sensitive roles
- **Applications**: Identify suspicious applications with high-risk permissions
- **OAuthGrants**: Detect suspicious OAuth permission grants, especially to external applications
- **FederationSettings**: Analyze federation configurations for unauthorized changes
- **ConditionalAccess**: Detect weakened or disabled conditional access policies
- **SignInAnalysis**: Identify unusual sign-in patterns or dormant accounts suddenly becoming active

### Entra ID Advanced Checks

- **AdminUnits**: Detect administrative units with suspicious scoped role assignments
- **PartnerRelationships**: Identify unauthorized partner/delegated admin relationships
- **DeviceRegistrations**: Detect suspicious device registrations, especially for privileged accounts
- **GuestAccess**: Identify unusual guest access, especially to sensitive resources
- **PrivilegedGroups**: Detect changes to groups with privileged roles
- **CrossTenantSync**: Identify suspicious cross-tenant synchronization configurations

### SharePoint & OneDrive Checks

- **SiteAdmins**: Detect suspicious site collection administrators, especially external users
- **ExternalSharing**: Identify sites with elevated sharing capabilities and external links
- **AddIns**: Detect potentially malicious SharePoint add-ins and SPFx solutions
- **InformationBarriers**: Identify changes to information barrier policies
- **SitePermissions**: Detect unusual permissions granted to sites, especially for external users

### Teams & Collaboration Checks

- **ExternalAccess**: Identify risky external access configurations and guest access
- **TeamOwnership**: Detect teams with suspicious ownership patterns or single owners
- **TeamsApps**: Identify suspicious Teams apps with excessive permissions
- **PrivateChannels**: Detect private channels with suspicious membership configurations

### Power Platform Checks

- **PowerAutomateFlows**: Identify suspicious flows that could be used for data exfiltration
- **PowerApps**: Detect apps with suspicious permissions or external connections
- **CustomConnectors**: Identify custom connectors to external services
- **DataverseRoles**: Detect unusual security role assignments in Dataverse
- **DataLossPrevention**: Identify weakened or disabled data loss prevention policies

### Cross-Service & Azure Integration Checks

- **AzureAutomation**: Detect suspicious Azure Automation accounts, runbooks, and webhooks
- **GraphSubscriptions**: Identify suspicious Graph API subscriptions
- **AppProxy**: Detect suspicious Application Proxy configurations
- **SecureScore**: Analyze changes to Secure Score and disabled security controls
- **ApiPermissions**: Identify suspicious API permission changes and grants
- **CustomEndpoints**: Detect webhooks and custom integration endpoints
- **DlpPolicies**: Identify weakened or disabled DLP policies
- **AuditLogs**: Detect changes to audit log policies and retention settings
- **SiemIntegration**: Check SIEM integrations and log forwarding configurations
- **KeyVault**: Analyze Azure Key Vault access policies for suspicious access

## Using This Framework

To use this framework effectively:

1. Run the relevant module scans on a suspected compromised tenant
2. Review the findings and prioritize remediation based on severity
3. Use the unified analysis to identify patterns and systemic issues
4. Generate reports for stakeholders and remediation teams

This framework should be part of a broader incident response strategy and used in conjunction with other security tools and practices.

## Security Considerations

- Run this tool with appropriate permissions but in a secure, controlled environment
- Ensure that the account used for scanning cannot be monitored by potential attackers
- Consider running scans from a clean, isolated workstation
- Be aware that sophisticated attackers may attempt to hide their persistence mechanisms

## Important Notes

- This framework focuses on detecting persistence mechanisms, not necessarily the initial compromise
- Some checks require specific modules or permissions that may not be available in all environments
- False positives are possible and all findings should be investigated before remediation
- Regular scanning can help identify unauthorized changes over time
