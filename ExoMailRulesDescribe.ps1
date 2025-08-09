#!/usr/bin/env pwsh
# ExoMailRuleDescribe.ps1
# Prints reconstructable console descriptions of:
#  - Exchange Online Transport Rules
#  - Mailbox-level forwarding/delegation
#  - (optional) Inbox Rules per mailbox
#
# Requires: ExchangeOnlineManagement (>= 3.2.0)
# Usage:
#   pwsh ./ExoMailRuleDescribe.ps1
#   pwsh ./ExoMailRuleDescribe.ps1 -InboxRules
#
# Notes:
#  - Output is deterministic and ASCII-clean.
#  - "Recreate" lines approximate the minimal parameter set to reproduce the visible behavior.
#  - Not all advanced predicates/actions are exposed here; extend the predicate/action maps if you use rarer fields.

param(
  [switch]$InboxRules
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Module {
  param([string]$Name, [string]$MinVersion = $null)
  $m = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
  if (-not $m -or ($MinVersion -and [version]$m.Version -lt [version]$MinVersion)) {
    Install-Module $Name -Scope CurrentUser -Force -AllowClobber
  }
  Import-Module $Name -ErrorAction Stop
}

function Connect-ExoSafe {
  Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
  Connect-ExchangeOnline -ShowProgress $true
}

function J {
  # Quote a single scalar value for PowerShell (string or number)
  param($v)
  if ($null -eq $v) { return '$null' }
  if ($v -is [bool]) { return ($v ? '$true' : '$false') }
  if ($v -is [int] -or $v -is [long] -or $v -is [double]) { return "$v" }
  $s = ($v.ToString() -replace "'", "''")
  return "'$s'"
}
function JA {
  # Quote an array as a PS array literal
  param([object[]]$arr)
  if (-not $arr -or $arr.Count -eq 0) { return '@()' }
  $q = $arr | ForEach-Object { J $_ }
  return "@(" + ($q -join ", ") + ")"
}

function Print-Header($text) {
  Write-Host ""
  Write-Host $text
  Write-Host ("-" * $text.Length)
}

# Map selected predicates/actions we will render. Extend as needed.
$PredicateFields = @(
  # Left side = property name from Get-TransportRule; Right = switch/param name for New-TransportRule
  @{ P="FromAddressContainsWords";          K="-FromAddressContainsWords" },
  @{ P="SenderDomainIs";                    K="-SenderDomainIs" },
  @{ P="RecipientDomainIs";                 K="-RecipientDomainIs" },
  @{ P="SubjectContainsWords";              K="-SubjectContainsWords" },
  @{ P="HeaderMatchesMessageHeader";        K="-HeaderMatchesMessageHeader" },
  @{ P="HeaderMatchesPatterns";             K="-HeaderMatchesPatterns" },
  @{ P="HasSenderOverride";                 K="-HasSenderOverride" },
  @{ P="MessageTypeMatches";                K="-MessageTypeMatches" },
  @{ P="AttachmentExtensionMatchesWords";   K="-AttachmentExtensionMatchesWords" },
  @{ P="AttachmentContainsWords";           K="-AttachmentContainsWords" },
  @{ P="SenderIpRanges";                    K="-SenderIpRanges" },
  @{ P="AnyOfRecipientAddressMatchesPatterns"; K="-AnyOfRecipientAddressMatchesPatterns" },
  @{ P="ExceptIfRecipientDomainIs";         K="-ExceptIfRecipientDomainIs" },
  @{ P="ExceptIfSubjectContainsWords";      K="-ExceptIfSubjectContainsWords" },
  @{ P
