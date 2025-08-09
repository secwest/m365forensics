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
#  - Extend the predicate/action maps if you use rarer fields.

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
  param($v)
  if ($null -eq $v) { return '$null' }
  if ($v -is [bool]) {
    if ($v) { return '$true' } else { return '$false' }
  }
  if ($v -is [int] -or $v -is [long] -or $v -is [double]) { return "$v" }
  $s = ($v.ToString() -replace "'", "''")
  return "'$s'"
}

function JA {
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
  @{ P = "FromAddressContainsWords";            K = "-FromAddressContainsWords" },
  @{ P = "SenderDomainIs";                      K = "-SenderDomainIs" },
  @{ P = "RecipientDomainIs";                   K = "-RecipientDomainIs" },
  @{ P = "SubjectContainsWords";                K = "-SubjectContainsWords" },
  @{ P = "HeaderMatchesMessageHeader";          K = "-HeaderMatchesMessageHeader" },
  @{ P = "HeaderMatchesPatterns";               K = "-HeaderMatchesPatterns" },
  @{ P = "HasSenderOverride";                   K = "-HasSenderOverride" },
  @{ P = "MessageTypeMatches";                  K = "-MessageTypeMatches" },
  @{ P = "AttachmentExtensionMatchesWords";     K = "-AttachmentExtensionMatchesWords" },
  @{ P = "AttachmentContainsWords";             K = "-AttachmentContainsWords" },
  @{ P = "SenderIpRanges";                      K = "-SenderIpRanges" },
  @{ P = "AnyOfRecipientAddressMatchesPatterns";K = "-AnyOfRecipientAddressMatchesPatterns" },
  @{ P = "ExceptIfRecipientDomainIs";           K = "-ExceptIfRecipientDomainIs" },
  @{ P = "ExceptIfSubjectContainsWords";        K = "-ExceptIfSubjectContainsWords" },
  @{ P = "ExceptIfHeaderMatchesMessageHeader";  K = "-ExceptIfHeaderMatchesMessageHeader" },
  @{ P = "ExceptIfHeaderMatchesPatterns";       K = "-ExceptIfHeaderMatchesPatterns" }
)

$ActionFields = @(
  @{ P = "RedirectMessageTo";                   K = "-RedirectMessageTo" },
  @{ P = "BlindCopyTo";                         K = "-BlindCopyTo" },
  @{ P = "AddToRecipients";                     K = "-AddToRecipients" },
  @{ P = "RouteMessageOutboundConnector";       K = "-RouteMessageOutboundConnector" },
  @{ P = "ApplyHtmlDisclaimerLocation";         K = "-ApplyHtmlDisclaimerLocation" },
  @{ P = "PrependSubject";                      K = "-PrependSubject" },
  @{ P = "ModifySubject";                       K = "-ModifySubject" },
  @{ P = "SetAuditSeverity";                    K = "-SetAuditSeverity" },
  @{ P = "DeleteMessage";                       K = "-DeleteMessage" },
  @{ P = "RejectMessageReasonText";             K = "-RejectMessageReasonText" },
  @{ P = "SetSCL";                              K = "-SetSCL" }
)

function Describe-TransportRule {
  param($r)

  Write-Host "BEGIN EXO-TRANSPORT-RULE"
  Write-Host ("Name: "      + $r.Name)
  Write-Host ("Enabled: "   + $r.Enabled)
  Write-Host ("Mode: "      + $r.Mode)            # Enforce, Audit, TestWith/WithoutPolicyTips
  Write-Host ("Priority: "  + $r.Priority)
  if ($r.Comments) { Write-Host ("Comments: " + ($r.Comments -replace "`r?`n"," | ")) }

  # Conditions
  $condPairs = @()
  foreach ($m in $PredicateFields) {
    $pv = $r.($m.P)
    if ($null -ne $pv -and ($pv -isnot [bool] -or $pv)) {
      if ($pv -is [System.Collections.IEnumerable] -and -not ($pv -is [string])) {
        $pv = @($pv)
      }
      $val = ""
      if ($pv -is [System.Array]) { $val = ($pv -join ", ") } else { $val = "$pv" }
      $condPairs += ("  - {0}: {1}" -f $m.P, $val)
    }
  }
  if ($condPairs.Count -gt 0) {
    Write-Host "If:"
    $condPairs | ForEach-Object { Write-Host $_ }
  } else {
    Write-Host "If: <none>"
  }

  # Actions
  $actPairs = @()
  foreach ($m in $ActionFields) {
    $pv = $r.($m.P)
    if ($null -ne $pv -and ($pv -isnot [bool] -or $pv)) {
      if ($pv -is [System.Collections.IEnumerable] -and -not ($pv -is [string])) {
        $pv = @($pv)
      }
      $val = ""
      if ($pv -is [System.Array]) { $val = ($pv -join ", ") } else { $val = "$pv" }
      $actPairs += ("  - {0}: {1}" -f $m.P, $val)
    }
  }
  if ($actPairs.Count -gt 0) {
    Write-Host "Then:"
    $actPairs | ForEach-Object { Write-Host $_ }
  } else {
    Write-Host "Then: <none>"
  }

  # Recreate command
  $parts = @()
  $parts += ("New-TransportRule -Name " + (J $r.Name))

  $enabledStr = '$false'
  if ($r.Enabled) { $enabledStr = '$true' }
  $parts += ("-Enabled " + $enabledStr)

  if ($r.Mode) { $parts += ("-Mode " + (J $r.Mode)) }
  if ($r.Priority -ne $null) { $parts += ("-Priority {0}" -f [int]$r.Priority) }

  foreach ($m in $PredicateFields) {
    $pv = $r.($m.P)
    if ($null -ne $pv -and ($pv -isnot [bool] -or $pv)) {
      if ($pv -is [System.Collections.IEnumerable] -and -not ($pv -is [string])) { $pv = @($pv) }
      if ($pv -is [System.Array]) { $parts += ("{0} {1}" -f $m.K, (JA $pv)) }
      else { $parts += ("{0} {1}" -f $m.K, (J $pv)) }
    }
  }
  foreach ($m in $ActionFields) {
    $pv = $r.($m.P)
    if ($null -ne $pv -and ($pv -isnot [bool] -or $pv)) {
      if ($pv -is [System.Collections.IEnumerable] -and -not ($pv -is [string])) { $pv = @($pv) }
      if ($pv -is [System.Array]) {
        $parts += ("{0} {1}" -f $m.K, (JA $pv))
      } else {
        if ($pv -is [bool]) {
          if ($pv) { $parts += $m.K }
        } else {
          $parts += ("{0} {1}" -f $m.K, (J $pv))
        }
      }
    }
  }

  Write-Host ("Recreate: " + ($parts -join " ")) -ForegroundColor Yellow
  Write-Host "END EXO-TRANSPORT-RULE"
  Write-Host ""
}

function Is-ExternalAddress {
  param([string]$Address, [string[]]$AcceptedDomains)
  if (-not $Address) { return $false }
  $addr = $Address.Trim('<>').ToLowerInvariant()
  $domain = ($addr -split '@')[-1]
  return -not ($AcceptedDomains -contains $domain)
}

function Print-MailboxPosture {
  param($mbx, [string[]]$AcceptedDomains)

  $upn = $mbx.PrimarySmtpAddress
  Write-Host ("BEGIN MAILBOX-POSTURE " + $upn)
  Write-Host ("RecipientTypeDetails: " + $mbx.RecipientTypeDetails)
  Write-Host ("AuditEnabled: " + $mbx.AuditEnabled)

  if ($mbx.ForwardingSMTPAddress) {
    $ext = Is-ExternalAddress -Address $mbx.ForwardingSMTPAddress -AcceptedDomains $AcceptedDomains
    Write-Host ("ForwardingSMTPAddress: {0}" -f $mbx.ForwardingSMTPAddress)
    Write-Host ("DeliverToMailboxAndForward: {0}" -f $mbx.DeliverToMailboxAndForward)
    Write-Host ("ForwardingSMTPAddressIsExternal: {0}" -f $ext)

    $deliverStr = '$false'
    if ($mbx.DeliverToMailboxAndForward) { $deliverStr = '$true' }

    $cmd = @(
      "Set-Mailbox -Identity", (J $upn),
      "-ForwardingSMTPAddress", (J $mbx.ForwardingSMTPAddress.ToString()),
      "-DeliverToMailboxAndForward", $deliverStr
    ) -join " "
    Write-Host ("Recreate: " + $cmd) -ForegroundColor Yellow
  } else {
    Write-Host "ForwardingSMTPAddress: <none>"
  }

  if ($mbx.ForwardingAddress) {
    Write-Host ("ForwardingAddress (directory object): {0}" -f $mbx.ForwardingAddress)
    $cmd2 = @(
      "Set-Mailbox -Identity", (J $upn),
      "-ForwardingAddress", (J $mbx.ForwardingAddress.ToString())
    ) -join " "
    Write-Host ("Recreate: " + $cmd2) -ForegroundColor Yellow
  } else {
    Write-Host "ForwardingAddress: <none>"
  }

  # Delegations
  $sendAs = (Get-RecipientPermission -Identity $upn -ErrorAction SilentlyContinue |
              Where-Object { $_.Trustee -ne "NT AUTHORITY\SELF" -and $_.AccessRights -contains "SendAs" }) |
              Select-Object -ExpandProperty Trustee -ErrorAction SilentlyContinue
  $mailboxPerm = (Get-MailboxPermission -Identity $upn -ErrorAction SilentlyContinue |
                  Where-Object { -not $_.IsInherited -and $_.User -notmatch '^S-1-5-' -and $_.User -ne "NT AUTHORITY\SELF" })

  if ($sendAs) { Write-Host ("SendAs: " + ($sendAs -join ", ")) } else { Write-Host "SendAs: <none>" }
  if ($mailboxPerm) {
    Write-Host "MailboxPermissions:"
    foreach ($p in $mailboxPerm) {
      Write-Host ("  - {0}: {1}" -f $p.User, ($p.AccessRights -join "+"))
    }
  } else {
    Write-Host "MailboxPermissions: <none>"
  }

  Write-Host "END MAILBOX-POSTURE"
  Write-Host ""
}

function Describe-InboxRule {
  param($ir, $mailbox)

  Write-Host ("BEGIN INBOX-RULE {0} :: {1}" -f $mailbox, $ir.Name)
  Write-Host ("Enabled: " + $ir.Enabled)
  Write-Host ("Priority: " + $ir.Priority)
  Write-Host ("StopProcessing: " + $ir.StopProcessingRules)

  # Conditions (subset commonly used; extend as needed)
  $conds = @()
  if ($ir.From) { $conds += ("From: " + ($ir.From -join ", ")) }
  if ($ir.SenderAddressContainsWords) { $conds += ("SenderAddressContainsWords: " + ($ir.SenderAddressContainsWords -join ", ")) }
  if ($ir.SubjectContainsWords) { $conds += ("SubjectContainsWords: " + ($ir.SubjectContainsWords -join ", ")) }
  if ($ir.BodyContainsWords) { $conds += ("BodyContainsWords: " + ($ir.BodyContainsWords -join ", ")) }
  if ($ir.MyNameInToOrCcBox) { $conds += "MyNameInToOrCcBox: True" }
  if ($ir.HasAttachment) { $conds += "HasAttachment: True" }
  if ($conds.Count -gt 0) {
    Write-Host "When:"
    $conds | ForEach-Object { Write-Host ("  - " + $_) }
  } else { Write-Host "When: <none>" }

  # Actions
  $acts = @()
  if ($ir.RedirectTo)      { $acts += ("RedirectTo: " + ($ir.RedirectTo -join ", ")) }
  if ($ir.ForwardTo)       { $acts += ("ForwardTo: " + ($ir.ForwardTo -join ", ")) }
  if ($ir.MoveToFolder)    { $acts += ("MoveToFolder: " + $ir.MoveToFolder) }
  if ($ir.CopyToFolder)    { $acts += ("CopyToFolder: " + $ir.CopyToFolder) }
  if ($ir.DeleteMessage)   { $acts += "DeleteMessage: True" }
  if ($ir.PermanentDelete) { $acts += "PermanentDelete: True" }
  if ($ir.MarkAsRead)      { $acts += "MarkAsRead: True" }
  if ($ir.AssignCategories){ $acts += ("AssignCategories: " + ($ir.AssignCategories -join ", ")) }
  if ($acts.Count -gt 0) {
    Write-Host "Then:"
    $acts | ForEach-Object { Write-Host ("  - " + $_) }
  } else { Write-Host "Then: <none>" }

  # Recreate
  $enabledRuleStr = '$false'
  if ($ir.Enabled) { $enabledRuleStr = '$true' }

  $cmd = @("New-InboxRule -Mailbox", (J $mailbox), "-Name", (J $ir.Name), "-Priority", ([int]$ir.Priority), "-Enabled", $enabledRuleStr)
  if ($ir.From)                      { $cmd += @("-From", (JA @($ir.From))) }
  if ($ir.SenderAddressContainsWords){ $cmd += @("-SenderAddressContainsWords", (JA @($ir.SenderAddressContainsWords))) }
  if ($ir.SubjectContainsWords)      { $cmd += @("-SubjectContainsWords", (JA @($ir.SubjectContainsWords))) }
  if ($ir.BodyContainsWords)         { $cmd += @("-BodyContainsWords", (JA @($ir.BodyContainsWords))) }
  if ($ir.MyNameInToOrCcBox)         { $cmd += "-MyNameInToOrCcBox" }
  if ($ir.HasAttachment)             { $cmd += "-HasAttachment" }
  if ($ir.RedirectTo)                { $cmd += @("-RedirectTo", (JA @($ir.RedirectTo))) }
  if ($ir.ForwardTo)                 { $cmd += @("-ForwardTo", (JA @($ir.ForwardTo))) }
  if ($ir.MoveToFolder)              { $cmd += @("-MoveToFolder", (J $ir.MoveToFolder)) }
  if ($ir.CopyToFolder)              { $cmd += @("-CopyToFolder", (J $ir.CopyToFolder)) }
  if ($ir.DeleteMessage)             { $cmd += "-DeleteMessage" }
  if ($ir.PermanentDelete)           { $cmd += "-PermanentDelete" }
  if ($ir.MarkAsRead)                { $cmd += "-MarkAsRead" }
  if ($ir.AssignCategories)          { $cmd += @("-AssignCategories", (JA @($ir.AssignCategories))) }
  if ($ir.StopProcessingRules)       { $cmd += "-StopProcessingRules" }

  Write-Host ("Recreate: " + ($cmd -join " ")) -ForegroundColor Yellow
  Write-Host "END INBOX-RULE"
  Write-Host ""
}

function Main {
  Ensure-Module -Name ExchangeOnlineManagement -MinVersion "3.2.0"
  Connect-ExoSafe

  # Accepted domains for external detection (used in mailbox posture)
  $acceptedDomains = (Get-AcceptedDomain | Select-Object -ExpandProperty DomainName) | ForEach-Object { $_.ToLowerInvariant() }

  Print-Header "Transport Rules"
  $trs = Get-TransportRule -ResultSize Unlimited
  foreach ($r in $trs | Sort-Object Priority) {
    Describe-TransportRule -r $r
  }

  Print-Header "Mailbox Forwarding / Delegation"
  $mbxs = Get-ExoMailbox -ResultSize Unlimited -Properties ForwardingSMTPAddress,ForwardingAddress,DeliverToMailboxAndForward,RecipientTypeDetails,AuditEnabled,PrimarySmtpAddress
  foreach ($m in $mbxs | Sort-Object PrimarySmtpAddress) {
    Print-MailboxPosture -mbx $m -AcceptedDomains $acceptedDomains
  }

  if ($InboxRules) {
    Print-Header "Inbox Rules (Per Mailbox)"
    foreach ($m in $mbxs) {
      $upn = $m.PrimarySmtpAddress
      try {
        $rules = Get-InboxRule -Mailbox $upn -ErrorAction Stop
        foreach ($ir in $rules | Sort-Object Priority) {
          Describe-InboxRule -ir $ir -mailbox $upn
        }
      } catch {
        Write-Warning ("Failed to enumerate Inbox rules for {0}: {1}" -f $upn, $_.Exception.Message)
      }
    }
  }

  Write-Host ""
  Write-Host "Done."
}

Main
