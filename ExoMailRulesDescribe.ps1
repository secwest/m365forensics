#!/usr/bin/env pwsh
# ExoMailRuleDescribe.ps1 (robust)
# Console descriptions + reconstructable commands for:
#   - Exchange Online Transport Rules
#   - Mailbox forwarding/delegation
#   - (optional) Inbox Rules
#
# Requirements: ExchangeOnlineManagement (>= 3.2.0)

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
  Connect-ExchangeOnline -ShowProgress:$true
}

# ----- Safe access helpers -----
function Has-Prop {
  param($obj, [string]$Name)
  if ($null -eq $obj) { return $false }
  try {
    $m = $obj | Get-Member -Name $Name -ErrorAction Stop
    return $null -ne $m
  } catch { return $false }
}
function Get-Prop {
  param($obj, [string]$Name, $Default = $null)
  if (Has-Prop $obj $Name) {
    try { return $obj.$Name } catch { return $Default }
  }
  return $Default
}

# ----- Quoting helpers (PS5/7 clean) -----
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
function To-Flat {
  param($v)
  if ($null -eq $v) { return "" }
  if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
    $a = @($v)
    return ($a -join ", ")
  }
  return "$v"
}

function Print-Header($text) {
  Write-Host ""
  Write-Host $text
  Write-Host ("-" * $text.Length)
}

# Maps we render (extend as needed)
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
  Write-Host ("Name: " + (Get-Prop $r 'Name' '<unknown>'))

  # Enabled is not always present; some builds have State: Enabled/Disabled
  $enabledBool = $null
  if (Has-Prop $r 'Enabled') {
    $enabledBool = [bool](Get-Prop $r 'Enabled' $false)
  } elseif (Has-Prop $r 'State') {
    $st = (Get-Prop $r 'State' '')
    if ($st -is [string]) { $enabledBool = ($st -eq 'Enabled') }
    else { $enabledBool = ($st.ToString() -eq 'Enabled') }
  } else {
    $enabledBool = $null
  }
  if ($null -ne $enabledBool) {
    Write-Host ("Enabled: " + $enabledBool)
  } else {
    Write-Host "Enabled: <unknown>"
  }

  if (Has-Prop $r 'Mode') { Write-Host ("Mode: " + (Get-Prop $r 'Mode' '')) } else { Write-Host "Mode: <none>" }
  if (Has-Prop $r 'Priority') { Write-Host ("Priority: " + (Get-Prop $r 'Priority' '')) } else { Write-Host "Priority: <unknown>" }

  $comments = Get-Prop $r 'Comments' $null
  if ($comments) { Write-Host ("Comments: " + ($comments -replace "`r?`n"," | ")) }

  # Conditions
  $condPairs = @()
  foreach ($m in $PredicateFields) {
    $v = $null
    if (Has-Prop $r $m.P) { $v = Get-Prop $r $m.P }
    if ($null -ne $v -and ($v -isnot [bool] -or $v)) {
      $val = To-Flat $v
      if ([string]::IsNullOrWhiteSpace($val)) { continue }
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
    $v = $null
    if (Has-Prop $r $m.P) { $v = Get-Prop $r $m.P }
    if ($null -ne $v -and ($v -isnot [bool] -or $v)) {
      $val = To-Flat $v
      if ([string]::IsNullOrWhiteSpace($val)) { continue }
      $actPairs += ("  - {0}: {1}" -f $m.P, $val)
    } elseif ($v -is [bool] -and $v) {
      $actPairs += ("  - {0}: True" -f $m.P)
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
  $parts += ("New-TransportRule -Name " + (J (Get-Prop $r 'Name' 'Rule')))
  if ($null -ne $enabledBool) {
    if ($enabledBool) { $parts += "-Enabled $true" } else { $parts += "-Enabled $false" }
  }
  if (Has-Prop $r 'Mode')     { $parts += ("-Mode " + (J (Get-Prop $r 'Mode'))) }
  if (Has-Prop $r 'Priority') { $parts += ("-Priority {0}" -f [int](Get-Prop $r 'Priority' 0)) }

  foreach ($m in $PredicateFields) {
    if (Has-Prop $r $m.P) {
      $pv = Get-Prop $r $m.P
      if ($null -ne $pv -and ($pv -isnot [bool] -or $pv)) {
        if ($pv -is [System.Collections.IEnumerable] -and -not ($pv -is [string])) { $pv = @($pv) }
        if ($pv -is [System.Array]) { $parts += ("{0} {1}" -f $m.K, (JA $pv)) }
        else { $parts += ("{0} {1}" -f $m.K, (J $pv)) }
      }
    }
  }
  foreach ($m in $ActionFields) {
    if (Has-Prop $r $m.P) {
      $pv = Get-Prop $r $m.P
      if ($null -ne $pv -and ($pv -isnot [bool] -or $pv)) {
        if ($pv -is [System.Collections.IEnumerable] -and -not ($pv -is [string])) { $pv = @($pv) }
        if ($pv -is [System.Array]) { $parts += ("{0} {1}" -f $m.K, (JA $pv)) }
        else {
          if ($pv -is [bool]) {
            if ($pv) { $parts += $m.K }
          } else {
            $parts += ("{0} {1}" -f $m.K, (J $pv))
          }
        }
      } elseif ($pv -is [bool] -and $pv) {
        $parts += $m.K
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

  $upn = Get-Prop $mbx 'PrimarySmtpAddress' '<unknown>'
  Write-Host ("BEGIN MAILBOX-POSTURE " + $upn)
  Write-Host ("RecipientTypeDetails: " + (Get-Prop $mbx 'RecipientTypeDetails' ''))
  Write-Host ("AuditEnabled: " + (Get-Prop $mbx 'AuditEnabled' ''))

  $fwdSmtp = Get-Prop $mbx 'ForwardingSMTPAddress' $null
  $deliver = [bool](Get-Prop $mbx 'DeliverToMailboxAndForward' $false)
  if ($fwdSmtp) {
    $ext = Is-ExternalAddress -Address $fwdSmtp -AcceptedDomains $AcceptedDomains
    Write-Host ("ForwardingSMTPAddress: {0}" -f $fwdSmtp)
    Write-Host ("DeliverToMailboxAndForward: {0}" -f $deliver)
    Write-Host ("ForwardingSMTPAddressIsExternal: {0}" -f $ext)

    $deliverStr = '$false'; if ($deliver) { $deliverStr = '$true' }
    $cmd = @(
      "Set-Mailbox -Identity", (J $upn),
      "-ForwardingSMTPAddress", (J $fwdSmtp.ToString()),
      "-DeliverToMailboxAndForward", $deliverStr
    ) -join " "
    Write-Host ("Recreate: " + $cmd) -ForegroundColor Yellow
  } else {
    Write-Host "ForwardingSMTPAddress: <none>"
  }

  $fwdAddr = Get-Prop $mbx 'ForwardingAddress' $null
  if ($fwdAddr) {
    Write-Host ("ForwardingAddress (directory object): {0}" -f $fwdAddr)
    $cmd2 = @(
      "Set-Mailbox -Identity", (J $upn),
      "-ForwardingAddress", (J $fwdAddr.ToString())
    ) -join " "
    Write-Host ("Recreate: " + $cmd2) -ForegroundColor Yellow
  } else {
    Write-Host "ForwardingAddress: <none>"
  }

  # Delegations
  try {
    $sendAs = (Get-RecipientPermission -Identity $upn -ErrorAction Stop |
      Where-Object { $_.Trustee -ne "NT AUTHORITY\SELF" -and $_.AccessRights -contains "SendAs" }) |
      Select-Object -ExpandProperty Trustee -ErrorAction SilentlyContinue
    if ($sendAs) { Write-Host ("SendAs: " + ($sendAs -join ", ")) } else { Write-Host "SendAs: <none>" }
  } catch {
    Write-Warning ("Get-RecipientPermission failed for {0}: {1}" -f $upn, $_.Exception.Message)
  }

  try {
    $mailboxPerm = (Get-MailboxPermission -Identity $upn -ErrorAction Stop |
      Where-Object { -not $_.IsInherited -and $_.User -notmatch '^S-1-5-' -and $_.User -ne "NT AUTHORITY\SELF" })
    if ($mailboxPerm) {
      Write-Host "MailboxPermissions:"
      foreach ($p in $mailboxPerm) {
        Write-Host ("  - {0}: {1}" -f $p.User, ($p.AccessRights -join "+"))
      }
    } else {
      Write-Host "MailboxPermissions: <none>"
    }
  } catch {
    Write-Warning ("Get-MailboxPermission failed for {0}: {1}" -f $upn, $_.Exception.Message)
  }

  Write-Host "END MAILBOX-POSTURE"
  Write-Host ""
}

function Describe-InboxRule {
  param($ir, $mailbox)

  Write-Host ("BEGIN INBOX-RULE {0} :: {1}" -f $mailbox, (Get-Prop $ir 'Name' '<unnamed>'))
  Write-Host ("Enabled: " + (Get-Prop $ir 'Enabled' ''))
  Write-Host ("Priority: " + (Get-Prop $ir 'Priority' ''))
  Write-Host ("StopProcessing: " + (Get-Prop $ir 'StopProcessingRules' ''))

  $conds = @()
  if (Has-Prop $ir 'From' -and $ir.From) { $conds += ("From: " + (To-Flat $ir.From)) }
  if (Has-Prop $ir 'SenderAddressContainsWords' -and $ir.SenderAddressContainsWords) { $conds += ("SenderAddressContainsWords: " + (To-Flat $ir.SenderAddressContainsWords)) }
  if (Has-Prop $ir 'SubjectContainsWords' -and $ir.SubjectContainsWords) { $conds += ("SubjectContainsWords: " + (To-Flat $ir.SubjectContainsWords)) }
  if (Has-Prop $ir 'BodyContainsWords' -and $ir.BodyContainsWords) { $conds += ("BodyContainsWords: " + (To-Flat $ir.BodyContainsWords)) }
  if (Has-Prop $ir 'MyNameInToOrCcBox' -and $ir.MyNameInToOrCcBox) { $conds += "MyNameInToOrCcBox: True" }
  if (Has-Prop $ir 'HasAttachment' -and $ir.HasAttachment) { $conds += "HasAttachment: True" }
  if ($conds.Count -gt 0) { Write-Host "When:"; $conds | ForEach-Object { Write-Host ("  - " + $_) } } else { Write-Host "When: <none>" }

  $acts = @()
  if (Has-Prop $ir 'RedirectTo' -and $ir.RedirectTo) { $acts += ("RedirectTo: " + (To-Flat $ir.RedirectTo)) }
  if (Has-Prop $ir 'ForwardTo' -and $ir.ForwardTo) { $acts += ("ForwardTo: " + (To-Flat $ir.ForwardTo)) }
  if (Has-Prop $ir 'MoveToFolder' -and $ir.MoveToFolder) { $acts += ("MoveToFolder: " + $ir.MoveToFolder) }
  if (Has-Prop $ir 'CopyToFolder' -and $ir.CopyToFolder) { $acts += ("CopyToFolder: " + $ir.CopyToFolder) }
  if (Has-Prop $ir 'DeleteMessage' -and $ir.DeleteMessage) { $acts += "DeleteMessage: True" }
  if (Has-Prop $ir 'PermanentDelete' -and $ir.PermanentDelete) { $acts += "PermanentDelete: True" }
  if (Has-Prop $ir 'MarkAsRead' -and $ir.MarkAsRead) { $acts += "MarkAsRead: True" }
  if (Has-Prop $ir 'AssignCategories' -and $ir.AssignCategories) { $acts += ("AssignCategories: " + (To-Flat $ir.AssignCategories)) }
  if ($acts.Count -gt 0) { Write-Host "Then:"; $acts | ForEach-Object { Write-Host ("  - " + $_) } } else { Write-Host "Then: <none>" }

  # Recreate
  $enabledRuleStr = '$false'; if ((Get-Prop $ir 'Enabled' $false)) { $enabledRuleStr = '$true' }
  $prio = [int](Get-Prop $ir 'Priority' 0)

  $cmd = @("New-InboxRule -Mailbox", (J $mailbox), "-Name", (J (Get-Prop $ir 'Name' 'Rule')), "-Priority", $prio, "-Enabled", $enabledRuleStr)
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

  # Accepted domains for external detection
  $acceptedDomains = @()
  try {
    $acceptedDomains = (Get-AcceptedDomain -ErrorAction Stop | Select-Object -ExpandProperty DomainName) | ForEach-Object { $_.ToLowerInvariant() }
  } catch {
    Write-Warning ("Get-AcceptedDomain failed: {0}" -f $_.Exception.Message)
    $acceptedDomains = @()
  }

  Print-Header "Transport Rules"
  $trs = @()
  try {
    $trs = Get-TransportRule -ResultSize Unlimited -ErrorAction Stop
  } catch {
    Write-Warning ("Get-TransportRule failed: {0}" -f $_.Exception.Message)
  }
  foreach ($r in $trs | Sort-Object Priority) {
    try {
      Describe-TransportRule -r $r
    } catch {
      Write-Warning ("Describe-TransportRule error for '{0}': {1}" -f (Get-Prop $r 'Name' '<unknown>'), $_.Exception.Message)
    }
  }

  Print-Header "Mailbox Forwarding / Delegation"
  $mbxs = @()
  try {
    $mbxs = Get-ExoMailbox -ResultSize Unlimited -Properties ForwardingSMTPAddress,ForwardingAddress,DeliverToMailboxAndForward,RecipientTypeDetails,AuditEnabled,PrimarySmtpAddress -ErrorAction Stop
  } catch {
    Write-Warning ("Get-ExoMailbox failed: {0}" -f $_.Exception.Message)
  }
  foreach ($m in $mbxs | Sort-Object PrimarySmtpAddress) {
    try {
      Print-MailboxPosture -mbx $m -AcceptedDomains $acceptedDomains
    } catch {
      Write-Warning ("Mailbox posture error for '{0}': {1}" -f (Get-Prop $m 'PrimarySmtpAddress' '<unknown>'), $_.Exception.Message)
    }
  }

  if ($InboxRules) {
    Print-Header "Inbox Rules (Per Mailbox)"
    foreach ($m in $mbxs) {
      $upn = Get-Prop $m 'PrimarySmtpAddress' '<unknown>'
      try {
        $rules = Get-InboxRule -Mailbox $upn -ErrorAction Stop
        foreach ($ir in $rules | Sort-Object Priority) {
          try {
            Describe-InboxRule -ir $ir -mailbox $upn
          } catch {
            Write-Warning ("Describe-InboxRule error for {0}: {1}" -f $upn, $_.Exception.Message)
          }
        }
      } catch {
        Write-Warning ("Get-InboxRule failed for {0}: {1}" -f $upn, $_.Exception.Message)
      }
    }
  }

  Write-Host ""
  Write-Host "Done."
}

Main
