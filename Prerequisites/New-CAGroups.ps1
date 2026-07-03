<#
.SYNOPSIS
    Creates every CA-IN-* and CA-EX-* group referenced by the policy scripts in this repo.

.DESCRIPTION
    Creates the include and exclude groups the Conditional Access framework depends on.
    Existing groups are skipped, so the script is safe to re-run.

    CA-IN-GuestUsers is created as a DYNAMIC group with membership rule
    (user.userType -eq "Guest") and processing state On. It must never be an assigned,
    manually maintained group. A stale assigned group is a silent coverage gap.

.NOTES
    Run order     : Run this FIRST, before New-BreakGlassAccount.ps1 and all policy scripts.
    License       : Dynamic groups require Entra ID P1.
    Gotchas:
        - After creation, verify the dynamic group's membership rule processing state
          shows 'On' and that membership evaluation has completed before trusting
          CA-IN-GuestUsers as coverage.
        - CA-IN-Admins is created empty. Populate it with the tenant's admin accounts
          (excluding break glass) before deploying CA-07 or CA-15.

.EXAMPLE
    .\New-CAGroups.ps1

.EXAMPLE
    .\New-CAGroups.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param()

$ErrorActionPreference = 'Stop'

#region Connect
$RequiredScopes = @('Group.ReadWrite.All')
$Context = Get-MgContext
$NeedsConnect = $true
if ($Context) {
    $MissingScopes = @($RequiredScopes | Where-Object { $_ -notin $Context.Scopes })
    if ($MissingScopes.Count -eq 0) { $NeedsConnect = $false }
}
if ($NeedsConnect) {
    Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
}
#endregion

#region Group definitions
# Assigned (static) security groups
$StaticGroups = @(
    @{ Name = 'CA-IN-Admins';                          Description = 'CA framework: include group for admin accounts. Populate with all privileged accounts except break glass.' }
    @{ Name = 'CA-EX-BreakGlass';                      Description = 'CA framework: break glass accounts excluded from every Conditional Access policy. Keep membership minimal (1-2 accounts).' }
    @{ Name = 'CA-EX-ServiceAccounts';                 Description = 'CA framework: service accounts excluded from MFA policies. Every member requires documented justification.' }
    @{ Name = 'CA-EX-AllowLegacyAuthentication';       Description = 'CA framework: devices/accounts permitted legacy authentication. This exclusion group IS the exception mechanism for CA-01.' }
    @{ Name = 'CA-EX-Exclusions-DeviceCodeFlow';       Description = 'CA framework: exclusions from the device code flow block (CA-03). Documented business justification required.' }
    @{ Name = 'CA-EX-Exclusions-GeoIP';                Description = 'CA framework: exclusions from the geo allowlist block (CA-04), e.g. approved travelers.' }
    @{ Name = 'CA-EX-Exclusions-AzureMgmt';            Description = 'CA framework: identities with legitimate Azure management API access, excluded from CA-13.' }
    @{ Name = 'CA-EX-Exclusions-CompliantDevice';      Description = 'CA framework: exclusions from the compliant device requirement (CA-14) during phased rollout.' }
    @{ Name = 'CA-EX-Exclusions-TokenProtection';      Description = 'CA framework: clients/identities incompatible with token binding, excluded from CA-21.' }
)
#endregion

#region Create static groups
foreach ($GroupDef in $StaticGroups) {
    $Existing = @(Get-MgGroup -Filter "displayName eq '$($GroupDef.Name)'" -All)
    if ($Existing.Count -gt 0) {
        Write-Host "Exists, skipping : $($GroupDef.Name)" -ForegroundColor Yellow
        continue
    }
    if ($PSCmdlet.ShouldProcess($GroupDef.Name, 'Create assigned security group')) {
        $Body = @{
            displayName     = $GroupDef.Name
            description     = $GroupDef.Description
            mailEnabled     = $false
            mailNickname    = ($GroupDef.Name -replace '[^a-zA-Z0-9]', '')
            securityEnabled = $true
        }
        $NewGroup = New-MgGroup -BodyParameter $Body
        Write-Host "Created          : $($GroupDef.Name) ($($NewGroup.Id))" -ForegroundColor Green
    }
}
#endregion

#region Create dynamic guest group
$GuestGroupName = 'CA-IN-GuestUsers'
$ExistingGuest = @(Get-MgGroup -Filter "displayName eq '$GuestGroupName'" -All -Property Id, DisplayName, GroupTypes, MembershipRule, MembershipRuleProcessingState)
if ($ExistingGuest.Count -gt 0) {
    Write-Host "Exists, skipping : $GuestGroupName" -ForegroundColor Yellow
    $Guest = $ExistingGuest[0]
    if ($Guest.GroupTypes -notcontains 'DynamicMembership') {
        Write-Warning "$GuestGroupName exists but is NOT dynamic. The framework requires a dynamic group with rule (user.userType -eq ""Guest""). Delete and recreate it, or guest coverage will silently drift."
    }
    elseif ($Guest.MembershipRuleProcessingState -ne 'On') {
        Write-Warning "$GuestGroupName dynamic processing is '$($Guest.MembershipRuleProcessingState)', not 'On'. A paused dynamic group is a silent gap. Turn processing on."
    }
}
else {
    if ($PSCmdlet.ShouldProcess($GuestGroupName, 'Create dynamic security group (user.userType -eq "Guest")')) {
        $Body = @{
            displayName                   = $GuestGroupName
            description                   = 'CA framework: DYNAMIC group of all guest users. Rule: (user.userType -eq "Guest"). Do not convert to assigned membership.'
            mailEnabled                   = $false
            mailNickname                  = 'CAINGuestUsers'
            securityEnabled               = $true
            groupTypes                    = @('DynamicMembership')
            membershipRule                = '(user.userType -eq "Guest")'
            membershipRuleProcessingState = 'On'
        }
        $NewGroup = New-MgGroup -BodyParameter $Body
        Write-Host "Created          : $GuestGroupName ($($NewGroup.Id)) [dynamic]" -ForegroundColor Green
        Write-Host 'Dynamic membership evaluation can take several minutes. Verify membership has populated before deploying guest policies (CA-06, CA-17, CA-18).' -ForegroundColor Yellow
    }
}
#endregion

Write-Host ''
Write-Host 'Next steps:' -ForegroundColor Cyan
Write-Host '  1. Run New-BreakGlassAccount.ps1 to create and add the break glass account to CA-EX-BreakGlass.'
Write-Host '  2. Populate CA-IN-Admins with the tenant''s privileged accounts (not the break glass account).'
Write-Host '  3. Run New-NamedLocations.ps1 and New-AuthenticationStrengths.ps1.'
