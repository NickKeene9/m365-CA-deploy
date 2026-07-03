<#
.SYNOPSIS
    CA-06-Require-GuestUsers-MFA

.DESCRIPTION
    B2B guests inherit their home tenant's MFA posture, not yours. This policy closes
    that inherited weakness by requiring MFA for every member of the dynamic
    CA-IN-GuestUsers group.

.NOTES
    Policy        : CA-06-Require-GuestUsers-MFA
    License       : Entra ID P1
    Default state : Report-only (enabledForReportingButNotEnforced). Pass -Enforce to deploy enabled.
    Gotchas:
        - CA-IN-GuestUsers must be a dynamic group with rule (user.userType -eq "Guest"), built via New-CAGroups.ps1, never manually maintained.
        - An empty or paused dynamic group is a silent coverage gap. This script verifies the dynamic rule and processing state before deploying.

.EXAMPLE
    .\CA-06-Require-GuestUsers-MFA.ps1
    Deploys the policy in report-only mode (enabledForReportingButNotEnforced).

.EXAMPLE
    .\CA-06-Require-GuestUsers-MFA.ps1 -Enforce
    Deploys the policy enabled.

.EXAMPLE
    .\CA-06-Require-GuestUsers-MFA.ps1 -WhatIf
    Shows what would be created without creating anything.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Enforce
)

$ErrorActionPreference = 'Stop'

#region Connect with the minimum required scopes for this policy
$RequiredScopes = @('Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'Group.Read.All')
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

#region Helper functions
function Get-CAGroupId {
    param([Parameter(Mandatory = $true)][string]$DisplayName)
    $Group = @(Get-MgGroup -Filter "displayName eq '$DisplayName'" -All)
    if ($Group.Count -eq 0) {
        throw "Required group '$DisplayName' was not found in this tenant. Run prerequisites/New-CAGroups.ps1 first. Refusing to build a policy with a missing include or exclude group."
    }
    if ($Group.Count -gt 1) {
        throw "Multiple groups named '$DisplayName' were found. Resolve the duplicates before deploying so the policy cannot target the wrong group."
    }
    return $Group[0].Id
}

function Test-BreakGlassMembership {
    param([Parameter(Mandatory = $true)][string]$GroupId)
    $Members = @(Get-MgGroupMember -GroupId $GroupId -All -ErrorAction SilentlyContinue)
    if ($Members.Count -eq 0) {
        Write-Warning "CA-EX-BreakGlass has no members. Deploying policies without a populated break glass exclusion risks tenant lockout. Run prerequisites/New-BreakGlassAccount.ps1 before enforcing anything."
    }
}
#endregion

#region Runtime lookups (no hardcoded GUIDs)
$BreakGlassGroupId = Get-CAGroupId -DisplayName 'CA-EX-BreakGlass'
Test-BreakGlassMembership -GroupId $BreakGlassGroupId
$GuestGroup = @(Get-MgGroup -Filter "displayName eq 'CA-IN-GuestUsers'" -All -Property Id, DisplayName, GroupTypes, MembershipRule, MembershipRuleProcessingState)
if ($GuestGroup.Count -eq 0) {
    throw "Required group 'CA-IN-GuestUsers' was not found. Run prerequisites/New-CAGroups.ps1 first."
}
if ($GuestGroup.Count -gt 1) {
    throw "Multiple groups named 'CA-IN-GuestUsers' were found. Resolve the duplicates before deploying."
}
$GuestGroup = $GuestGroup[0]

# An empty or paused dynamic group is a silent coverage gap. Verify before trusting it.
if ($GuestGroup.GroupTypes -notcontains 'DynamicMembership') {
    throw "CA-IN-GuestUsers exists but is not a dynamic group. It must use dynamic membership so guest coverage cannot silently drift. Recreate it via prerequisites/New-CAGroups.ps1."
}
if ($GuestGroup.MembershipRule -notmatch 'user\.userType\s+-eq\s+"Guest"') {
    throw "CA-IN-GuestUsers has an unexpected membership rule: '$($GuestGroup.MembershipRule)'. Expected (user.userType -eq ""Guest""). Fix the rule before deploying."
}
if ($GuestGroup.MembershipRuleProcessingState -ne 'On') {
    throw "CA-IN-GuestUsers dynamic membership processing is '$($GuestGroup.MembershipRuleProcessingState)', not 'On'. A paused dynamic group is a silent gap. Turn processing on before deploying."
}
$GuestGroupId = $GuestGroup.Id
#endregion


#region Policy state
$State = 'enabledForReportingButNotEnforced'
if ($Enforce) { $State = 'enabled' }
if ($State -eq 'enabledForReportingButNotEnforced') {
    Write-Host 'Deploying in report-only mode. Review report-only results in the sign-in logs, then re-run with -Enforce.' -ForegroundColor Yellow
}
else {
    Write-Host 'Deploying ENFORCED (state = enabled).' -ForegroundColor Red
}
#endregion

#region Duplicate check
$PolicyName = 'CA-06-Require-GuestUsers-MFA'
$Existing = @(Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$PolicyName'" -All)
if ($Existing.Count -gt 0) {
    Write-Warning "A Conditional Access policy named '$PolicyName' already exists (Id: $($Existing[0].Id)). Refusing to create a duplicate. Delete or rename the existing policy if you intend to redeploy."
    return
}
#endregion

#region Build and create the policy
$Policy = @{
    displayName = $PolicyName
    state       = $State
    conditions  = @{
        users = @{
            includeGroups = @($GuestGroupId)
            excludeGroups = @($BreakGlassGroupId)
        }
        applications = @{ includeApplications = @('All') }
    }
    grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
}

if ($PSCmdlet.ShouldProcess($PolicyName, "Create Conditional Access policy in state '$State'")) {
    $Result = New-MgIdentityConditionalAccessPolicy -BodyParameter $Policy
    Write-Host ''
    Write-Host "Created policy : $($Result.DisplayName)" -ForegroundColor Green
    Write-Host "Policy Id      : $($Result.Id)"
    Write-Host "State          : $State"
}
#endregion
