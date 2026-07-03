<#
.SYNOPSIS
    CA-05-Require-AllUsers-MFA-EntraDeviceRegistrationOrJoin

.DESCRIPTION
    Closes the gap where device join status alone might grant access without MFA in
    some policy combinations. Uses a device filter targeting Entra ID joined and
    Hybrid Entra joined devices and requires MFA on those sign-ins.

.NOTES
    Policy        : CA-05-Require-AllUsers-MFA-EntraDeviceRegistrationOrJoin
    License       : Entra ID P1
    Default state : Report-only (enabledForReportingButNotEnforced). Pass -Enforce to deploy enabled.
    Gotchas:
        - Device filter syntax is case sensitive.
        - device.trustType 'AzureAD' means Entra ID joined, 'ServerAD' means Hybrid Entra joined.
        - BUILD NOTE: the source framework spec used device.joinType with values AzureADJoined and ServerAD. joinType is not a supported device filter attribute in the Graph schema and policy creation fails validation with it. This script uses the equivalent supported attribute device.trustType. If your testing says otherwise, adjust the rule below.

.EXAMPLE
    .\CA-05-Require-AllUsers-MFA-EntraDeviceRegistrationOrJoin.ps1
    Deploys the policy in report-only mode (enabledForReportingButNotEnforced).

.EXAMPLE
    .\CA-05-Require-AllUsers-MFA-EntraDeviceRegistrationOrJoin.ps1 -Enforce
    Deploys the policy enabled.

.EXAMPLE
    .\CA-05-Require-AllUsers-MFA-EntraDeviceRegistrationOrJoin.ps1 -WhatIf
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
$ServiceAccountsGroupId = Get-CAGroupId -DisplayName 'CA-EX-ServiceAccounts'
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
$PolicyName = 'CA-05-Require-AllUsers-MFA-EntraDeviceRegistrationOrJoin'
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
            includeUsers  = @('All')
            excludeGroups = @($BreakGlassGroupId, $ServiceAccountsGroupId)
        }
        applications = @{ includeApplications = @('All') }
        devices      = @{
            deviceFilter = @{
                mode = 'include'
                rule = 'device.trustType -eq "AzureAD" -or device.trustType -eq "ServerAD"'
            }
        }
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
