<#
.SYNOPSIS
    CA-24-Require-AllUsers-MFA-Reregistration

.DESCRIPTION
    *** DEPLOYS ENABLED BY DEFAULT. IR USE ONLY. RUN MANUALLY DURING AN ACTIVE
    INCIDENT, NOT AS PART OF ROUTINE DEPLOYMENT. ***

    Two-part IR control. Part one is done by you in Entra: force MFA re-registration
    for affected users, invalidating any attacker-registered methods. Part two is this
    policy, which blocks new security info registration from anywhere outside the
    corporate network so the attacker cannot simply re-register remotely.

.NOTES
    Policy        : CA-24-Require-AllUsers-MFA-Reregistration
    License       : Entra ID P1
    Default state : ENABLED. Deploys enforced immediately by design. No -Enforce switch.
    Gotchas:
        - Force re-registration in Entra FIRST, then deploy this policy. The order matters.
        - Uses the 'Register security information' User Action, not cloud apps.
        - Requires the NL-Corporate-IPs named location. Without it this policy would block re-registration from EVERYWHERE, including the office, which strands legitimate users mid-incident. The script refuses to deploy without it.

.EXAMPLE
    .\CA-24-Require-AllUsers-MFA-Reregistration.ps1
    Deploys the policy ENABLED. This script intentionally has no -Enforce switch.

.EXAMPLE
    .\CA-24-Require-AllUsers-MFA-Reregistration.ps1 -WhatIf
    Shows what would be created without creating anything.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param()

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
$CorporateIps = @(Get-MgIdentityConditionalAccessNamedLocation -Filter "displayName eq 'NL-Corporate-IPs'" -All)
if ($CorporateIps.Count -eq 0) {
    throw "Named location 'NL-Corporate-IPs' was not found. Without a trusted location exclusion this policy blocks security info registration from everywhere, stranding legitimate users mid-incident. Run prerequisites/New-NamedLocations.ps1 with the client's corporate IP ranges first."
}
$CorporateIpsId = $CorporateIps[0].Id
#endregion


#region Policy state
# INTENTIONAL: this policy deploys enabled by default. There is no -Enforce switch
# and no report-only phase. See the header notes for why.
$State = 'enabled'
Write-Host 'This policy deploys ENABLED by default by design. There is no report-only phase for this one.' -ForegroundColor Red
#endregion

#region Duplicate check
$PolicyName = 'CA-24-Require-AllUsers-MFA-Reregistration'
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
            excludeGroups = @($BreakGlassGroupId)
        }
        applications = @{ includeUserActions = @('urn:user:registersecurityinfo') }
        locations    = @{
            includeLocations = @('All')
            excludeLocations = @($CorporateIpsId)
        }
    }
    grantControls = @{ operator = 'OR'; builtInControls = @('block') }
}

if ($PSCmdlet.ShouldProcess($PolicyName, "Create Conditional Access policy in state '$State'")) {
    $Result = New-MgIdentityConditionalAccessPolicy -BodyParameter $Policy
    Write-Host ''
    Write-Host "Created policy : $($Result.DisplayName)" -ForegroundColor Green
    Write-Host "Policy Id      : $($Result.Id)"
    Write-Host "State          : $State"
    Write-Host ''
    Write-Host 'Reminder: force MFA re-registration for affected users in Entra BEFORE relying on this policy. This policy only prevents new remote registrations, it does not invalidate methods the attacker already registered.' -ForegroundColor Yellow
}
#endregion
