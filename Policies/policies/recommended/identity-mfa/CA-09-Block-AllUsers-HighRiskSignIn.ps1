<#
.SYNOPSIS
    CA-09-Block-AllUsers-HighRiskSignIn

.DESCRIPTION
    Blocks any sign-in that Identity Protection scores as high risk. Requires Entra ID
    P2 / Identity Protection. The script checks for the P2 service plan before
    deploying.

.NOTES
    Policy        : CA-09-Block-AllUsers-HighRiskSignIn
    License       : Entra ID P2 (Identity Protection)
    Default state : Report-only (enabledForReportingButNotEnforced). Pass -Enforce to deploy enabled.
    Gotchas:
        - The sign-in risk condition only functions if the tenant has Entra ID P2.
        - If the license is not provisioned, document this policy as a gap. Do not approximate it with other conditions.

.EXAMPLE
    .\CA-09-Block-AllUsers-HighRiskSignIn.ps1
    Deploys the policy in report-only mode (enabledForReportingButNotEnforced).

.EXAMPLE
    .\CA-09-Block-AllUsers-HighRiskSignIn.ps1 -Enforce
    Deploys the policy enabled.

.EXAMPLE
    .\CA-09-Block-AllUsers-HighRiskSignIn.ps1 -WhatIf
    Shows what would be created without creating anything.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Enforce
)

$ErrorActionPreference = 'Stop'

#region Connect with the minimum required scopes for this policy
$RequiredScopes = @('Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'Group.Read.All', 'Organization.Read.All')
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
#endregion

#region License preflight (Entra ID P2 / Identity Protection)
$Skus = @(Get-MgSubscribedSku -All)
$HasP2 = $false
foreach ($Sku in $Skus) {
    if ($Sku.ServicePlans.ServicePlanName -contains 'AAD_PREMIUM_P2') { $HasP2 = $true; break }
}
if (-not $HasP2) {
    Write-Warning 'No Entra ID P2 service plan (AAD_PREMIUM_P2) detected in this tenant. Risk-based conditions require Identity Protection. If the risk condition is not available, document this as a licensing gap rather than approximating it with other conditions.'
    $Answer = Read-Host 'Type YES to attempt deployment anyway, anything else to abort'
    if ($Answer -ne 'YES') { Write-Host 'Aborted.'; return }
}
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
$PolicyName = 'CA-09-Block-AllUsers-HighRiskSignIn'
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
        applications     = @{ includeApplications = @('All') }
        signInRiskLevels = @('high')
    }
    grantControls = @{ operator = 'OR'; builtInControls = @('block') }
}

if ($PSCmdlet.ShouldProcess($PolicyName, "Create Conditional Access policy in state '$State'")) {
    $Result = New-MgIdentityConditionalAccessPolicy -BodyParameter $Policy
    Write-Host ''
    Write-Host "Created policy : $($Result.DisplayName)" -ForegroundColor Green
    Write-Host "Policy Id      : $($Result.Id)"
    Write-Host "State          : $State"
}
#endregion
