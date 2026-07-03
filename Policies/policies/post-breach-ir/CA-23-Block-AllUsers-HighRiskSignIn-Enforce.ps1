<#
.SYNOPSIS
    CA-23-Block-AllUsers-HighRiskSignIn-Enforce

.DESCRIPTION
    *** DEPLOYS ENABLED BY DEFAULT. IR USE ONLY. RUN MANUALLY DURING AN ACTIVE
    INCIDENT, NOT AS PART OF ROUTINE DEPLOYMENT. ***

    Incident response control. Hard blocks every sign-in Identity Protection scores as
    high risk, effective immediately. During an active incident there is no time for a
    report-only phase.

.NOTES
    Policy        : CA-23-Block-AllUsers-HighRiskSignIn-Enforce
    License       : Entra ID P2 (Identity Protection)
    Default state : ENABLED. Deploys enforced immediately by design. No -Enforce switch.
    Gotchas:
        - If P2 is not licensed, compensating controls are: Set-MgUser -AccountEnabled:$false on compromised accounts, Revoke-MgUserSignInSession, and a named-location block as a stopgap.
        - Remove or convert this policy deliberately once the incident is contained. Do not leave IR controls unmanaged.

.EXAMPLE
    .\CA-23-Block-AllUsers-HighRiskSignIn-Enforce.ps1
    Deploys the policy ENABLED. This script intentionally has no -Enforce switch.

.EXAMPLE
    .\CA-23-Block-AllUsers-HighRiskSignIn-Enforce.ps1 -WhatIf
    Shows what would be created without creating anything.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param()

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
# INTENTIONAL: this policy deploys enabled by default. There is no -Enforce switch
# and no report-only phase. See the header notes for why.
$State = 'enabled'
Write-Host 'This policy deploys ENABLED by default by design. There is no report-only phase for this one.' -ForegroundColor Red
#endregion

#region Duplicate check
$PolicyName = 'CA-23-Block-AllUsers-HighRiskSignIn-Enforce'
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
