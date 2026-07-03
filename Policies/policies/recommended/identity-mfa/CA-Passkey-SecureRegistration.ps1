<#
.SYNOPSIS
    CA-Passkey-SecureRegistration

.DESCRIPTION
    Closes the gap where an attacker with a live session registers their own MFA method
    during compromise. Gates the 'Register security information' user action behind the
    AS-Passkey-Onboarding authentication strength: an existing passkey or a Temporary
    Access Pass issued out-of-band.

.NOTES
    Policy        : CA-Passkey-SecureRegistration
    License       : Entra ID P1
    Default state : Report-only (enabledForReportingButNotEnforced). Pass -Enforce to deploy enabled.
    Gotchas:
        - Depends on AS-Passkey-Onboarding existing first. Run prerequisites/New-AuthenticationStrengths.ps1.
        - Allowed combinations must be Passkey (FIDO2) plus BOTH TAP variants, matched exactly to the tenant's TAP policy setting, or the strength silently rejects valid TAPs.

.EXAMPLE
    .\CA-Passkey-SecureRegistration.ps1
    Deploys the policy in report-only mode (enabledForReportingButNotEnforced).

.EXAMPLE
    .\CA-Passkey-SecureRegistration.ps1 -Enforce
    Deploys the policy enabled.

.EXAMPLE
    .\CA-Passkey-SecureRegistration.ps1 -WhatIf
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
$AuthStrength = @(Get-MgPolicyAuthenticationStrengthPolicy -All | Where-Object { $_.DisplayName -eq 'AS-Passkey-Onboarding' })
if ($AuthStrength.Count -eq 0) {
    throw "Authentication strength 'AS-Passkey-Onboarding' was not found. Run prerequisites/New-AuthenticationStrengths.ps1 first."
}
$AuthStrengthId = $AuthStrength[0].Id

# Sanity check the allowed combinations so a mismatched strength does not silently reject valid TAPs
$Expected = @('fido2', 'temporaryAccessPassOneTime', 'temporaryAccessPassMultiUse')
$Combos = @($AuthStrength[0].AllowedCombinations)
$Missing = @($Expected | Where-Object { $_ -notin $Combos })
if ($Missing.Count -gt 0) {
    Write-Warning "AS-Passkey-Onboarding is missing expected combination(s): $($Missing -join ', '). Verify it matches the tenant's TAP policy (one-time vs multi-use) or valid TAPs will be rejected."
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
$PolicyName = 'CA-Passkey-SecureRegistration'
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
    }
    grantControls = @{ operator = 'OR'; authenticationStrength = @{ id = $AuthStrengthId } }
}

if ($PSCmdlet.ShouldProcess($PolicyName, "Create Conditional Access policy in state '$State'")) {
    $Result = New-MgIdentityConditionalAccessPolicy -BodyParameter $Policy
    Write-Host ''
    Write-Host "Created policy : $($Result.DisplayName)" -ForegroundColor Green
    Write-Host "Policy Id      : $($Result.Id)"
    Write-Host "State          : $State"
}
#endregion
