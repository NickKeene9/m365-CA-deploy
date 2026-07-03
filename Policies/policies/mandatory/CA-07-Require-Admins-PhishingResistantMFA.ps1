<#
.SYNOPSIS
    CA-07-Require-Admins-PhishingResistantMFA

.DESCRIPTION
    Requires the built-in 'Phishing-resistant MFA' authentication strength (FIDO2,
    Windows Hello for Business, certificate-based auth) for every member of
    CA-IN-Admins.

    HARD GATE: -Enforce refuses to run until every member of CA-IN-Admins has a
    registered FIDO2 or Windows Hello for Business method. The gate queries each
    admin's registered authentication methods via Graph and lists any account missing
    coverage. This is lockout prevention and it is non-negotiable. Do not remove it.

.NOTES
    Policy        : CA-07-Require-Admins-PhishingResistantMFA
    License       : Entra ID P1
    Default state : Report-only (enabledForReportingButNotEnforced). Pass -Enforce to deploy enabled.
    Gotchas:
        - Never let this policy move to enforced without the readiness gate passing.
        - Enforcing without hardware locks out every admin at once.
        - The gate checks transitive membership of CA-IN-Admins, so nested groups are covered.

.EXAMPLE
    .\CA-07-Require-Admins-PhishingResistantMFA.ps1
    Deploys the policy in report-only mode (enabledForReportingButNotEnforced).

.EXAMPLE
    .\CA-07-Require-Admins-PhishingResistantMFA.ps1 -Enforce
    Deploys the policy enabled.

.EXAMPLE
    .\CA-07-Require-Admins-PhishingResistantMFA.ps1 -WhatIf
    Shows what would be created without creating anything.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Enforce
)

$ErrorActionPreference = 'Stop'

#region Connect with the minimum required scopes for this policy
$RequiredScopes = @('Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'Group.Read.All', 'GroupMember.Read.All', 'UserAuthenticationMethod.Read.All', 'User.Read.All')
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
$AdminsGroupId = Get-CAGroupId -DisplayName 'CA-IN-Admins'

$AuthStrength = @(Get-MgPolicyAuthenticationStrengthPolicy -All | Where-Object { $_.DisplayName -eq 'Phishing-resistant MFA' })
if ($AuthStrength.Count -eq 0) {
    throw "The built-in authentication strength 'Phishing-resistant MFA' was not found. This is a built-in strength and should exist in every tenant. Investigate before proceeding."
}
$AuthStrengthId = $AuthStrength[0].Id
#endregion

#region HARD GATE: admin phishing-resistant MFA readiness check
# NON-NEGOTIABLE lockout prevention gate. This policy must never silently move to
# enforced. Enforcing without every admin holding phishing-resistant hardware locks
# out every admin at once.
if ($Enforce) {
    Write-Host 'Running admin phishing-resistant MFA readiness gate...' -ForegroundColor Cyan
    $AdminMembers = @(Get-MgGroupTransitiveMember -GroupId $AdminsGroupId -All |
        Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' })
    if ($AdminMembers.Count -eq 0) {
        throw 'CA-IN-Admins has no user members. Populate it before enforcing CA-07.'
    }

    $NotReady = @()
    foreach ($Member in $AdminMembers) {
        $Upn = $Member.AdditionalProperties.userPrincipalName
        $HasPhishingResistant = $false
        $Methods = @(Get-MgUserAuthenticationMethod -UserId $Member.Id)
        foreach ($Method in $Methods) {
            $MethodType = $Method.AdditionalProperties.'@odata.type'
            if ($MethodType -eq '#microsoft.graph.fido2AuthenticationMethod' -or
                $MethodType -eq '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod') {
                $HasPhishingResistant = $true
                break
            }
        }
        if (-not $HasPhishingResistant) { $NotReady += $Upn }
    }

    if ($NotReady.Count -gt 0) {
        Write-Host ''
        Write-Host 'ENFORCEMENT BLOCKED. These admin accounts have no registered FIDO2 or Windows Hello for Business method:' -ForegroundColor Red
        foreach ($Account in $NotReady) { Write-Host "  - $Account" -ForegroundColor Red }
        Write-Host ''
        throw "Refusing to enforce CA-07. Enforcing now would lock out $($NotReady.Count) admin account(s). Register a phishing-resistant method for every member of CA-IN-Admins, then re-run with -Enforce."
    }
    Write-Host "Gate passed. All $($AdminMembers.Count) members of CA-IN-Admins have a registered phishing-resistant method." -ForegroundColor Green
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
$PolicyName = 'CA-07-Require-Admins-PhishingResistantMFA'
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
            includeGroups = @($AdminsGroupId)
            excludeGroups = @($BreakGlassGroupId)
        }
        applications = @{ includeApplications = @('All') }
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
