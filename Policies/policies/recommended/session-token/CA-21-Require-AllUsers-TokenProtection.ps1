<#
.SYNOPSIS
    CA-21-Require-AllUsers-TokenProtection

.DESCRIPTION
    Requires sign-in session tokens to be cryptographically bound to the device (PRT
    binding). A stolen token replayed from another device fails validation. Implemented
    per the current Graph schema as the secureSignInSession session control.

    Scoped per Microsoft's deployment guidance: Windows platform, mobile apps and
    desktop clients only, Exchange Online and SharePoint Online only. Token Protection
    supports native applications only, so applying it to browser traffic or other
    platforms causes hard authentication failures, not soft ones.

.NOTES
    Policy        : CA-21-Require-AllUsers-TokenProtection
    License       : Entra ID P1
    Default state : Report-only (enabledForReportingButNotEnforced). Pass -Enforce to deploy enabled.
    Gotchas:
        - As of mid-2026, GA on Windows, still Preview on iOS/iPadOS and macOS. Confirm current status before relying on it for Apple devices.
        - BUILD NOTE: the source framework spec carried a placeholder grant control (requireCompliantApp) with an instruction to use the token protection session control per the current Graph schema. That schema is sessionControls.secureSignInSession, which is what this script uses. Verified against Microsoft Learn as of the build date.
        - Clients without token binding support fail authentication entirely, not a soft failure. Start scoped to Exchange/SharePoint only, expand gradually.
        - Long report-only phase with review of interactive AND non-interactive sign-in logs is mandatory before enforcing.

.EXAMPLE
    .\CA-21-Require-AllUsers-TokenProtection.ps1
    Deploys the policy in report-only mode (enabledForReportingButNotEnforced).

.EXAMPLE
    .\CA-21-Require-AllUsers-TokenProtection.ps1 -Enforce
    Deploys the policy enabled.

.EXAMPLE
    .\CA-21-Require-AllUsers-TokenProtection.ps1 -WhatIf
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
$TokenProtectionExGroupId = Get-CAGroupId -DisplayName 'CA-EX-Exclusions-TokenProtection'
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
$PolicyName = 'CA-21-Require-AllUsers-TokenProtection'
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
            excludeGroups = @($BreakGlassGroupId, $TokenProtectionExGroupId)
        }
        applications = @{
            includeApplications = @(
                '00000002-0000-0ff1-ce00-000000000000',  # Exchange Online
                '00000003-0000-0ff1-ce00-000000000000'   # SharePoint Online
            )
        }
        platforms      = @{ includePlatforms = @('windows') }
        clientAppTypes = @('mobileAppsAndDesktopClients')
    }
    sessionControls = @{ secureSignInSession = @{ isEnabled = $true } }
}

if ($PSCmdlet.ShouldProcess($PolicyName, "Create Conditional Access policy in state '$State'")) {
    $Result = New-MgIdentityConditionalAccessPolicy -BodyParameter $Policy
    Write-Host ''
    Write-Host "Created policy : $($Result.DisplayName)" -ForegroundColor Green
    Write-Host "Policy Id      : $($Result.Id)"
    Write-Host "State          : $State"
}
#endregion
