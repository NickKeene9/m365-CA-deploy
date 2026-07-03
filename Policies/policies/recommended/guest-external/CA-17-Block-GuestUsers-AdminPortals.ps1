<#
.SYNOPSIS
    CA-17-Block-GuestUsers-AdminPortals

.DESCRIPTION
    *** DEPLOYS ENABLED BY DEFAULT. NOT REPORT-ONLY. NO -ENFORCE SWITCH. ***

    There is no legitimate reason for a guest to reach admin portals, so this policy
    skips the report-only phase entirely and deploys enabled.

.NOTES
    Policy        : CA-17-Block-GuestUsers-AdminPortals
    License       : Entra ID P1
    Default state : ENABLED. Deploys enforced immediately by design. No -Enforce switch.
    Gotchas:
        - Uses the built-in 'MicrosoftAdminPortals' application target, which Microsoft maintains to cover all first-party admin portals. Add any org-specific admin-adjacent app IDs to the $AdminApps array alongside it if needed.
        - MicrosoftAdminPortals covers browser access to admin portals. It does not cover Graph PowerShell, Graph API, or CLI access. CA-13 handles the Azure management API surface.
        - Uses the dynamic CA-IN-GuestUsers group. Same silent-gap caveats as CA-06 apply.

.EXAMPLE
    .\CA-17-Block-GuestUsers-AdminPortals.ps1
    Deploys the policy ENABLED. This script intentionally has no -Enforce switch.

.EXAMPLE
    .\CA-17-Block-GuestUsers-AdminPortals.ps1 -WhatIf
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
$GuestGroupId = Get-CAGroupId -DisplayName 'CA-IN-GuestUsers'
#endregion


#region Policy state
# INTENTIONAL: this policy deploys enabled by default. There is no -Enforce switch
# and no report-only phase. See the header notes for why.
$State = 'enabled'
Write-Host 'This policy deploys ENABLED by default by design. There is no report-only phase for this one.' -ForegroundColor Red
#endregion

#region Duplicate check
$PolicyName = 'CA-17-Block-GuestUsers-AdminPortals'
$Existing = @(Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$PolicyName'" -All)
if ($Existing.Count -gt 0) {
    Write-Warning "A Conditional Access policy named '$PolicyName' already exists (Id: $($Existing[0].Id)). Refusing to create a duplicate. Delete or rename the existing policy if you intend to redeploy."
    return
}
#endregion

#region Build and create the policy
# Uses the built-in MicrosoftAdminPortals target, which covers Azure portal, Entra
# admin center, Intune, M365 admin center, Defender portal, Purview, Exchange admin,
# Teams admin, and the rest of Microsoft's admin surfaces as a maintained group. This
# replaced a hand-curated app ID list so coverage cannot drift as Microsoft adds portals.
$AdminApps = @('MicrosoftAdminPortals')

$Policy = @{
    displayName = $PolicyName
    state       = $State
    conditions  = @{
        users = @{
            includeGroups = @($GuestGroupId)
            excludeGroups = @($BreakGlassGroupId)
        }
        applications = @{ includeApplications = $AdminApps }
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
