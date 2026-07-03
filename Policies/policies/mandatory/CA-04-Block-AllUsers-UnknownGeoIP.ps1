<#
.SYNOPSIS
    CA-04-Block-AllUsers-UnknownGeoIP

.DESCRIPTION
    Allowlist pattern, not a blocklist. Includes ALL locations and excludes only the
    approved named locations, so anything not explicitly approved is blocked. Requires
    NL-Approved-Countries (and optionally NL-Corporate-IPs) built first via
    prerequisites/New-NamedLocations.ps1.

.NOTES
    Policy        : CA-04-Block-AllUsers-UnknownGeoIP
    License       : Entra ID P1
    Default state : Report-only (enabledForReportingButNotEnforced). Pass -Enforce to deploy enabled.
    Gotchas:
        - includeLocations = 'All' means every location, not just trusted ones. That detail is what makes the allowlist pattern work.
        - Using 'AllTrusted' here would invert the intent. Do not change it.
        - NL-Approved-Countries must have 'Include unknown countries/regions' left unchecked.
        - NL-Corporate-IPs is optional depending on client infrastructure. The script proceeds without it if absent.

.EXAMPLE
    .\CA-04-Block-AllUsers-UnknownGeoIP.ps1
    Deploys the policy in report-only mode (enabledForReportingButNotEnforced).

.EXAMPLE
    .\CA-04-Block-AllUsers-UnknownGeoIP.ps1 -Enforce
    Deploys the policy enabled.

.EXAMPLE
    .\CA-04-Block-AllUsers-UnknownGeoIP.ps1 -WhatIf
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
$GeoIpExGroupId = Get-CAGroupId -DisplayName 'CA-EX-Exclusions-GeoIP'

$ApprovedCountries = @(Get-MgIdentityConditionalAccessNamedLocation -Filter "displayName eq 'NL-Approved-Countries'" -All)
if ($ApprovedCountries.Count -eq 0) {
    throw "Named location 'NL-Approved-Countries' was not found. Run prerequisites/New-NamedLocations.ps1 first. Refusing to build the allowlist policy without it."
}
$ExcludeLocationIds = @($ApprovedCountries[0].Id)

$CorporateIps = @(Get-MgIdentityConditionalAccessNamedLocation -Filter "displayName eq 'NL-Corporate-IPs'" -All)
if ($CorporateIps.Count -gt 0) {
    $ExcludeLocationIds += $CorporateIps[0].Id
}
else {
    Write-Warning "Named location 'NL-Corporate-IPs' was not found. It is optional. Proceeding with NL-Approved-Countries as the only excluded location."
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
$PolicyName = 'CA-04-Block-AllUsers-UnknownGeoIP'
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
            excludeGroups = @($BreakGlassGroupId, $GeoIpExGroupId)
        }
        applications = @{ includeApplications = @('All') }
        locations    = @{
            includeLocations = @('All')
            excludeLocations = $ExcludeLocationIds
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
}
#endregion
