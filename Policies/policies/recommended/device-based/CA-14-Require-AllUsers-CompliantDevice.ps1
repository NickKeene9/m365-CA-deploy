<#
.SYNOPSIS
    CA-14-Require-AllUsers-CompliantDevice

.DESCRIPTION
    Requires every sign-in to come from an Intune-compliant device or a hybrid joined
    device. This is the highest-risk policy to enforce in the whole framework, so the
    -Enforce path runs an Intune enrollment coverage check and requires typed
    confirmation.

.NOTES
    Policy        : CA-14-Require-AllUsers-CompliantDevice
    License       : Entra ID P1 + Intune
    Default state : Report-only (enabledForReportingButNotEnforced). Pass -Enforce to deploy enabled.
    Gotchas:
        - Highest-risk policy to enforce in the framework. Every non-enrolled device loses access on enforce.
        - Check enrollment first: Get-MgDeviceManagementManagedDevice | Group-Object ComplianceState (the -Enforce path does this for you).
        - Minimum one week in report-only. Review sign-in logs daily. Enroll remaining devices. Enforce in waves.

.EXAMPLE
    .\CA-14-Require-AllUsers-CompliantDevice.ps1
    Deploys the policy in report-only mode (enabledForReportingButNotEnforced).

.EXAMPLE
    .\CA-14-Require-AllUsers-CompliantDevice.ps1 -Enforce
    Deploys the policy enabled.

.EXAMPLE
    .\CA-14-Require-AllUsers-CompliantDevice.ps1 -WhatIf
    Shows what would be created without creating anything.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Enforce
)

$ErrorActionPreference = 'Stop'

#region Connect with the minimum required scopes for this policy
$RequiredScopes = @('Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'Group.Read.All', 'DeviceManagementManagedDevices.Read.All')
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
$CompliantDeviceExGroupId = Get-CAGroupId -DisplayName 'CA-EX-Exclusions-CompliantDevice'
#endregion

#region Enforcement preflight: Intune enrollment coverage
if ($Enforce) {
    Write-Host 'Checking Intune managed device compliance state before enforcing...' -ForegroundColor Cyan
    $Devices = @(Get-MgDeviceManagementManagedDevice -All)
    if ($Devices.Count -eq 0) {
        throw 'No Intune managed devices were found in this tenant. Enforcing CA-14 now would cut off every device. Aborting.'
    }
    $Devices | Group-Object ComplianceState | Select-Object Name, Count | Format-Table -AutoSize | Out-String | Write-Host
    Write-Warning 'Every device that is not enrolled and compliant loses access the moment this enforces. Expected path: minimum one week in report-only, daily sign-in log review, enroll remaining devices, enforce in waves.'
    $Answer = Read-Host 'Type ENFORCE to confirm you have reviewed report-only results and enrollment coverage'
    if ($Answer -ne 'ENFORCE') { Write-Host 'Aborted.'; return }
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
$PolicyName = 'CA-14-Require-AllUsers-CompliantDevice'
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
            excludeGroups = @($BreakGlassGroupId, $CompliantDeviceExGroupId)
        }
        applications = @{ includeApplications = @('All') }
    }
    grantControls = @{ operator = 'OR'; builtInControls = @('compliantDevice', 'domainJoinedDevice') }
}

if ($PSCmdlet.ShouldProcess($PolicyName, "Create Conditional Access policy in state '$State'")) {
    $Result = New-MgIdentityConditionalAccessPolicy -BodyParameter $Policy
    Write-Host ''
    Write-Host "Created policy : $($Result.DisplayName)" -ForegroundColor Green
    Write-Host "Policy Id      : $($Result.Id)"
    Write-Host "State          : $State"
}
#endregion
