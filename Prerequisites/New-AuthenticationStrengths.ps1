<#
.SYNOPSIS
    Creates the AS-Passkey-Onboarding custom authentication strength.

.DESCRIPTION
    Creates the authentication strength used by CA-Passkey-SecureRegistration to gate
    the 'Register security information' user action. Allowed combinations:

      - fido2                        (an existing passkey)
      - temporaryAccessPassOneTime   (TAP issued out-of-band, one-time)
      - temporaryAccessPassMultiUse  (TAP issued out-of-band, multi-use)

    Both TAP variants are included on purpose so the strength matches the tenant's TAP
    policy regardless of whether it issues one-time or multi-use passes. A strength
    that only allows one variant while the tenant issues the other silently rejects
    valid TAPs, which strands users at registration.

.NOTES
    Run order     : After New-CAGroups.ps1, before CA-Passkey-SecureRegistration.ps1.
    License       : Entra ID P1.
    Gotchas:
        - Confirm the Temporary Access Pass authentication method is ENABLED in the
          tenant's Authentication methods policy, and note whether it issues one-time
          or multi-use passes. The strength allows both, but TAP itself must be turned
          on or nobody can onboard.
        - The built-in 'Phishing-resistant MFA' strength used by CA-07 already exists
          in every tenant and is not created here.

.EXAMPLE
    .\New-AuthenticationStrengths.ps1

.EXAMPLE
    .\New-AuthenticationStrengths.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param()

$ErrorActionPreference = 'Stop'

#region Connect
$RequiredScopes = @('Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess')
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

#region Create AS-Passkey-Onboarding
$StrengthName = 'AS-Passkey-Onboarding'
$Existing = @(Get-MgPolicyAuthenticationStrengthPolicy -All | Where-Object { $_.DisplayName -eq $StrengthName })
if ($Existing.Count -gt 0) {
    Write-Host "Exists, skipping : $StrengthName ($($Existing[0].Id))" -ForegroundColor Yellow
    $Expected = @('fido2', 'temporaryAccessPassOneTime', 'temporaryAccessPassMultiUse')
    $Missing = @($Expected | Where-Object { $_ -notin @($Existing[0].AllowedCombinations) })
    if ($Missing.Count -gt 0) {
        Write-Warning "Existing $StrengthName is missing combination(s): $($Missing -join ', '). Fix it or CA-Passkey-SecureRegistration will silently reject valid TAPs."
    }
}
elseif ($PSCmdlet.ShouldProcess($StrengthName, 'Create custom authentication strength (fido2 + both TAP variants)')) {
    $Body = @{
        displayName         = $StrengthName
        description         = 'CA framework: passkey onboarding. Allows an existing passkey (FIDO2) or an out-of-band Temporary Access Pass (one-time or multi-use) to register security info.'
        allowedCombinations = @('fido2', 'temporaryAccessPassOneTime', 'temporaryAccessPassMultiUse')
    }
    $New = New-MgPolicyAuthenticationStrengthPolicy -BodyParameter $Body
    Write-Host "Created          : $StrengthName ($($New.Id))" -ForegroundColor Green
    Write-Host 'Reminder: confirm Temporary Access Pass is enabled in the tenant''s Authentication methods policy and note the one-time vs multi-use setting.' -ForegroundColor Yellow
}
#endregion
