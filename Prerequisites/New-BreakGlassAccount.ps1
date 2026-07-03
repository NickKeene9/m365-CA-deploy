<#
.SYNOPSIS
    Creates a cloud-only break glass account, assigns Global Administrator, and adds it
    to the CA-EX-BreakGlass exclusion group.

.DESCRIPTION
    The break glass account is the lockout insurance for the entire framework. Every
    policy in this repo excludes CA-EX-BreakGlass. This script:

      1. Creates a cloud-only account on the tenant's initial .onmicrosoft.com domain
         (never a federated or synced domain, so it survives on-prem or federation
         outages).
      2. Generates a long random password and disables password expiration.
      3. Assigns the Global Administrator role.
      4. Adds the account to CA-EX-BreakGlass.

.NOTES
    Run order     : Run AFTER New-CAGroups.ps1 (CA-EX-BreakGlass must exist).
    License       : None required for the account itself.
    Gotchas:
        - The generated password is displayed ONCE. Store it offline in a sealed,
          access-controlled location per the client's break glass procedure. It is not
          stored anywhere else.
        - Do NOT add the break glass account to CA-IN-Admins. It must stay excluded
          from every CA policy via CA-EX-BreakGlass only.
        - Register a FIDO2 key for this account where practical and store the key with
          the sealed credentials. Excluded is not the same as unprotected.
        - Monitor sign-ins by this account. Any authentication by break glass should
          page a human. Alerting is configured separately, this script does not do it.
        - Best practice is two break glass accounts. Re-run with a different
          -AccountName for the second.

.EXAMPLE
    .\New-BreakGlassAccount.ps1
    Creates 'breakglass-admin' on the initial onmicrosoft.com domain.

.EXAMPLE
    .\New-BreakGlassAccount.ps1 -AccountName 'bg-emergency-02'
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$AccountName = 'breakglass-admin',
    [string]$DisplayName = 'Break Glass Emergency Access'
)

$ErrorActionPreference = 'Stop'

#region Connect
$RequiredScopes = @('User.ReadWrite.All', 'Group.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'Domain.Read.All')
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

#region Resolve the initial onmicrosoft.com domain (cloud-only, survives federation outages)
$InitialDomain = @(Get-MgDomain -All | Where-Object { $_.IsInitial -eq $true })
if ($InitialDomain.Count -eq 0) {
    throw 'Could not resolve the tenant''s initial .onmicrosoft.com domain. Aborting.'
}
$Upn = "$AccountName@$($InitialDomain[0].Id)"
#endregion

#region Guard rails
$ExistingUser = @(Get-MgUser -Filter "userPrincipalName eq '$Upn'" -All)
if ($ExistingUser.Count -gt 0) {
    throw "An account with UPN '$Upn' already exists. Pick a different -AccountName rather than reusing an account of unknown provenance for break glass."
}

$BreakGlassGroup = @(Get-MgGroup -Filter "displayName eq 'CA-EX-BreakGlass'" -All)
if ($BreakGlassGroup.Count -eq 0) {
    throw "Group 'CA-EX-BreakGlass' was not found. Run New-CAGroups.ps1 first. The break glass account is useless without the CA exclusion group."
}
$BreakGlassGroupId = $BreakGlassGroup[0].Id
#endregion

#region Generate a long random password (cryptographically random, 48 chars)
$CharSet = ([char[]](33..126)) | Where-Object { $_ -notin @('"', "'", '`', '\') }
$Bytes = [byte[]]::new(48)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($Bytes)
$Password = -join ($Bytes | ForEach-Object { $CharSet[ $_ % $CharSet.Count ] })
#endregion

#region Create the account
if ($PSCmdlet.ShouldProcess($Upn, 'Create break glass account, assign Global Administrator, add to CA-EX-BreakGlass')) {
    $UserBody = @{
        accountEnabled    = $true
        displayName       = $DisplayName
        mailNickname      = ($AccountName -replace '[^a-zA-Z0-9]', '')
        userPrincipalName = $Upn
        usageLocation     = 'US'
        passwordPolicies  = 'DisablePasswordExpiration'
        passwordProfile   = @{
            password                             = $Password
            forceChangePasswordNextSignIn        = $false
            forceChangePasswordNextSignInWithMfa = $false
        }
    }
    $NewUser = New-MgUser -BodyParameter $UserBody
    Write-Host "Created account : $Upn ($($NewUser.Id))" -ForegroundColor Green

    # Assign Global Administrator. Activate the directory role from template if needed.
    $GlobalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'
    $Role = @(Get-MgDirectoryRole -All | Where-Object { $_.RoleTemplateId -eq $GlobalAdminTemplateId })
    if ($Role.Count -eq 0) {
        $Role = @(New-MgDirectoryRole -BodyParameter @{ roleTemplateId = $GlobalAdminTemplateId })
    }
    New-MgDirectoryRoleMemberByRef -DirectoryRoleId $Role[0].Id -BodyParameter @{
        '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($NewUser.Id)"
    }
    Write-Host 'Assigned role   : Global Administrator' -ForegroundColor Green

    # Add to the CA exclusion group
    New-MgGroupMemberByRef -GroupId $BreakGlassGroupId -BodyParameter @{
        '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($NewUser.Id)"
    }
    Write-Host 'Added to group  : CA-EX-BreakGlass' -ForegroundColor Green

    Write-Host ''
    Write-Host '================= BREAK GLASS CREDENTIALS (SHOWN ONCE) =================' -ForegroundColor Red
    Write-Host "  UPN      : $Upn"
    Write-Host "  Password : $Password"
    Write-Host '=========================================================================' -ForegroundColor Red
    Write-Host 'Store these offline in a sealed, access-controlled location NOW. This password is not recorded anywhere else.' -ForegroundColor Yellow
    Write-Host 'Then: register a FIDO2 key for this account if practical, and configure sign-in alerting for it.' -ForegroundColor Yellow
}
#endregion
