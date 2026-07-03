<#
.SYNOPSIS
    Creates the named locations the framework depends on: NL-Approved-Countries and
    NL-Corporate-IPs.

.DESCRIPTION
    Creates two named locations, taking per-tenant input as parameters or interactive
    prompts. Nothing is hardcoded because every client's geography and infrastructure
    differ.

      NL-Approved-Countries : Countries/regions type. 'Include unknown countries/
                              regions' is left UNCHECKED (includeUnknownCountriesAndRegions
                              = false). Used by CA-04 as the geo allowlist.
      NL-Corporate-IPs      : IP ranges type, marked TRUSTED. Optional depending on
                              client infrastructure. Used by CA-04 (allowlist exclusion)
                              and required by CA-24 (IR re-registration control).

.NOTES
    Run order     : After New-CAGroups.ps1, before CA-04 and CA-24.
    License       : Entra ID P1.
    Gotchas:
        - Country codes are ISO 3166-1 alpha-2 (US, CA, GB, ...).
        - IP ranges are CIDR notation (e.g. 203.0.113.0/24). Get these from the
          client's firewall/WAN documentation, not from guesswork. An IPv6 egress
          range you forget to include will generate blocks under CA-04.
        - Leaving 'Include unknown countries/regions' unchecked on the approved list
          means sign-ins from unresolvable geo are BLOCKED by CA-04. That is
          intentional for a post-breach posture.
        - Skipping NL-Corporate-IPs is fine for CA-04 but CA-24 refuses to deploy
          without it.

.EXAMPLE
    .\New-NamedLocations.ps1 -ApprovedCountries US,CA -CorporateIpRanges '203.0.113.0/24','198.51.100.0/24'

.EXAMPLE
    .\New-NamedLocations.ps1 -ApprovedCountries US
    Creates the country allowlist only and skips NL-Corporate-IPs.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string[]]$ApprovedCountries,
    [string[]]$CorporateIpRanges
)

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

#region Gather input if not supplied
if (-not $ApprovedCountries -or $ApprovedCountries.Count -eq 0) {
    $Raw = Read-Host 'Enter approved country codes (ISO 3166-1 alpha-2, comma separated, e.g. US,CA)'
    $ApprovedCountries = @($Raw -split ',' | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { $_ })
}
if ($ApprovedCountries.Count -eq 0) {
    throw 'No approved countries supplied. Refusing to create an empty country allowlist, which would block everything under CA-04.'
}
$InvalidCodes = @($ApprovedCountries | Where-Object { $_ -notmatch '^[A-Z]{2}$' })
if ($InvalidCodes.Count -gt 0) {
    throw "These are not valid two-letter country codes: $($InvalidCodes -join ', ')"
}

if (-not $PSBoundParameters.ContainsKey('CorporateIpRanges')) {
    $Raw = Read-Host 'Enter corporate egress IP ranges in CIDR (comma separated), or press Enter to skip NL-Corporate-IPs'
    $CorporateIpRanges = @($Raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
#endregion

#region NL-Approved-Countries
$CountriesName = 'NL-Approved-Countries'
$Existing = @(Get-MgIdentityConditionalAccessNamedLocation -Filter "displayName eq '$CountriesName'" -All)
if ($Existing.Count -gt 0) {
    Write-Host "Exists, skipping : $CountriesName ($($Existing[0].Id))" -ForegroundColor Yellow
}
elseif ($PSCmdlet.ShouldProcess($CountriesName, "Create country named location [$($ApprovedCountries -join ', ')]")) {
    $Body = @{
        '@odata.type'                     = '#microsoft.graph.countryNamedLocation'
        displayName                       = $CountriesName
        countriesAndRegions               = $ApprovedCountries
        includeUnknownCountriesAndRegions = $false   # intentionally unchecked, unknown geo gets blocked by CA-04
        countryLookupMethod               = 'clientIpAddress'
    }
    $New = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $Body
    Write-Host "Created          : $CountriesName ($($New.Id))" -ForegroundColor Green
}
#endregion

#region NL-Corporate-IPs (optional)
$IpName = 'NL-Corporate-IPs'
if (-not $CorporateIpRanges -or $CorporateIpRanges.Count -eq 0) {
    Write-Warning "No corporate IP ranges supplied. Skipping $IpName. CA-04 will proceed without it, but CA-24 (IR re-registration control) requires it and will refuse to deploy."
}
else {
    $InvalidCidrs = @($CorporateIpRanges | Where-Object { $_ -notmatch '^[0-9a-fA-F\.:]+/\d{1,3}$' })
    if ($InvalidCidrs.Count -gt 0) {
        throw "These do not look like CIDR ranges: $($InvalidCidrs -join ', ')"
    }

    $Existing = @(Get-MgIdentityConditionalAccessNamedLocation -Filter "displayName eq '$IpName'" -All)
    if ($Existing.Count -gt 0) {
        Write-Host "Exists, skipping : $IpName ($($Existing[0].Id))" -ForegroundColor Yellow
    }
    elseif ($PSCmdlet.ShouldProcess($IpName, "Create trusted IP named location [$($CorporateIpRanges -join ', ')]")) {
        $Ranges = @()
        foreach ($Cidr in $CorporateIpRanges) {
            if ($Cidr -match ':') {
                $Ranges += @{ '@odata.type' = '#microsoft.graph.iPv6CidrRange'; cidrAddress = $Cidr }
            }
            else {
                $Ranges += @{ '@odata.type' = '#microsoft.graph.iPv4CidrRange'; cidrAddress = $Cidr }
            }
        }
        $Body = @{
            '@odata.type' = '#microsoft.graph.ipNamedLocation'
            displayName   = $IpName
            isTrusted     = $true
            ipRanges      = $Ranges
        }
        $New = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $Body
        Write-Host "Created          : $IpName ($($New.Id)) [trusted]" -ForegroundColor Green
    }
}
#endregion
