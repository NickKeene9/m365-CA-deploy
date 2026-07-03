# Mandatory policies (CA-01 through CA-08)

The baseline every remediated tenant gets, regardless of licensing tier beyond Entra ID P1. Deploy in numeric order after `/prerequisites/` is complete.

## Behavior

Every script here deploys **report-only** (`enabledForReportingButNotEnforced`) and takes an `-Enforce` switch to deploy enabled instead, with two exceptions:

- **CA-07** has a hard enforcement gate. `-Enforce` refuses to run until every member of `CA-IN-Admins` has a registered FIDO2 or Windows Hello for Business method, and it lists any account missing coverage. This is lockout prevention. Do not work around it.
- **CA-08** deploys **enabled by default** with no `-Enforce` switch. Report-only does not revoke anything, so it provides no safety margin for a CAE session control. This is flagged in the script header so nobody assumes it behaves like the rest.

## Deployment flow

1. Run all eight scripts with no switches. Everything except CA-08 lands in report-only.
2. Monitor report-only results in the sign-in logs for at least a week. Look for legitimate traffic that would have been blocked, then fix root causes (enroll devices, migrate legacy auth clients, populate exception groups with documented justification) rather than widening exclusions.
3. Enforce CA-01 through CA-06 with `-Enforce` as report-only data comes back clean.
4. For CA-07: register phishing-resistant methods for every admin first, then run with `-Enforce`. The gate verifies readiness before it allows enforcement.
5. Enable tenant-wide CAE under Entra > Security > Continuous access evaluation to complement CA-08. The policy does not flip that setting for you.

## Per-policy notes

| Policy | Watch for |
|--------|-----------|
| CA-01 | Client apps condition covers both Exchange ActiveSync and Other clients. `CA-EX-AllowLegacyAuthentication` is the entire exception mechanism, there is no allow policy. |
| CA-02 | Disable Security Defaults first, they conflict. |
| CA-03 | Device code flow exclusions require documented business justification. |
| CA-04 | Allowlist pattern: `includeLocations = 'All'` with approved locations excluded. `'AllTrusted'` would invert the intent, do not change it. |
| CA-05 | Device filter targets Entra joined (`trustType AzureAD`) and hybrid joined (`trustType ServerAD`). Filter syntax is case sensitive. |
| CA-06 | Script verifies the `CA-IN-GuestUsers` dynamic rule and processing state before deploying. An empty or paused dynamic group is a silent gap. |
| CA-07 | Hard gate on enforce. Enforcing without hardware locks out every admin at once. |
| CA-08 | Enabled by default, strict location mode. Needs accurate named locations or you get spurious token revocations. |
