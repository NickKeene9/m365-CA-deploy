# Prerequisites

Everything in `/policies/` resolves group, named location, and authentication strength IDs at runtime by display name. These scripts create the objects those lookups depend on. Nothing in the policy scripts works until this folder has been run.

## Run order

| # | Script | Creates | Notes |
|---|--------|---------|-------|
| 1 | `New-CAGroups.ps1` | All `CA-IN-*` and `CA-EX-*` groups, including the **dynamic** `CA-IN-GuestUsers` | Safe to re-run, skips existing groups. Verify the dynamic group's processing state is On and membership has populated before trusting guest coverage. |
| 2 | `New-BreakGlassAccount.ps1` | Cloud-only break glass account with Global Administrator, added to `CA-EX-BreakGlass` | Needs `CA-EX-BreakGlass` to exist (step 1). Password is shown once, store it offline immediately. Run twice with different `-AccountName` values if the client wants two break glass accounts. |
| 3 | `New-NamedLocations.ps1` | `NL-Approved-Countries` (allowlist, unknown geo NOT included) and `NL-Corporate-IPs` (trusted) | Per-tenant input via parameters or prompts, nothing hardcoded. `NL-Corporate-IPs` is optional for CA-04 but required by CA-24. |
| 4 | `New-AuthenticationStrengths.ps1` | `AS-Passkey-Onboarding` (fido2 + both TAP variants) | Confirm TAP is enabled in the tenant's Authentication methods policy. |

## Manual steps the scripts do not do

- **Populate `CA-IN-Admins`.** Created empty by step 1. Add every privileged account except break glass before deploying CA-07 or CA-15.
- **Populate exception groups only with documented justification.** `CA-EX-ServiceAccounts`, `CA-EX-AllowLegacyAuthentication`, and the `CA-EX-Exclusions-*` groups are the entire exception mechanism for their policies. Every member is attack surface.
- **Break glass hygiene.** Register a FIDO2 key for the break glass account where practical, seal the credentials offline, and configure sign-in alerting for the account. Any break glass authentication should page a human.
- **Terms of Use.** CA-18 needs an agreement named `Guest Terms of Use` created under Entra ID > Identity Governance > Terms of use. There is no Graph-scripted path for the document upload in this repo.
- **Disable Security Defaults** before enforcing CA-02. They conflict with Conditional Access.

## What each policy script assumes exists

| Object | Consumed by |
|--------|-------------|
| `CA-EX-BreakGlass` (with members) | Every policy |
| `CA-IN-Admins` (populated) | CA-07, CA-15 |
| `CA-IN-GuestUsers` (dynamic, processing On) | CA-06, CA-17, CA-18 |
| `CA-EX-ServiceAccounts` | CA-02, CA-05 |
| `CA-EX-AllowLegacyAuthentication` | CA-01 |
| `CA-EX-Exclusions-DeviceCodeFlow` | CA-03 |
| `CA-EX-Exclusions-GeoIP` | CA-04 |
| `CA-EX-Exclusions-AzureMgmt` | CA-13 |
| `CA-EX-Exclusions-CompliantDevice` | CA-14 |
| `CA-EX-Exclusions-TokenProtection` | CA-21 |
| `NL-Approved-Countries` | CA-04 |
| `NL-Corporate-IPs` | CA-04 (optional), CA-24 (required) |
| `AS-Passkey-Onboarding` | CA-Passkey-SecureRegistration |
| Built-in `Phishing-resistant MFA` strength | CA-07 (exists in every tenant) |
| `Guest Terms of Use` agreement (manual) | CA-18 |

Every policy script fails loudly with a pointer back here if a lookup returns nothing. None of them will silently build a policy with a null include or exclude list.
