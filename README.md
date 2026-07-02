# Entra ID Conditional Access Hardening Framework

Deployable Conditional Access policy set for post-breach Microsoft 365 tenant hardening. Built for my own use remediating breached client tenants for cyber insurance engagements. The design goal above all others is **reducing the chance of a second breach**, which means every script is safe by default, not just functional.

## Design principles

- **One self-contained PowerShell script per policy.** Grab a script, run it against a client tenant, done. No deploy engine, no JSON interpreter, no shared module dependency.
- **No hardcoded GUIDs.** Every script resolves group, named location, and authentication strength IDs at runtime by display name via Microsoft Graph. Lookups that return nothing fail loudly with a pointer to the prerequisite that creates the missing object. No script will silently build a policy with a null include or exclude list.
- **Report-only by default.** Every policy deploys as `enabledForReportingButNotEnforced` unless explicitly noted below. Each script takes an `-Enforce` switch to deploy enabled. There is no separate enforce script.
- **Break glass everywhere.** Every policy excludes `CA-EX-BreakGlass`, and every script warns if that group is empty before deploying.
- **Duplicate protection.** Scripts refuse to create a policy whose display name already exists in the tenant.
- **`-WhatIf` support** on every script via `SupportsShouldProcess`.

## Deliberate exceptions to report-only

These four deploy **enabled by default**, flagged in each script header:

| Policy | Why it skips report-only |
|--------|--------------------------|
| CA-08 CAE strict location | Report-only never revokes a token, so it provides zero safety margin for this control. |
| CA-17 Block guests from admin portals | No legitimate reason for a guest to reach an admin portal exists. |
| CA-23 Block high risk sign-ins (IR) | Incident response control, run manually during an active incident. There is no time for a monitoring phase mid-breach. |
| CA-24 Block remote MFA re-registration (IR) | Same. Deployed after forcing MFA re-registration to stop the attacker re-registering remotely. |

## The one hard gate

**CA-07 (Admin phishing-resistant MFA) must never silently move to enforced.** Its `-Enforce` path queries every transitive member of `CA-IN-Admins` against their registered authentication methods and refuses to enforce unless every admin has a FIDO2 or Windows Hello for Business method registered, listing any account missing coverage. Enforcing without hardware locks out every admin at once. The gate is lockout prevention and is non-negotiable.

## Repo structure

```
/prerequisites/                      Groups, break glass, named locations, auth strengths. Run first.
/policies/mandatory/                 CA-01 to CA-08. Every tenant, P1 baseline.
/policies/recommended/identity-mfa/  CA-09 to CA-13 + CA-Passkey-SecureRegistration.
/policies/recommended/device-based/  CA-14 to CA-16. Requires Intune.
/policies/recommended/guest-external/ CA-17, CA-18.
/policies/recommended/session-token/ CA-19 to CA-22.
/policies/post-breach-ir/            CA-23, CA-24. IR runbook only, not routine deployment.
```

## License requirements

| Tier | Policies |
|------|----------|
| Entra ID P1 (baseline) | CA-01 to CA-08 (mandatory), CA-13, CA-Passkey-SecureRegistration, CA-17, CA-18, CA-19, CA-20, CA-21, CA-24 |
| Entra ID P2 (Identity Protection) | CA-09, CA-10, CA-11, CA-12, CA-23. Scripts check for the `AAD_PREMIUM_P2` service plan before deploying. If unlicensed, document as a gap, do not approximate with other conditions. |
| P1 + Intune | CA-14, CA-15, CA-16 |
| P1 + Defender for Cloud Apps | CA-22 (plus app onboarding in the MCAS portal, the CA policy only routes the session) |
| Extra dependencies | CA-10/CA-11 need SSPR enabled (passwordChange grant). CA-18 needs a Terms of Use agreement created manually. CA-21 needs token-binding-capable clients: GA on Windows, still Preview on iOS/iPadOS/macOS as of mid-2026. |

## Deployment order

1. **Prerequisites.** Run the four scripts in `/prerequisites/` in the order in that folder's README. Populate `CA-IN-Admins` manually. Confirm break glass credentials are sealed offline.
2. **Mandatory, report-only.** Run CA-01 through CA-08 with no switches. CA-08 lands enabled by design, everything else lands report-only.
3. **Monitor.** Minimum one week of report-only sign-in log review. Fix root causes rather than widening exclusion groups.
4. **Enforce mandatory.** CA-01 through CA-06 with `-Enforce` as report-only data comes back clean.
5. **CA-07 readiness gate.** Register FIDO2 or Windows Hello for Business for every member of `CA-IN-Admins`, then run CA-07 with `-Enforce`. The gate will verify and refuse if anyone lacks coverage.
6. **Recommended tiers as licensing allows.** Identity/MFA (P2 checks built in), then device-based (CA-15 before or alongside CA-14, CA-16 as a stepping stone, CA-14 enforced in waves after its own Intune coverage preflight), guest/external, session/token (CA-21 last and gradually).
7. **IR folder stays holstered.** CA-23 and CA-24 are runbook scripts for active incidents only.

## Standard exclusion group model

Exception groups (`CA-EX-*`) are the entire exception mechanism for their policies. There are no allow policies. Every member of an exception group is attack surface and requires documented business justification. Review exception group membership during every engagement.
