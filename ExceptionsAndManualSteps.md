# Exceptions, Manual Steps & Needs-Review Items
## CIS Microsoft Windows Server 2025 Benchmark v2.0.0 - Level 1

This document lists every recommendation that the automation **did not** fully encode as an
INF / registry / audit setting, and therefore needs a manual decision, a site-specific value,
or human review before deployment. Everything else is implemented in the INF files,
`RegistrySettings.ps1`, or the audit CSVs (see `ImplementationMatrix.xlsx` for the full map).

## 1. Manual / interactive configuration (site-specific values)

| CIS ID | Recommendation | Action required |
|--------|----------------|-----------------|
| 1.2.3 | 'Allow Administrator account lockout' is set to 'Enabled' (M | 'Allow Administrator account lockout' (MS only, Manual). AllowAdministratorLockout=1 is staged in the Member INF; verify lockout threshold > 0. |
| 2.3.11.5 | 'Network security: Force logoff when logon hours expire' is  | Manual assessment per benchmark audit/remediation text. |
| 2.3.1.3 | 'Accounts: Rename administrator account' | Set NewAdministratorName in the INF to your standard renamed-admin value (placeholder 'CIS-Admin'). |
| 2.3.1.4 | 'Accounts: Rename guest account' | Set NewGuestName in the INF to your standard renamed-guest value (placeholder 'CIS-Guest'). |
| 2.3.7.4 | 'Interactive logon: Message text for users attempting to log | Provide your organisation's legal logon banner TEXT (LegalNoticeText) - set as REG_SZ. |
| 2.3.7.5 | 'Interactive logon: Message title for users attempting to lo | Provide your organisation's legal logon banner TITLE (LegalNoticeCaption) - set as REG_SZ. |
| 2.3.7.7 | 'Interactive logon: Prompt user to change password before ex | 'Prompt to change password' is a range (5-14 days). Automation defaults to 14; adjust if required. |

## 2. List / multi-value settings not auto-encoded (provide explicit values)

These are REG_MULTI_SZ or multi-field policies whose CIS value is a *list* that should be
set deliberately rather than guessed:

| CIS ID | Recommendation | Desired | Note |
|--------|----------------|---------|------|
| 2.3.10.6 | 'Network access: Named Pipes that can be accessed anony | (Configured per CIS li | NullSessionPipes - CIS value is an empty/curated list. Set REG_MULTI_SZ explicitly. |
| 2.3.10.7 | 'Network access: Named Pipes that can be accessed anony | (Configured per CIS li | NullSessionPipes (alt) - reconcile with 2.3.10.6 list. |
| 2.3.10.8 | 'Network access: Remotely accessible registry paths' is | (Configured per CIS li | Remotely accessible registry paths (Machine\...) - set the exact CIS path list. |
| 2.3.10.9 | 'Network access: Remotely accessible registry paths and | (Configured per CIS li | Remotely accessible registry paths AND sub-paths - set the exact CIS path list. |
| 2.3.10.11 | 'Network access: Restrict clients allowed to make remot | Administrators: Remote | Restrict remote SAM (restrictremotesam) - REG_SZ SDDL string; CIS = O:BAG:BAD:(A;;RC;;;BA). |
| 2.3.10.12 | 'Network access: Shares that can be accessed anonymousl | None | NullSessionShares - set REG_MULTI_SZ (CIS = empty). |
| 18.6.14.1 | 'Hardened UNC Paths' is set to 'Enabled, with "Require  | Enabled, with "Require | Hardened UNC Paths - set \\*\SYSVOL and \\*\NETLOGON to 'RequireMutualAuthentication=1, RequireIntegrity=1'. |
| 18.10.42.6.1.2 | 'Configure Attack Surface Reduction rules: Set the stat | (Configured per CIS li | Defender ASR rules - enable each rule GUID = 1 (Block). Deploy in Audit (2) first. |
| 2.3.5.2 | 'Domain controller: Allow vulnerable Netlogon secure ch | Not Configured | Netlogon VulnerableChannelAllowList - REG_SZ; CIS = Not Configured (leave undefined). |

## 3. Privilege Rights needing SID confirmation

The Server 2025 benchmark introduces the restricted **PrintSpoolerService** identity in two
User-Rights settings. Its SID is not officially published at time of writing, so the INF keeps
the friendly name `RESTRICTED SERVICES\PrintSpoolerService`. Confirm the SID resolves on your
build (it should auto-resolve when the Print Spooler restricted-service feature is present).

- **2.2.30** Generate security audits
- **2.2.31 / 2.2.32** Impersonate a client after authentication

## 4. Delivery mechanisms that are not INF

- **Advanced Audit Policy (section 17, 34 subcategories):** delivered via `CIS_AuditPolicy_*.csv`
  + `Set-CIS-AuditPolicy.ps1`. Requires INF setting 2.3.2.1 (SCENoApplyLegacyAuditPolicy=1).
- **Windows Firewall (section 9, 23 settings):** delivered via `Set-NetFirewallProfile` in the
  Create-*.ps1 scripts (profile state, default actions, logging). The per-setting log *Name*
  (9.1.4/9.2.4/9.3.6) is site-specific.
- **Administrative Templates (sections 18-19):** delivered via `RegistrySettings.ps1`
  (`Set-GPRegistryValue`). 173 Level-1 settings auto-mapped.

## 5. Recommended deployment sequence

1. Create a **pilot OU** with a handful of representative servers per role.
2. Run `Create-CIS-MemberServer-GPO.ps1` / `Create-CIS-DC-GPO.ps1` linked to the pilot OU.
3. Resolve every item in sections 1-3 above (site-specific values, lists, SIDs).
4. Put Defender ASR (18.10.42.6.1.2) and NTLM restrictions (2.3.11.13) in **audit** mode first.
5. Validate role workloads against `PotentiallyDisruptiveSettings.md`.
6. `gpupdate /force`, reboot a pilot node, run a CIS-CAT assessment, then widen the OU scope.
