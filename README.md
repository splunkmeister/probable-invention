# CIS Microsoft Windows Server 2025 Benchmark v2.0.0 — Level 1 Implementation Packages

Group Policy hardening packages generated from
`CIS_Microsoft_Windows_Server_2025_Benchmark_v2.0.0.pdf`, with full automation,
post-deployment verification, and safe rollback.

Two GPOs are produced:

| GPO Name | Applies to |
|----------|-----------|
| `CIS - Windows Server 2025 - Member Servers - Level 1` | Domain member servers |
| `CIS - Windows Server 2025 - Domain Controllers - Level 1` | Domain controllers |

> **Quick start:** see [`RUNBOOK.md`](RUNBOOK.md) for the step-by-step deployment workflow.

---

## What this is

The benchmark's **454 recommendations** were parsed from the source PDF and turned into ready-to-run
artifacts: two security templates, a registry/Administrative-Template applier, advanced-audit and
firewall configuration, a full traceability matrix, role-impact analysis, and the operational scripts
to deploy, verify, and roll back. Every recommendation that could not be confidently and safely
auto-mapped is explicitly flagged **Needs Review** rather than guessed.

### Coverage

| Metric | Count |
|--------|------:|
| Recommendations parsed | 454 |
| Level 1 / Level 2 / Next-Gen | 360 / 86 / 8 |
| Applies to Member Server / Domain Controller | 423 / 418 |
| Member Server INF settings | 99 |
| Domain Controller INF settings | 101 |
| Administrative-Template / registry settings (PowerShell) | 173 |
| Advanced Audit subcategories (Member / DC) | 27 / 34 |
| Windows Firewall settings | 23 |
| Manual / Needs Review | 19 |

---

## How settings are delivered

Each recommendation is routed to the mechanism that handles its setting type correctly:

| Setting type (benchmark section) | Mechanism | Artifact |
|----------------------------------|-----------|----------|
| Account & lockout policy (§1) | INF `[System Access]` | `CIS_Server2025_*_Level1.inf` |
| User Rights Assignment (§2.2) | INF `[Privilege Rights]` (privilege constants + SIDs) | INF |
| Security Options (§2.3) | INF `[Registry Values]` / `[System Access]` | INF |
| System Services (§5) | INF `[Service General Setting]` | INF |
| Advanced Audit Policy (§17) | `auditpol` / GPO `audit.csv` | `CIS_AuditPolicy_*.csv`, `Set-CIS-AuditPolicy.ps1` |
| Administrative Templates (§18–19) | `Set-GPRegistryValue` | `RegistrySettings.ps1` |
| Windows Firewall (§9) | `Set-NetFirewallProfile` | inside the Create scripts |

The registry and firewall sides use **native cmdlets** (reliable). The INF + advanced-audit side is
staged into SYSVOL with the **CSE registration** and **version bookkeeping** that GPMC performs
internally — the part that must be exact, which the Create scripts do and then verify.

---

## Files

### Implementation
| File | Purpose |
|------|---------|
| `CIS_Server2025_Member_Level1.inf` | Member Server security template (UTF-16, secedit format) |
| `CIS_Server2025_DC_Level1.inf` | Domain Controller security template |
| `RegistrySettings.ps1` | Applies the 173 Administrative-Template settings via `Set-GPRegistryValue` |
| `CIS_AuditPolicy_Member.csv` / `CIS_AuditPolicy_DC.csv` | Advanced Audit Policy data |
| `Set-CIS-AuditPolicy.ps1` | Applies audit policy locally (`auditpol`) or to a GPO |

### Orchestration
| File | Purpose |
|------|---------|
| `Create-CIS-MemberServer-GPO.ps1` | Build + configure + link the Member GPO (supports `-WhatIf`) |
| `Create-CIS-DC-GPO.ps1` | Build + configure + link the DC GPO (supports `-WhatIf`) |
| `Test-CIS-Compliance.ps1` | Post-deployment verifier — actual-vs-expected PASS/FAIL per setting |
| `Rollback-CIS-GPO.ps1` | Safe undo: disable-links / unlink / backup+delete / restore |

### Documentation
| File | Purpose |
|------|---------|
| `README.md` | This file — overview, coverage, file index |
| `RUNBOOK.md` | Step-by-step deployment runbook |
| `ImplementationMatrix.xlsx` | Full traceability matrix + validation + MS-baseline cross-check + summary |
| `AdministrativeTemplateMappings.md` | Every Admin-Template setting: GPO path, value, registry, PowerShell |
| `PotentiallyDisruptiveSettings.md` | Settings that can break specific roles, with mitigations |
| `ExceptionsAndManualSteps.md` | Items not fully automated + site-specific values + deployment sequence |

---

## Deployment in brief

```powershell
# On a domain-joined host with RSAT (GroupPolicy + ActiveDirectory):
.\Create-CIS-MemberServer-GPO.ps1 -TargetOU "OU=Pilot,DC=corp,DC=com" -WhatIf   # 1. preview (no changes)
.\Create-CIS-MemberServer-GPO.ps1 -TargetOU "OU=Pilot,DC=corp,DC=com"           # 2. build + link to PILOT OU
#    on a pilot node:  gpupdate /force ; reboot
.\Test-CIS-Compliance.ps1 -Scope Member -CsvPath .\result.csv                   # 3. verify (target: 0 FAIL)
#    validate role workloads against PotentiallyDisruptiveSettings.md, then widen scope
.\Rollback-CIS-GPO.ps1 -Scope Member                                            # undo anytime (reversible)
```

Full procedure, per-role validation checklist, and rollback options are in [`RUNBOOK.md`](RUNBOOK.md).

---

## Maps to the original 6-phase brief

| Phase | Deliverable |
|-------|-------------|
| 1 — Analyze benchmark / matrix | `ImplementationMatrix.xlsx` |
| 2 — Security templates | the two `.inf` files |
| 3 — Administrative Templates | `AdministrativeTemplateMappings.md`, `RegistrySettings.ps1` |
| 4 — GPO automation | `Create-CIS-*-GPO.ps1` |
| 5 — Validation | matrix validation columns, `Test-CIS-Compliance.ps1`, `ExceptionsAndManualSteps.md` |
| 6 — MS baseline cross-check | matrix "MS Baseline" column (expert mapping — see caveats) |
| Special — disruptive settings | `PotentiallyDisruptiveSettings.md` |

---

## Validation status

- All PowerShell scripts pass the **PowerShell language parser**.
- `RegistrySettings.ps1` data array loads (173 entries, 0 malformed); `-WhatIf` proven to make **0**
  changes while previewing all 170 scoped settings.
- `Merge-Cse` (CSE registration) unit-tested: correct sorted output, preserves existing CSEs,
  idempotent.
- `Test-CIS-Compliance.ps1` comparison logic unit-tested (SID normalization, audit parsing,
  pass/fail/review).
- INF/DC scoping verified (MS-only vs DC-only variants correctly separated).

**Not yet done:** end-to-end execution against a live domain. The live AD / registry / `secedit` /
`auditpol` calls only run on Windows — exercise them on a **pilot OU** first (the `-WhatIf` preview and
`Test-CIS-Compliance.ps1` exist to de-risk exactly this).

## Caveats

1. **Pilot before production.** Link to a pilot OU, verify, validate workloads, then widen.
2. **Site-specific values** (renamed accounts, logon banners, firewall log names) are placeholders —
   set them per `ExceptionsAndManualSteps.md` §1.
3. **List/SDDL settings** (null-session pipes, remote SAM, Hardened UNC Paths, Defender ASR rules) are
   not guessed — see §2. Deploy ASR and NTLM restrictions in **audit mode** first.
4. **Account/lockout policy (§1)** is domain-wide only via the **Default Domain Policy**; the server
   GPO governs local accounts.
5. **`PrintSpoolerService` SID** (new in Server 2025) is kept as a friendly name pending confirmation.
6. **MS Baseline cross-check** is an expert mapping, not a byte-diff (the baseline GPO backup wasn't
   supplied) — verify against the real baseline where it matters.

---

*Generated from CIS Microsoft Windows Server 2025 Benchmark v2.0.0. CIS Benchmarks are © Center for
Internet Security; this package references recommendation IDs/titles for implementation and does not
redistribute the benchmark document.*
