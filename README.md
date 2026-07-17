# CIS Microsoft Windows Server 2025 — Level 1 Implementation Packages

Hardening packages generated from the CIS source PDFs, with full automation,
post-deployment verification, and safe rollback.

**Three profiles from two source documents:**

| Profile | Applies to | Source benchmark | Delivery |
|---------|-----------|------------------|----------|
| `CIS - Windows Server 2025 - Member Servers - Level 1` | Domain member servers | Benchmark **v2.0.0** | GPO or local |
| `CIS - Windows Server 2025 - Domain Controllers - Level 1` | Domain controllers | Benchmark **v2.0.0** | GPO or local |
| **Standalone** | **Workgroup / non-domain-joined servers** | **Stand-alone Benchmark v1.0.0** | Local only |

> **Quick start:** see [`RUNBOOK.md`](RUNBOOK.md) for the step-by-step deployment workflow.

> **⚠ Standalone servers use a different benchmark.** CIS publishes a separate *Stand-alone
> Benchmark v1.0.0* for them, because the v2.0.0 document is "not intended for use on standalone
> or workgroup systems". Applying the **Member** profile to a workgroup host **denies RDP to every
> administrator** — it denies `S-1-5-113` *Local account*, which on a workgroup host is every
> account. Use `Apply-CIS-Local.ps1 -Scope Standalone`; the script refuses a mismatched profile.
> See [`ExceptionsAndManualSteps.md` §4](ExceptionsAndManualSteps.md).

> **Numbering is not shared between the documents.** Standalone `2.2.16`/`2.2.20` are the settings
> Member calls `2.2.21`/`2.2.26`. Never cross-reference an ID between packages.

---

## What this is

Both benchmarks were parsed from their source PDFs and turned into ready-to-run artifacts:
three security templates, registry/Administrative-Template appliers, advanced-audit and firewall
configuration, full traceability matrices, role-impact analysis, and the operational scripts to
deploy, verify, and roll back. Every recommendation that could not be confidently and safely
auto-mapped is explicitly flagged **Needs Review** rather than guessed.

### Coverage — Member / DC (Benchmark v2.0.0)

| Metric | Count |
|--------|------:|
| Recommendations parsed | 454 |
| Level 1 / Level 2 / Next-Gen | 360 / 86 / 8 |
| Applies to Member Server / Domain Controller | 423 / 418 |
| Member Server INF settings | 99 |
| Domain Controller INF settings | 101 |
| Administrative-Template / registry settings (PowerShell) | 175 values / 173 recommendations |
| Advanced Audit subcategories (Member / DC) | 27 / 34 |
| Windows Firewall settings | 23 |
| Manual / Needs Review | 19 |

> Two recommendations take **two registry values each** — 18.10.77.2.1 (SmartScreen:
> `EnableSmartScreen` + `ShellSmartScreenLevel`) and 18.10.94.4.2 (Quality Updates:
> `DeferQualityUpdates` + `DeferQualityUpdatesPeriodInDays`) — hence 175 values for 173
> recommendations. Setting only the first of each pair applies half the recommendation.

### Coverage — Standalone (Stand-alone Benchmark v1.0.0)

| Metric | Count |
|--------|------:|
| Recommendations parsed | 389 |
| Level 1 / Level 2 / Next-Gen | **307** / 75 / 7 |
| INF `[System Access]` (§1, §2.3) | 15 |
| INF `[Privilege Rights]` (§2.2) | 37 |
| INF `[Registry Values]` (§2.3) | 47 |
| Administrative-Template / registry settings (§18–19) | 156 (159 values — 3 take two each) |
| Advanced Audit subcategories (§17) | 27 |
| Windows Firewall settings (§9, Private + Public) | 14 |
| Manual / Needs Review | 11 |
| **Total** | **307** ✓ |

Traceability: [`StandaloneImplementationMatrix.csv`](StandaloneImplementationMatrix.csv) — one row
per Level 1 recommendation, with the mechanism that delivers it.

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

> **§19 (User Configuration) is not force-applied on server OUs — by design.** The six §19 settings
> are written into the GPO's User Configuration, but a server/computer OU does not apply user policy
> to the computer, and this package does not enable loopback. They are low-value interactive-desktop
> controls on a server; the machine-scope hardening (§1, §2, §5, §9, §17, §18) applies in full. A
> CIS-CAT scan in an interactive server session reports the six §19 items as FAIL — that is expected.
> To enforce them, enable loopback (Merge) on the GPO or link a user-targeted GPO to the users' OU.
> See [`ExceptionsAndManualSteps.md` §5.1](ExceptionsAndManualSteps.md).

### Configuration note — 2.3.17.2 UAC elevation prompt (`ConsentPromptBehaviorAdmin`)

*User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode.*
CIS accepts **either** value and says so explicitly: *"The recommended state … is: Prompt for
consent on the secure desktop. Configuring this setting to Prompt for credentials on the secure
desktop also conforms to the benchmark"* (audit: `ConsentPromptBehaviorAdmin` = **1 or 2**). So both
values below are fully CIS Level 1 compliant.

| Host type | Value | Behavior | Rationale |
|-----------|:-----:|----------|-----------|
| **Standalone** | `2` | Prompt for **consent** (Yes/No) on the secure desktop | CIS's primary recommended value. Admins log in interactively; a password prompt on every elevation is high friction for no compliance gain. |
| **Member** | `2` | Prompt for **consent** (Yes/No) on the secure desktop | Same as above, kept consistent with Standalone. |
| **DC** | `1` | Prompt for **credentials** (password) on the secure desktop | Domain controllers are the highest-value target, so the stricter of the two accepted values is retained. |

The secure desktop itself (2.3.17.7 `PromptOnSecureDesktop=1`) is enabled on **all** host types — it
is the anti-spoofing control; the value above only chooses consent vs. credentials. This is a
deliberate configuration choice, not a deviation: all three settings pass a CIS-CAT Level 1 audit.

---

## Files

### Implementation
| File | Purpose |
|------|---------|
| `CIS_Server2025_Member_Level1.inf` | Member Server security template (UTF-16, secedit format) |
| `CIS_Server2025_DC_Level1.inf` | Domain Controller security template |
| `CIS_Server2025_Standalone_Level1.inf` | **Standalone** security template (Stand-alone v1.0.0) |
| `CIS-Scope.ps1` | Shared profile definitions: which benchmark each `-Scope` implements, host-role detection |
| `RegistrySettings.ps1` | Member/DC Administrative-Template settings (173) via `Set-GPRegistryValue` |
| `RegistrySettings-Standalone.ps1` | **Standalone** §18–19 registry settings (156), standalone numbering |
| `CIS-Standalone-Data.ps1` | **Standalone** §17 audit (27), §9 firewall (14), and the 11 Needs-Review items |
| `CIS_AuditPolicy_Member.csv` / `_DC.csv` / `_Standalone.csv` | Advanced Audit Policy data |
| `Set-CIS-AuditPolicy.ps1` | Applies audit policy locally (`auditpol`) or to a GPO |
| `StandaloneImplementationMatrix.csv` | **Standalone** traceability — 307 rows, one per L1 recommendation |

> The audit CSVs stage into SYSVOL, which a workgroup host has no use for, so `-Mode GpoCsv` is
> rejected for `-Scope Standalone` — it applies via `auditpol` instead (`Apply-CIS-Local.ps1`
> calls this for you). `CIS_AuditPolicy_Standalone.csv` exists for delivery via `LGPO.exe` into
> the **local** GPO. Both benchmarks prescribe the same 27 subcategories, but under different
> recommendation numbers, so the standalone CSV carries standalone IDs.

### Orchestration
| File | Purpose |
|------|---------|
| `Apply-CIS-Local.ps1` | **Build-time / standalone apply** to the local machine (no domain): pre-apply state capture + `secedit` INF + registry + audit + firewall (supports `-WhatIf`) |
| `Create-CIS-MemberServer-GPO.ps1` | Build + configure + link the Member GPO (supports `-WhatIf`) |
| `Create-CIS-DC-GPO.ps1` | Build + configure + link the DC GPO (supports `-WhatIf`) |
| `Test-CIS-Compliance.ps1` | Post-deployment verifier — actual-vs-expected PASS/FAIL per setting |
| `Rollback-CIS-GPO.ps1` | Safe undo **for the domain GPOs**: disable-links / unlink / backup+delete / restore |

> **Undo differs by delivery model.** A GPO is undone by unlinking it (`Rollback-CIS-GPO.ps1`) —
> instant and reversible. A **local apply writes straight to the host**, so there is no link to
> pull: `Apply-CIS-Local.ps1` therefore takes a **pre-apply capture** of security policy
> (`secedit /export`) and audit policy (`auditpol /backup`) before writing anything, and prints
> the restore commands at the end. It **aborts rather than proceed** if that capture fails.
> Administrative-Template values (§18–19) are policy registry values and are *not* covered by
> that capture — revert them via GPO, re-imaging, or by hand. This matters most for
> **Standalone**, which is local-only and has no GPO to fall back on.

### Two delivery models — pick one or both
- **Build-time (local):** `Apply-CIS-Local.ps1` hardens each host during provisioning (golden image,
  MDT/SCCM, Packer, Ansible/DSC) via `secedit /configure` + direct registry/audit/firewall. Deterministic,
  no domain dependency, **no SYSVOL/AD changes** — but does not self-heal drift.
- **Domain GPO:** `Create-CIS-*-GPO.ps1` stages the template into a GPO; clients apply it at refresh.
  Central and self-healing, but mutates the domain.
- **Both (common):** bake the baseline at build time, link a GPO for drift enforcement. Where both touch a
  setting, the GPO wins (applied last).
- **Standalone: local only.** There is no domain, so no GPO and no self-healing. Re-run
  `Apply-CIS-Local.ps1 -Scope Standalone` on a schedule (or via your config-management tool) if
  you want drift correction.

---

## Standalone / workgroup servers

**These use a different CIS benchmark.** The v2.0.0 document excludes them from its own scope
(*Intended Audience*, p.27):

> The Microsoft Windows Benchmarks are written for Active Directory domain-joined systems using
> Active Directory's Group Policy Manager only. **This benchmark is not intended for use on
> standalone or workgroup systems**…

CIS publishes a separate document for them — *CIS Microsoft Windows Server 2025 **Stand-alone**
Benchmark v1.0.0*: **"This CIS Benchmark is written for stand-alone systems only."**

`-Scope Standalone` implements that benchmark **verbatim**. There are **no local deviations**, so
a host hardened with it can legitimately be described as *"Hardened to CIS Microsoft Windows
Server 2025 Stand-alone Benchmark v1.0.0, Level 1."* Assess it with a CIS-CAT profile for the
**Stand-alone** benchmark — grading a workgroup host against the *Member Server* profile produces
false failures, because the documents prescribe different values.

**It is not a Member variant.** Different document, different numbering, smaller set:

| | Member/DC (v2.0.0) | Stand-alone (v1.0.0) |
|---|---|---|
| Recommendations | 454 (360 L1) | **389 (307 L1)** |
| §9 firewall | Domain + Private + Public | **Private + Public** (no Domain profile) |
| §17 audit | 27 / 34 | 27 — same subcategories, **different IDs** |
| Windows LAPS | 18.9.26.1–.8 | **absent** — LAPS can't work standalone |
| `PrintSpoolerService` SID | present | **absent** |

**Why the Member profile is dangerous here.** It denies logon rights to `S-1-5-113`
(*Local account*) and `S-1-5-114` (*…member of Administrators*). On a domain member those match
only break-glass accounts; on a workgroup host they match **every account**. CIS says so in the
Member benchmark's own Impact text:

> **2.2.26** — "Caution: Configuring a standalone (non-domain-joined) or a system hosted in the
> Cloud (Azure) as described above (Local account) **will result in an inability to remotely
> administer** the workstation."

The Stand-alone benchmark therefore prescribes plain `Guests` for both rights (its `2.2.20` and
`2.2.16`), and does not include `LocalAccountTokenFilterPolicy` at all.

```powershell
.\Apply-CIS-Local.ps1 -Scope Standalone -WhatIf     # preview, change nothing
.\Apply-CIS-Local.ps1 -Scope Standalone             # apply Stand-alone v1.0.0 L1
.\Test-CIS-Compliance.ps1 -Scope Standalone -CsvPath .\standalone-result.csv
```

`Apply-CIS-Local.ps1` **refuses a profile that doesn't match the host's actual domain role**
(`Win32_ComputerSystem.DomainRole`) unless you pass `-Force`, so the Member profile can't reach a
workgroup box by accident. The 11 recommendations that aren't auto-applied are printed at apply
time, listed by the verifier, and marked `NEEDS REVIEW` in the matrix — a clean report never
implies coverage it doesn't have.

> **Three standalone risks the domain profiles don't have.** §1 account policy now governs the SAM
> directly, so **1.2.3 `AllowAdministratorLockout`** means the built-in Administrator can be locked
> out by 5 bad passwords — keep a second admin account. **NTP** has no domain time hierarchy to
> sync from; set an explicit source or your audit timestamps drift. And **Windows LAPS cannot run
> standalone**, so local-admin password rotation needs another mechanism — the control is not
> waived, only the tool. All three are in
> [`ExceptionsAndManualSteps.md` §4](ExceptionsAndManualSteps.md).

### Documentation
| File | Purpose |
|------|---------|
| `README.md` | This file — overview, coverage, file index |
| `RUNBOOK.md` | Step-by-step deployment runbook |
| `ImplementationMatrix.xlsx` | Member/DC traceability + validation + MS-baseline cross-check |
| `StandaloneImplementationMatrix.csv` | Standalone traceability — 307 L1 rows, mechanism per recommendation |
| `AdministrativeTemplateMappings.md` | Every Admin-Template setting: GPO path, value, registry, PowerShell |
| `PotentiallyDisruptiveSettings.md` | Settings that can break specific roles, with mitigations |
| `ExceptionsAndManualSteps.md` | Items not fully automated + site-specific values + standalone (§4) |

---

## Deployment in brief

```powershell
# On a domain-joined host with RSAT (GroupPolicy + ActiveDirectory):
.\Create-CIS-MemberServer-GPO.ps1 -WhatIf                            # 1. preview (no changes)
.\Create-CIS-MemberServer-GPO.ps1                                    # 2. build WITHOUT linking (affects no servers)
#    review the GPO in GPMC, then link DELIBERATELY to a pilot OU:
.\Create-CIS-MemberServer-GPO.ps1 -TargetOU "OU=Pilot,DC=corp,DC=com"   # 3. link -> goes live at next gpupdate
#    on a pilot node:  gpupdate /force ; reboot
.\Test-CIS-Compliance.ps1 -Scope Member -CsvPath .\result.csv        # 4. verify (target: 0 FAIL)
#    validate role workloads against PotentiallyDisruptiveSettings.md, then widen scope
.\Rollback-CIS-GPO.ps1 -Scope Member                                 # undo anytime (DisableLink = reversible)
```

> **Linking is opt-in.** The Create scripts build and configure the GPO but **do not link** unless you
> pass `-TargetOU`. Linking is the only step that affects running servers. `-NoLink` forces build-only
> even if an OU is given.

For a **standalone** host there is no OU, GPO or `gpupdate` — `Apply-CIS-Local.ps1` is the whole
deployment:

```powershell
.\Apply-CIS-Local.ps1 -Scope Standalone -WhatIf                       # 1. preview (no changes)
.\Apply-CIS-Local.ps1 -Scope Standalone                               # 2. apply, then reboot
.\Test-CIS-Compliance.ps1 -Scope Standalone -CsvPath .\result.csv     # 3. verify (target: 0 FAIL)
```

Full procedure, per-role validation checklist, and rollback options are in [`RUNBOOK.md`](RUNBOOK.md).

---

## Maps to the original 6-phase brief

| Phase | Deliverable |
|-------|-------------|
| 1 — Analyze benchmark / matrix | `ImplementationMatrix.xlsx`, `StandaloneImplementationMatrix.csv` |
| 2 — Security templates | the three `.inf` files |
| 3 — Administrative Templates | `AdministrativeTemplateMappings.md`, `RegistrySettings.ps1`, `RegistrySettings-Standalone.ps1` |
| 4 — GPO automation | `Create-CIS-*-GPO.ps1` (domain); `Apply-CIS-Local.ps1` (standalone) |
| 5 — Validation | matrix validation columns, `Test-CIS-Compliance.ps1`, `ExceptionsAndManualSteps.md` |
| 6 — MS baseline cross-check | matrix "MS Baseline" column (expert mapping — see caveats) |
| Special — disruptive settings | `PotentiallyDisruptiveSettings.md` |

---

## Logging

**Script logs (what the automation did).** Every script writes a timestamped PowerShell transcript —
the full run, including warnings and errors — and prints the path at start and end:

| Script | Default log | Override |
|--------|-------------|----------|
| `Create-CIS-*-GPO.ps1` | `.\Logs\Create-CIS-<scope>-<timestamp>.log` | `-LogPath` |
| `Apply-CIS-Local.ps1` | `%windir%\Temp\CIS-Apply-<scope>.log` (+ `secedit` log `%windir%\Temp\CIS-secedit-<scope>.log`) | `-LogPath` |
| `Rollback-CIS-GPO.ps1` | `.\Logs\Rollback-CIS-<scope>-<timestamp>.log` | `-LogPath` |
| `Test-CIS-Compliance.ps1` | `.\Logs\Test-CIS-<scope>-<timestamp>.log` | `-LogPath`; machine-readable results via `-CsvPath` |

**Native logs (what happened when the policy applied on a server)** — already built into Windows:

- **Group Policy processing:** Event Viewer → *Applications and Services Logs → Microsoft → Windows →
  GroupPolicy → Operational* (and the System log, source `GroupPolicy`).
- **What actually applied / who won:** `gpresult /h C:\rsop.html` (or `/r`).
- **Security template (INF) application:** `%windir%\security\logs\winlogon.log`; dump current state with
  `secedit /export /cfg C:\current.inf`.
- **Advanced Audit Policy in effect:** the **Security** event log; current config via `auditpol /get /category:*`.
- **Firewall:** `%SystemRoot%\System32\logfiles\firewall\pfirewall.log` (this baseline turns logging on).

## Validation status

- All PowerShell scripts pass the **PowerShell language parser**.
- `RegistrySettings.ps1` data array loads (175 values, 0 malformed); `-WhatIf` proven to make **0**
  changes while previewing all scoped settings.
- `Merge-Cse` (CSE registration) unit-tested: correct sorted output, preserves existing CSEs,
  idempotent.
- INF/DC scoping verified (MS-only vs DC-only variants correctly separated).
- **Member/DC swept for the extraction defects found during the standalone rebuild** — welded
  paths, GUID hyphen loss, truncated value names, malformed values: **clean**. The sweep did find
  two half-applied recommendations (18.10.77.2.1 and 18.10.94.4.2 set only the first value of a
  two-value pair, and the verifier reported PASS on them); both are now fixed in
  `RegistrySettings.ps1`, `Test-CIS-Compliance.ps1` and `AdministrativeTemplateMappings.md`.

**Standalone package — how it was verified.** It is generated from the Stand-alone v1.0.0 PDF, so
the extraction itself is the risk. It is cross-checked against the hand-verified Member package
wherever the two benchmarks prescribe the same thing:

- **All 389 recommendations anchored**; 307 Level 1 accounted for with **zero unclassified**:
  15 + 37 + 47 (INF) + 156 (registry) + 27 (audit) + 14 (firewall) + 11 (Needs Review) = **307**.
- **User rights: 31 of 36 generate byte-identical to the Member INF.** The 5 differences are the
  genuinely standalone ones (2.2.16 / 2.2.20 deny rights, `PrintSpoolerService` absent, and two
  role-conditional principals that are documented rather than applied).
- **`[System Access]` 15/15 and shared `[Registry Values]` 41/41 identical to the Member INF**;
  **180 of 181** shared registry paths agree (the one difference is the §19 `HKU\[USER SID]`
  convention, not an error).
- **Registry values are validated before emission.** The PDF wraps long paths mid-token, spells
  the hive two ways (`HKLM` and `HKEY_LOCAL_MACHINE`), and contains a typo
  (`"REG_DWORD value of 1or 2"`). Both `pdftotext` modes were reconciled against each other and
  against the Member table; **0 conflicts remain unresolved**, and any value that is still not
  well-formed for its type becomes a Needs-Review item rather than being guessed.
- Data modules dot-source with **no errors, 0 malformed values, 0 duplicate IDs**; the INF is
  UTF-16LE+BOM as `secedit` requires.

**Not yet done:** end-to-end execution against a live domain, and end-to-end execution of the
standalone path on a real Server 2025 workgroup host (the `secedit` / `auditpol` / firewall calls
need an elevated session on Windows Server). Exercise the domain path on a **pilot OU** and the
standalone path on **one pilot host** first — the `-WhatIf` preview and `Test-CIS-Compliance.ps1`
exist to de-risk exactly this.

## Caveats

1. **Pilot before production.** Link to a pilot OU, verify, validate workloads, then widen.
   For standalone hosts, pilot on one representative box — there is no OU to stage through.
2. **Use the matching benchmark, and assess against it.** Member/DC = Benchmark v2.0.0;
   Standalone = Stand-alone Benchmark v1.0.0. Grading a workgroup host against the *Member Server*
   CIS-CAT profile produces **false failures** — the documents prescribe different values (§4).
   Their IDs are not comparable either.
3. **Site-specific values** (renamed accounts, logon banners, firewall log names) are placeholders —
   set them per `ExceptionsAndManualSteps.md` §1. The **account renames** (2.3.1.3/2.3.1.4) are now
   config-driven: pass `-AdminName`/`-GuestName` to `Apply-CIS-Local.ps1` or `Create-CIS-*-GPO.ps1`
   (the scripts warn if left at the predictable placeholder). On a standalone host the account rename
   touches the local SAM account you may be logged in with; set it *before* applying.
4. **List/SDDL settings** (null-session pipes, remote SAM, Hardened UNC Paths, Defender ASR rules) are
   not guessed — see §2. Deploy ASR and NTLM restrictions in **audit mode** first.
5. **Account/lockout policy (§1)** on a domain is domain-wide only via the **Default Domain
   Policy**; the server GPO governs local accounts. On a **standalone** host there is no Default
   Domain Policy — §1 governs the SAM directly and is the only account policy in force, including
   `AllowAdministratorLockout` (see §4.4).
6. **Windows LAPS cannot run on a standalone host** — CIS omits it from the Stand-alone benchmark
   entirely. The *control* still matters: give each host a unique local admin password via a
   PAM/secrets tool (§4.3). This is the biggest real gap in a workgroup fleet.
7. **`PrintSpoolerService` SID** (new in Server 2025) is kept as a friendly name pending
   confirmation. It is in the Member/DC INF only — Stand-alone v1.0.0 does not include it.
8. **MS Baseline cross-check** is an expert mapping, not a byte-diff (the baseline GPO backup wasn't
   supplied) — verify against the real baseline where it matters. It covers Member/DC only.
9. **The standalone package is generated from a PDF.** Extraction is cross-validated against the
   hand-verified Member package (see *Validation status*), but the PDF is imperfect — it wraps
   paths mid-token and contains at least one typo. Spot-check anything that matters to you against
   the source document before production.

---

*Generated from CIS Microsoft Windows Server 2025 Benchmark v2.0.0 and CIS Microsoft Windows
Server 2025 Stand-alone Benchmark v1.0.0. CIS Benchmarks are © Center for Internet Security; this
package references recommendation IDs/titles for implementation and does not redistribute the
benchmark documents.*
