# Runbook — CIS Windows Server 2025 Level 1 GPO Deployment

Operational, step-by-step. On-prem AD, run by an admin with GPO create/link rights.
Estimated pilot time: ~1 hour + workload soak. Keep all package files in one folder.

---

## 0. Prerequisites (once)

```powershell
# On a domain-joined management host or DC:
Install-WindowsFeature GPMC, RSAT-AD-PowerShell      # or Add-WindowsCapability for Win10/11 RSAT
Set-ExecutionPolicy -Scope Process Bypass            # per-session, for running these scripts
```
- Copy the whole package folder to the host (e.g. `C:\CIS`).
- Confirm you can resolve the domain: `Get-ADDomain | Select DNSRoot, DistinguishedName`.

---

## 1. Tailor site-specific values (once)

Edit per `ExceptionsAndManualSteps.md` **§1–§2** before building:

| Where | What to set |
|-------|-------------|
| Both `.inf` files (UTF-16 — use VS Code/Notepad) | `NewAdministratorName`, `NewGuestName` → your renamed accounts |
| `ExceptionsAndManualSteps.md` §2 | Decide the list/SDDL settings (null-session pipes, remote SAM, Hardened UNC, **ASR rules → start in Audit mode**) |
| Decide OUs | A **pilot OU** per role now; production OUs later |

> Account & lockout policy (section 1) only takes domain-wide effect from the **Default Domain
> Policy**. For domain accounts, copy the `[System Access]` password/lockout lines from the INF into
> the Default Domain Policy. The server GPO governs *local* accounts only.

---

## Alternative: build-time local apply (no domain GPO)

If hardening happens during host build (golden image / MDT / SCCM / Packer / Ansible), apply the
baseline locally instead of via GPO — deterministic and with no domain/SYSVOL changes:

```powershell
.\Apply-CIS-Local.ps1 -Scope Member -WhatIf    # preview
.\Apply-CIS-Local.ps1 -Scope Member            # secedit INF + registry + audit + firewall, locally
# reboot, then:  .\Test-CIS-Compliance.ps1 -Scope Member
```

This sets a known-good baseline but does **not** self-heal drift — pair it with the domain GPO below
for ongoing enforcement if you want both. The GPO steps (sections 2–7) are for the domain model.

`Apply-CIS-Local.ps1` refuses a profile that doesn't match the host's actual domain role. When
building a golden image that will be domain-joined *later*, pass `-Force` to apply `-Scope Member`
to a host that is still in a workgroup at build time.

---

## Standalone (workgroup) servers

Standalone hosts use a **different CIS document** — *Stand-alone Benchmark v1.0.0*, 307 Level 1
recommendations with its own numbering. There is no domain, so **sections 2–7 below do not apply**
— no OU, no GPO, no `gpupdate`, no GPO rollback. `Apply-CIS-Local.ps1` is the whole deployment.

> **Do not apply the Member profile to a workgroup host.** It denies RDP to `S-1-5-113`
> (*Local account*), which on a workgroup host is **every account**. CIS's own 2.2.26 Impact text:
> *"…will result in an inability to remotely administer the workstation."* A host with no console
> access is then unrecoverable. `-Scope Standalone` uses the benchmark written for these hosts,
> which prescribes plain `Guests`. The script refuses a mismatched profile unless you `-Force`.

```powershell
.\Apply-CIS-Local.ps1 -Scope Standalone -WhatIf                     # 1. preview — changes nothing
.\Apply-CIS-Local.ps1 -Scope Standalone                             # 2. capture state, then apply
#    reboot
.\Test-CIS-Compliance.ps1 -Scope Standalone -CsvPath .\result.csv   # 3. verify (target: 0 FAIL)
```

> **There is no GPO to unlink here, so the pre-apply capture is your only undo.**
> `Apply-CIS-Local.ps1` writes it to `%windir%\Temp\CIS-Backup-Standalone-<timestamp>` before
> touching anything, prints the `secedit /configure` + `auditpol /restore` commands at the end,
> and aborts if the capture fails. Note the capture does **not** cover Administrative-Template
> values (§18–19). Keep the backup folder until the host has soaked.

Standalone checklist:

1. Set the real values for the site-specific items (**rename Administrator/Guest**, logon banner)
   *before* applying — `CIS-Admin` / `CIS-Guest` are placeholders that hit the local SAM, and the
   rename can hit the account you are logged in with.
2. **Create a second local admin account.** §1 governs the SAM directly here, so 1.2.3
   `AllowAdministratorLockout = Enabled` means the built-in Administrator can be locked out by 5
   bad passwords — remotely triggerable if RDP is exposed.
3. Set an explicit **NTP source** — a workgroup host has no domain time hierarchy, so `NT5DS`
   never resolves and audit timestamps drift:
   `w32tm /config /manualpeerlist:"time.windows.com,0x9" /syncfromflags:manual /update`
4. Decide the **local admin password story**. Windows LAPS is absent from this benchmark because it
   cannot work standalone — but the control isn't waived. Unique per-host passwords via a
   PAM/secrets tool ([§4.3](ExceptionsAndManualSteps.md)). This is the biggest real gap.
5. Work through the **11 Needs-Review items** the apply run prints (lists, SDDL, ASR rules,
   banner text) — [§4.5](ExceptionsAndManualSteps.md).
6. Verify, validate the workload against `PotentiallyDisruptiveSettings.md`, then bake into the image.
7. **Re-run on a schedule** if you want drift correction — nothing self-heals without a GPO.
8. Assess with a CIS-CAT profile for the **Stand-alone** benchmark. Grading against the *Member
   Server* profile produces false failures — the two documents prescribe different values.

---

## 2. Dry-run (preview — changes nothing)

```powershell
cd C:\CIS
.\Create-CIS-MemberServer-GPO.ps1 -TargetOU "OU=Pilot Servers,DC=corp,DC=com" -WhatIf
```
Read the `What if:` output — it lists every registry value, the INF/audit staging, CSE registration,
version sync, and the OU link, **without making any change**. Do the same for the DC script with
`-Scope`-appropriate OU. When the plan looks right, proceed.

---

## 3. Build the GPO (without linking), then link deliberately

**Linking is opt-in** — without `-TargetOU` the GPO is built but affects no servers. Build first, review
in GPMC, then link to a pilot OU:

```powershell
.\Create-CIS-MemberServer-GPO.ps1                                       # build only, NOT linked
#  ...review the GPO in GPMC...
.\Create-CIS-MemberServer-GPO.ps1 -TargetOU "OU=Pilot Servers,DC=corp,DC=com"   # now link (goes live)
.\Create-CIS-DC-GPO.ps1           -TargetOU "OU=Pilot DCs,DC=corp,DC=com"
```
`-NoLink` forces build-only even if `-TargetOU` is supplied. Watch the `--- Verification ---` block:
all five checks should read **True** (INF staged, audit staged, Security CSE, Audit CSE, version in sync).
If any is False, the script prints the GPMC `Import Policy…` fallback — use it before linking.

---

## 4. Apply on a pilot node and verify

On a pilot server (one per role if possible):
```powershell
gpupdate /force          # then REBOOT once (security template + audit settle on reboot)
gpresult /h C:\rsop.html # confirm the CIS GPO won
```
Back on any host, score actual vs. expected (no CIS-CAT needed):
```powershell
.\Test-CIS-Compliance.ps1 -Scope Member -CsvPath .\result-member.csv    # use -Scope DC on DCs
```
Target: **0 FAIL**. Investigate every `FAIL`; `REVIEW` = eyeball (e.g. PrintSpoolerService SID);
`SKIP` = per-user HKCU (re-run with `-IncludeUser` in the user's session).

---

## 5. Validate workloads (the real gate)

For each role on your pilot boxes, walk `PotentiallyDisruptiveSettings.md`:

- **Print/RDS:** printing works (Spooler 5.x), RDS logon rights (2.2.10/2.2.26)
- **SQL:** service/app-pool accounts not locked out (1.2.2), named-pipe/SMB (2.3.10.x, 2.3.9.2), port 1433 reachable
- **Failover Cluster / Hyper-V:** cluster comms (firewall 9.x: 3343, RPC), live migration (6600), local-account network logon (2.2.21), VBS/Credential Guard (18.9.5.2)
- **CA:** LDAP signing/channel binding for enrollment (2.3.5.3/2.3.5.4)
- **Azure Arc / WAC:** agent/mgmt reachability (firewall 9.3.1, WinRM), NTLM (2.3.11.13), remote SAM (2.3.10.11)
- **Legacy apps:** SMBv1 (18.4.2/3), NTLM/LM (2.3.11.6/9/10), null sessions, guest access

Keep **ASR (18.10.42.6.1.2)** and **outgoing-NTLM restriction (2.3.11.13)** in **audit** mode until clean.

---

## 6. Widen scope

Once a role passes, link the GPO to that role's production OU (re-run the Create script with the
production `-TargetOU`, or `New-GPLink`). Roll out in waves; re-run `Test-CIS-Compliance.ps1` after each.

---

## 7. Rollback (anytime during piloting)

```powershell
.\Rollback-CIS-GPO.ps1 -Scope Member                    # DISABLE links - instant, reversible, deletes nothing
.\Rollback-CIS-GPO.ps1 -Scope Member -Action Unlink     # remove links, keep GPO
.\Rollback-CIS-GPO.ps1 -Scope Member -Action Remove     # backup -> delete (confirms)
.\Rollback-CIS-GPO.ps1 -Scope Member -Action Restore -BackupPath .\GPO-Backups -TargetOU "OU=Pilot Servers,DC=corp,DC=com"
```
Then `gpupdate /force` on affected hosts. `Remove` always backs up first, so it's recoverable.

---

## Quick reference

| Task | Command |
|------|---------|
| Preview | `Create-CIS-*-GPO.ps1 -TargetOU <ou> -WhatIf` |
| Build + link | `Create-CIS-*-GPO.ps1 -TargetOU <ou>` |
| Pull policy | `gpupdate /force` + reboot |
| Verify | `Test-CIS-Compliance.ps1 -Scope Member\|DC\|Standalone -CsvPath <file>` |
| Audit policy only (local) | `Set-CIS-AuditPolicy.ps1 -Scope Member -Mode Local` |
| Undo (safe) | `Rollback-CIS-GPO.ps1 -Scope Member` |
| **Harden a standalone/workgroup host** | `Apply-CIS-Local.ps1 -Scope Standalone` |
| Verify a standalone host | `Test-CIS-Compliance.ps1 -Scope Standalone -CsvPath <file>` |
| Build-time apply to a golden image | `Apply-CIS-Local.ps1 -Scope Member -Force` |

**Golden rule:** Preview → Pilot → Verify → Soak → Widen. Never link straight to production.

**Standalone rule:** never apply `-Scope Member` (or its INF via `LGPO.exe`) to a workgroup host —
the Member benchmark's 2.2.26 denies RDP to every local account and strands any box without console
access. Use `-Scope Standalone`, which implements the Stand-alone benchmark written for these hosts;
`Apply-CIS-Local.ps1` blocks the mismatch unless you pass `-Force`.
