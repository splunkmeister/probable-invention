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

## 3. Build + link to the PILOT OU

```powershell
.\Create-CIS-MemberServer-GPO.ps1 -TargetOU "OU=Pilot Servers,DC=corp,DC=com"
.\Create-CIS-DC-GPO.ps1           -TargetOU "OU=Pilot DCs,DC=corp,DC=com"
```
Watch the `--- Verification ---` block: all five checks should read **True** (INF staged, audit staged,
Security CSE, Audit CSE, version in sync). If any is False, the script prints the GPMC
`Import Policy…` fallback — use it before continuing.

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
| Verify | `Test-CIS-Compliance.ps1 -Scope Member|DC -CsvPath <file>` |
| Audit policy only (local) | `Set-CIS-AuditPolicy.ps1 -Scope Member -Mode Local` |
| Undo (safe) | `Rollback-CIS-GPO.ps1 -Scope Member` |
| Test INF on standalone box | `LGPO.exe /s CIS_Server2025_Member_Level1.inf` |

**Golden rule:** Preview → Pilot → Verify → Soak → Widen. Never link straight to production.
