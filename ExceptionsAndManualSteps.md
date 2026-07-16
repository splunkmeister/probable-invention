# Exceptions, Manual Steps & Needs-Review Items
## CIS Microsoft Windows Server 2025 — Level 1

Items the packages do **not** fully automate, plus the site-specific values you must supply.
Two source documents are covered:

| Package | Source document |
|---------|-----------------|
| Member / DC | CIS Microsoft Windows Server 2025 Benchmark **v2.0.0** — Level 1 Member Server / Domain Controller |
| Standalone | CIS Microsoft Windows Server 2025 **Stand-alone** Benchmark **v1.0.0** — Level 1 |

> **Numbering is not shared between the two.** Standalone `2.2.16` is the setting Member calls
> `2.2.21`. Never cross-reference an ID between packages.

---

## 1. Manual / interactive configuration (site-specific values)

These carry placeholders and must be set to your real values before you apply to production.
Applies to **all three** profiles unless noted.

| Setting | Placeholder | What to do |
|---------|-------------|-----------|
| Rename administrator account (Member 2.3.1.3 / Standalone 2.3.1.3) | `CIS-Admin` | Choose a non-obvious name. On a **standalone** host this renames the local SAM account you may be logged in with — set it before applying. |
| Rename guest account (Member 2.3.1.4 / Standalone 2.3.1.4) | `CIS-Guest` | Choose a non-obvious name. |
| Logon banner text (Standalone 2.3.7.4) | *not set* | `LegalNoticeText`, REG_MULTI_SZ — your legal wording. |
| Logon banner title (Standalone 2.3.7.5) | *not set* | `LegalNoticeCaption`, REG_SZ. |
| Firewall log file names (§9) | default paths | Per-profile log names are site-specific. |

## 2. List / multi-value settings not auto-encoded (provide explicit values)

The benchmark expresses these as lists or SDDL rather than a single value. They are **not
guessed** — supply them explicitly. Deploy NTLM restrictions and Defender ASR in **audit mode**
first.

| Standalone ID | Setting | Why it is not auto-encoded |
|---------------|---------|----------------------------|
| 2.3.10.7 | Network access: Remotely accessible registry paths | explicit `AllowedExactPaths\Machine` list |
| 2.3.10.8 | Network access: Remotely accessible registry paths and sub-paths | explicit `AllowedPaths\Machine` list |
| 2.3.10.10 | Network access: Restrict clients allowed to make remote calls to SAM | SDDL string |
| 18.6.14.1 | Hardened UNC Paths | multi-value policy |
| 18.10.43.6.1.2 | Configure Attack Surface Reduction rules | per-rule GUID list |

## 3. Privilege Rights needing SID confirmation

- **`RESTRICTED SERVICES\PrintSpoolerService`** (new in Server 2025) is kept as a friendly name
  pending SID confirmation. It appears in the **Member/DC** INF only — the Stand-alone
  benchmark v1.0.0 does **not** include it in `SeAuditPrivilege` / `SeImpersonatePrivilege`.
- **Role-conditional principals** are documented, not applied — add them deliberately if the
  role is installed:

  | Standalone ID | Right | Add when |
  |---------------|-------|----------|
  | 2.2.14 | Create symbolic links | Hyper-V installed → add `NT VIRTUAL MACHINE\Virtual Machines` |
  | 2.2.24 | Impersonate a client after authentication | Web Server (IIS) role with Web Services → add `IIS_IUSRS` |

---

## 4. Standalone (workgroup) servers

### 4.0 There IS a CIS standalone benchmark — use it

The Member/DC benchmark explicitly excludes workgroup hosts from its own scope
(*Intended Audience*, p.27):

> The Microsoft Windows Benchmarks are written for Active Directory domain-joined systems using
> Active Directory's Group Policy Manager only. **This benchmark is not intended for use on
> standalone or workgroup systems**…

CIS publishes a **separate document** for them — *CIS Microsoft Windows Server 2025 Stand-alone
Benchmark v1.0.0*:

> **This CIS Benchmark is written for stand-alone systems only.**

This package implements that benchmark **verbatim**, for `-Scope Standalone`. There are **no
local deviations**: everything applied is what CIS prescribes for a standalone host. A host
hardened with it can legitimately be described as:

> Hardened to CIS Microsoft Windows Server 2025 Stand-alone Benchmark v1.0.0, Level 1.

Assess it with a CIS-CAT profile for the **Stand-alone** benchmark. Grading a workgroup host
against the *Member Server* profile will produce false failures, because the two documents
prescribe different values (see 4.2).

### 4.1 It is a different benchmark, not a Member variant

| | Member/DC (v2.0.0) | Stand-alone (v1.0.0) |
|---|---|---|
| Recommendations | 454 (360 L1) | **389 (307 L1)** |
| Numbering | its own | **its own** — not comparable |
| §9 firewall | Domain + Private + Public | **Private + Public only** (no Domain profile — a workgroup host never uses it) |
| §17 audit | 27 (Member) / 34 (DC) | 27 — same subcategories, **different IDs** |
| Windows LAPS | 18.9.26.1–.8 | **absent** — "Windows LAPS does not support standalone computers" |
| `PrintSpoolerService` SID | present | **absent** |

Data files: `CIS_Server2025_Standalone_Level1.inf`, `RegistrySettings-Standalone.ps1`,
`CIS-Standalone-Data.ps1`, `CIS_AuditPolicy_Standalone.csv`. Full traceability:
`StandaloneImplementationMatrix.csv`.

### 4.2 Why the deny-logon rights differ — and why the Member profile is dangerous here

The Member profile denies logon rights to `S-1-5-113` (*Local account*) and `S-1-5-114`
(*Local account and member of Administrators group*). On a domain member those match only the
local break-glass accounts. **On a workgroup host they match every account.**

| Right | Member value | Stand-alone value |
|-------|--------------|-------------------|
| Deny log on through Remote Desktop Services | `Guests, Local account` (2.2.26) | **`Guests`** (2.2.20) |
| Deny access to this computer from the network | `Guests, Local account and member of Administrators group` (2.2.21) | **`Guests`** (2.2.16) |

CIS says so itself, in the **Member** benchmark's own Impact text:

> **2.2.26** — "Caution: Configuring a standalone (non-domain-joined) or a system hosted in the
> Cloud (Azure) as described above (Local account) **will result in an inability to remotely
> administer** the workstation."

> **2.2.21** — "Caution: Configuring a standalone (non-domain-joined) server as described above
> **may result in an inability to remotely administer** the server."

So applying the **Member** profile to a workgroup host denies RDP to every administrator and
strands any box without console access. `Apply-CIS-Local.ps1` refuses a profile that does not
match the host's real `Win32_ComputerSystem.DomainRole` unless you pass `-Force`.

`LocalAccountTokenFilterPolicy` (Member 18.4.1) is **not a recommendation in the Stand-alone
benchmark at all**, so this package does not set it for standalone hosts.

### 4.3 Local administrator password rotation — the real gap

Windows LAPS is absent from the Stand-alone benchmark because it cannot work:

> "Windows LAPS does not support standalone computers — they must be joined to an Active
> Directory domain or Entra ID (formerly Azure Active Directory)."

The **control is not waived, only the mechanism.** A workgroup fleet sharing one local admin
password is exactly the pass-the-hash exposure LAPS exists to close, and on a standalone host
`Guests`-only deny rights mean local credentials *are* usable over the network. Pick one:

- **Unique per-host admin password** issued and rotated by a PAM/secrets tool (preferred).
- **Entra join + Windows LAPS `BackupDirectory = 2`** — restores real rotation, but the host is
  then no longer standalone and leaves this benchmark's scope.
- **Third-party local-password manager.** CIS permits this explicitly: *"Organizations that
  utilize third-party commercial software to manage unique & complex local Administrator
  passwords … may opt to disregard these LAPS recommendations."*

Also **firewall the management ports** (WinRM 5985/5986, SMB 445, RPC 135) to an admin subnet or
jump host. Section 9 turns the firewall on; scoping the rules is site-specific and yours.

### 4.4 Standalone-specific manual steps

- **§1 account policy is fully in force.** On a domain member §1 governs only local accounts and
  the Default Domain Policy governs the rest. On a workgroup host §1 governs the SAM directly and
  is the *only* account policy. That includes **1.2.3 `AllowAdministratorLockout = Enabled`** —
  the built-in Administrator **can be locked out** by 5 bad passwords (1.2.2) for 15 minutes
  (1.2.1). With RDP exposed this is remotely triggerable. **Keep a second local admin account**
  and/or console access.
- **Set an NTP source.** A workgroup host has no domain time hierarchy, so `NT5DS` never
  resolves and the clock drifts — silently degrading every §17 audit timestamp:
  ```powershell
  w32tm /config /manualpeerlist:"time.windows.com,0x9" /syncfromflags:manual /update
  Restart-Service w32time
  ```
- **Re-run to correct drift.** No GPO means no self-healing. Schedule
  `Apply-CIS-Local.ps1 -Scope Standalone`, or bake it into your image pipeline.

### 4.5 The 11 recommendations not auto-applied

`Apply-CIS-Local.ps1 -Scope Standalone` prints these at run time and
`Test-CIS-Compliance.ps1` lists them as not covered. They are in `$CISStandaloneReview`
(`CIS-Standalone-Data.ps1`) and marked `NEEDS REVIEW` in `StandaloneImplementationMatrix.csv`.
They are the site-specific values (§1), the lists/SDDL (§2), plus a few the benchmark does not
state as one encodable value — including **18.10.14.1**, where the benchmark text itself reads
`"REG_DWORD value of 1or 2"` (a typo in the source document; the setting accepts *First Time* or
*Always*, so pick one deliberately).

## 5. Delivery mechanisms that are not INF

- **Advanced Audit Policy (§17):** `CIS_AuditPolicy_*.csv` + `Set-CIS-AuditPolicy.ps1`.
  Requires the INF setting *Force audit policy subcategory settings* (2.3.2.1 in both benchmarks).
- **Windows Firewall (§9):** `Set-NetFirewallProfile`. Member/DC = Domain+Private+Public;
  Standalone = Private+Public.
- **Administrative Templates (§18–19):** `RegistrySettings.ps1` (Member/DC) or
  `RegistrySettings-Standalone.ps1` (Standalone).

## 6. Recommended deployment sequence

1. Create a **pilot OU** with a handful of representative servers per role.
2. Run `Create-CIS-MemberServer-GPO.ps1` / `Create-CIS-DC-GPO.ps1` linked to the pilot OU.
3. Resolve every item in sections 1–3 above (site-specific values, lists, SIDs).
4. Put Defender ASR and NTLM restrictions in **audit** mode first.
5. Validate role workloads against `PotentiallyDisruptiveSettings.md`.
6. `gpupdate /force`, reboot a pilot node, run a CIS-CAT assessment, then widen the OU scope.

For **standalone hosts** there is no OU and no GPO: pilot on one representative host with
`Apply-CIS-Local.ps1 -Scope Standalone`, verify, validate the workload, then bake into the image
and schedule a re-run for drift. See section 4.
