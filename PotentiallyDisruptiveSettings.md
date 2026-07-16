# Potentially Disruptive CIS Settings
## CIS Microsoft Windows Server 2025 Benchmark v2.0.0 - Level 1

These recommendations are correct from a hardening standpoint but can break specific server
roles or legacy workloads. **Pilot each in audit/monitor mode and stage by OU** before enforcing.
Map your servers to roles and create scoped exceptions (separate OU + GPO, or WMI/security
filtering) where a setting conflicts with a supported workload.

Legend of affected roles considered: Hyper-V Hosts, SQL Servers, IIS Servers, Certificate Authorities, Failover Clusters, RD Session Hosts, Azure Arc connected machines, Windows Admin Center, Legacy applications.

---

## ⚠ Standalone (workgroup) hosts — read first

**The table below rates impact for the Member/DC benchmark (v2.0.0).** Workgroup hosts use a
different document — *Stand-alone Benchmark v1.0.0* — which already prescribes safe values for the
settings that would otherwise strand them. Use `Apply-CIS-Local.ps1 -Scope Standalone`; see
[`ExceptionsAndManualSteps.md` §4](ExceptionsAndManualSteps.md).

**Never apply the Member profile to a workgroup host.** `S-1-5-113` (*Local account*) and
`S-1-5-114` (*…member of Administrators group*) match **every account** there, not just the
break-glass ones:

| Setting | Member value (v2.0.0) | Stand-alone value (v1.0.0) | If you apply Member anyway |
|---------|----------------------|---------------------------|---------------------------|
| Deny log on through RDS | `Guests, Local account` (2.2.26) | **`Guests`** (2.2.20) | **RDP denied to every account.** Unrecoverable without console access (cloud VM, colo, headless). CIS: *"…**will** result in an inability to remotely administer the workstation."* |
| Deny access from the network | `Guests, Local account and member of Administrators group` (2.2.21) | **`Guests`** (2.2.16) | WinRM, SMB admin shares and remote WMI denied to every admin. CIS: *"…**may** result in an inability to remotely administer the server."* |
| Apply UAC restrictions to local accounts | `Enabled`, LATFP=0 (18.4.1) | **not in the benchmark** | Remote local admins get a filtered token with no elevation path (2.3.17.1 closes the RID-500 escape) |

Three risks that are *specific to* standalone, because §1 governs the SAM directly instead of
deferring to the Default Domain Policy:

| Setting | Why it bites on a workgroup host | Mitigation |
|---------|----------------------------------|------------|
| **1.2.3** `AllowAdministratorLockout = Enabled` (+ 1.2.2 threshold = 5) | The **built-in Administrator can be locked out** by 5 bad passwords for 15 minutes. With RDP exposed this is remotely triggerable — and there may be no other admin to recover with. | Create a **second local admin account** before applying; keep console access; firewall RDP to an admin subnet. |
| **NTP client** | No domain time hierarchy, so `NT5DS` never resolves and the clock drifts — silently degrading every §17 audit timestamp. | `w32tm /config /manualpeerlist:"time.windows.com,0x9" /syncfromflags:manual /update` |
| **Windows LAPS** | Absent from the Stand-alone benchmark: *"Windows LAPS does not support standalone computers."* But standalone deny-rights are `Guests`-only, so local credentials **are** usable over the network — a shared local admin password turns one stolen hash into fleet-wide lateral movement. | Unique per-host admin password via a PAM/secrets tool; firewall the management ports ([§4.3](ExceptionsAndManualSteps.md)). |

---

| CIS ID | Recommendation | Desired | Affected Roles | Why it can break | Mitigation |
|--------|----------------|---------|----------------|------------------|------------|
| 1.2.2 | 'Account lockout threshold' is set to '5 or fewer inval | 5 or fewer invalid logon | SQL Servers, IIS Servers, Legacy applications | Account lockout threshold=5 - service/app-pool accounts can be locked out by repeated bad auth. | Use managed service accounts / app-pool identities exempt from interactive lockout; monitor lockout source. |
| 2.2.10 | 'Allow log on through Remote Desktop Services' is set t | Administrators, Remote D | RD Session Hosts | Logon-through-RDS limited to Administrators + Remote Desktop Users; verify RDS user groups. | Add required RDS user groups to 'Allow log on through RDS' on session hosts. |
| 2.2.21 | 'Deny access to this computer from the network' to incl | Include: Guests, Local a | Failover Clusters, WAC, Hyper-V Hosts | Deny network access for Local accounts/Local-admins - can break local-account based remote admin & some cluster scenarios. | Exempt cluster/Hyper-V/WAC nodes needing local-account network logon, or use gMSA. |
| 2.2.26 | 'Deny log on through Remote Desktop Services' is set to | Guests, Local account | RD Session Hosts | Deny RDS logon for Local account - can lock out local break-glass admin over RDP. | Keep a non-local break-glass admin; exempt RDS hosts that need local-account RDP. |
| 2.3.1.1 | 'Accounts: Guest account status' is set to 'Disabled' ( | Disabled | Legacy applications | Guest account disabled - breaks apps relying on anonymous/guest share access. | Refactor apps off guest/anonymous access before disabling. |
| 2.3.2.2 | 'Audit: Shut down system immediately if unable to log s | Disabled | All | CrashOnAuditFail=0 keeps default; if set to shut down, full audit log halts the server. | Keep CrashOnAuditFail=0 (CIS value); never enable the shutdown variant in production. |
| 2.3.4.1 | 'Devices: Prevent users from installing printer drivers | Enabled | Print Servers, RD Session Hosts | Only admins can install printer drivers - impacts user-driven printer install. | Pre-stage signed printer drivers / use a print server; or exempt print servers. |
| 2.3.5.3 | 'Domain controller: LDAP server channel binding token r | Always | Certificate Authorities, Legacy applications | LDAP channel binding enforced on DCs - breaks LDAP clients/appliances not using channel binding. | Audit LDAP binds; update appliances/clients to use channel binding before enforcing. |
| 2.3.5.4 | 'Domain controller: LDAP server signing requirements En | Enabled | Legacy applications | LDAP server signing required - breaks unsigned LDAP simple binds. | Move LDAP clients to signed/LDAPS binds; pilot on one DC. |
| 2.3.6.1 | 'Domain member: Digitally encrypt or sign secure channe | Enabled | Legacy applications | Secure channel sign/seal required - breaks very old domain members. | Retire pre-2008 domain members; this is default on modern OS. |
| 2.3.8.1 | 'Microsoft network client: Digitally sign communication | Enabled | Legacy applications, Failover Clusters | SMB client signing required - perf cost and breaks non-signing SMB targets/NAS. | Confirm all SMB targets support signing (modern NAS/Windows do); retire SMBv1 first. |
| 2.3.9.2 | 'Microsoft network server: Digitally sign communication | Enabled | Legacy applications, Failover Clusters, SQL Servers | SMB server signing required - breaks legacy SMBv1/non-signing clients. | Validate clients support SMB2/3 signing; replace legacy SMBv1 clients. |
| 2.3.9.4 | 'Microsoft network server: Server SPN target name valid | Accept if provided by cl | Legacy applications | SPN target name validation can break apps using mismatched/hardcoded SPNs. | Fix/register correct SPNs for affected apps before raising hardening level. |
| 2.3.10.5 | 'Network access: Let Everyone permissions apply to anon | Disabled | Legacy applications | EveryoneIncludesAnonymous=0 - tightens anonymous access; may break legacy share access. | Inventory anonymous share consumers; migrate to authenticated access. |
| 2.3.10.6 | 'Network access: Named Pipes that can be accessed anony | (Configured per CIS list | SQL Servers, Legacy applications | Null session pipes restricted - can break SQL named-pipe and legacy RPC apps. | Use TCP/IP for SQL instead of named pipes; remove unneeded null-session pipes. |
| 2.3.10.10 | 'Network access: Restrict anonymous access to Named Pip | Enabled | Failover Clusters, Legacy applications | RestrictNullSessAccess=1 - blocks anonymous share/pipe access used by some clustered/legacy apps. | Test clustered/legacy share access; add required pipes/shares explicitly. |
| 2.3.10.11 | 'Network access: Restrict clients allowed to make remot | Administrators: Remote A | Legacy applications, Azure Arc connected machines | Restrict remote SAM calls - can break remote enumeration tools and some agents. | Add management agents/SIDs to the SAM remote-access SDDL if enumeration is required. |
| 2.3.11.6 | 'Network security: LAN Manager authentication level' is | Send NTLMv2 response onl | Legacy applications | LmCompatibilityLevel=5 (NTLMv2 only) - breaks LM/NTLMv1 legacy clients/appliances. | Upgrade/retire NTLMv1/LM clients and appliances first. |
| 2.3.11.9 | 'Network security: Minimum session security for NTLM SS | Require NTLMv2 session s | Legacy applications | NTLM min client security (128-bit + NTLMv2) - breaks weak-crypto legacy clients. | Ensure clients support 128-bit NTLMv2 session security. |
| 2.3.11.10 | 'Network security: Minimum session security for NTLM SS | Require NTLMv2 session s | Legacy applications | NTLM min server security (128-bit + NTLMv2) - breaks weak-crypto legacy clients. | Ensure servers/peers support 128-bit NTLMv2 session security. |
| 2.3.11.13 | 'Network security: Restrict NTLM: Outgoing NTLM traffic | Audit all | Legacy applications, Azure Arc connected machines | Restrict outgoing NTLM - can break NTLM-dependent apps; audit first. | Run NTLM auditing (17.x) first; whitelist required servers via 'Add remote server exceptions'. |
| 2.3.17.1 | 'User Account Control: Admin Approval Mode for the Buil | Enabled | WAC, Failover Clusters | FilterAdministratorToken=1 - built-in Administrator gets filtered token remotely; can break remote admin scripts. | Use a domain admin (not built-in local Administrator) for remote management/scripts. |
| 2.3.17.6 | 'User Account Control: Run all administrators in Admin  | Enabled | Legacy applications | EnableLUA=1 (UAC on) - some legacy installers/apps misbehave; required by CIS. | Required - test legacy installers; use app-compat shims if needed. |
| 5.1 | 'Print Spooler (Spooler)' is set to 'Disabled' (DC only | Disabled | Print Servers, RD Session Hosts, Certificate Authorities (web enroll printing) | Print Spooler disabled - no local/network printing; breaks print servers and RDS easy-print. | Leave Spooler enabled on print/RDS servers; apply RpcAuthnLevelPrivacyEnabled hardening instead. |
| 5.2 | 'Print Spooler (Spooler)' is set to 'Disabled' (MS only | Disabled | Print Servers, RD Session Hosts | Print Spooler disabled (L2) - no printing on member servers. | Exempt print/RDS servers; otherwise this is L2 and optional for member servers. |
| 9.1.1 | 'Windows Firewall: Domain: Firewall state' is set to 'O | On (recommended) | SQL Servers, Failover Clusters, WAC, Hyper-V Hosts | Firewall ON (Domain) - ensure cluster/SQL/WAC/live-migration ports are explicitly allowed. | Define explicit inbound allow rules for cluster (3343/UDP, RPC), SQL (1433/named), WAC (6516), live migration (6600), before enabling. |
| 9.2.1 | 'Windows Firewall: Private: Firewall state' is set to ' | On (recommended) | SQL Servers, Failover Clusters | Firewall ON (Private) - verify required inbound rules exist before enforcing. | Stage required Private-profile rules; verify on a pilot node. |
| 9.3.1 | 'Windows Firewall: Public: Firewall state' is set to 'O | On (recommended) | Azure Arc connected machines, WAC | Firewall ON (Public) - tightest profile; verify management traffic is allowed. | Ensure mgmt/agent traffic (Arc, WinRM 5985/5986) is allowed before enforcing Public profile. |
| 18.4.2 | 'Configure SMB v1 client driver' is set to 'Enabled: Di | Enabled: Disable driver  | Legacy applications | SMBv1 client driver disabled - breaks SMBv1-only NAS/appliances/legacy apps. | Remove SMBv1 dependencies (old NAS/scanners) first. |
| 18.4.3 | 'Configure SMB v1 server' is set to 'Disabled' | Disabled | Legacy applications | SMBv1 server disabled - breaks SMBv1-only clients (old scanners, NAS, XP). | Confirm no SMBv1-only clients remain. |
| 18.9.5.2 | 'Turn On Virtualization Based Security: Select Platform | Secure Boot | Hyper-V Hosts, Legacy applications | Virtualization Based Security / Credential Guard - can conflict with nested virtualization, some 3rd-party hypervisors and drivers. | Validate driver/hypervisor compatibility; Credential Guard can block nested virt and some 3rd-party drivers. |
| 18.10.42.6.1.2 | 'Configure Attack Surface Reduction rules: Set the stat | (Configured per CIS list | Legacy applications, Line-of-business apps | Defender ASR rules - can block legitimate Office/script/LOB behaviors; pilot in audit mode. | Deploy ASR rules in Audit mode first; exclude validated LOB app paths. |

## Role-by-role quick reference

**Hyper-V Hosts:** 18.9.5.2 (VBS/Credential Guard nested-virt & driver conflicts), 2.2.21 (local-account network logon for cluster), 9.x firewall (live-migration 6600, cluster 3343).

**SQL Servers:** 1.2.2 (service-account lockout), 2.3.10.6/2.3.10.10 (named-pipe/null-session), 2.3.9.2 (SMB signing for backup shares), 9.x firewall (1433/named instances).

**IIS Servers:** 1.2.2 (app-pool identity lockout), 2.3.17.x UAC, 9.x firewall (80/443), URA changes affecting app-pool identities.

**Certificate Authorities:** 2.3.5.3/2.3.5.4 (LDAP signing/channel binding for enrollment), 5.1 spooler if web-enroll prints, RPC/firewall for enrollment.

**Failover Clusters:** 2.2.21 (deny local-account network logon), 2.3.10.x (null session/SMB), 9.x firewall (3343/UDP+TCP, RPC dynamic), 2.3.8/2.3.9 SMB signing.

**RD Session Hosts:** 5.1/5.2 (Spooler - printing), 2.2.10/2.2.26 (RDS logon rights), 2.3.4.1 (printer driver install).

**Azure Arc connected machines:** 9.3.1 (Public firewall vs agent), 2.3.11.13 (outgoing NTLM), 2.3.10.11 (remote SAM), WinRM/HTTPS reachability.

**Windows Admin Center:** 2.3.17.1 (FilterAdministratorToken), 2.2.21 (local-account network logon), 9.x firewall (6516), CredSSP/Negotiate delegation.

**Legacy applications:** SMBv1 (18.4.2/18.4.3), NTLM/LM (2.3.11.6/9/10/13), null sessions (2.3.10.x), guest access (2.3.1.1), LDAP signing.
