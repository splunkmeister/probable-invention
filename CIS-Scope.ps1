<#
.SYNOPSIS
  Shared profile definitions for the CIS Windows Server 2025 hardening packages.
.DESCRIPTION
  Single source of truth for what each -Scope means, dot-sourced by Apply-CIS-Local.ps1,
  Test-CIS-Compliance.ps1 and Set-CIS-AuditPolicy.ps1 so "apply" and "verify" can never
  disagree about scope.

  THREE PROFILES, TWO SOURCE DOCUMENTS:

    Member      | CIS Microsoft Windows Server 2025 Benchmark v2.0.0, Level 1 - Member Server
    DC          | CIS Microsoft Windows Server 2025 Benchmark v2.0.0, Level 1 - Domain Controller
    Standalone  | CIS Microsoft Windows Server 2025 STAND-ALONE Benchmark v1.0.0, Level 1

  Standalone is NOT a variant of the Member profile - it is a different benchmark. CIS publishes
  it separately because the Member/DC document explicitly excludes workgroup hosts from its own
  scope ("Intended Audience", p.27):

      "The Microsoft Windows Benchmarks are written for Active Directory domain-joined systems
       using Active Directory's Group Policy Manager only. This benchmark is not intended for
       use on standalone or workgroup systems..."

  while the Stand-alone benchmark states: "This CIS Benchmark is written for stand-alone
  systems only."

  CONSEQUENCE - NUMBERING IS NOT SHARED. The Stand-alone benchmark has its own IDs and its own
  (smaller) recommendation set: 389 recommendations / 307 Level 1, against 454 / 360 for
  Member+DC. Equivalent settings carry different numbers:

      Deny log on through Remote Desktop Services   standalone 2.2.20   member 2.2.26
      Deny access to this computer from the network  standalone 2.2.16   member 2.2.21

  Never cross-reference an ID between the two packages. Standalone data lives in
  RegistrySettings-Standalone.ps1 and CIS-Standalone-Data.ps1; Member/DC data lives in
  RegistrySettings.ps1 and the tables inside Test-CIS-Compliance.ps1.

  WHY THE TWO BENCHMARKS DIFFER WHERE THEY DO. The Member profile denies logon rights to
  S-1-5-113 ("Local account") and S-1-5-114 ("Local account and member of Administrators").
  On a domain member those match only the local break-glass accounts. On a workgroup host they
  match EVERY account, so the Member values lock out every administrator - CIS says so itself in
  the Member benchmark's own Impact text for 2.2.26: "Configuring a standalone (non-domain-joined)
  or a system hosted in the Cloud (Azure) as described above (Local account) will result in an
  inability to remotely administer the workstation." The Stand-alone benchmark therefore
  prescribes plain 'Guests' for both rights. That is the benchmark's answer, not a local
  deviation - this package applies it verbatim and there are no deviations to track.
#>

# Which document and profile each scope implements. Used for banners, logs and reports so an
# operator can never be in doubt about which benchmark a result was graded against.
$CISProfile = @{
    'Member'     = @{ Benchmark = 'CIS Microsoft Windows Server 2025 Benchmark';            Version = 'v2.0.0'; Profile = 'Level 1 - Member Server';      Recommendations = 360 }
    'DC'         = @{ Benchmark = 'CIS Microsoft Windows Server 2025 Benchmark';            Version = 'v2.0.0'; Profile = 'Level 1 - Domain Controller';  Recommendations = 360 }
    'Standalone' = @{ Benchmark = 'CIS Microsoft Windows Server 2025 Stand-alone Benchmark'; Version = 'v1.0.0'; Profile = 'Level 1';                      Recommendations = 307 }
}

function Get-CISProfileInfo {
    param([Parameter(Mandatory)][ValidateSet('Member','DC','Standalone')][string] $Scope)
    return $CISProfile[$Scope]
}

# Tag filter for the Member/DC setting tables ('Both' / 'MS' / 'DC'). Standalone does not use
# this - its data files contain exactly its own profile and need no filtering.
function Get-CISScopeFilter {
    param([Parameter(Mandatory)][ValidateSet('Member','DC','Standalone')][string] $Scope)
    switch ($Scope) {
        'DC'         { @('Both','DC') }
        'Member'     { @('Both','MS') }
        'Standalone' { @()  }   # not applicable - see note above
    }
}

# Domain membership of the local host, used to catch "wrong profile for this box" before
# secedit writes anything. DomainRole: 0/1 = workgroup, 2/3 = domain member, 4/5 = DC.
function Get-CISHostRole {
    $role = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).DomainRole
    switch ($role) {
        { $_ -in 0, 1 } { 'Standalone'; break }
        { $_ -in 2, 3 } { 'Member';     break }
        { $_ -in 4, 5 } { 'DC';         break }
        default         { 'Unknown' }
    }
}
