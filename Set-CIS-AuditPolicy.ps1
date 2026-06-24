<#
.SYNOPSIS
  Apply CIS Windows Server 2025 Advanced Audit Policy (section 17) to a GPO or local system.
.DESCRIPTION
  Two delivery options:
   1) GPO  : copies the supplied audit.csv into the GPO's SYSVOL Audit folder and enables it.
   2) Local: applies each subcategory directly with auditpol.exe (for standalone/testing).
  Subcategory GUIDs are stable Windows constants.
.NOTES
  Requires section 2.3.2.1 'Force audit policy subcategory settings' = Enabled (set via INF).
#>
param(
  [Parameter(Mandatory)][ValidateSet('Member','DC')] [string] $Scope,
  [ValidateSet('Local','GpoCsv')] [string] $Mode = 'Local',
  [string] $GpoName,
  [string] $CsvPath
)

# CIS S2025 audit subcategories (Subcategory, GUID, auditpol flag)
$Audit = @(
  @{ Id="17.1.1"; Sub="Credential Validation"; Guid="{0CCE923F-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable"; Scope="Both" },
  @{ Id="17.1.2"; Sub="Kerberos Authentication Service"; Guid="{0CCE9242-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable"; Scope="DC" },
  @{ Id="17.1.3"; Sub="Kerberos Service Ticket Operations"; Guid="{0CCE9240-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable"; Scope="DC" },
  @{ Id="17.2.1"; Sub="Application Group Management"; Guid="{0CCE9239-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable"; Scope="Both" },
  @{ Id="17.2.2"; Sub="Computer Account Management"; Guid="{0CCE9236-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="DC" },
  @{ Id="17.2.3"; Sub="Distribution Group Management"; Guid="{0CCE9238-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="DC" },
  @{ Id="17.2.4"; Sub="Other Account Management Events"; Guid="{0CCE923A-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="DC" },
  @{ Id="17.2.5"; Sub="Security Group Management"; Guid="{0CCE9237-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="Both" },
  @{ Id="17.2.6"; Sub="User Account Management"; Guid="{0CCE9235-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable"; Scope="Both" },
  @{ Id="17.3.1"; Sub="PNP Activity"; Guid="{0CCE9248-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="Both" },
  @{ Id="17.3.2"; Sub="Process Creation"; Guid="{0CCE922B-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="Both" },
  @{ Id="17.4.1"; Sub="Directory Service Access"; Guid="{0CCE923B-69AE-11D9-BED3-505054503030}"; Setting="Failure"; Flag="/success:disable /failure:enable"; Scope="DC" },
  @{ Id="17.4.2"; Sub="Directory Service Changes"; Guid="{0CCE923C-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="DC" },
  @{ Id="17.5.1"; Sub="Account Lockout"; Guid="{0CCE9217-69AE-11D9-BED3-505054503030}"; Setting="Failure"; Flag="/success:disable /failure:enable"; Scope="Both" },
  @{ Id="17.5.2"; Sub="Group Membership"; Guid="{0CCE9249-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="Both" },
  @{ Id="17.5.3"; Sub="Logoff"; Guid="{0CCE9216-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="Both" },
  @{ Id="17.5.4"; Sub="Logon"; Guid="{0CCE9215-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable"; Scope="Both" },
  @{ Id="17.5.5"; Sub="Other Logon/Logoff Events"; Guid="{0CCE921C-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable"; Scope="Both" },
  @{ Id="17.5.6"; Sub="Special Logon"; Guid="{0CCE921B-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="Both" },
  @{ Id="17.6.1"; Sub="Detailed File Share"; Guid="{0CCE9244-69AE-11D9-BED3-505054503030}"; Setting="Failure"; Flag="/success:disable /failure:enable"; Scope="Both" },
  @{ Id="17.6.2"; Sub="File Share"; Guid="{0CCE9224-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable"; Scope="Both" },
  @{ Id="17.6.3"; Sub="Other Object Access Events"; Guid="{0CCE9227-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable"; Scope="Both" },
  @{ Id="17.6.4"; Sub="Removable Storage"; Guid="{0CCE9245-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable"; Scope="Both" },
  @{ Id="17.7.1"; Sub="Audit Policy Change"; Guid="{0CCE922F-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="Both" },
  @{ Id="17.7.2"; Sub="Authentication Policy Change"; Guid="{0CCE9230-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="Both" },
  @{ Id="17.7.3"; Sub="Authorization Policy Change"; Guid="{0CCE9231-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="Both" },
  @{ Id="17.7.4"; Sub="MPSSVC Rule-Level Policy Change"; Guid="{0CCE9232-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable"; Scope="Both" },
  @{ Id="17.7.5"; Sub="Other Policy Change Events"; Guid="{0CCE9234-69AE-11D9-BED3-505054503030}"; Setting="Failure"; Flag="/success:disable /failure:enable"; Scope="Both" },
  @{ Id="17.8.1"; Sub="Sensitive Privilege Use"; Guid="{0CCE9228-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="Both" },
  @{ Id="17.9.1"; Sub="IPsec Driver"; Guid="{0CCE9213-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable"; Scope="Both" },
  @{ Id="17.9.2"; Sub="Other System Events"; Guid="{0CCE9214-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable"; Scope="Both" },
  @{ Id="17.9.3"; Sub="Security State Change"; Guid="{0CCE9210-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="Both" },
  @{ Id="17.9.4"; Sub="Security System Extension"; Guid="{0CCE9211-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable"; Scope="Both" },
  @{ Id="17.9.5"; Sub="System Integrity"; Guid="{0CCE9212-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable"; Scope="Both" }
)

$applicable = $Audit | Where-Object { $_.Scope -eq 'Both' -or $_.Scope -eq $Scope }

if ($Mode -eq 'Local') {
  Write-Host "Applying $($applicable.Count) audit subcategories locally via auditpol..." -ForegroundColor Cyan
  # Apply by GUID (canonical, locale-independent). Subcategory *names* differ from the OS
  # display names in places (e.g. CIS 'PNP Activity' = OS 'Plug and Play Events'), which makes
  # /subcategory:"<name>" fail with 0x57 'The parameter is incorrect'. GUIDs avoid that entirely.
  $ok = 0; $fail = 0
  foreach ($a in $applicable) {
    $argv = @('/set', "/subcategory:$($a.Guid)") + $a.Flag.Split(' ')
    $out  = & auditpol.exe @argv 2>&1
    if ($LASTEXITCODE -eq 0) {
      $ok++
      Write-Host ("  [+] {0,-12} {1,-40} {2}" -f $a.Id, $a.Sub, $a.Setting)
    } else {
      $fail++
      Write-Warning ("[{0}] {1} ({2}): {3}" -f $a.Id, $a.Sub, $a.Guid, ($out -join ' '))
    }
  }
  Write-Host "Audit subcategories: $ok applied, $fail failed." -ForegroundColor $(if ($fail) {'Yellow'} else {'Green'})
  Write-Host "Verify with: auditpol /get /category:*" -ForegroundColor Cyan
}
elseif ($Mode -eq 'GpoCsv') {
  if (-not $GpoName -or -not $CsvPath) { throw "GpoCsv mode requires -GpoName and -CsvPath" }
  Import-Module GroupPolicy
  $gpo = Get-GPO -Name $GpoName
  $domain = (Get-ADDomain).DNSRoot
  $dst = "\\$domain\SYSVOL\$domain\Policies\{$($gpo.Id)}\Machine\Microsoft\Windows NT\Audit"
  New-Item -ItemType Directory -Force -Path $dst | Out-Null
  Copy-Item $CsvPath (Join-Path $dst 'audit.csv') -Force
  Write-Host "audit.csv staged to $dst" -ForegroundColor Green
  Write-Host "Ensure GPO registry value AuditPolicy CSV is referenced and bump GPT.ini version." -ForegroundColor Yellow
}
