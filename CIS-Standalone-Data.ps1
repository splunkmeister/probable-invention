<#
.SYNOPSIS
  CIS Microsoft Windows Server 2025 STAND-ALONE Benchmark v1.0.0 - Level 1
  Advanced Audit Policy (section 17), Windows Firewall (section 9) and the items that
  are not auto-encoded.
.DESCRIPTION
  Data only - dot-source to load $CISStandaloneAudit / $CISStandaloneFirewall /
  $CISStandaloneReview. IDs are STAND-ALONE numbering (its own document); they do not
  line up with the Member/DC package.

  Section 9 covers the PRIVATE and PUBLIC profiles only. The Stand-alone benchmark
  defines no Domain-profile recommendations - a workgroup host never uses that profile.
#>

$CISStandaloneAudit = @(
  @{ Id="17.1.1"; Sub="Credential Validation"; Guid="{0CCE923F-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable" }
  @{ Id="17.2.1"; Sub="Application Group Management"; Guid="{0CCE9239-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable" }
  @{ Id="17.2.2"; Sub="Security Group Management"; Guid="{0CCE9237-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable" }
  @{ Id="17.2.3"; Sub="User Account Management"; Guid="{0CCE9235-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable" }
  @{ Id="17.3.1"; Sub="PNP Activity"; Guid="{0CCE9248-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable" }
  @{ Id="17.3.2"; Sub="Process Creation"; Guid="{0CCE922B-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable" }
  @{ Id="17.5.1"; Sub="Account Lockout"; Guid="{0CCE9217-69AE-11D9-BED3-505054503030}"; Setting="Failure"; Flag="/success:disable /failure:enable" }
  @{ Id="17.5.2"; Sub="Group Membership"; Guid="{0CCE9249-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable" }
  @{ Id="17.5.3"; Sub="Logoff"; Guid="{0CCE9216-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable" }
  @{ Id="17.5.4"; Sub="Logon"; Guid="{0CCE9215-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable" }
  @{ Id="17.5.5"; Sub="Other Logon/Logoff Events"; Guid="{0CCE921C-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable" }
  @{ Id="17.5.6"; Sub="Special Logon"; Guid="{0CCE921B-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable" }
  @{ Id="17.6.1"; Sub="Detailed File Share"; Guid="{0CCE9244-69AE-11D9-BED3-505054503030}"; Setting="Failure"; Flag="/success:disable /failure:enable" }
  @{ Id="17.6.2"; Sub="File Share"; Guid="{0CCE9224-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable" }
  @{ Id="17.6.3"; Sub="Other Object Access Events"; Guid="{0CCE9227-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable" }
  @{ Id="17.6.4"; Sub="Removable Storage"; Guid="{0CCE9245-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable" }
  @{ Id="17.7.1"; Sub="Audit Policy Change"; Guid="{0CCE922F-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable" }
  @{ Id="17.7.2"; Sub="Authentication Policy Change"; Guid="{0CCE9230-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable" }
  @{ Id="17.7.3"; Sub="Authorization Policy Change"; Guid="{0CCE9231-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable" }
  @{ Id="17.7.4"; Sub="MPSSVC Rule-Level Policy Change"; Guid="{0CCE9232-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable" }
  @{ Id="17.7.5"; Sub="Other Policy Change Events"; Guid="{0CCE9234-69AE-11D9-BED3-505054503030}"; Setting="Failure"; Flag="/success:disable /failure:enable" }
  @{ Id="17.8.1"; Sub="Sensitive Privilege Use"; Guid="{0CCE9228-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable" }
  @{ Id="17.9.1"; Sub="IPsec Driver"; Guid="{0CCE9213-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable" }
  @{ Id="17.9.2"; Sub="Other System Events"; Guid="{0CCE9214-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable" }
  @{ Id="17.9.3"; Sub="Security State Change"; Guid="{0CCE9210-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable" }
  @{ Id="17.9.4"; Sub="Security System Extension"; Guid="{0CCE9211-69AE-11D9-BED3-505054503030}"; Setting="Success"; Flag="/success:enable /failure:disable" }
  @{ Id="17.9.5"; Sub="System Integrity"; Guid="{0CCE9212-69AE-11D9-BED3-505054503030}"; Setting="Success and Failure"; Flag="/success:enable /failure:enable" }
)

# Section 9 is applied with Set-NetFirewallProfile (native cmdlet), not the INF.
$CISStandaloneFirewall = @(
  @{ Id="9.2.1"; Profile="Private"; Setting="Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"; Recommended="On (recommended)" }
  @{ Id="9.2.2"; Profile="Private"; Setting="Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"; Recommended="Block (default)" }
  @{ Id="9.2.3"; Profile="Private"; Setting="Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'"; Recommended="No" }
  @{ Id="9.2.4"; Profile="Private"; Setting="Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\fire"; Recommended="%SystemRoot%\System32\logfiles\firewall\privatefw.log" }
  @{ Id="9.2.5"; Profile="Private"; Setting="Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"; Recommended="16,384 KB or greater" }
  @{ Id="9.2.6"; Profile="Private"; Setting="Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"; Recommended="Yes" }
  @{ Id="9.2.7"; Profile="Private"; Setting="Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"; Recommended="Yes" }
  @{ Id="9.3.1"; Profile="Public"; Setting="Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"; Recommended="On (recommended)" }
  @{ Id="9.3.2"; Profile="Public"; Setting="Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"; Recommended="Block (default)" }
  @{ Id="9.3.3"; Profile="Public"; Setting="Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'"; Recommended="No" }
  @{ Id="9.3.4"; Profile="Public"; Setting="Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firew"; Recommended="%SystemRoot%\System32\logfiles\firewall\publicfw.log" }
  @{ Id="9.3.5"; Profile="Public"; Setting="Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"; Recommended="16,384 KB or greater" }
  @{ Id="9.3.6"; Profile="Public"; Setting="Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"; Recommended="Yes" }
  @{ Id="9.3.7"; Profile="Public"; Setting="Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"; Recommended="Yes" }
)

# Recommendations the benchmark does not express as a single encodable value.
# Applying a guess here is worse than not applying it - see ExceptionsAndManualSteps.md 4.
$CISStandaloneReview = @(
  @{ Id="2.3.7.4"; Title="Configure 'Interactive logon: Message text for users attempting to log on'" }
  @{ Id="2.3.7.5"; Title="Configure 'Interactive logon: Message title for users attempting to log on'" }
  @{ Id="2.3.10.6"; Title="Ensure 'Network access: Named Pipes that can be accessed anonymously' is configured" }
  @{ Id="2.3.10.7"; Title="Ensure 'Network access: Remotely accessible registry paths' is configured" }
  @{ Id="2.3.10.8"; Title="Ensure 'Network access: Remotely accessible registry paths and sub-paths' is configured" }
  @{ Id="2.3.10.10"; Title="Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Adminis" }
  @{ Id="18.4.3"; Title="Ensure 'Enable Certificate Padding' is set to 'Enabled'" }
  @{ Id="18.6.14.1"; Title="Ensure 'Hardened UNC Paths' is set to 'Enabled, with 'Require Mutual Authentication', 'Require I" }
  @{ Id="18.10.14.1"; Title="Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'" }
  @{ Id="18.10.43.6.1.2"; Title="Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured" }
  @{ Id="19.7.8.5"; Title="Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled'" }
)
