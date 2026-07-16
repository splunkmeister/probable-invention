<#
.SYNOPSIS
  Local compliance check for the CIS Windows Server 2025 Benchmark v2.0.0 - Level 1 GPO.
.DESCRIPTION
  Run ON A PILOT SERVER after the CIS GPO has applied (gpupdate /force + reboot).
  Compares the machine's ACTUAL state against the CIS expected values and reports PASS/FAIL.
  No CIS-CAT required. Covers:
    * Registry-backed settings (Administrative Templates + Security Options)  -> live registry
    * Advanced Audit Policy (section 17)                                       -> auditpol
    * User Rights Assignment (section 2.2)                                     -> secedit /export
    * Account / lockout policy (section 1)                                     -> secedit /export
    * Windows Firewall profiles (section 9)                                    -> Get-NetFirewallProfile
  Run elevated. -Scope must match the GPO (or local apply) you deployed.
.PARAMETER Scope
  Member      -> verify against the Member Server package    (Benchmark v2.0.0, L1 Member Server)
  DC          -> verify against the Domain Controller package (Benchmark v2.0.0, L1 DC)
  Standalone  -> verify against the workgroup package         (Stand-alone Benchmark v1.0.0, L1)

  Standalone is a different benchmark with its own numbering and its own data files, so its
  results are graded from RegistrySettings-Standalone.ps1 + CIS-Standalone-Data.ps1 and its own
  INF - not from the Member tables in this script.
.PARAMETER CsvPath
  Optional path to also write the full result table as CSV.
.PARAMETER IncludeUser
  Also check HKCU (section 19) settings in the CURRENT user's hive (per-user policy).
.EXAMPLE
  .\Test-CIS-Compliance.ps1 -Scope Member -CsvPath .\cis-result.csv
.EXAMPLE
  .\Test-CIS-Compliance.ps1 -Scope Standalone -CsvPath .\standalone-result.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Member','DC','Standalone')][string] $Scope,
    [string] $CsvPath,
    [string] $LogPath,
    [switch] $IncludeUser
)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Run elevated for accurate results (secedit/auditpol need admin)."
}

# ---- Logging: full transcript of this assessment --------------------------
if (-not $LogPath) {
    $LogPath = Join-Path $PSScriptRoot ("Logs\Test-CIS-{0}-{1:yyyyMMdd-HHmmss}.log" -f $Scope, (Get-Date))
}
try {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LogPath) | Out-Null
    Start-Transcript -Path $LogPath -Force | Out-Null; $script:Transcribing = $true
} catch { $script:Transcribing = $false }
Write-Host "Log file: $LogPath" -ForegroundColor DarkCyan

$ScopeMod = Join-Path $PSScriptRoot 'CIS-Scope.ps1'
if (-not (Test-Path -LiteralPath $ScopeMod)) { throw "Missing required file: $ScopeMod" }
. $ScopeMod

$scopeFilter = Get-CISScopeFilter -Scope $Scope
$pi = Get-CISProfileInfo -Scope $Scope
Write-Host ("Grading against: {0} {1}, {2}" -f $pi.Benchmark, $pi.Version, $pi.Profile) -ForegroundColor Cyan

# Warn when the box's real role does not match what we are grading it against - otherwise the
# report is a confident-looking list of results for the wrong benchmark profile.
$hostRole = try { Get-CISHostRole } catch { 'Unknown' }
if ($hostRole -ne 'Unknown' -and $hostRole -ne $Scope) {
    Write-Warning "This host is '$hostRole' but you are verifying the '$Scope' profile. Results below grade against '$Scope'."
}

$results = New-Object System.Collections.Generic.List[object]
function Add-Result($id,$area,$setting,$expected,$actual,$result){
    $results.Add([pscustomobject]@{ Id=$id; Area=$area; Setting=$setting; Expected=$expected; Actual=$actual; Result=$result })
}

# ============================ data (expected values) ============================
$RegistryChecks = @(
  @{ Id="2.3.1.2"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa"; Name="LimitBlankPasswordUse"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.2.1"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa"; Name="SCENoApplyLegacyAuditPolicy"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.2.2"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa"; Name="CrashOnAuditFail"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.4.1"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"; Name="AddPrinterDrivers"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.5.1"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa"; Name="SubmitControl"; Expected="0"; Type="REG_DWORD"; Scope="DC" }
  @{ Id="2.3.5.3"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\NTDS\Parameters"; Name="LdapEnforceChannelBinding"; Expected="2"; Type="REG_DWORD"; Scope="DC" }
  @{ Id="2.3.5.4"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\NTDS\Parameters"; Name="LDAPServerForceIntegrity"; Expected="1"; Type="REG_DWORD"; Scope="DC" }
  @{ Id="2.3.5.5"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RefusePasswordChange"; Expected="0"; Type="REG_DWORD"; Scope="DC" }
  @{ Id="2.3.6.1"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RequireSignOrSeal"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.6.2"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="SealSecureChannel"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.6.3"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="SignSecureChannel"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.6.4"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="DisablePasswordChange"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.6.5"; Hive="HKLM"; Path="System\CurrentControlSet\Services\Netlogon\Parameters"; Name="MaximumPasswordAge"; Expected="30"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.6.6"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RequireStrongKey"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.7.2"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DontDisplayLastUserName"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.7.3"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="InactivityTimeoutSecs"; Expected="900"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.7.7"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="PasswordExpiryWarning"; Expected="14"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.7.8"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="ForceUnlockLogon"; Expected="1"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="2.3.7.9"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="ScRemoveOption"; Expected="1"; Type="REG_SZ"; Scope="Both" }
  @{ Id="2.3.8.1"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="RequireSecuritySignature"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.8.2"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnablePlainTextPassword"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.9.1"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="AutoDisconnect"; Expected="15"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.9.2"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RequireSecuritySignature"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.9.3"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="enableforcedlogoff"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.9.4"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="SMBServerNameHardeningLevel"; Expected="1"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="2.3.10.2"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Expected="1"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="2.3.10.3"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"; Expected="1"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="2.3.10.5"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa"; Name="EveryoneIncludesAnonymous"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.10.10"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RestrictNullSessAccess"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.10.13"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa"; Name="ForceGuest"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.11.1"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa"; Name="UseMachineId"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.11.2"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="AllowNullSessionFallback"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.11.3"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa\pku2u"; Name="AllowOnlineID"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.11.4"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"; Name="SupportedEncryptionTypes"; Expected="2147483640"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.11.6"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Expected="5"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.11.7"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\LDAP"; Name="LDAPClientConfidentiality"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.11.8"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\LDAP"; Name="LDAPClientIntegrity"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.11.9"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinClientSec"; Expected="537395200"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.11.10"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinServerSec"; Expected="537395200"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.11.11"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="AuditReceivingNTLMTraffic"; Expected="2"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.11.12"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="AuditNTLMInDomain"; Expected="7"; Type="REG_DWORD"; Scope="DC" }
  @{ Id="2.3.11.13"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="RestrictSendingNTLMTraffic"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.13.1"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ShutdownWithoutLogon"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.15.1"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"; Name="ObCaseInsensitive"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.15.2"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Session Manager"; Name="ProtectionMode"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.17.1"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="FilterAdministratorToken"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  # CIS 2.3.17.2 accepts EITHER value: "Prompt for consent on the secure desktop" (2, the recommended
  # state) or "Prompt for credentials on the secure desktop" (1) - the benchmark audit passes on 1 or 2.
  # Our INFs set 2 for Member/Standalone and 1 for DC, so accept both here to avoid a false FAIL.
  @{ Id="2.3.17.2"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Expected="2"; Accept=@("1"); Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.17.3"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorUser"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.17.4"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableInstallerDetection"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.17.5"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableSecureUIAPaths"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.17.6"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.17.7"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="PromptOnSecureDesktop"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="2.3.17.8"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableVirtualization"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.1.1.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoLockScreenCamera"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.1.1.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoLockScreenSlideshow"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.1.2.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\InputPersonalization"; Name="AllowInputPersonalization"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.4.1"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LocalAccountTokenFilterPolicy"; Expected="0"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="18.4.2"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\mrxsmb10"; Name="Start"; Expected="4"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.4.3"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SMB1"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.4.4"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Cryptography\Wintrust\Config"; Name="EnableCertPaddingCheck"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.4.5"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name="DisableExceptionChainValidation"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.4.6"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name="NodeType"; Expected="2"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.5.1"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="AutoAdminLogon"; Expected="0"; Type="REG_SZ"; Scope="Both" }
  @{ Id="18.5.2"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name="DisableIPSourceRouting"; Expected="2"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.5.3"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="DisableIPSourceRouting"; Expected="2"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.5.4"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableICMPRedirect"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.5.6"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name="NoNameReleaseOnDemand"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.5.8"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Session Manager"; Name="SafeDllSearchMode"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.5.11"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Services\Eventlog\Security"; Name="WarningLevel"; Expected="90"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.4.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name="EnableMDNS"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.4.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name="EnableNetbios"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.4.4"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name="EnableMulticast"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.7.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\LanmanServer"; Name="AuditClientDoesNotSupportEncryption"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.7.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\LanmanServer"; Name="AuditClientDoesNotSupportSigning"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.7.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\LanmanServer"; Name="AuditInsecureGuestLogon"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.7.4"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\LanmanServer"; Name="EnableAuthRateLimiter"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.7.5"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Bowser"; Name="EnableMailslots"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.7.6"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\LanmanServer"; Name="MinSmb2Dialect"; Expected="785"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.7.7"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\LanmanServer"; Name="InvalidAuthenticationDelayTimeInMs"; Expected="2000"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.8.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name="AuditInsecureGuestLogon"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.8.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name="AuditServerDoesNotSupportEncryption"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.8.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name="AuditServerDoesNotSupportSigning"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.8.4"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name="AllowInsecureGuestAuth"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.8.5"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\NetworkProvider"; Name="EnableMailslots"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.8.6"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name="MinSmb2Dialect"; Expected="785"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.8.7"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name="RequireEncryption"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.11.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name="NC_AllowNetBridge_NLA"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.11.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name="NC_ShowSharedAccessUI"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.11.4"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name="NC_StdDomainUserSetLocation"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.6.21.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"; Name="fMinimizeConnections"; Expected="3"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.7.1"; Hive="HKLM"; Path="Software\Policies\Microsoft\Windows NT\Printers"; Name="RegisterSpoolerRemoteRpcEndPoint"; Expected="2"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.7.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="RedirectionguardPolicy"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.7.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"; Name="RpcUseNamedPipeProtocol"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.7.4"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"; Name="RpcAuthentication"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.7.5"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"; Name="RpcProtocols"; Expected="5"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.7.6"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"; Name="ForceKerberosForRpc"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.7.7"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"; Name="RpcTcpPort"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.7.8"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Control\Print"; Name="RpcAuthnLevelPrivacyEnabled"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.7.10"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"; Name="RestrictDriverInstallationToAdministrators"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.7.11"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="CopyFilesPolicy"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.7.12"; Hive="HKLM"; Path="Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"; Name="NoWarningNoElevationOnInstall"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.7.13"; Hive="HKLM"; Path="Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"; Name="UpdatePromptSettings"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.3.1"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Name="ProcessCreationIncludeCmdLine_Enabled"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.4.1"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"; Name="AllowEncryptionOracle"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.4.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"; Name="AllowProtectedCreds"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.7.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Device Metadata"; Name="PreventDeviceMetadataFromNetwork"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.13.1"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Policies\EarlyLaunch"; Name="DriverLoadPolicy"; Expected="3"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.17.1"; Hive="HKLM"; Path="SYSTEM\CurrentControlSet\Policies"; Name="ClfsAuthenticationChecking"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.19.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"; Name="NoBackgroundPolicy"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.19.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"; Name="NoGPOListChanges"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.19.4"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableCdp"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.20.1.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="DisableWebPnPDownload"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.20.1.5"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoWebServices"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.24.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"; Name="DeviceEnumerationPolicy"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.26.1"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="BackupDirectory"; Expected="1"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="18.9.26.2"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="PasswordExpirationProtectionEnabled"; Expected="1"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="18.9.26.3"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="ADPasswordEncryptionEnabled"; Expected="1"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="18.9.26.4"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="PasswordComplexity"; Expected="4"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="18.9.26.5"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="PasswordLength"; Expected="15"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="18.9.26.6"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="PasswordAgeDays"; Expected="30"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="18.9.26.7"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="PostAuthenticationResetDelay"; Expected="8"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="18.9.26.8"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="PostAuthenticationActions"; Expected="3"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="18.9.27.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\System"; Name="AllowCustomSSPsAPs"; Expected="0"; Type="REG_DWORD"; Scope="DC" }
  @{ Id="18.9.29.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\System"; Name="BlockUserFromShowingAccountDetailsOnSignin"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.29.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\System"; Name="DontDisplayNetworkSelectionUI"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.29.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\System"; Name="DontEnumerateConnectedUsers"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.29.4"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnumerateLocalUsers"; Expected="0"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="18.9.29.5"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\System"; Name="DisableLockScreenAppNotifications"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.29.6"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\System"; Name="AllowDomainPINLogon"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.31.1.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Netlogon\Parameters"; Name="BlockNetbiosDiscovery"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.35.6.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"; Name="DCSettingIndex"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.35.6.4"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"; Name="ACSettingIndex"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.37.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fAllowUnsolicited"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.37.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fAllowToGetHelp"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.38.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Rpc"; Name="EnableAuthEpResolution"; Expected="1"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="18.9.41.1"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM"; Name="SamNGCKeyROCAValidation"; Expected="2"; Type="REG_DWORD"; Scope="DC" }
  @{ Id="18.9.41.2"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM"; Name="SamrChangeUserPasswordApiPolicy"; Expected="2"; Type="REG_DWORD"; Scope="DC" }
  @{ Id="18.9.41.3"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM"; Name="SamrChangeUserPasswordApiPolicy"; Expected="1"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="18.9.53.1.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"; Name="Enabled"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.9.53.1.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer"; Name="Enabled"; Expected="0"; Type="REG_DWORD"; Scope="MS" }
  @{ Id="18.10.4.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Appx"; Name="DisablePerUserUnsignedPackagesByDefault"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.6.1"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="MSAOptional"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.8.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoAutoplayfornonVolume"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.8.2"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoAutorun"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.8.3"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Expected="255"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.9.1.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"; Name="EnhancedAntiSpoofing"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.13.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableConsumerAccountStateContent"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.14.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Connect"; Name="RequirePinForPairing"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.15.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\CredUI"; Name="DisablePasswordReveal"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.15.2"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"; Name="EnumerateAdministrators"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.16.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.16.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="DoNotShowFeedbackNotifications"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.18.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\AppInstaller"; Name="EnableExperimentalFeatures"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.18.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\AppInstaller"; Name="EnableHashOverride"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.18.4"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\AppInstaller"; Name="EnableLocalArchiveMalwareScanOverride"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.18.5"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\AppInstaller"; Name="EnableMSAppInstallerProtocol"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.18.6"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\AppInstaller"; Name="EnableBypassCertificatePinningForMicrosoftStore"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.26.1.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"; Name="Retention"; Expected="0"; Type="REG_SZ"; Scope="Both" }
  @{ Id="18.10.26.1.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"; Name="MaxSize"; Expected="32768"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.26.2.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"; Name="Retention"; Expected="0"; Type="REG_SZ"; Scope="Both" }
  @{ Id="18.10.26.2.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"; Name="MaxSize"; Expected="196608"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.26.3.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"; Name="Retention"; Expected="0"; Type="REG_SZ"; Scope="Both" }
  @{ Id="18.10.26.3.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"; Name="MaxSize"; Expected="32768"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.26.4.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\EventLog\System"; Name="Retention"; Expected="0"; Type="REG_SZ"; Scope="Both" }
  @{ Id="18.10.26.4.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\EventLog\System"; Name="MaxSize"; Expected="32768"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.29.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="DisableMotWOnInsecurePathCopy"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.29.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoDataExecutionPrevention"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.29.4"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoHeapTerminationOnCorruption"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.29.5"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="PreXPSP2ShellProtocolBehavior"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.41.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\MicrosoftAccount"; Name="DisableUserAuth"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.4.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Features"; Name="PassiveRemediation"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.5.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name="LocalSettingOverrideSpynetReporting"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.5.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name="SpynetReporting"; Expected="2"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.6.1.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"; Name="ExploitGuard_ASR_Rules"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.6.1.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="26190899"; Expected="1"; Type="REG_SZ"; Scope="Both" }
  @{ Id="18.10.42.6.3.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"; Name="EnableNetworkProtection"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.7.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"; Name="EnableFileHashComputation"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.10.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="OobeEnableRtpAndSigUpdate"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.10.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableIOAVProtection"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.10.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableRealtimeMonitoring"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.10.4"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableBehaviorMonitoring"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.10.5"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableScriptScanning"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.11.1.1.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection"; Name="BruteForceProtectionConfiguredState"; Expected="2"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.13.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="QuickScanIncludeExclusions"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.13.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="DisablePackedExeScanning"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.13.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="DisableRemovableDriveScanning"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.13.4"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="DaysUntilAggressiveCatchupQuickScan"; Expected="7"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.13.5"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="DisableEmailScanning"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.16"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender"; Name="PUAProtection"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.42.17"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender"; Name="HideExclusionsFromLocalUsers"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.57.2.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="DisablePasswordSaving"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.57.3.3.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fDisableCdm"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.57.3.9.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fPromptForPassword"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.57.3.9.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fEncryptRPCTraffic"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.57.3.9.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="SecurityLayer"; Expected="2"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.57.3.9.4"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="UserAuthentication"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.57.3.9.5"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="MinEncryptionLevel"; Expected="3"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.57.3.11.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="DeleteTempDirsOnExit"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.57.3.11.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="PerSessionTempDir"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.58.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"; Name="DisableEnclosureDownload"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.59.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowIndexingEncryptedStoresOrItems"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.77.2.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableSmartScreen"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  # Both halves of 18.10.77.2.1 are checked. Checking only EnableSmartScreen reported PASS while
  # ShellSmartScreenLevel was never set - a half-applied recommendation that looked compliant.
  @{ Id="18.10.77.2.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\System"; Name="ShellSmartScreenLevel"; Expected="Block"; Type="REG_SZ"; Scope="Both" }
  @{ Id="18.10.81.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"; Name="AllowWindowsInkWorkspace"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.82.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="EnableUserControl"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.82.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.83.1"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableMPR"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.83.2"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableAutomaticRestartSignOn"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.90.1.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowBasic"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.90.1.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowUnencryptedTraffic"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.90.1.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowDigest"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.90.2.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowBasic"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.90.2.3"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowUnencryptedTraffic"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.90.2.4"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="DisableRunAs"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.93.2.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"; Name="DisallowExploitProtectionOverride"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.94.1.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="NoAutoRebootWithLoggedOnUsers"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.94.2.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="NoAutoUpdate"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.94.2.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="ScheduledInstallDay"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.94.4.1"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="ManagePreviewBuildsPolicyValue"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.10.94.4.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="DeferQualityUpdates"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  # Both halves of 18.10.94.4.2 - see the note on 18.10.77.2.1 above.
  @{ Id="18.10.94.4.2"; Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="DeferQualityUpdatesPeriodInDays"; Expected="0"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.11.1"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"; Name="DisableWpad"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="18.11.2"; Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"; Name="DisableProxyAuthenticationSchemes"; Expected="256"; Type="REG_DWORD"; Scope="Both" }
)
$UserRegistryChecks = @(
  @{ Id="19.5.1.1"; Hive="HKCU"; Path="Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"; Name="NoToastApplicationNotificationOnLockScreen"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="19.7.5.1"; Hive="HKCU"; Path="Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"; Name="SaveZoneInformation"; Expected="2"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="19.7.5.2"; Hive="HKCU"; Path="Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"; Name="ScanWithAntiVirus"; Expected="3"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="19.7.8.1"; Hive="HKCU"; Path="Software\Policies\Microsoft\Windows\CloudContent"; Name="ConfigureWindowsSpotlight"; Expected="2"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="19.7.8.2"; Hive="HKCU"; Path="Software\Policies\Microsoft\Windows\CloudContent"; Name="DisableThirdPartySuggestions"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
  @{ Id="19.7.26.1"; Hive="HKCU"; Path="Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoInplaceSharing"; Expected="1"; Type="REG_DWORD"; Scope="Both" }
)
$AuditChecks = @(
  @{ Id="17.1.1"; Sub="Credential Validation"; Guid="{0CCE923F-69AE-11D9-BED3-505054503030}"; Expected="Success and Failure"; Scope="Both" }
  @{ Id="17.1.2"; Sub="Kerberos Authentication Service"; Guid="{0CCE9242-69AE-11D9-BED3-505054503030}"; Expected="Success and Failure"; Scope="DC" }
  @{ Id="17.1.3"; Sub="Kerberos Service Ticket Operations"; Guid="{0CCE9240-69AE-11D9-BED3-505054503030}"; Expected="Success and Failure"; Scope="DC" }
  @{ Id="17.2.1"; Sub="Application Group Management"; Guid="{0CCE9239-69AE-11D9-BED3-505054503030}"; Expected="Success and Failure"; Scope="Both" }
  @{ Id="17.2.2"; Sub="Computer Account Management"; Guid="{0CCE9236-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="DC" }
  @{ Id="17.2.3"; Sub="Distribution Group Management"; Guid="{0CCE9238-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="DC" }
  @{ Id="17.2.4"; Sub="Other Account Management Events"; Guid="{0CCE923A-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="DC" }
  @{ Id="17.2.5"; Sub="Security Group Management"; Guid="{0CCE9237-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="Both" }
  @{ Id="17.2.6"; Sub="User Account Management"; Guid="{0CCE9235-69AE-11D9-BED3-505054503030}"; Expected="Success and Failure"; Scope="Both" }
  @{ Id="17.3.1"; Sub="PNP Activity"; Guid="{0CCE9248-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="Both" }
  @{ Id="17.3.2"; Sub="Process Creation"; Guid="{0CCE922B-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="Both" }
  @{ Id="17.4.1"; Sub="Directory Service Access"; Guid="{0CCE923B-69AE-11D9-BED3-505054503030}"; Expected="Failure"; Scope="DC" }
  @{ Id="17.4.2"; Sub="Directory Service Changes"; Guid="{0CCE923C-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="DC" }
  @{ Id="17.5.1"; Sub="Account Lockout"; Guid="{0CCE9217-69AE-11D9-BED3-505054503030}"; Expected="Failure"; Scope="Both" }
  @{ Id="17.5.2"; Sub="Group Membership"; Guid="{0CCE9249-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="Both" }
  @{ Id="17.5.3"; Sub="Logoff"; Guid="{0CCE9216-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="Both" }
  @{ Id="17.5.4"; Sub="Logon"; Guid="{0CCE9215-69AE-11D9-BED3-505054503030}"; Expected="Success and Failure"; Scope="Both" }
  @{ Id="17.5.5"; Sub="Other Logon/Logoff Events"; Guid="{0CCE921C-69AE-11D9-BED3-505054503030}"; Expected="Success and Failure"; Scope="Both" }
  @{ Id="17.5.6"; Sub="Special Logon"; Guid="{0CCE921B-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="Both" }
  @{ Id="17.6.1"; Sub="Detailed File Share"; Guid="{0CCE9244-69AE-11D9-BED3-505054503030}"; Expected="Failure"; Scope="Both" }
  @{ Id="17.6.2"; Sub="File Share"; Guid="{0CCE9224-69AE-11D9-BED3-505054503030}"; Expected="Success and Failure"; Scope="Both" }
  @{ Id="17.6.3"; Sub="Other Object Access Events"; Guid="{0CCE9227-69AE-11D9-BED3-505054503030}"; Expected="Success and Failure"; Scope="Both" }
  @{ Id="17.6.4"; Sub="Removable Storage"; Guid="{0CCE9245-69AE-11D9-BED3-505054503030}"; Expected="Success and Failure"; Scope="Both" }
  @{ Id="17.7.1"; Sub="Audit Policy Change"; Guid="{0CCE922F-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="Both" }
  @{ Id="17.7.2"; Sub="Authentication Policy Change"; Guid="{0CCE9230-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="Both" }
  @{ Id="17.7.3"; Sub="Authorization Policy Change"; Guid="{0CCE9231-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="Both" }
  @{ Id="17.7.4"; Sub="MPSSVC Rule-Level Policy Change"; Guid="{0CCE9232-69AE-11D9-BED3-505054503030}"; Expected="Success and Failure"; Scope="Both" }
  @{ Id="17.7.5"; Sub="Other Policy Change Events"; Guid="{0CCE9234-69AE-11D9-BED3-505054503030}"; Expected="Failure"; Scope="Both" }
  @{ Id="17.8.1"; Sub="Sensitive Privilege Use"; Guid="{0CCE9228-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="Both" }
  @{ Id="17.9.1"; Sub="IPsec Driver"; Guid="{0CCE9213-69AE-11D9-BED3-505054503030}"; Expected="Success and Failure"; Scope="Both" }
  @{ Id="17.9.2"; Sub="Other System Events"; Guid="{0CCE9214-69AE-11D9-BED3-505054503030}"; Expected="Success and Failure"; Scope="Both" }
  @{ Id="17.9.3"; Sub="Security State Change"; Guid="{0CCE9210-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="Both" }
  @{ Id="17.9.4"; Sub="Security System Extension"; Guid="{0CCE9211-69AE-11D9-BED3-505054503030}"; Expected="Success"; Scope="Both" }
  @{ Id="17.9.5"; Sub="System Integrity"; Guid="{0CCE9212-69AE-11D9-BED3-505054503030}"; Expected="Success and Failure"; Scope="Both" }
)
$PrivilegeChecks = @(
  @{ Id="2.2.1"; Const="SeTrustedCredManAccessPrivilege"; Expected=""; Scope="Both" }
  @{ Id="2.2.2"; Const="SeNetworkLogonRight"; Expected="*S-1-5-32-544;*S-1-5-11;*S-1-5-9"; Scope="DC" }
  @{ Id="2.2.3"; Const="SeNetworkLogonRight"; Expected="*S-1-5-32-544;*S-1-5-11"; Scope="MS" }
  @{ Id="2.2.4"; Const="SeTcbPrivilege"; Expected=""; Scope="Both" }
  @{ Id="2.2.5"; Const="SeMachineAccountPrivilege"; Expected="*S-1-5-32-544"; Scope="DC" }
  @{ Id="2.2.6"; Const="SeIncreaseQuotaPrivilege"; Expected="*S-1-5-32-544;*S-1-5-19;*S-1-5-20"; Scope="Both" }
  @{ Id="2.2.7"; Const="SeInteractiveLogonRight"; Expected="*S-1-5-32-544;*S-1-5-9"; Scope="DC" }
  @{ Id="2.2.8"; Const="SeInteractiveLogonRight"; Expected="*S-1-5-32-544"; Scope="MS" }
  @{ Id="2.2.9"; Const="SeRemoteInteractiveLogonRight"; Expected="*S-1-5-32-544"; Scope="DC" }
  @{ Id="2.2.10"; Const="SeRemoteInteractiveLogonRight"; Expected="*S-1-5-32-544;*S-1-5-32-555"; Scope="MS" }
  @{ Id="2.2.11"; Const="SeBackupPrivilege"; Expected="*S-1-5-32-544"; Scope="Both" }
  @{ Id="2.2.12"; Const="SeSystemtimePrivilege"; Expected="*S-1-5-32-544;*S-1-5-19"; Scope="Both" }
  @{ Id="2.2.13"; Const="SeCreatePagefilePrivilege"; Expected="*S-1-5-32-544"; Scope="Both" }
  @{ Id="2.2.14"; Const="SeCreateTokenPrivilege"; Expected=""; Scope="Both" }
  @{ Id="2.2.15"; Const="SeCreateGlobalPrivilege"; Expected="*S-1-5-32-544;*S-1-5-19;*S-1-5-20;*S-1-5-6"; Scope="Both" }
  @{ Id="2.2.16"; Const="SeCreatePermanentPrivilege"; Expected=""; Scope="Both" }
  @{ Id="2.2.17"; Const="SeCreateSymbolicLinkPrivilege"; Expected="*S-1-5-32-544"; Scope="DC" }
  @{ Id="2.2.18"; Const="SeCreateSymbolicLinkPrivilege"; Expected="*S-1-5-32-544;*S-1-5-83-0"; Scope="MS" }
  @{ Id="2.2.19"; Const="SeDebugPrivilege"; Expected="*S-1-5-32-544"; Scope="Both" }
  @{ Id="2.2.20"; Const="SeDenyNetworkLogonRight"; Expected="*S-1-5-32-546"; Scope="DC" }
  @{ Id="2.2.21"; Const="SeDenyNetworkLogonRight"; Expected="*S-1-5-32-546;*S-1-5-114"; Scope="MS" }
  @{ Id="2.2.22"; Const="SeDenyBatchLogonRight"; Expected="*S-1-5-32-546"; Scope="Both" }
  @{ Id="2.2.23"; Const="SeDenyServiceLogonRight"; Expected="*S-1-5-32-546"; Scope="Both" }
  @{ Id="2.2.24"; Const="SeDenyInteractiveLogonRight"; Expected="*S-1-5-32-546"; Scope="Both" }
  @{ Id="2.2.25"; Const="SeDenyRemoteInteractiveLogonRight"; Expected="*S-1-5-32-546"; Scope="DC" }
  @{ Id="2.2.26"; Const="SeDenyRemoteInteractiveLogonRight"; Expected="*S-1-5-32-546;*S-1-5-113"; Scope="MS" }
  @{ Id="2.2.27"; Const="SeEnableDelegationPrivilege"; Expected="*S-1-5-32-544"; Scope="DC" }
  @{ Id="2.2.28"; Const="SeEnableDelegationPrivilege"; Expected=""; Scope="MS" }
  @{ Id="2.2.29"; Const="SeRemoteShutdownPrivilege"; Expected="*S-1-5-32-544"; Scope="Both" }
  @{ Id="2.2.30"; Const="SeAuditPrivilege"; Expected="*S-1-5-19;*S-1-5-20;RESTRICTED SERVICES\PrintSpoolerService"; Scope="Both" }
  @{ Id="2.2.31"; Const="SeImpersonatePrivilege"; Expected="*S-1-5-32-544;*S-1-5-19;*S-1-5-20;*S-1-5-6;RESTRICTED SERVICES\PrintSpoolerService"; Scope="DC" }
  @{ Id="2.2.32"; Const="SeImpersonatePrivilege"; Expected="*S-1-5-32-544;*S-1-5-19;*S-1-5-20;*S-1-5-6;RESTRICTED SERVICES\PrintSpoolerService"; Scope="MS" }
  @{ Id="2.2.33"; Const="SeIncreaseBasePriorityPrivilege"; Expected="*S-1-5-32-544;*S-1-5-90-0"; Scope="Both" }
  @{ Id="2.2.34"; Const="SeLoadDriverPrivilege"; Expected="*S-1-5-32-544"; Scope="Both" }
  @{ Id="2.2.35"; Const="SeLockMemoryPrivilege"; Expected=""; Scope="Both" }
  @{ Id="2.2.37"; Const="SeSecurityPrivilege"; Expected="*S-1-5-32-544"; Scope="DC" }
  @{ Id="2.2.38"; Const="SeSecurityPrivilege"; Expected="*S-1-5-32-544"; Scope="MS" }
  @{ Id="2.2.39"; Const="SeRelabelPrivilege"; Expected=""; Scope="Both" }
  @{ Id="2.2.40"; Const="SeSystemEnvironmentPrivilege"; Expected="*S-1-5-32-544"; Scope="Both" }
  @{ Id="2.2.41"; Const="SeManageVolumePrivilege"; Expected="*S-1-5-32-544"; Scope="Both" }
  @{ Id="2.2.42"; Const="SeProfileSingleProcessPrivilege"; Expected="*S-1-5-32-544"; Scope="Both" }
  @{ Id="2.2.43"; Const="SeSystemProfilePrivilege"; Expected="*S-1-5-32-544;*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"; Scope="Both" }
  @{ Id="2.2.44"; Const="SeAssignPrimaryTokenPrivilege"; Expected="*S-1-5-19;*S-1-5-20"; Scope="Both" }
  @{ Id="2.2.45"; Const="SeRestorePrivilege"; Expected="*S-1-5-32-544"; Scope="Both" }
  @{ Id="2.2.46"; Const="SeShutdownPrivilege"; Expected="*S-1-5-32-544"; Scope="Both" }
  @{ Id="2.2.47"; Const="SeSyncAgentPrivilege"; Expected=""; Scope="DC" }
  @{ Id="2.2.48"; Const="SeTakeOwnershipPrivilege"; Expected="*S-1-5-32-544"; Scope="Both" }
)
$SystemAccessChecks = @(
  @{ Id="1.1.1"; Token="PasswordHistorySize"; Expected="24"; Scope="Both" }
  @{ Id="1.1.2"; Token="MaximumPasswordAge"; Expected="365"; Scope="Both" }
  @{ Id="1.1.3"; Token="MinimumPasswordAge"; Expected="1"; Scope="Both" }
  @{ Id="1.1.4"; Token="MinimumPasswordLength"; Expected="14"; Scope="Both" }
  @{ Id="1.1.5"; Token="PasswordComplexity"; Expected="1"; Scope="Both" }
  @{ Id="1.1.7"; Token="ClearTextPassword"; Expected="0"; Scope="Both" }
  @{ Id="1.2.1"; Token="LockoutDuration"; Expected="15"; Scope="Both" }
  @{ Id="1.2.2"; Token="LockoutBadCount"; Expected="5"; Scope="Both" }
  @{ Id="1.2.3"; Token="AllowAdministratorLockout"; Expected="1"; Scope="MS" }
  @{ Id="1.2.4"; Token="ResetLockoutCount"; Expected="15"; Scope="Both" }
  @{ Id="2.3.1.1"; Token="EnableGuestAccount"; Expected="0"; Scope="MS" }
  @{ Id="2.3.10.1"; Token="LSAAnonymousNameLookup"; Expected="0"; Scope="Both" }
  @{ Id="2.3.11.5"; Token="ForceLogoffWhenHourExpire"; Expected="1"; Scope="Both" }
)

# ============================ Standalone: swap in its own tables =============
# Standalone implements a different benchmark with different numbering, so none of the tables
# above apply to it. Its expectations are read from the artifacts that were actually applied:
# the standalone data files, and the standalone INF for user rights / account policy. Reading
# the INF rather than restating its values keeps apply and verify from drifting apart.
if ($Scope -eq 'Standalone') {
    $DataMod = Join-Path $PSScriptRoot 'CIS-Standalone-Data.ps1'
    $RegMod  = Join-Path $PSScriptRoot 'RegistrySettings-Standalone.ps1'
    $InfFile = Join-Path $PSScriptRoot 'CIS_Server2025_Standalone_Level1.inf'
    foreach ($f in @($DataMod, $RegMod, $InfFile)) {
        if (-not (Test-Path -LiteralPath $f)) { throw "Missing required file: $f" }
    }
    . $DataMod
    . $RegMod

    $scopeFilter = @('MS','USER')

    $RegistryChecks = @(
        $CISStandaloneRegistry | Where-Object { $_.Key -like 'HKLM\*' } | ForEach-Object {
            @{ Id = $_.Id; Hive = 'HKLM'; Path = ($_.Key -replace '^HKLM\\',''); Name = $_.Name
               Expected = "$($_.Value)"; Type = $_.Type; Scope = 'MS' }
        }
    )
    $UserRegistryChecks = @(
        $CISStandaloneRegistry | Where-Object { $_.Key -like 'HKCU\*' } | ForEach-Object {
            @{ Id = $_.Id; Hive = 'HKCU'; Path = ($_.Key -replace '^HKCU\\',''); Name = $_.Name
               Expected = "$($_.Value)"; Type = $_.Type; Scope = 'USER' }
        }
    )
    $AuditChecks = @(
        $CISStandaloneAudit | ForEach-Object {
            @{ Id = $_.Id; Sub = $_.Sub; Guid = $_.Guid; Expected = $_.Setting; Scope = 'MS' }
        }
    )

    # Parse the standalone INF for the two secedit-delivered areas.
    $infLines = Get-Content -LiteralPath $InfFile -Encoding Unicode
    $section  = ''
    $pr = @(); $sa = @(); $lastId = ''
    foreach ($line in $infLines) {
        $t = $line.Trim()
        if ($t -match '^\[(.+)\]$') { $section = $Matches[1]; continue }
        if ($t -match '^;\s*([\d.]+)\s*$') { $lastId = $Matches[1]; continue }
        if (-not $t -or $t.StartsWith(';')) { continue }
        if ($section -eq 'Privilege Rights' -and $t -match '^(Se\w+)\s*=\s*(.*)$') {
            $pr += @{ Id = $lastId; Const = $Matches[1]; Expected = ($Matches[2].Trim() -replace ',', ';'); Scope = 'MS' }
        }
        elseif ($section -eq 'System Access' -and $t -match '^(\w+)\s*=\s*(.*)$') {
            $sa += @{ Id = $lastId; Token = $Matches[1]; Expected = $Matches[2].Trim().Trim('"'); Scope = 'MS' }
        }
    }
    $PrivilegeChecks     = $pr
    $SystemAccessChecks  = $sa
    Write-Host ("Standalone tables: {0} registry, {1} user-registry, {2} audit, {3} user rights, {4} account policy" `
                -f $RegistryChecks.Count, $UserRegistryChecks.Count, $AuditChecks.Count, $pr.Count, $sa.Count) -ForegroundColor DarkCyan
}

# ============================ 1) Registry ============================
function Test-RegistrySet($checks,$area){
    foreach($c in ($checks | Where-Object { $_.Scope -in $scopeFilter })){
        $exp  = @{ Expected = "$($c.Expected)"; IsDeviation = $false }
        # Some controls accept more than one compliant value (e.g. 2.3.17.2 passes on 1 or 2). An
        # optional Accept list holds the additional values; the displayed Expected shows all of them.
        $accept  = @($c.Accept) | Where-Object { $_ }
        $expDisp = if ($accept.Count) { (@($exp.Expected) + $accept) -join ' or ' } else { $exp.Expected }
        $full = "$($c.Hive):\$($c.Path)"
        $actual = $null
        try { $actual = (Get-ItemProperty -Path $full -Name $c.Name -ErrorAction Stop).$($c.Name) } catch { $actual = $null }
        if ($null -eq $actual) { Add-Result $c.Id $area "$($c.Path)\$($c.Name)" $expDisp "<not set>" "FAIL"; continue }
        $a = "$actual"
        $ok = ($a -eq $exp.Expected) -or ($accept -contains $a)
        $res = if (-not $ok) { "FAIL" } elseif ($exp.IsDeviation) { "DEVIATION" } else { "PASS" }
        Add-Result $c.Id $area "$($c.Path)\$($c.Name)" $expDisp $a $res
    }
}
Test-RegistrySet $RegistryChecks "Registry"
if ($IncludeUser) { Test-RegistrySet $UserRegistryChecks "Registry(User)" }
else { foreach($c in ($UserRegistryChecks | Where-Object { $_.Scope -in $scopeFilter })){ Add-Result $c.Id "Registry(User)" "$($c.Path)\$($c.Name)" $c.Expected "(skipped - use -IncludeUser)" "SKIP" } }

# ============================ 2) Advanced Audit Policy ============================
foreach($c in ($AuditChecks | Where-Object { $_.Scope -in $scopeFilter })){
    $line = (& auditpol.exe /get /subcategory:"$($c.Guid)" /r 2>$null | Select-Object -Skip 1 | Where-Object { $_ -match '\S' } | Select-Object -First 1)
    if (-not $line) { Add-Result $c.Id "Audit" $c.Sub $c.Expected "<no data>" "REVIEW"; continue }
    $cols = $line -split ','
    $actual = if ($cols.Count -ge 5) { $cols[4].Trim() } else { "<parse error>" }
    if ([string]::IsNullOrWhiteSpace($actual)) { $actual = "No Auditing" }
    $res = if ($actual -eq $c.Expected) { "PASS" } else { "FAIL" }
    Add-Result $c.Id "Audit" $c.Sub $c.Expected $actual $res
}

# ============================ secedit export (URA + System Access) ============================
$secTmp = Join-Path $env:TEMP ("cisaudit_{0}.inf" -f ([guid]::NewGuid().ToString('N')))
& secedit.exe /export /cfg $secTmp /quiet | Out-Null
$secText = if (Test-Path $secTmp) { Get-Content $secTmp } else { @() }
Remove-Item $secTmp -ErrorAction SilentlyContinue
function Get-SecLine($key){ ($secText | Where-Object { $_ -match "^\s*$([regex]::Escape($key))\s*=" } | Select-Object -First 1) }
function Norm-Sids($s){
    if ([string]::IsNullOrWhiteSpace($s)) { return @() }
    ($s -split '[,;]' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ }) | Sort-Object -Unique
}

# 3) Privilege Rights
foreach($c in ($PrivilegeChecks | Where-Object { $_.Scope -in $scopeFilter })){
    $exp = @{ Expected = "$($c.Expected)"; IsDeviation = $false }
    $line = Get-SecLine $c.Const
    $actualRaw = if ($line) { ($line -split '=',2)[1].Trim() } else { "" }
    $expSet = Norm-Sids $exp.Expected
    $actSet = Norm-Sids $actualRaw
    $expDisp = if ($expSet.Count) { ($expSet -join ',') } else { "<none>" }
    $actDisp = if ($actSet.Count) { ($actSet -join ',') } else { "<none>" }
    # ignore unresolved friendly names (e.g. PrintSpoolerService) for the strict compare
    $expCmp = $expSet | Where-Object { $_ -like 'S-1-*' }
    $actCmp = $actSet | Where-Object { $_ -like 'S-1-*' }
    $res = if ((($expCmp -join ',') -eq ($actCmp -join ',')) ) {
               if ($expSet.Count -ne $expCmp.Count) { "REVIEW" } elseif ($exp.IsDeviation) { "DEVIATION" } else { "PASS" }
           } else { "FAIL" }
    Add-Result $c.Id "UserRights" $c.Const $expDisp $actDisp $res
}

# 4) System Access (account/lockout policy)
foreach($c in ($SystemAccessChecks | Where-Object { $_.Scope -in $scopeFilter })){
    $line = Get-SecLine $c.Token
    # secedit /export writes string values quoted in the INF (e.g. NewAdministratorName = "laadmin"),
    # while the expected value is unquoted. Strip surrounding double quotes so a correct account name
    # does not read as a FAIL. Numeric settings are unquoted in the export and are unaffected.
    $actual = if ($line) { (($line -split '=',2)[1].Trim()).Trim('"') } else { "<not set>" }
    $res = if ($actual -eq $c.Expected) { "PASS" } elseif ($actual -eq "<not set>") { "FAIL" } else { "FAIL" }
    Add-Result $c.Id "AccountPolicy" $c.Token $c.Expected $actual $res
}

# ============================ 5) Firewall profiles (section 9) ============================
# The Stand-alone benchmark has no Domain-profile recommendations (a workgroup host never uses
# that profile), so checking it would report a result for something the benchmark never asked for.
$fwProfiles = if ($Scope -eq 'Standalone') { @('Private','Public') } else { @('Domain','Private','Public') }
foreach($p in $fwProfiles){
    try {
        $fp = Get-NetFirewallProfile -Profile $p -ErrorAction Stop
        $en = "$($fp.Enabled)"; $resEn = if ($en -in 'True','1') { "PASS" } else { "FAIL" }
        Add-Result "9.$($p)" "Firewall" "$p`:Enabled" "True" $en $resEn
        $ib = "$($fp.DefaultInboundAction)"; $resIb = if ($ib -eq 'Block') { "PASS" } else { "FAIL" }
        Add-Result "9.$($p)" "Firewall" "$p`:DefaultInboundAction" "Block" $ib $resIb
    } catch { Add-Result "9.$($p)" "Firewall" "$p" "Enabled/Block" "<error>" "REVIEW" }
}

# ============================ report ============================
$summary = $results | Group-Object Result | Sort-Object Name | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }
Write-Host ""
# Build a lexicographically sortable key from the dotted Id. [version] can't be used because CIS
# Ids have up to 5 components (e.g. 18.9.20.1.1) and non-numeric segments (e.g. firewall '9.Private').
# Each segment is reduced to its digits (blank -> 0) and zero-padded to a fixed width so string sort
# orders them numerically and keeps parents ahead of their children.
$idSortKey = { ($_.Id -split '\.' | ForEach-Object { '{0:D6}' -f [int]("0" + ($_ -replace '\D','')) }) -join '.' }
$sorted = $results | Sort-Object @{e=$idSortKey}, Area
# -Wrap, not -AutoSize alone: in a narrow console AutoSize silently truncates Setting/Expected/Actual
# with "..." so the very values you need to act on get cut off. Wrap keeps them whole.
$sorted | Format-Table Id, Area, Setting, Expected, Actual, Result -AutoSize -Wrap | Out-Host

# A dedicated FAIL-only table. The full table above can run to 200+ rows, so FAIL rows scroll off the
# top and "see FAIL rows above" is not actionable. Repeat just the failures here, right next to the
# count, so an operator sees exactly what to fix without scrolling.
$failRows = @($sorted | Where-Object Result -eq 'FAIL')
if ($failRows.Count) {
    Write-Host ""
    Write-Host ("FAILED settings ({0}) - these are NON-COMPLIANT:" -f $failRows.Count) -ForegroundColor Red
    $failRows | Format-Table Id, Area, Setting, Expected, Actual -AutoSize -Wrap | Out-Host
}
Write-Host ("CIS S2025 L1 ({0}) compliance: {1}  (total {2})" -f $Scope, ($summary -join '  '), $results.Count) -ForegroundColor Cyan
if ($failRows.Count) { Write-Host "$($failRows.Count) setting(s) NON-COMPLIANT - listed in the FAILED settings table above." -ForegroundColor Red }
else { Write-Host "No FAIL rows. Review any REVIEW/SKIP items manually." -ForegroundColor Green }

# The standalone profile has a handful of recommendations that cannot be auto-verified because
# they were never auto-applied (lists, SDDL, site-specific text). Listing them keeps a clean
# report from being mistaken for full benchmark coverage.
if ($Scope -eq 'Standalone' -and $CISStandaloneReview) {
    Write-Host ""
    Write-Host ("$($CISStandaloneReview.Count) recommendation(s) are NOT covered by this report - they are not") -ForegroundColor Yellow
    Write-Host  "auto-applied and must be checked by hand (ExceptionsAndManualSteps.md section 4):" -ForegroundColor Yellow
    foreach ($r in $CISStandaloneReview) {
        Write-Host ("  [REVIEW] {0,-14} {1}" -f $r.Id, $r.Title) -ForegroundColor DarkYellow
    }
}
if ($CsvPath) { $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8; Write-Host "Full results -> $CsvPath" }
Write-Host "Full log: $LogPath" -ForegroundColor DarkCyan
if ($script:Transcribing) { try { Stop-Transcript | Out-Null } catch {} }
