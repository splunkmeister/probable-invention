<#
.SYNOPSIS
  CIS Microsoft Windows Server 2025 Benchmark v2.0.0 - Level 1
  Administrative Template / Registry-backed settings applied to a GPO via Set-GPRegistryValue.
.DESCRIPTION
  Data-driven. Each entry carries its CIS ID, registry key/value, type and applicability scope.
  Call Set-CISRegistrySettings -GpoName <name> -Scope <Member|DC>.
.NOTES
  Generated from the benchmark. Settings marked for review (Hardened UNC Paths 18.6.14.1,
  ASR rules 18.10.42.6.1.2) are intentionally excluded - see ExceptionsAndManualSteps.md.
#>

$CISRegistrySettings = @(
  @{ Id="18.1.1.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoLockScreenCamera"; Type="DWord"; Value=1; Scope="Both" }  # 'Prevent enabling lock screen camera' is set to 'Enabled'
  @{ Id="18.1.1.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoLockScreenSlideshow"; Type="DWord"; Value=1; Scope="Both" }  # 'Prevent enabling lock screen slide show' is set to 'Enabled'
  @{ Id="18.1.2.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name="AllowInputPersonalization"; Type="DWord"; Value=0; Scope="Both" }  # 'Allow users to enable online speech recognition services' is set to '
  @{ Id="18.4.1"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LocalAccountTokenFilterPolicy"; Type="DWord"; Value=0; Scope="MS" }  # 'Apply UAC restrictions to local accounts on network logons' is set to
  @{ Id="18.4.2"; Key="HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10"; Name="Start"; Type="DWord"; Value=4; Scope="Both" }  # 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (r
  @{ Id="18.4.3"; Key="HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SMB1"; Type="DWord"; Value=0; Scope="Both" }  # 'Configure SMB v1 server' is set to 'Disabled'
  @{ Id="18.4.4"; Key="HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config"; Name="EnableCertPaddingCheck"; Type="DWord"; Value=1; Scope="Both" }  # 'Enable Certificate Padding' is set to 'Enabled'
  @{ Id="18.4.5"; Key="HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name="DisableExceptionChainValidation"; Type="DWord"; Value=0; Scope="Both" }  # 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is
  @{ Id="18.4.6"; Key="HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name="NodeType"; Type="DWord"; Value=2; Scope="Both" }  # 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended
  @{ Id="18.5.1"; Key="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="AutoAdminLogon"; Type="String"; Value="0"; Scope="Both" }  # 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled'
  @{ Id="18.5.2"; Key="HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name="DisableIPSourceRouting"; Type="DWord"; Value=2; Scope="Both" }  # 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level
  @{ Id="18.5.3"; Key="HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="DisableIPSourceRouting"; Type="DWord"; Value=2; Scope="Both" }  # 'MSS: (DisableIPSourceRouting) IP source routing protection level' is 
  @{ Id="18.5.4"; Key="HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableICMPRedirect"; Type="DWord"; Value=0; Scope="Both" }  # 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF gener
  @{ Id="18.5.6"; Key="HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name="NoNameReleaseOnDemand"; Type="DWord"; Value=1; Scope="Both" }  # 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS nam
  @{ Id="18.5.8"; Key="HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"; Name="SafeDllSearchMode"; Type="DWord"; Value=1; Scope="Both" }  # 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enab
  @{ Id="18.5.11"; Key="HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security"; Name="WarningLevel"; Type="DWord"; Value=90; Scope="Both" }  # 'MSS: (WarningLevel) Percentage threshold for the security event log a
  @{ Id="18.6.4.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name="EnableMDNS"; Type="DWord"; Value=0; Scope="Both" }  # 'Configure multicast DNS (mDNS) protocol' is set to 'Disabled'
  @{ Id="18.6.4.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name="EnableNetbios"; Type="DWord"; Value=0; Scope="Both" }  # 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name 
  @{ Id="18.6.4.4"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name="EnableMulticast"; Type="DWord"; Value=0; Scope="Both" }  # 'Turn off multicast name resolution' is set to 'Enabled'
  @{ Id="18.6.7.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer"; Name="AuditClientDoesNotSupportEncryption"; Type="DWord"; Value=1; Scope="Both" }  # 'Audit client does not support encryption' is set to 'Enabled'
  @{ Id="18.6.7.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer"; Name="AuditClientDoesNotSupportSigning"; Type="DWord"; Value=1; Scope="Both" }  # 'Audit client does not support signing' is set to 'Enabled'
  @{ Id="18.6.7.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer"; Name="AuditInsecureGuestLogon"; Type="DWord"; Value=1; Scope="Both" }  # 'Audit insecure guest logon' is set to 'Enabled'
  @{ Id="18.6.7.4"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer"; Name="EnableAuthRateLimiter"; Type="DWord"; Value=1; Scope="Both" }  # 'Enable authentication rate limiter' is set to 'Enabled'
  @{ Id="18.6.7.5"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Bowser"; Name="EnableMailslots"; Type="DWord"; Value=0; Scope="Both" }  # 'Enable remote mailslots' is set to 'Disabled'
  @{ Id="18.6.7.6"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer"; Name="MinSmb2Dialect"; Type="DWord"; Value=785; Scope="Both" }  # 'Mandate the minimum version of SMB' is set to 'Enabled: 3.1.1'
  @{ Id="18.6.7.7"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer"; Name="InvalidAuthenticationDelayTimeInMs"; Type="DWord"; Value=2000; Scope="Both" }  # 'Set authentication rate limiter delay (milliseconds)' is set to 'Enab
  @{ Id="18.6.8.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name="AuditInsecureGuestLogon"; Type="DWord"; Value=1; Scope="Both" }  # 'Audit insecure guest logon' is set to 'Enabled'
  @{ Id="18.6.8.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name="AuditServerDoesNotSupportEncryption"; Type="DWord"; Value=1; Scope="Both" }  # 'Audit server does not support encryption' is set to 'Enabled'
  @{ Id="18.6.8.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name="AuditServerDoesNotSupportSigning"; Type="DWord"; Value=1; Scope="Both" }  # 'Audit server does not support signing' is set to 'Enabled'
  @{ Id="18.6.8.4"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name="AllowInsecureGuestAuth"; Type="DWord"; Value=0; Scope="Both" }  # 'Enable insecure guest logons' is set to 'Disabled'
  @{ Id="18.6.8.5"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider"; Name="EnableMailslots"; Type="DWord"; Value=0; Scope="Both" }  # 'Enable remote mailslots' is set to 'Disabled'
  @{ Id="18.6.8.6"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name="MinSmb2Dialect"; Type="DWord"; Value=785; Scope="Both" }  # 'Mandate the minimum version of SMB' is set to 'Enabled: 3.1.1'
  @{ Id="18.6.8.7"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name="RequireEncryption"; Type="DWord"; Value=1; Scope="Both" }  # 'Require Encryption' is set to 'Enabled'
  @{ Id="18.6.11.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name="NC_AllowNetBridge_NLA"; Type="DWord"; Value=0; Scope="Both" }  # 'Prohibit installation and configuration of Network Bridge on your DNS
  @{ Id="18.6.11.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name="NC_ShowSharedAccessUI"; Type="DWord"; Value=0; Scope="Both" }  # 'Prohibit use of Internet Connection Sharing on your DNS domain networ
  @{ Id="18.6.11.4"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name="NC_StdDomainUserSetLocation"; Type="DWord"; Value=1; Scope="Both" }  # 'Require domain users to elevate when setting a network's location' is
  @{ Id="18.6.21.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"; Name="fMinimizeConnections"; Type="DWord"; Value=3; Scope="Both" }  # 'Minimize the number of simultaneous connections to the Internet or a 
  @{ Id="18.7.1"; Key="HKLM\Software\Policies\Microsoft\Windows NT\Printers"; Name="RegisterSpoolerRemoteRpcEndPoint"; Type="DWord"; Value=2; Scope="Both" }  # 'Allow Print Spooler to accept client connections' is set to 'Disabled
  @{ Id="18.7.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="RedirectionguardPolicy"; Type="DWord"; Value=1; Scope="Both" }  # 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard En
  @{ Id="18.7.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"; Name="RpcUseNamedPipeProtocol"; Type="DWord"; Value=0; Scope="Both" }  # 'Configure RPC connection settings: Protocol to use for outgoing RPC c
  @{ Id="18.7.4"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"; Name="RpcAuthentication"; Type="DWord"; Value=0; Scope="Both" }  # 'Configure RPC connection settings: Use authentication for outgoing RP
  @{ Id="18.7.5"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"; Name="RpcProtocols"; Type="DWord"; Value=5; Scope="Both" }  # 'Configure RPC listener settings: Protocols to allow for incoming RPC 
  @{ Id="18.7.6"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"; Name="ForceKerberosForRpc"; Type="DWord"; Value=0; Scope="Both" }  # 'Configure RPC listener settings: Authentication protocol to use for i
  @{ Id="18.7.7"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"; Name="RpcTcpPort"; Type="DWord"; Value=0; Scope="Both" }  # 'Configure RPC over TCP port' is set to 'Enabled: 0'
  @{ Id="18.7.8"; Key="HKLM\SYSTEM\CurrentControlSet\Control\Print"; Name="RpcAuthnLevelPrivacyEnabled"; Type="DWord"; Value=1; Scope="Both" }  # 'Configure RPC packet level privacy setting for incoming connections' 
  @{ Id="18.7.10"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"; Name="RestrictDriverInstallationToAdministrators"; Type="DWord"; Value=1; Scope="Both" }  # 'Limits print driver installation to Administrators' is set to 'Enable
  @{ Id="18.7.11"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="CopyFilesPolicy"; Type="DWord"; Value=1; Scope="Both" }  # 'Manage processing of Queue-specific files' is set to 'Enabled: Limit 
  @{ Id="18.7.12"; Key="HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"; Name="NoWarningNoElevationOnInstall"; Type="DWord"; Value=0; Scope="Both" }  # 'Point and Print Restrictions: When installing drivers for a new conne
  @{ Id="18.7.13"; Key="HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"; Name="UpdatePromptSettings"; Type="DWord"; Value=0; Scope="Both" }  # 'Point and Print Restrictions: When updating drivers for an existing c
  @{ Id="18.9.3.1"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Name="ProcessCreationIncludeCmdLine_Enabled"; Type="DWord"; Value=1; Scope="Both" }  # 'Include command line in process creation events' is set to 'Enabled'
  @{ Id="18.9.4.1"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"; Name="AllowEncryptionOracle"; Type="DWord"; Value=0; Scope="Both" }  # 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clie
  @{ Id="18.9.4.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"; Name="AllowProtectedCreds"; Type="DWord"; Value=1; Scope="Both" }  # 'Remote host allows delegation of non-exportable credentials' is set t
  @{ Id="18.9.7.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"; Name="PreventDeviceMetadataFromNetwork"; Type="DWord"; Value=1; Scope="Both" }  # 'Prevent automatic download of applications associated with device met
  @{ Id="18.9.13.1"; Key="HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"; Name="DriverLoadPolicy"; Type="DWord"; Value=3; Scope="Both" }  # 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, un
  @{ Id="18.9.17.1"; Key="HKLM\SYSTEM\CurrentControlSet\Policies"; Name="ClfsAuthenticationChecking"; Type="DWord"; Value=1; Scope="Both" }  # 'Enable / disable CLFS logfile authentication' is set to 'Enabled'
  @{ Id="18.9.19.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"; Name="NoBackgroundPolicy"; Type="DWord"; Value=0; Scope="Both" }  # 'Configure security policy processing: Do not apply during periodic ba
  @{ Id="18.9.19.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"; Name="NoGPOListChanges"; Type="DWord"; Value=0; Scope="Both" }  # 'Configure security policy processing: Process even if the Group Polic
  @{ Id="18.9.19.4"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableCdp"; Type="DWord"; Value=0; Scope="Both" }  # 'Continue experiences on this device' is set to 'Disabled'
  @{ Id="18.9.20.1.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="DisableWebPnPDownload"; Type="DWord"; Value=1; Scope="Both" }  # 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
  @{ Id="18.9.20.1.5"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoWebServices"; Type="DWord"; Value=1; Scope="Both" }  # 'Turn off Internet download for Web publishing and online ordering wiz
  @{ Id="18.9.24.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"; Name="DeviceEnumerationPolicy"; Type="DWord"; Value=0; Scope="Both" }  # 'Enumeration policy for external devices incompatible with Kernel DMA 
  @{ Id="18.9.26.1"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="BackupDirectory"; Type="DWord"; Value=1; Scope="MS" }  # 'Configure password backup directory' is set to 'Enabled: Active Direc
  @{ Id="18.9.26.2"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="PasswordExpirationProtectionEnabled"; Type="DWord"; Value=1; Scope="MS" }  # 'Do not allow password expiration time longer than required by policy'
  @{ Id="18.9.26.3"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="ADPasswordEncryptionEnabled"; Type="DWord"; Value=1; Scope="MS" }  # 'Enable password encryption' is set to 'Enabled'
  @{ Id="18.9.26.4"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="PasswordComplexity"; Type="DWord"; Value=4; Scope="MS" }  # 'Password Settings: Password Complexity' is set to 'Enabled: Large let
  @{ Id="18.9.26.5"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="PasswordLength"; Type="DWord"; Value=15; Scope="MS" }  # 'Password Settings: Password Length' is set to 'Enabled: 15 or more'
  @{ Id="18.9.26.6"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="PasswordAgeDays"; Type="DWord"; Value=30; Scope="MS" }  # 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or few
  @{ Id="18.9.26.7"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="PostAuthenticationResetDelay"; Type="DWord"; Value=8; Scope="MS" }  # 'Post-authentication actions: Grace period (hours)' is set to 'Enabled
  @{ Id="18.9.26.8"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Name="PostAuthenticationActions"; Type="DWord"; Value=3; Scope="MS" }  # 'Post-authentication actions: Actions' is set to 'Enabled: Reset the p
  @{ Id="18.9.27.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\System"; Name="AllowCustomSSPsAPs"; Type="DWord"; Value=0; Scope="DC" }  # 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disable
  @{ Id="18.9.29.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\System"; Name="BlockUserFromShowingAccountDetailsOnSignin"; Type="DWord"; Value=1; Scope="Both" }  # 'Block user from showing account details on sign-in' is set to 'Enable
  @{ Id="18.9.29.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\System"; Name="DontDisplayNetworkSelectionUI"; Type="DWord"; Value=1; Scope="Both" }  # 'Do not display network selection UI' is set to 'Enabled'
  @{ Id="18.9.29.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\System"; Name="DontEnumerateConnectedUsers"; Type="DWord"; Value=1; Scope="Both" }  # 'Do not enumerate connected users on domain- joined computers' is set 
  @{ Id="18.9.29.4"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnumerateLocalUsers"; Type="DWord"; Value=0; Scope="MS" }  # 'Enumerate local users on domain-joined computers' is set to 'Disabled
  @{ Id="18.9.29.5"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\System"; Name="DisableLockScreenAppNotifications"; Type="DWord"; Value=1; Scope="Both" }  # 'Turn off app notifications on the lock screen' is set to 'Enabled'
  @{ Id="18.9.29.6"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\System"; Name="AllowDomainPINLogon"; Type="DWord"; Value=0; Scope="Both" }  # 'Turn on convenience PIN sign-in' is set to 'Disabled'
  @{ Id="18.9.31.1.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Netlogon\Parameters"; Name="BlockNetbiosDiscovery"; Type="DWord"; Value=1; Scope="Both" }  # 'Block NetBIOS-based discovery for domain controller location' is set 
  @{ Id="18.9.35.6.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"; Name="DCSettingIndex"; Type="DWord"; Value=1; Scope="Both" }  # 'Require a password when a computer wakes (on battery)' is set to 'Ena
  @{ Id="18.9.35.6.4"; Key="HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"; Name="ACSettingIndex"; Type="DWord"; Value=1; Scope="Both" }  # 'Require a password when a computer wakes (plugged in)' is set to 'Ena
  @{ Id="18.9.37.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fAllowUnsolicited"; Type="DWord"; Value=0; Scope="Both" }  # 'Configure Offer Remote Assistance' is set to 'Disabled'
  @{ Id="18.9.37.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fAllowToGetHelp"; Type="DWord"; Value=0; Scope="Both" }  # 'Configure Solicited Remote Assistance' is set to 'Disabled'
  @{ Id="18.9.38.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"; Name="EnableAuthEpResolution"; Type="DWord"; Value=1; Scope="MS" }  # 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'
  @{ Id="18.9.41.1"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM"; Name="SamNGCKeyROCAValidation"; Type="DWord"; Value=2; Scope="DC" }  # 'Configure validation of ROCA-vulnerable WHfB keys during authenticati
  @{ Id="18.9.41.2"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM"; Name="SamrChangeUserPasswordApiPolicy"; Type="DWord"; Value=2; Scope="DC" }  # 'Configure SAM change password RPC methods policy' is set to 'Enabled:
  @{ Id="18.9.41.3"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM"; Name="SamrChangeUserPasswordApiPolicy"; Type="DWord"; Value=1; Scope="MS" }  # 'Configure SAM change password RPC methods policy' is set to 'Enabled:
  @{ Id="18.9.53.1.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"; Name="Enabled"; Type="DWord"; Value=1; Scope="Both" }  # 'Enable Windows NTP Client' is set to 'Enabled'
  @{ Id="18.9.53.1.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer"; Name="Enabled"; Type="DWord"; Value=0; Scope="MS" }  # 'Enable Windows NTP Server' is set to 'Disabled' (MS only)
  @{ Id="18.10.4.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx"; Name="DisablePerUserUnsignedPackagesByDefault"; Type="DWord"; Value=1; Scope="Both" }  # 'Not allow per-user unsigned packages to install by default (requires 
  @{ Id="18.10.6.1"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="MSAOptional"; Type="DWord"; Value=1; Scope="Both" }  # 'Allow Microsoft accounts to be optional' is set to 'Enabled'
  @{ Id="18.10.8.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoAutoplayfornonVolume"; Type="DWord"; Value=1; Scope="Both" }  # 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
  @{ Id="18.10.8.2"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoAutorun"; Type="DWord"; Value=1; Scope="Both" }  # 'Set the default behavior for AutoRun' is set to 'Enabled: Do not exec
  @{ Id="18.10.8.3"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Type="DWord"; Value=255; Scope="Both" }  # 'Turn off Autoplay' is set to 'Enabled: All drives'
  @{ Id="18.10.9.1.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"; Name="EnhancedAntiSpoofing"; Type="DWord"; Value=1; Scope="Both" }  # 'Configure enhanced anti-spoofing' is set to 'Enabled'
  @{ Id="18.10.13.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableConsumerAccountStateContent"; Type="DWord"; Value=1; Scope="Both" }  # 'Turn off cloud consumer account state content' is set to 'Enabled'
  @{ Id="18.10.14.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect"; Name="RequirePinForPairing"; Type="DWord"; Value=1; Scope="Both" }  # 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled:
  @{ Id="18.10.15.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI"; Name="DisablePasswordReveal"; Type="DWord"; Value=1; Scope="Both" }  # 'Do not display the password reveal button' is set to 'Enabled'
  @{ Id="18.10.15.2"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"; Name="EnumerateAdministrators"; Type="DWord"; Value=0; Scope="Both" }  # 'Enumerate administrator accounts on elevation' is set to 'Disabled'
  @{ Id="18.10.16.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Type="DWord"; Value=0; Scope="Both" }  # 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not r
  @{ Id="18.10.16.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="DoNotShowFeedbackNotifications"; Type="DWord"; Value=1; Scope="Both" }  # 'Do not show feedback notifications' is set to 'Enabled'
  @{ Id="18.10.18.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"; Name="EnableExperimentalFeatures"; Type="DWord"; Value=0; Scope="Both" }  # 'Enable App Installer Experimental Features' is set to 'Disabled'
  @{ Id="18.10.18.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"; Name="EnableHashOverride"; Type="DWord"; Value=0; Scope="Both" }  # 'Enable App Installer Hash Override' is set to 'Disabled'
  @{ Id="18.10.18.4"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"; Name="EnableLocalArchiveMalwareScanOverride"; Type="DWord"; Value=0; Scope="Both" }  # 'Enable App Installer Local Archive Malware Scan Override' is set to '
  @{ Id="18.10.18.5"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"; Name="EnableMSAppInstallerProtocol"; Type="DWord"; Value=0; Scope="Both" }  # 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled'
  @{ Id="18.10.18.6"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"; Name="EnableBypassCertificatePinningForMicrosoftStore"; Type="DWord"; Value=0; Scope="Both" }  # 'Enable App Installer Microsoft Store Source Certificate Validation By
  @{ Id="18.10.26.1.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"; Name="Retention"; Type="String"; Value="0"; Scope="Both" }  # 'Application: Control Event Log behavior when the log file reaches its
  @{ Id="18.10.26.1.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"; Name="MaxSize"; Type="DWord"; Value=32768; Scope="Both" }  # 'Application: Specify the maximum log file size (KB)' is set to 'Enabl
  @{ Id="18.10.26.2.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"; Name="Retention"; Type="String"; Value="0"; Scope="Both" }  # 'Security: Control Event Log behavior when the log file reaches its ma
  @{ Id="18.10.26.2.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"; Name="MaxSize"; Type="DWord"; Value=196608; Scope="Both" }  # 'Security: Specify the maximum log file size (KB)' is set to 'Enabled:
  @{ Id="18.10.26.3.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"; Name="Retention"; Type="String"; Value="0"; Scope="Both" }  # 'Setup: Control Event Log behavior when the log file reaches its maxim
  @{ Id="18.10.26.3.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"; Name="MaxSize"; Type="DWord"; Value=32768; Scope="Both" }  # 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32
  @{ Id="18.10.26.4.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"; Name="Retention"; Type="String"; Value="0"; Scope="Both" }  # 'System: Control Event Log behavior when the log file reaches its maxi
  @{ Id="18.10.26.4.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"; Name="MaxSize"; Type="DWord"; Value=32768; Scope="Both" }  # 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 3
  @{ Id="18.10.29.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="DisableMotWOnInsecurePathCopy"; Type="DWord"; Value=0; Scope="Both" }  # 'Do not apply the Mark of the Web tag to files copied from insecure so
  @{ Id="18.10.29.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoDataExecutionPrevention"; Type="DWord"; Value=0; Scope="Both" }  # 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
  @{ Id="18.10.29.4"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoHeapTerminationOnCorruption"; Type="DWord"; Value=0; Scope="Both" }  # 'Turn off heap termination on corruption' is set to 'Disabled'
  @{ Id="18.10.29.5"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="PreXPSP2ShellProtocolBehavior"; Type="DWord"; Value=0; Scope="Both" }  # 'Turn off shell protocol protected mode' is set to 'Disabled'
  @{ Id="18.10.41.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount"; Name="DisableUserAuth"; Type="DWord"; Value=1; Scope="Both" }  # 'Block all consumer Microsoft account user authentication' is set to '
  @{ Id="18.10.42.4.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Features"; Name="PassiveRemediation"; Type="DWord"; Value=1; Scope="Both" }  # 'Enable EDR in block mode' is set to 'Enabled'
  @{ Id="18.10.42.5.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name="LocalSettingOverrideSpynetReporting"; Type="DWord"; Value=0; Scope="Both" }  # 'Configure local setting override for reporting to Microsoft MAPS' is 
  @{ Id="18.10.42.5.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name="SpynetReporting"; Type="DWord"; Value=2; Scope="Both" }  # 'Join Microsoft MAPS' is set to 'Enabled: Advanced'
  @{ Id="18.10.42.6.1.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"; Name="ExploitGuard_ASR_Rules"; Type="DWord"; Value=1; Scope="Both" }  # 'Configure Attack Surface Reduction rules' is set to 'Enabled'
  @{ Id="18.10.42.6.3.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"; Name="EnableNetworkProtection"; Type="DWord"; Value=1; Scope="Both" }  # 'Prevent users and apps from accessing dangerous websites' is set to '
  @{ Id="18.10.42.7.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"; Name="EnableFileHashComputation"; Type="DWord"; Value=1; Scope="Both" }  # 'Enable file hash computation feature' is set to 'Enabled'
  @{ Id="18.10.42.10.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="OobeEnableRtpAndSigUpdate"; Type="DWord"; Value=1; Scope="Both" }  # 'Configure real-time protection and Security Intelligence Updates duri
  @{ Id="18.10.42.10.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableIOAVProtection"; Type="DWord"; Value=0; Scope="Both" }  # 'Scan all downloaded files and attachments' is set to 'Enabled'
  @{ Id="18.10.42.10.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableRealtimeMonitoring"; Type="DWord"; Value=0; Scope="Both" }  # 'Turn off real-time protection' is set to 'Disabled'
  @{ Id="18.10.42.10.4"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableBehaviorMonitoring"; Type="DWord"; Value=0; Scope="Both" }  # 'Turn on behavior monitoring' is set to 'Enabled'
  @{ Id="18.10.42.10.5"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableScriptScanning"; Type="DWord"; Value=0; Scope="Both" }  # 'Turn on script scanning' is set to 'Enabled'
  @{ Id="18.10.42.11.1.1.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection"; Name="BruteForceProtectionConfiguredState"; Type="DWord"; Value=2; Scope="Both" }  # 'Configure Remote Encryption Protection Mode' is set to 'Enabled: Audi
  @{ Id="18.10.42.13.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="QuickScanIncludeExclusions"; Type="DWord"; Value=1; Scope="Both" }  # 'Scan excluded files and directories during quick scans' is set to 'En
  @{ Id="18.10.42.13.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="DisablePackedExeScanning"; Type="DWord"; Value=0; Scope="Both" }  # 'Scan packed executables' is set to 'Enabled'
  @{ Id="18.10.42.13.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="DisableRemovableDriveScanning"; Type="DWord"; Value=0; Scope="Both" }  # 'Scan removable drives' is set to 'Enabled'
  @{ Id="18.10.42.13.4"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="DaysUntilAggressiveCatchupQuickScan"; Type="DWord"; Value=7; Scope="Both" }  # 'Trigger a quick scan after X days without any scans' is set to 'Enabl
  @{ Id="18.10.42.13.5"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="DisableEmailScanning"; Type="DWord"; Value=0; Scope="Both" }  # 'Turn on e-mail scanning' is set to 'Enabled'
  @{ Id="18.10.42.16"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"; Name="PUAProtection"; Type="DWord"; Value=1; Scope="Both" }  # 'Configure detection for potentially unwanted applications' is set to 
  @{ Id="18.10.42.17"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"; Name="HideExclusionsFromLocalUsers"; Type="DWord"; Value=1; Scope="Both" }  # 'Control whether exclusions are visible to local users' is set to 'Ena
  @{ Id="18.10.57.2.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="DisablePasswordSaving"; Type="DWord"; Value=1; Scope="Both" }  # 'Do not allow passwords to be saved' is set to 'Enabled'
  @{ Id="18.10.57.3.3.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fDisableCdm"; Type="DWord"; Value=1; Scope="Both" }  # 'Do not allow drive redirection' is set to 'Enabled'
  @{ Id="18.10.57.3.9.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fPromptForPassword"; Type="DWord"; Value=1; Scope="Both" }  # 'Always prompt for password upon connection' is set to 'Enabled'
  @{ Id="18.10.57.3.9.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fEncryptRPCTraffic"; Type="DWord"; Value=1; Scope="Both" }  # 'Require secure RPC communication' is set to 'Enabled'
  @{ Id="18.10.57.3.9.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="SecurityLayer"; Type="DWord"; Value=2; Scope="Both" }  # 'Require use of specific security layer for remote (RDP) connections' 
  @{ Id="18.10.57.3.9.4"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="UserAuthentication"; Type="DWord"; Value=1; Scope="Both" }  # 'Require user authentication for remote connections by using Network L
  @{ Id="18.10.57.3.9.5"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="MinEncryptionLevel"; Type="DWord"; Value=3; Scope="Both" }  # 'Set client connection encryption level' is set to 'Enabled: High Leve
  @{ Id="18.10.57.3.11.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="DeleteTempDirsOnExit"; Type="DWord"; Value=1; Scope="Both" }  # 'Do not delete temp folders upon exit' is set to 'Disabled'
  @{ Id="18.10.57.3.11.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="PerSessionTempDir"; Type="DWord"; Value=1; Scope="Both" }  # 'Do not use temporary folders per session' is set to 'Disabled'
  @{ Id="18.10.58.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"; Name="DisableEnclosureDownload"; Type="DWord"; Value=1; Scope="Both" }  # 'Prevent downloading of enclosures' is set to 'Enabled'
  @{ Id="18.10.59.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowIndexingEncryptedStoresOrItems"; Type="DWord"; Value=0; Scope="Both" }  # 'Allow indexing of encrypted files' is set to 'Disabled'
  @{ Id="18.10.77.2.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableSmartScreen"; Type="DWord"; Value=1; Scope="Both" }  # 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and
  # 18.10.77.2.1 needs BOTH values: the benchmark states "a REG_DWORD value of 1 (EnableSmartScreen)
  # and REG_SZ value of Block (ShellSmartScreenLevel)". Without the level, SmartScreen is on but
  # users can still bypass the warning, which is the half the recommendation is actually about.
  @{ Id="18.10.77.2.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\System"; Name="ShellSmartScreenLevel"; Type="String"; Value="Block"; Scope="Both" }  # 'Configure Windows Defender SmartScreen' - prevent bypass
  @{ Id="18.10.81.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"; Name="AllowWindowsInkWorkspace"; Type="DWord"; Value=0; Scope="Both" }  # 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow acc
  @{ Id="18.10.82.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="EnableUserControl"; Type="DWord"; Value=0; Scope="Both" }  # 'Allow user control over installs' is set to 'Disabled'
  @{ Id="18.10.82.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; Type="DWord"; Value=0; Scope="Both" }  # 'Always install with elevated privileges' is set to 'Disabled'
  @{ Id="18.10.83.1"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableMPR"; Type="DWord"; Value=0; Scope="Both" }  # 'Configure the transmission of the user's password in the content of M
  @{ Id="18.10.83.2"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableAutomaticRestartSignOn"; Type="DWord"; Value=1; Scope="Both" }  # 'Sign-in and lock last interactive user automatically after a restart'
  @{ Id="18.10.90.1.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowBasic"; Type="DWord"; Value=0; Scope="Both" }  # 'Allow Basic authentication' is set to 'Disabled'
  @{ Id="18.10.90.1.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowUnencryptedTraffic"; Type="DWord"; Value=0; Scope="Both" }  # 'Allow unencrypted traffic' is set to 'Disabled'
  @{ Id="18.10.90.1.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowDigest"; Type="DWord"; Value=0; Scope="Both" }  # 'Disallow Digest authentication' is set to 'Enabled'
  @{ Id="18.10.90.2.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowBasic"; Type="DWord"; Value=0; Scope="Both" }  # 'Allow Basic authentication' is set to 'Disabled'
  @{ Id="18.10.90.2.3"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowUnencryptedTraffic"; Type="DWord"; Value=0; Scope="Both" }  # 'Allow unencrypted traffic' is set to 'Disabled'
  @{ Id="18.10.90.2.4"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="DisableRunAs"; Type="DWord"; Value=1; Scope="Both" }  # 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
  @{ Id="18.10.93.2.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"; Name="DisallowExploitProtectionOverride"; Type="DWord"; Value=1; Scope="Both" }  # 'Prevent users from modifying settings' is set to 'Enabled'
  @{ Id="18.10.94.1.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="NoAutoRebootWithLoggedOnUsers"; Type="DWord"; Value=0; Scope="Both" }  # 'No auto-restart with logged on users for scheduled automatic updates 
  @{ Id="18.10.94.2.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="NoAutoUpdate"; Type="DWord"; Value=0; Scope="Both" }  # 'Configure Automatic Updates' is set to 'Enabled'
  @{ Id="18.10.94.2.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="ScheduledInstallDay"; Type="DWord"; Value=0; Scope="Both" }  # 'Configure Automatic Updates: Scheduled install day' is set to '0 - Ev
  @{ Id="18.10.94.4.1"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="ManagePreviewBuildsPolicyValue"; Type="DWord"; Value=1; Scope="Both" }  # 'Manage preview builds' is set to 'Disabled'
  @{ Id="18.10.94.4.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="DeferQualityUpdates"; Type="DWord"; Value=1; Scope="Both" }  # 'Select when Quality Updates are received' is set to 'Enabled: 0 days'
  # 18.10.94.4.2 needs BOTH values: the benchmark states "a REG_DWORD value of 1
  # (DeferQualityUpdates) and 0 (DeferQualityUpdatesPeriodInDays)". DeferQualityUpdates alone
  # turns deferral ON without setting the period, which is the opposite of 'Enabled: 0 days'.
  @{ Id="18.10.94.4.2"; Key="HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="DeferQualityUpdatesPeriodInDays"; Type="DWord"; Value=0; Scope="Both" }  # 'Select when Quality Updates are received' - 0 days
  @{ Id="18.11.1"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"; Name="DisableWpad"; Type="DWord"; Value=1; Scope="Both" }  # 'Disable HTTP proxy features: Disable WPAD' is set to 'Enabled: Checke
  @{ Id="18.11.2"; Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"; Name="DisableProxyAuthenticationSchemes"; Type="DWord"; Value=256; Scope="Both" }  # 'Disable HTTP proxy features: Disable proxy authentication' is set to 
  @{ Id="19.5.1.1"; Key="HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"; Name="NoToastApplicationNotificationOnLockScreen"; Type="DWord"; Value=1; Scope="Both" }  # 'Turn off toast notifications on the lock screen' is set to 'Enabled'
  @{ Id="19.7.5.1"; Key="HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"; Name="SaveZoneInformation"; Type="DWord"; Value=2; Scope="Both" }  # 'Do not preserve zone information in file attachments' is set to 'Disa
  @{ Id="19.7.5.2"; Key="HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"; Name="ScanWithAntiVirus"; Type="DWord"; Value=3; Scope="Both" }  # 'Notify antivirus programs when opening attachments' is set to 'Enable
  @{ Id="19.7.8.1"; Key="HKCU\Software\Policies\Microsoft\Windows\CloudContent"; Name="ConfigureWindowsSpotlight"; Type="DWord"; Value=2; Scope="Both" }  # 'Configure Windows spotlight on lock screen' is set to 'Disabled'
  @{ Id="19.7.8.2"; Key="HKCU\Software\Policies\Microsoft\Windows\CloudContent"; Name="DisableThirdPartySuggestions"; Type="DWord"; Value=1; Scope="Both" }  # 'Do not suggest third-party content in Windows spotlight' is set to 'E
  @{ Id="19.7.26.1"; Key="HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoInplaceSharing"; Type="DWord"; Value=1; Scope="Both" }  # 'Prevent users from sharing files within their profile.' is set to 'En
)

function Set-CISRegistrySettings {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string] $GpoName,
        [Parameter(Mandatory)][ValidateSet('Member','DC')][string] $Scope
    )
    Import-Module GroupPolicy -ErrorAction Stop
    $scopeFilter = if ($Scope -eq 'DC') { @('Both','DC') } else { @('Both','MS') }
    $applicable  = $CISRegistrySettings | Where-Object { $_.Scope -in $scopeFilter }
    Write-Host "Registry-backed settings for GPO '$GpoName' ($Scope): $($applicable.Count)" -ForegroundColor Cyan
    $ok = 0; $fail = 0; $skip = 0
    foreach ($s in $applicable) {
        if (-not $PSCmdlet.ShouldProcess("$($s.Key)\$($s.Name)", "Set = $($s.Value)  [$($s.Id)]")) { $skip++; continue }
        try {
            Set-GPRegistryValue -Name $GpoName -Key $s.Key -ValueName $s.Name `
                -Type $s.Type -Value $s.Value -ErrorAction Stop | Out-Null
            $ok++
        }
        catch {
            Write-Warning "[$($s.Id)] $($s.Key)\$($s.Name) : $($_.Exception.Message)"
            $fail++
        }
    }
    if ($skip) { Write-Host "[WhatIf] Would apply $skip registry settings to '$GpoName' ($Scope)." -ForegroundColor Yellow }
    else       { Write-Host "Registry settings applied: $ok succeeded, $fail failed." -ForegroundColor Green }
}

# Allow running standalone: .\RegistrySettings.ps1 ; Set-CISRegistrySettings -GpoName X -Scope Member
