# Administrative Template Settings - CIS Windows Server 2025 Benchmark v2.0.0 (Level 1)

> **Scope: Member Server / Domain Controller only.** These mappings come from the CIS Windows
> Server 2025 Benchmark **v2.0.0** and are applied by `RegistrySettings.ps1`.
>
> **Standalone (workgroup) hosts use a different document** — the CIS Stand-alone Benchmark
> **v1.0.0** — with its own numbering and a different set of settings. Its Administrative-Template
> mappings live in `RegistrySettings-Standalone.ps1` (156 settings) and
> `StandaloneImplementationMatrix.csv`. **Do not cross-reference IDs between the two:** standalone
> `2.2.16`/`2.2.20` are the settings this document calls `2.2.21`/`2.2.26`, and several settings
> here (18.4.1 `LocalAccountTokenFilterPolicy`, Windows LAPS 18.9.26.x) are **not in the
> Stand-alone benchmark at all**. See [`ExceptionsAndManualSteps.md` §4](ExceptionsAndManualSteps.md).

Every setting below lives under **Computer Configuration \ Policies \ Administrative Templates**
(or **User Configuration** for section 19) and is realised as a registry policy value.
Each block lists the GPO path, the CIS desired value, the backing registry value, and an
equivalent `Set-GPRegistryValue` example. Apply in bulk with `RegistrySettings.ps1`.

Total Administrative-Template / registry-backed Level 1 settings auto-mapped: **173**.

> Settings requiring manual / list configuration (Hardened UNC Paths 18.6.14.1, Defender ASR
> rules 18.10.42.6.1.2) are documented in `ExceptionsAndManualSteps.md`.

---

## Control Panel

### 18.1.1.1 - 'Prevent enabling lock screen camera' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Control Panel\Personalization\Prevent enabling lock screen camera`
- **Setting:** Prevent enabling lock screen camera
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
  -ValueName "NoLockScreenCamera" `
  -Type DWord `
  -Value 1
```

### 18.1.1.2 - 'Prevent enabling lock screen slide show' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Control Panel\Personalization\Prevent enabling lock screen slide show`
- **Setting:** Prevent enabling lock screen slide show
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
  -ValueName "NoLockScreenSlideshow" `
  -Type DWord `
  -Value 1
```

### 18.1.2.2 - 'Allow users to enable online speech recognition services' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Control Panel\Regional and Language Options\Allow users to enable online speech recognition services`
- **Setting:** Allow users to enable online speech recognition services
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" `
  -ValueName "AllowInputPersonalization" `
  -Type DWord `
  -Value 0
```

## MS Security Guide

### 18.4.1 - 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' (MS only)

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\MS Security Guide\Apply UAC restrictions to local accounts on network logons`
- **Setting:** Apply UAC restrictions to local accounts on network logons
- **Value:** Enabled
- **Applies to:** Member Servers only
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -ValueName "LocalAccountTokenFilterPolicy" `
  -Type DWord `
  -Value 0
```

### 18.4.2 - 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\MS Security Guide\Configure SMB v1 client driver`
- **Setting:** Configure SMB v1 client driver
- **Value:** Enabled: Disable driver (recommended)
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start` = `4` (REG_DWORD)
- **⚠ Potentially disruptive:** SMBv1 client driver disabled - breaks SMBv1-only NAS/appliances/legacy apps.

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" `
  -ValueName "Start" `
  -Type DWord `
  -Value 4
```

### 18.4.3 - 'Configure SMB v1 server' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\MS Security Guide\Configure SMB v1 server`
- **Setting:** Configure SMB v1 server
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1` = `0` (REG_DWORD)
- **⚠ Potentially disruptive:** SMBv1 server disabled - breaks SMBv1-only clients (old scanners, NAS, XP).

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
  -ValueName "SMB1" `
  -Type DWord `
  -Value 0
```

### 18.4.4 - 'Enable Certificate Padding' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\MS Security Guide\Enable Certificate Padding`
- **Setting:** Enable Certificate Padding
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" `
  -ValueName "EnableCertPaddingCheck" `
  -Type DWord `
  -Value 1
```

### 18.4.5 - 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\MS Security Guide\Enable Structured Exception Handling Overwrite Protection (SEHOP)`
- **Setting:** Enable Structured Exception Handling Overwrite Protection (SEHOP)
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
  -ValueName "DisableExceptionChainValidation" `
  -Type DWord `
  -Value 0
```

### 18.4.6 - 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\MS Security Guide\NetBT NodeType configuration`
- **Setting:** NetBT NodeType configuration
- **Value:** Enabled: P-node (recommended)
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NodeType` = `2` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" `
  -ValueName "NodeType" `
  -Type DWord `
  -Value 2
```

## MSS (Legacy)

### 18.5.1 - 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (AutoAdminLogon) Enable Automatic Logon`
- **Setting:** MSS: (AutoAdminLogon) Enable Automatic Logon
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon` = `0` (REG_SZ)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
  -ValueName "AutoAdminLogon" `
  -Type String `
  -Value "0"
```

### 18.5.2 - 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (DisableIPSourceRouting IPv6) IP source routing protection level`
- **Setting:** MSS: (DisableIPSourceRouting IPv6) IP source routing protection level
- **Value:** Enabled: Highest protection, source routing is completely disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting` = `2` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
  -ValueName "DisableIPSourceRouting" `
  -Type DWord `
  -Value 2
```

### 18.5.3 - 'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (DisableIPSourceRouting) IP source routing protection level`
- **Setting:** MSS: (DisableIPSourceRouting) IP source routing protection level
- **Value:** Enabled: Highest protection, source routing is completely disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting` = `2` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
  -ValueName "DisableIPSourceRouting" `
  -Type DWord `
  -Value 2
```

### 18.5.4 - 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes`
- **Setting:** MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
  -ValueName "EnableICMPRedirect" `
  -Type DWord `
  -Value 0
```

### 18.5.6 - 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers`
- **Setting:** MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NoNameReleaseOnDemand` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" `
  -ValueName "NoNameReleaseOnDemand" `
  -Type DWord `
  -Value 1
```

### 18.5.8 - 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (SafeDllSearchMode) Enable Safe DLL search mode`
- **Setting:** MSS: (SafeDllSearchMode) Enable Safe DLL search mode
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" `
  -ValueName "SafeDllSearchMode" `
  -Type DWord `
  -Value 1
```

### 18.5.11 - 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning`
- **Setting:** MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning
- **Value:** Enabled: 90% or less
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel` = `90` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security" `
  -ValueName "WarningLevel" `
  -Type DWord `
  -Value 90
```

## Network

### 18.6.4.1 - 'Configure multicast DNS (mDNS) protocol' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\DNS Client\Configure multicast DNS (mDNS) protocol`
- **Setting:** Configure multicast DNS (mDNS) protocol
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMDNS` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
  -ValueName "EnableMDNS" `
  -Type DWord `
  -Value 0
```

### 18.6.4.2 - 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\DNS Client\Configure NetBIOS settings`
- **Setting:** Configure NetBIOS settings
- **Value:** Enabled: Disable NetBIOS name resolution on public networks
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableNetbios` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
  -ValueName "EnableNetbios" `
  -Type DWord `
  -Value 0
```

### 18.6.4.4 - 'Turn off multicast name resolution' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\DNS Client\Turn off multicast name resolution`
- **Setting:** Turn off multicast name resolution
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
  -ValueName "EnableMulticast" `
  -Type DWord `
  -Value 0
```

### 18.6.7.1 - 'Audit client does not support encryption' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Lanman Server\Audit client does not support encryption`
- **Setting:** Audit client does not support encryption
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer\AuditClientDoesNotSupportEncryption` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" `
  -ValueName "AuditClientDoesNotSupportEncryption" `
  -Type DWord `
  -Value 1
```

### 18.6.7.2 - 'Audit client does not support signing' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Lanman Server\Audit client does not support signing`
- **Setting:** Audit client does not support signing
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer\AuditClientDoesNotSupportSigning` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" `
  -ValueName "AuditClientDoesNotSupportSigning" `
  -Type DWord `
  -Value 1
```

### 18.6.7.3 - 'Audit insecure guest logon' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Lanman Server\Audit insecure guest logon`
- **Setting:** Audit insecure guest logon
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer\AuditInsecureGuestLogon` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" `
  -ValueName "AuditInsecureGuestLogon" `
  -Type DWord `
  -Value 1
```

### 18.6.7.4 - 'Enable authentication rate limiter' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Lanman Server\Enable authentication rate limiter`
- **Setting:** Enable authentication rate limiter
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer\EnableAuthRateLimiter` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" `
  -ValueName "EnableAuthRateLimiter" `
  -Type DWord `
  -Value 1
```

### 18.6.7.5 - 'Enable remote mailslots' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Lanman Server\Enable remote mailslots`
- **Setting:** Enable remote mailslots
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Bowser\EnableMailslots` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Bowser" `
  -ValueName "EnableMailslots" `
  -Type DWord `
  -Value 0
```

### 18.6.7.6 - 'Mandate the minimum version of SMB' is set to 'Enabled: 3.1.1'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Lanman Server\Mandate the minimum version of SMB`
- **Setting:** Mandate the minimum version of SMB
- **Value:** Enabled: 3.1.1
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer\MinSmb2Dialect` = `785` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" `
  -ValueName "MinSmb2Dialect" `
  -Type DWord `
  -Value 785
```

### 18.6.7.7 - 'Set authentication rate limiter delay (milliseconds)' is set to 'Enabled: 2000' or more

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Lanman Server\Set authentication rate limiter delay (milliseconds)`
- **Setting:** Set authentication rate limiter delay (milliseconds)
- **Value:** Enabled: 2000
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer\InvalidAuthenticationDelayTimeInMs` = `2000` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" `
  -ValueName "InvalidAuthenticationDelayTimeInMs" `
  -Type DWord `
  -Value 2000
```

### 18.6.8.1 - 'Audit insecure guest logon' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation\Audit insecure guest logon`
- **Setting:** Audit insecure guest logon
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AuditInsecureGuestLogon` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
  -ValueName "AuditInsecureGuestLogon" `
  -Type DWord `
  -Value 1
```

### 18.6.8.2 - 'Audit server does not support encryption' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation\Audit server does not support encryption`
- **Setting:** Audit server does not support encryption
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AuditServerDoesNotSupportEncryption` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
  -ValueName "AuditServerDoesNotSupportEncryption" `
  -Type DWord `
  -Value 1
```

### 18.6.8.3 - 'Audit server does not support signing' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation\Audit server does not support signing`
- **Setting:** Audit server does not support signing
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AuditServerDoesNotSupportSigning` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
  -ValueName "AuditServerDoesNotSupportSigning" `
  -Type DWord `
  -Value 1
```

### 18.6.8.4 - 'Enable insecure guest logons' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation\Enable insecure guest logons`
- **Setting:** Enable insecure guest logons
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
  -ValueName "AllowInsecureGuestAuth" `
  -Type DWord `
  -Value 0
```

### 18.6.8.5 - 'Enable remote mailslots' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation\Enable remote mailslots`
- **Setting:** Enable remote mailslots
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\EnableMailslots` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider" `
  -ValueName "EnableMailslots" `
  -Type DWord `
  -Value 0
```

### 18.6.8.6 - 'Mandate the minimum version of SMB' is set to 'Enabled: 3.1.1'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation\Mandate the minimum version of SMB`
- **Setting:** Mandate the minimum version of SMB
- **Value:** Enabled: 3.1.1
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\MinSmb2Dialect` = `785` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
  -ValueName "MinSmb2Dialect" `
  -Type DWord `
  -Value 785
```

### 18.6.8.7 - 'Require Encryption' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation\Require Encryption`
- **Setting:** Require Encryption
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\RequireEncryption` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
  -ValueName "RequireEncryption" `
  -Type DWord `
  -Value 1
```

### 18.6.11.2 - 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Network Connections\Prohibit installation and configuration of Network Bridge on your DNS domain network`
- **Setting:** Prohibit installation and configuration of Network Bridge on your DNS domain network
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" `
  -ValueName "NC_AllowNetBridge_NLA" `
  -Type DWord `
  -Value 0
```

### 18.6.11.3 - 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Network Connections\Prohibit use of Internet Connection Sharing on your DNS domain network`
- **Setting:** Prohibit use of Internet Connection Sharing on your DNS domain network
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" `
  -ValueName "NC_ShowSharedAccessUI" `
  -Type DWord `
  -Value 0
```

### 18.6.11.4 - 'Require domain users to elevate when setting a network's location' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Network Connections\Require domain users to elevate when setting a network's location`
- **Setting:** Require domain users to elevate when setting a network's location
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" `
  -ValueName "NC_StdDomainUserSetLocation" `
  -Type DWord `
  -Value 1
```

### 18.6.21.1 - 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Network\Windows Connection Manager\Minimize the number of simultaneous connections to the Internet or a Windows Domain`
- **Setting:** Minimize the number of simultaneous connections to the Internet or a Windows Domain
- **Value:** Enabled: 3 = Prevent Wi-Fi when on Ethernet
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections` = `3` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" `
  -ValueName "fMinimizeConnections" `
  -Type DWord `
  -Value 3
```

## Printers:Allow Print Spooler to accept client connections

### 18.7.1 - 'Allow Print Spooler to accept client connections' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Printers:Allow Print Spooler to accept client connections`
- **Setting:** Printers:Allow Print Spooler to accept client connections
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\Software\Policies\Microsoft\Windows NT\Printers\RegisterSpoolerRemoteRpcEndPoint` = `2` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\Software\Policies\Microsoft\Windows NT\Printers" `
  -ValueName "RegisterSpoolerRemoteRpcEndPoint" `
  -Type DWord `
  -Value 2
```

## Printers

### 18.7.2 - 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Printers\Configure Redirection Guard`
- **Setting:** Configure Redirection Guard
- **Value:** Enabled: Redirection Guard Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RedirectionguardPolicy` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
  -ValueName "RedirectionguardPolicy" `
  -Type DWord `
  -Value 1
```

### 18.7.3 - 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Printers\Configure RPC connection settings: Protocol to use for outgoing RPC connections`
- **Setting:** Configure RPC connection settings: Protocol to use for outgoing RPC connections
- **Value:** Enabled: RPC over TCP
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC\RpcUseNamedPipeProtocol` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" `
  -ValueName "RpcUseNamedPipeProtocol" `
  -Type DWord `
  -Value 0
```

### 18.7.4 - 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Printers\Configure RPC connection settings: Use authentication for outgoing RPC connections`
- **Setting:** Configure RPC connection settings: Use authentication for outgoing RPC connections
- **Value:** Enabled: Default
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC\RpcAuthentication` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" `
  -ValueName "RpcAuthentication" `
  -Type DWord `
  -Value 0
```

### 18.7.5 - 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Printers\Configure RPC listener settings: Configure protocol options for incoming RPC connections`
- **Setting:** Configure RPC listener settings: Configure protocol options for incoming RPC connections
- **Value:** Enabled: RPC over TCP
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC\RpcProtocols` = `5` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" `
  -ValueName "RpcProtocols" `
  -Type DWord `
  -Value 5
```

### 18.7.6 - 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Printers\Configure RPC listener settings: Configure protocol options for incoming RPC connections`
- **Setting:** Configure RPC listener settings: Configure protocol options for incoming RPC connections
- **Value:** Enabled: Negotiate
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC\ForceKerberosForRpc` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" `
  -ValueName "ForceKerberosForRpc" `
  -Type DWord `
  -Value 0
```

### 18.7.7 - 'Configure RPC over TCP port' is set to 'Enabled: 0'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Printers\Configure RPC over TCP port`
- **Setting:** Configure RPC over TCP port
- **Value:** Enabled: 0
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC\RpcTcpPort` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" `
  -ValueName "RpcTcpPort" `
  -Type DWord `
  -Value 0
```

## MS Security Guide

### 18.7.8 - 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\MS Security Guide\Configure RPC packet level privacy setting for incoming connections`
- **Setting:** Configure RPC packet level privacy setting for incoming connections
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Print\RpcAuthnLevelPrivacyEnabled` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SYSTEM\CurrentControlSet\Control\Print" `
  -ValueName "RpcAuthnLevelPrivacyEnabled" `
  -Type DWord `
  -Value 1
```

## Printers

### 18.7.10 - 'Limits print driver installation to Administrators' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Printers\Limits print driver installation to Administrators`
- **Setting:** Limits print driver installation to Administrators
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
  -ValueName "RestrictDriverInstallationToAdministrators" `
  -Type DWord `
  -Value 1
```

### 18.7.11 - 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Printers\Manage processing of Queue-specific files`
- **Setting:** Manage processing of Queue-specific files
- **Value:** Enabled: Limit Queue-specific files to Color profiles
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\CopyFilesPolicy` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
  -ValueName "CopyFilesPolicy" `
  -Type DWord `
  -Value 1
```

### 18.7.12 - 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Printers\Point and Print Restrictions: When installing drivers for a new connection`
- **Setting:** Point and Print Restrictions: When installing drivers for a new connection
- **Value:** Enabled: Show warning and elevation prompt
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnInstall` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
  -ValueName "NoWarningNoElevationOnInstall" `
  -Type DWord `
  -Value 0
```

### 18.7.13 - 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Printers\Point and Print Restrictions: When updating drivers for an existing connection`
- **Setting:** Point and Print Restrictions: When updating drivers for an existing connection
- **Value:** Enabled: Show warning and elevation prompt
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\UpdatePromptSettings` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
  -ValueName "UpdatePromptSettings" `
  -Type DWord `
  -Value 0
```

## System

### 18.9.3.1 - 'Include command line in process creation events' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Audit Process Creation\Include command line in process creation events`
- **Setting:** Include command line in process creation events
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -ValueName "ProcessCreationIncludeCmdLine_Enabled" `
  -Type DWord `
  -Value 1
```

### 18.9.4.1 - 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation\Encryption Oracle Remediation`
- **Setting:** Encryption Oracle Remediation
- **Value:** Enabled: Force Updated Clients
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\AllowEncryptionOracle` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" `
  -ValueName "AllowEncryptionOracle" `
  -Type DWord `
  -Value 0
```

### 18.9.4.2 - 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation\Remote host allows delegation of non-exportable credentials`
- **Setting:** Remote host allows delegation of non-exportable credentials
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" `
  -ValueName "AllowProtectedCreds" `
  -Type DWord `
  -Value 1
```

### 18.9.7.2 - 'Prevent automatic download of applications associated with device metadata' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Device Installation\Prevent automatic download of applications associated with device metadata`
- **Setting:** Prevent automatic download of applications associated with device metadata
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata\PreventDeviceMetadataFromNetwork` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" `
  -ValueName "PreventDeviceMetadataFromNetwork" `
  -Type DWord `
  -Value 1
```

### 18.9.13.1 - 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Early Launch Antimalware\Boot-Start Driver Initialization Policy`
- **Setting:** Boot-Start Driver Initialization Policy
- **Value:** Enabled: Good, unknown and bad but critical
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy` = `3` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" `
  -ValueName "DriverLoadPolicy" `
  -Type DWord `
  -Value 3
```

### 18.9.17.1 - 'Enable / disable CLFS logfile authentication' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Filesystem\Enable / disable CLFS logfile authentication`
- **Setting:** Enable / disable CLFS logfile authentication
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Policies\ClfsAuthenticationChecking` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SYSTEM\CurrentControlSet\Policies" `
  -ValueName "ClfsAuthenticationChecking" `
  -Type DWord `
  -Value 1
```

### 18.9.19.2 - 'Configure security policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Group Policy\Configure security policy processing`
- **Setting:** Configure security policy processing
- **Value:** Enabled: FALSE
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}\NoBackgroundPolicy` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" `
  -ValueName "NoBackgroundPolicy" `
  -Type DWord `
  -Value 0
```

### 18.9.19.3 - 'Configure security policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Group Policy\Configure security policy processing`
- **Setting:** Configure security policy processing
- **Value:** Enabled: TRUE
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}\NoGPOListChanges` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" `
  -ValueName "NoGPOListChanges" `
  -Type DWord `
  -Value 0
```

### 18.9.19.4 - 'Continue experiences on this device' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Group Policy\Continue experiences on this device`
- **Setting:** Continue experiences on this device
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableCdp` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" `
  -ValueName "EnableCdp" `
  -Type DWord `
  -Value 0
```

### 18.9.20.1.1 - 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off downloading of print drivers over HTTP`
- **Setting:** Turn off downloading of print drivers over HTTP
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
  -ValueName "DisableWebPnPDownload" `
  -Type DWord `
  -Value 1
```

### 18.9.20.1.5 - 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Internet download for Web publishing and online ordering wizards`
- **Setting:** Turn off Internet download for Web publishing and online ordering wizards
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
  -ValueName "NoWebServices" `
  -Type DWord `
  -Value 1
```

### 18.9.24.1 - 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Kernel DMA Protection\Enumeration policy for external devices incompatible with Kernel DMA Protection`
- **Setting:** Enumeration policy for external devices incompatible with Kernel DMA Protection
- **Value:** Enabled: Block All
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" `
  -ValueName "DeviceEnumerationPolicy" `
  -Type DWord `
  -Value 0
```

### 18.9.26.1 - 'Configure password backup directory' is set to 'Enabled: Active Directory' or 'Enabled: Azure Active Directory'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\LAPS\Configure password backup directory`
- **Setting:** Configure password backup directory
- **Value:** Enabled: Active Directory' or 'Enabled: Azure Active Directory
- **Applies to:** Member Servers only
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS\BackupDirectory` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
  -ValueName "BackupDirectory" `
  -Type DWord `
  -Value 1
```

### 18.9.26.2 - 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\LAPS\Do not allow password expiration time longer than required by policy`
- **Setting:** Do not allow password expiration time longer than required by policy
- **Value:** Enabled
- **Applies to:** Member Servers only
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordExpirationProtectionEnabled` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
  -ValueName "PasswordExpirationProtectionEnabled" `
  -Type DWord `
  -Value 1
```

### 18.9.26.3 - 'Enable password encryption' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\LAPS\Enable password encryption`
- **Setting:** Enable password encryption
- **Value:** Enabled
- **Applies to:** Member Servers only
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS\ADPasswordEncryptionEnabled` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
  -ValueName "ADPasswordEncryptionEnabled" `
  -Type DWord `
  -Value 1
```

### 18.9.26.4 - 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' or 'Passphrase'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\LAPS\Password Settings`
- **Setting:** Password Settings
- **Value:** Enabled: Large letters + small letters + numbers + special characters' or 'Passphrase
- **Applies to:** Member Servers only
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordComplexity` = `4` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
  -ValueName "PasswordComplexity" `
  -Type DWord `
  -Value 4
```

### 18.9.26.5 - 'Password Settings: Password Length' is set to 'Enabled: 15 or more'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\LAPS\Password Settings`
- **Setting:** Password Settings
- **Value:** Enabled: 15 or more
- **Applies to:** Member Servers only
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordLength` = `15` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
  -ValueName "PasswordLength" `
  -Type DWord `
  -Value 15
```

### 18.9.26.6 - 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\LAPS\Password Settings`
- **Setting:** Password Settings
- **Value:** Enabled: 30 or fewer
- **Applies to:** Member Servers only
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordAgeDays` = `30` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
  -ValueName "PasswordAgeDays" `
  -Type DWord `
  -Value 30
```

### 18.9.26.7 - 'Post-authentication actions: Grace period (hours)' is set to 'Enabled: 8 or fewer hours, but not 0'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\LAPS\Post- authentication actions: Grace period (hours)`
- **Setting:** Post- authentication actions: Grace period (hours)
- **Value:** Enabled: 8 or fewer hours, but not 0
- **Applies to:** Member Servers only
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS\PostAuthenticationResetDelay` = `8` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
  -ValueName "PostAuthenticationResetDelay" `
  -Type DWord `
  -Value 8
```

### 18.9.26.8 - 'Post-authentication actions: Actions' is set to 'Enabled: Reset the password and logoff the managed account' or higher

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\LAPS\Post- authentication actions: Actions`
- **Setting:** Post- authentication actions: Actions
- **Value:** Enabled: Reset the password and logoff the managed account
- **Applies to:** Member Servers only
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS\PostAuthenticationActions` = `3` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
  -ValueName "PostAuthenticationActions" `
  -Type DWord `
  -Value 3
```

### 18.9.27.1 - 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled' (DC only)

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Local Security Authority\Allow Custom SSPs and APs to be loaded into LSASS`
- **Setting:** Allow Custom SSPs and APs to be loaded into LSASS
- **Value:** Disabled
- **Applies to:** Domain Controllers only
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowCustomSSPsAPs` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" `
  -ValueName "AllowCustomSSPsAPs" `
  -Type DWord `
  -Value 0
```

### 18.9.29.1 - 'Block user from showing account details on sign-in' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Logon\Block user from showing account details on sign-in`
- **Setting:** Block user from showing account details on sign-in
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" `
  -ValueName "BlockUserFromShowingAccountDetailsOnSignin" `
  -Type DWord `
  -Value 1
```

### 18.9.29.2 - 'Do not display network selection UI' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Logon\Do not display network selection UI`
- **Setting:** Do not display network selection UI
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" `
  -ValueName "DontDisplayNetworkSelectionUI" `
  -Type DWord `
  -Value 1
```

### 18.9.29.3 - 'Do not enumerate connected users on domain- joined computers' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Logon\Do not enumerate connected users on domain-joined computers`
- **Setting:** Do not enumerate connected users on domain-joined computers
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontEnumerateConnectedUsers` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" `
  -ValueName "DontEnumerateConnectedUsers" `
  -Type DWord `
  -Value 1
```

### 18.9.29.4 - 'Enumerate local users on domain-joined computers' is set to 'Disabled' (MS only)

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Logon\Enumerate local users on domain-joined computers`
- **Setting:** Enumerate local users on domain-joined computers
- **Value:** Disabled
- **Applies to:** Member Servers only
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnumerateLocalUsers` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" `
  -ValueName "EnumerateLocalUsers" `
  -Type DWord `
  -Value 0
```

### 18.9.29.5 - 'Turn off app notifications on the lock screen' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Logon\Turn off app notifications on the lock screen`
- **Setting:** Turn off app notifications on the lock screen
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableLockScreenAppNotifications` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" `
  -ValueName "DisableLockScreenAppNotifications" `
  -Type DWord `
  -Value 1
```

### 18.9.29.6 - 'Turn on convenience PIN sign-in' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Logon\Turn on convenience PIN sign-in`
- **Setting:** Turn on convenience PIN sign-in
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogon` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" `
  -ValueName "AllowDomainPINLogon" `
  -Type DWord `
  -Value 0
```

### 18.9.31.1.1 - 'Block NetBIOS-based discovery for domain controller location' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Net Logon\DC Locator DNS Records\Block NetBIOS-based discovery for domain controller location`
- **Setting:** Block NetBIOS-based discovery for domain controller location
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Netlogon\Parameters\BlockNetbiosDiscovery` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Netlogon\Parameters" `
  -ValueName "BlockNetbiosDiscovery" `
  -Type DWord `
  -Value 1
```

### 18.9.35.6.3 - 'Require a password when a computer wakes (on battery)' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Power Management\Sleep Settings\Require a password when a computer wakes (on battery)`
- **Setting:** Require a password when a computer wakes (on battery)
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" `
  -ValueName "DCSettingIndex" `
  -Type DWord `
  -Value 1
```

### 18.9.35.6.4 - 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Power Management\Sleep Settings\Require a password when a computer wakes (plugged in)`
- **Setting:** Require a password when a computer wakes (plugged in)
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" `
  -ValueName "ACSettingIndex" `
  -Type DWord `
  -Value 1
```

### 18.9.37.1 - 'Configure Offer Remote Assistance' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Remote Assistance\Configure Offer Remote Assistance`
- **Setting:** Configure Offer Remote Assistance
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -ValueName "fAllowUnsolicited" `
  -Type DWord `
  -Value 0
```

### 18.9.37.2 - 'Configure Solicited Remote Assistance' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Remote Assistance\Configure Solicited Remote Assistance`
- **Setting:** Configure Solicited Remote Assistance
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -ValueName "fAllowToGetHelp" `
  -Type DWord `
  -Value 0
```

### 18.9.38.1 - 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call\Enable RPC Endpoint Mapper Client Authentication`
- **Setting:** Enable RPC Endpoint Mapper Client Authentication
- **Value:** Enabled
- **Applies to:** Member Servers only
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
  -ValueName "EnableAuthEpResolution" `
  -Type DWord `
  -Value 1
```

### 18.9.41.1 - 'Configure validation of ROCA-vulnerable WHfB keys during authentication' is set to 'Enabled: Block' (DC only)

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Security Account Manager\Configure validation of ROCA-vulnerable WHfB keys during authentication`
- **Setting:** Configure validation of ROCA-vulnerable WHfB keys during authentication
- **Value:** Enabled: Block
- **Applies to:** Domain Controllers only
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM\SamNGCKeyROCAValidation` = `2` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM" `
  -ValueName "SamNGCKeyROCAValidation" `
  -Type DWord `
  -Value 2
```

### 18.9.41.2 - 'Configure SAM change password RPC methods policy' is set to 'Enabled: Allow strong encryption change password RPC method only' (DC only)

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Security Account Manager\Configure SAM change password RPC methods policy`
- **Setting:** Configure SAM change password RPC methods policy
- **Value:** Enabled: Allow strong encryption change password RPC method only
- **Applies to:** Domain Controllers only
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM\SamrChangeUserPasswordApiPolicy` = `2` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM" `
  -ValueName "SamrChangeUserPasswordApiPolicy" `
  -Type DWord `
  -Value 2
```

### 18.9.41.3 - 'Configure SAM change password RPC methods policy' is set to 'Enabled: Block all change password RPC methods' (MS only)

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Security Account Manager\Configure SAM change password RPC methods policy`
- **Setting:** Configure SAM change password RPC methods policy
- **Value:** Enabled: Block all change password RPC methods
- **Applies to:** Member Servers only
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM\SamrChangeUserPasswordApiPolicy` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM" `
  -ValueName "SamrChangeUserPasswordApiPolicy" `
  -Type DWord `
  -Value 1
```

### 18.9.53.1.1 - 'Enable Windows NTP Client' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Windows Time Service\Time Providers\Enable Windows NTP Client`
- **Setting:** Enable Windows NTP Client
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient\Enabled` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" `
  -ValueName "Enabled" `
  -Type DWord `
  -Value 1
```

### 18.9.53.1.2 - 'Enable Windows NTP Server' is set to 'Disabled' (MS only)

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\System\Windows Time Service\Time Providers\Enable Windows NTP Server`
- **Setting:** Enable Windows NTP Server
- **Value:** Disabled
- **Applies to:** Member Servers only
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer\Enabled` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" `
  -ValueName "Enabled" `
  -Type DWord `
  -Value 0
```

## Windows Components

### 18.10.4.2 - 'Not allow per-user unsigned packages to install by default (requires explicitly allow per install)' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\App Package Deployment\Not allow per-user unsigned packages to install by default (requires explicitly allow per install)`
- **Setting:** Not allow per-user unsigned packages to install by default (requires explicitly allow per install)
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\DisablePerUserUnsignedPackagesByDefault` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx" `
  -ValueName "DisablePerUserUnsignedPackagesByDefault" `
  -Type DWord `
  -Value 1
```

### 18.10.6.1 - 'Allow Microsoft accounts to be optional' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\App runtime\Allow Microsoft accounts to be optional`
- **Setting:** Allow Microsoft accounts to be optional
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -ValueName "MSAOptional" `
  -Type DWord `
  -Value 1
```

### 18.10.8.1 - 'Disallow Autoplay for non-volume devices' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\Disallow Autoplay for non-volume devices`
- **Setting:** Disallow Autoplay for non-volume devices
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
  -ValueName "NoAutoplayfornonVolume" `
  -Type DWord `
  -Value 1
```

### 18.10.8.2 - 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\Set the default behavior for AutoRun`
- **Setting:** Set the default behavior for AutoRun
- **Value:** Enabled: Do not execute any autorun commands
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
  -ValueName "NoAutorun" `
  -Type DWord `
  -Value 1
```

### 18.10.8.3 - 'Turn off Autoplay' is set to 'Enabled: All drives'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\Turn off Autoplay`
- **Setting:** Turn off Autoplay
- **Value:** Enabled: All drives
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun` = `255` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
  -ValueName "NoDriveTypeAutoRun" `
  -Type DWord `
  -Value 255
```

### 18.10.9.1.1 - 'Configure enhanced anti-spoofing' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Biometrics\Facial Features\Configure enhanced anti-spoofing`
- **Setting:** Configure enhanced anti-spoofing
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" `
  -ValueName "EnhancedAntiSpoofing" `
  -Type DWord `
  -Value 1
```

### 18.10.13.1 - 'Turn off cloud consumer account state content' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Turn off cloud consumer account state content`
- **Setting:** Turn off cloud consumer account state content
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableConsumerAccountStateContent` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
  -ValueName "DisableConsumerAccountStateContent" `
  -Type DWord `
  -Value 1
```

### 18.10.14.1 - 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Connect\Require pin for pairing`
- **Setting:** Require pin for pairing
- **Value:** Enabled: First Time' OR 'Enabled: Always
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect\RequirePinForPairing` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect" `
  -ValueName "RequirePinForPairing" `
  -Type DWord `
  -Value 1
```

### 18.10.15.1 - 'Do not display the password reveal button' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\Do not display the password reveal button`
- **Setting:** Do not display the password reveal button
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI\DisablePasswordReveal` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" `
  -ValueName "DisablePasswordReveal" `
  -Type DWord `
  -Value 1
```

### 18.10.15.2 - 'Enumerate administrator accounts on elevation' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\Enumerate administrator accounts on elevation`
- **Setting:** Enumerate administrator accounts on elevation
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" `
  -ValueName "EnumerateAdministrators" `
  -Type DWord `
  -Value 0
```

### 18.10.16.1 - 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds\Allow Diagnostic Data`
- **Setting:** Allow Diagnostic Data
- **Value:** Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
  -ValueName "AllowTelemetry" `
  -Type DWord `
  -Value 0
```

### 18.10.16.3 - 'Do not show feedback notifications' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds\Do not show feedback notifications`
- **Setting:** Do not show feedback notifications
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
  -ValueName "DoNotShowFeedbackNotifications" `
  -Type DWord `
  -Value 1
```

### 18.10.18.2 - 'Enable App Installer Experimental Features' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Desktop App Installer\Enable App Installer Experimental Features`
- **Setting:** Enable App Installer Experimental Features
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller\EnableExperimentalFeatures` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" `
  -ValueName "EnableExperimentalFeatures" `
  -Type DWord `
  -Value 0
```

### 18.10.18.3 - 'Enable App Installer Hash Override' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Desktop App Installer\Enable App Installer Hash Override`
- **Setting:** Enable App Installer Hash Override
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller\EnableHashOverride` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" `
  -ValueName "EnableHashOverride" `
  -Type DWord `
  -Value 0
```

### 18.10.18.4 - 'Enable App Installer Local Archive Malware Scan Override' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Desktop App Installer\Enable App Installer Local Archive Malware Scan Override`
- **Setting:** Enable App Installer Local Archive Malware Scan Override
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller\EnableLocalArchiveMalwareScanOverride` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" `
  -ValueName "EnableLocalArchiveMalwareScanOverride" `
  -Type DWord `
  -Value 0
```

### 18.10.18.5 - 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Desktop App Installer\Enable App Installer ms-appinstaller protocol`
- **Setting:** Enable App Installer ms-appinstaller protocol
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller\EnableMSAppInstallerProtocol` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" `
  -ValueName "EnableMSAppInstallerProtocol" `
  -Type DWord `
  -Value 0
```

### 18.10.18.6 - 'Enable App Installer Microsoft Store Source Certificate Validation Bypass' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Desktop App Installer\Enable App Installer Microsoft Store Source Certificate Validation Bypass`
- **Setting:** Enable App Installer Microsoft Store Source Certificate Validation Bypass
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller\EnableBypassCertificatePinningForMicrosoftStore` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" `
  -ValueName "EnableBypassCertificatePinningForMicrosoftStore" `
  -Type DWord `
  -Value 0
```

### 18.10.26.1.1 - 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Application\Control Event Log behavior when the log file reaches its maximum size`
- **Setting:** Control Event Log behavior when the log file reaches its maximum size
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\Retention` = `0` (REG_SZ)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" `
  -ValueName "Retention" `
  -Type String `
  -Value "0"
```

### 18.10.26.1.2 - 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Application\Specify the maximum log file size (KB)`
- **Setting:** Specify the maximum log file size (KB)
- **Value:** Enabled: 32,768 or greater
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize` = `32768` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" `
  -ValueName "MaxSize" `
  -Type DWord `
  -Value 32768
```

### 18.10.26.2.1 - 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Security\Control Event Log behavior when the log file reaches its maximum size`
- **Setting:** Control Event Log behavior when the log file reaches its maximum size
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\Retention` = `0` (REG_SZ)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" `
  -ValueName "Retention" `
  -Type String `
  -Value "0"
```

### 18.10.26.2.2 - 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Security\Specify the maximum log file size (KB)`
- **Setting:** Specify the maximum log file size (KB)
- **Value:** Enabled: 196,608 or greater
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize` = `196608` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" `
  -ValueName "MaxSize" `
  -Type DWord `
  -Value 196608
```

### 18.10.26.3.1 - 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Setup\Control Event Log behavior when the log file reaches its maximum size`
- **Setting:** Control Event Log behavior when the log file reaches its maximum size
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\Retention` = `0` (REG_SZ)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" `
  -ValueName "Retention" `
  -Type String `
  -Value "0"
```

### 18.10.26.3.2 - 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Setup\Specify the maximum log file size (KB)`
- **Setting:** Specify the maximum log file size (KB)
- **Value:** Enabled: 32,768 or greater
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\MaxSize` = `32768` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" `
  -ValueName "MaxSize" `
  -Type DWord `
  -Value 32768
```

### 18.10.26.4.1 - 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\System\Control Event Log behavior when the log file reaches its maximum size`
- **Setting:** Control Event Log behavior when the log file reaches its maximum size
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\Retention` = `0` (REG_SZ)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" `
  -ValueName "Retention" `
  -Type String `
  -Value "0"
```

### 18.10.26.4.2 - 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\System\Specify the maximum log file size (KB)`
- **Setting:** Specify the maximum log file size (KB)
- **Value:** Enabled: 32,768 or greater
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize` = `32768` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" `
  -ValueName "MaxSize" `
  -Type DWord `
  -Value 32768
```

### 18.10.29.2 - 'Do not apply the Mark of the Web tag to files copied from insecure sources' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\Do not apply the Mark of the Web tag to files copied from insecure sources`
- **Setting:** Do not apply the Mark of the Web tag to files copied from insecure sources
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\DisableMotWOnInsecurePathCopy` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
  -ValueName "DisableMotWOnInsecurePathCopy" `
  -Type DWord `
  -Value 0
```

### 18.10.29.3 - 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\Turn off Data Execution Prevention for Explorer`
- **Setting:** Turn off Data Execution Prevention for Explorer
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
  -ValueName "NoDataExecutionPrevention" `
  -Type DWord `
  -Value 0
```

### 18.10.29.4 - 'Turn off heap termination on corruption' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\Turn off heap termination on corruption`
- **Setting:** Turn off heap termination on corruption
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
  -ValueName "NoHeapTerminationOnCorruption" `
  -Type DWord `
  -Value 0
```

### 18.10.29.5 - 'Turn off shell protocol protected mode' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\Turn off shell protocol protected mode`
- **Setting:** Turn off shell protocol protected mode
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
  -ValueName "PreXPSP2ShellProtocolBehavior" `
  -Type DWord `
  -Value 0
```

### 18.10.41.1 - 'Block all consumer Microsoft account user authentication' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft accounts\Block all consumer Microsoft account user authentication`
- **Setting:** Block all consumer Microsoft account user authentication
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount\DisableUserAuth` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount" `
  -ValueName "DisableUserAuth" `
  -Type DWord `
  -Value 1
```

### 18.10.42.4.1 - 'Enable EDR in block mode' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Features\Enable EDR in block mode`
- **Setting:** Enable EDR in block mode
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Features\PassiveRemediation` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Features" `
  -ValueName "PassiveRemediation" `
  -Type DWord `
  -Value 1
```

### 18.10.42.5.1 - 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\MAPS\Configure local setting override for reporting to Microsoft MAPS`
- **Setting:** Configure local setting override for reporting to Microsoft MAPS
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" `
  -ValueName "LocalSettingOverrideSpynetReporting" `
  -Type DWord `
  -Value 0
```

### 18.10.42.5.2 - 'Join Microsoft MAPS' is set to 'Enabled: Advanced'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\MAPS\Join Microsoft MAPS`
- **Setting:** Join Microsoft MAPS
- **Value:** Enabled: Advanced
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting` = `2` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" `
  -ValueName "SpynetReporting" `
  -Type DWord `
  -Value 2
```

### 18.10.42.6.1.1 - 'Configure Attack Surface Reduction rules' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Microsoft Defender Exploit Guard\Attack Surface Reduction\Configure Attack Surface Reduction rules`
- **Setting:** Configure Attack Surface Reduction rules
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" `
  -ValueName "ExploitGuard_ASR_Rules" `
  -Type DWord `
  -Value 1
```

### 18.10.42.6.3.1 - 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Microsoft Defender Exploit Guard\Network Protection\Prevent users and apps from accessing dangerous websites`
- **Setting:** Prevent users and apps from accessing dangerous websites
- **Value:** Enabled: Block
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" `
  -ValueName "EnableNetworkProtection" `
  -Type DWord `
  -Value 1
```

### 18.10.42.7.1 - 'Enable file hash computation feature' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\MpEngine\Enable file hash computation feature`
- **Setting:** Enable file hash computation feature
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine\EnableFileHashComputation` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" `
  -ValueName "EnableFileHashComputation" `
  -Type DWord `
  -Value 1
```

### 18.10.42.10.1 - 'Configure real-time protection and Security Intelligence Updates during OOBE' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Real-Time Protection\Configure real- time protection and Security Intelligence Updates during OOBE`
- **Setting:** Configure real- time protection and Security Intelligence Updates during OOBE
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\OobeEnableRtpAndSigUpdate` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
  -ValueName "OobeEnableRtpAndSigUpdate" `
  -Type DWord `
  -Value 1
```

### 18.10.42.10.2 - 'Scan all downloaded files and attachments' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Real-Time Protection\Scan all downloaded files and attachments`
- **Setting:** Scan all downloaded files and attachments
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableIOAVProtection` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
  -ValueName "DisableIOAVProtection" `
  -Type DWord `
  -Value 0
```

### 18.10.42.10.3 - 'Turn off real-time protection' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Real-Time Protection\Turn off real- time protection`
- **Setting:** Turn off real- time protection
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
  -ValueName "DisableRealtimeMonitoring" `
  -Type DWord `
  -Value 0
```

### 18.10.42.10.4 - 'Turn on behavior monitoring' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Real-Time Protection\Turn on behavior monitoring`
- **Setting:** Turn on behavior monitoring
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
  -ValueName "DisableBehaviorMonitoring" `
  -Type DWord `
  -Value 0
```

### 18.10.42.10.5 - 'Turn on script scanning' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Real-Time Protection\Turn on script scanning`
- **Setting:** Turn on script scanning
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableScriptScanning` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
  -ValueName "DisableScriptScanning" `
  -Type DWord `
  -Value 0
```

### 18.10.42.11.1.1.2 - 'Configure Remote Encryption Protection Mode' is set to 'Enabled: Audit' or higher

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Remediation\Behavioral Network Blocks\Brute-Force Protection\Configure Remote Encryption Protection Mode`
- **Setting:** Configure Remote Encryption Protection Mode
- **Value:** Enabled: Audit
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection\BruteForceProtectionConfiguredState` = `2` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection" `
  -ValueName "BruteForceProtectionConfiguredState" `
  -Type DWord `
  -Value 2
```

### 18.10.42.13.1 - 'Scan excluded files and directories during quick scans' is set to 'Enabled: 1'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Scan\Scan excluded files and directories during quick scans`
- **Setting:** Scan excluded files and directories during quick scans
- **Value:** Enabled: 1
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\QuickScanIncludeExclusions` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" `
  -ValueName "QuickScanIncludeExclusions" `
  -Type DWord `
  -Value 1
```

### 18.10.42.13.2 - 'Scan packed executables' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Scan\Scan packed executables`
- **Setting:** Scan packed executables
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisablePackedExeScanning` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" `
  -ValueName "DisablePackedExeScanning" `
  -Type DWord `
  -Value 0
```

### 18.10.42.13.3 - 'Scan removable drives' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Scan\Scan removable drives`
- **Setting:** Scan removable drives
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" `
  -ValueName "DisableRemovableDriveScanning" `
  -Type DWord `
  -Value 0
```

### 18.10.42.13.4 - 'Trigger a quick scan after X days without any scans' is set to 'Enabled: 7'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Scan\Trigger a quick scan after X days without any scans`
- **Setting:** Trigger a quick scan after X days without any scans
- **Value:** Enabled: 7
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DaysUntilAggressiveCatchupQuickScan` = `7` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" `
  -ValueName "DaysUntilAggressiveCatchupQuickScan" `
  -Type DWord `
  -Value 7
```

### 18.10.42.13.5 - 'Turn on e-mail scanning' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Scan\Turn on e-mail scanning`
- **Setting:** Turn on e-mail scanning
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" `
  -ValueName "DisableEmailScanning" `
  -Type DWord `
  -Value 0
```

### 18.10.42.16 - 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Configure detection for potentially unwanted applications`
- **Setting:** Configure detection for potentially unwanted applications
- **Value:** Enabled: Block
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\PUAProtection` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" `
  -ValueName "PUAProtection" `
  -Type DWord `
  -Value 1
```

### 18.10.42.17 - 'Control whether exclusions are visible to local users' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Control whether exclusions are visible to local users`
- **Setting:** Control whether exclusions are visible to local users
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\HideExclusionsFromLocalUsers` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" `
  -ValueName "HideExclusionsFromLocalUsers" `
  -Type DWord `
  -Value 1
```

### 18.10.57.2.2 - 'Do not allow passwords to be saved' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Connection Client\Do not allow passwords to be saved`
- **Setting:** Do not allow passwords to be saved
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -ValueName "DisablePasswordSaving" `
  -Type DWord `
  -Value 1
```

### 18.10.57.3.3.3 - 'Do not allow drive redirection' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Do not allow drive redirection`
- **Setting:** Do not allow drive redirection
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -ValueName "fDisableCdm" `
  -Type DWord `
  -Value 1
```

### 18.10.57.3.9.1 - 'Always prompt for password upon connection' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Always prompt for password upon connection`
- **Setting:** Always prompt for password upon connection
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -ValueName "fPromptForPassword" `
  -Type DWord `
  -Value 1
```

### 18.10.57.3.9.2 - 'Require secure RPC communication' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Require secure RPC communication`
- **Setting:** Require secure RPC communication
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -ValueName "fEncryptRPCTraffic" `
  -Type DWord `
  -Value 1
```

### 18.10.57.3.9.3 - 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Require use of specific security layer for remote (RDP) connections`
- **Setting:** Require use of specific security layer for remote (RDP) connections
- **Value:** Enabled: SSL
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\SecurityLayer` = `2` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -ValueName "SecurityLayer" `
  -Type DWord `
  -Value 2
```

### 18.10.57.3.9.4 - 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Require user authentication for remote connections by using Network Level Authentication`
- **Setting:** Require user authentication for remote connections by using Network Level Authentication
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -ValueName "UserAuthentication" `
  -Type DWord `
  -Value 1
```

### 18.10.57.3.9.5 - 'Set client connection encryption level' is set to 'Enabled: High Level'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Set client connection encryption level`
- **Setting:** Set client connection encryption level
- **Value:** Enabled: High Level
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel` = `3` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -ValueName "MinEncryptionLevel" `
  -Type DWord `
  -Value 3
```

### 18.10.57.3.11.1 - 'Do not delete temp folders upon exit' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Temporary Folders\Do not delete temp folders upon exit`
- **Setting:** Do not delete temp folders upon exit
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -ValueName "DeleteTempDirsOnExit" `
  -Type DWord `
  -Value 1
```

### 18.10.57.3.11.2 - 'Do not use temporary folders per session' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Temporary Folders\Do not use temporary folders per session`
- **Setting:** Do not use temporary folders per session
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -ValueName "PerSessionTempDir" `
  -Type DWord `
  -Value 1
```

### 18.10.58.1 - 'Prevent downloading of enclosures' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\RSS Feeds\Prevent downloading of enclosures`
- **Setting:** Prevent downloading of enclosures
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" `
  -ValueName "DisableEnclosureDownload" `
  -Type DWord `
  -Value 1
```

### 18.10.59.3 - 'Allow indexing of encrypted files' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Search\Allow indexing of encrypted files`
- **Setting:** Allow indexing of encrypted files
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
  -ValueName "AllowIndexingEncryptedStoresOrItems" `
  -Type DWord `
  -Value 0
```

### 18.10.77.2.1 - 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender SmartScreen\Explorer\Configure Windows Defender SmartScreen`
- **Setting:** Configure Windows Defender SmartScreen
- **Value:** Enabled: Warn and prevent bypass
- **Applies to:** Member Servers + Domain Controllers
- **Registry (both values are required):**
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen` = `1` (REG_DWORD)
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\ShellSmartScreenLevel` = `Block` (REG_SZ)

> This recommendation takes **two** values — the benchmark states *"a REG_DWORD value of 1
> (EnableSmartScreen) and REG_SZ value of Block (ShellSmartScreenLevel)"*. `EnableSmartScreen`
> alone turns SmartScreen on but still lets users **bypass** the warning, which is precisely what
> *"Warn and prevent bypass"* is asking for.

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" `
  -ValueName "EnableSmartScreen" `
  -Type DWord `
  -Value 1

Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" `
  -ValueName "ShellSmartScreenLevel" `
  -Type String `
  -Value "Block"
```

### 18.10.81.2 - 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Enabled: Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Ink Workspace\Allow Windows Ink Workspace`
- **Setting:** Allow Windows Ink Workspace
- **Value:** Enabled: On, but disallow access above lock' OR 'Enabled: Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" `
  -ValueName "AllowWindowsInkWorkspace" `
  -Type DWord `
  -Value 0
```

### 18.10.82.1 - 'Allow user control over installs' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\Allow user control over installs`
- **Setting:** Allow user control over installs
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\EnableUserControl` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" `
  -ValueName "EnableUserControl" `
  -Type DWord `
  -Value 0
```

### 18.10.82.2 - 'Always install with elevated privileges' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\Always install with elevated privileges`
- **Setting:** Always install with elevated privileges
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" `
  -ValueName "AlwaysInstallElevated" `
  -Type DWord `
  -Value 0
```

### 18.10.83.1 - 'Configure the transmission of the user's password in the content of MPR notifications sent by winlogon.' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options\Configure the transmission of the user's password in the content of MPR notifications sent by winlogon.`
- **Setting:** Configure the transmission of the user's password in the content of MPR notifications sent by winlogon.
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableMPR` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -ValueName "EnableMPR" `
  -Type DWord `
  -Value 0
```

### 18.10.83.2 - 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options\Sign-in and lock last interactive user automatically after a restart`
- **Setting:** Sign-in and lock last interactive user automatically after a restart
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -ValueName "DisableAutomaticRestartSignOn" `
  -Type DWord `
  -Value 1
```

### 18.10.90.1.1 - 'Allow Basic authentication' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\Allow Basic authentication`
- **Setting:** Allow Basic authentication
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowBasic` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
  -ValueName "AllowBasic" `
  -Type DWord `
  -Value 0
```

### 18.10.90.1.2 - 'Allow unencrypted traffic' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\Allow unencrypted traffic`
- **Setting:** Allow unencrypted traffic
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
  -ValueName "AllowUnencryptedTraffic" `
  -Type DWord `
  -Value 0
```

### 18.10.90.1.3 - 'Disallow Digest authentication' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\Disallow Digest authentication`
- **Setting:** Disallow Digest authentication
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowDigest` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
  -ValueName "AllowDigest" `
  -Type DWord `
  -Value 0
```

### 18.10.90.2.1 - 'Allow Basic authentication' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\Allow Basic authentication`
- **Setting:** Allow Basic authentication
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowBasic` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
  -ValueName "AllowBasic" `
  -Type DWord `
  -Value 0
```

### 18.10.90.2.3 - 'Allow unencrypted traffic' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\Allow unencrypted traffic`
- **Setting:** Allow unencrypted traffic
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
  -ValueName "AllowUnencryptedTraffic" `
  -Type DWord `
  -Value 0
```

### 18.10.90.2.4 - 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\Disallow WinRM from storing RunAs credentials`
- **Setting:** Disallow WinRM from storing RunAs credentials
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
  -ValueName "DisableRunAs" `
  -Type DWord `
  -Value 1
```

### 18.10.93.2.1 - 'Prevent users from modifying settings' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Security\App and browser protection\Prevent users from modifying settings`
- **Setting:** Prevent users from modifying settings
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\DisallowExploitProtectionOverride` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" `
  -ValueName "DisallowExploitProtectionOverride" `
  -Type DWord `
  -Value 1
```

### 18.10.94.1.1 - 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Legacy Policies\No auto-restart with logged on users for scheduled automatic updates installations`
- **Setting:** No auto-restart with logged on users for scheduled automatic updates installations
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
  -ValueName "NoAutoRebootWithLoggedOnUsers" `
  -Type DWord `
  -Value 0
```

### 18.10.94.2.1 - 'Configure Automatic Updates' is set to 'Enabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Manage end user experience\Configure Automatic Updates`
- **Setting:** Configure Automatic Updates
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
  -ValueName "NoAutoUpdate" `
  -Type DWord `
  -Value 0
```

### 18.10.94.2.2 - 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Manage end user experience\Configure Automatic Updates: Scheduled install day`
- **Setting:** Configure Automatic Updates: Scheduled install day
- **Value:** 0 - Every day
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay` = `0` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
  -ValueName "ScheduledInstallDay" `
  -Type DWord `
  -Value 0
```

### 18.10.94.4.1 - 'Manage preview builds' is set to 'Disabled'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Manage updates offered from Windows Update\Manage preview builds`
- **Setting:** Manage preview builds
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuildsPolicyValue` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
  -ValueName "ManagePreviewBuildsPolicyValue" `
  -Type DWord `
  -Value 1
```

### 18.10.94.4.2 - 'Select when Quality Updates are received' is set to 'Enabled: 0 days'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Manage updates offered from Windows Update\Select when Quality Updates are received`
- **Setting:** Select when Quality Updates are received
- **Value:** Enabled: 0 days
- **Applies to:** Member Servers + Domain Controllers
- **Registry (both values are required):**
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdates` = `1` (REG_DWORD)
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdatesPeriodInDays` = `0` (REG_DWORD)

> This recommendation takes **two** values — the benchmark states *"a REG_DWORD value of 1
> (DeferQualityUpdates) and 0 (DeferQualityUpdatesPeriodInDays)"*. `DeferQualityUpdates` alone
> switches deferral **on** without setting the period, which is the opposite of *"Enabled: 0 days"*.

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
  -ValueName "DeferQualityUpdates" `
  -Type DWord `
  -Value 1

Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
  -ValueName "DeferQualityUpdatesPeriodInDays" `
  -Type DWord `
  -Value 0
```

## Center for Internet Security (CIS)

### 18.11.1 - 'Disable HTTP proxy features: Disable WPAD' is set to 'Enabled: Checked'

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Center for Internet Security (CIS)\Additional Benchmark Settings\Disable HTTP proxy features: Disable WPAD`
- **Setting:** Disable HTTP proxy features: Disable WPAD
- **Value:** Enabled: Checked
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\DisableWpad` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" `
  -ValueName "DisableWpad" `
  -Type DWord `
  -Value 1
```

### 18.11.2 - 'Disable HTTP proxy features: Disable proxy authentication' is set to 'Enabled: Disable authentication over loopback interfaces' or higher

- **GPO Path:** `Computer Configuration\Policies\Administrative Templates\Center for Internet Security (CIS)\Additional Benchmark Settings\Disable HTTP proxy features: Disable proxy authentication`
- **Setting:** Disable HTTP proxy features: Disable proxy authentication
- **Value:** Enabled: Disable authentication over loopback interfaces
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\DisableProxyAuthenticationSchemes` = `256` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" `
  -ValueName "DisableProxyAuthenticationSchemes" `
  -Type DWord `
  -Value 256
```

## Start Menu and Taskbar

### 19.5.1.1 - 'Turn off toast notifications on the lock screen' is set to 'Enabled'

- **GPO Path:** `User Configuration\Policies\Administrative Templates\Start Menu and Taskbar\Notifications\Turn off toast notifications on the lock screen`
- **Setting:** Turn off toast notifications on the lock screen
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\NoToastApplicationNotificationOnLockScreen` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" `
  -ValueName "NoToastApplicationNotificationOnLockScreen" `
  -Type DWord `
  -Value 1
```

## Windows Components

### 19.7.5.1 - 'Do not preserve zone information in file attachments' is set to 'Disabled'

- **GPO Path:** `User Configuration\Policies\Administrative Templates\Windows Components\Attachment Manager\Do not preserve zone information in file attachments`
- **Setting:** Do not preserve zone information in file attachments
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\SaveZoneInformation` = `2` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" `
  -ValueName "SaveZoneInformation" `
  -Type DWord `
  -Value 2
```

### 19.7.5.2 - 'Notify antivirus programs when opening attachments' is set to 'Enabled'

- **GPO Path:** `User Configuration\Policies\Administrative Templates\Windows Components\Attachment Manager\Notify antivirus programs when opening attachments`
- **Setting:** Notify antivirus programs when opening attachments
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\ScanWithAntiVirus` = `3` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" `
  -ValueName "ScanWithAntiVirus" `
  -Type DWord `
  -Value 3
```

### 19.7.8.1 - 'Configure Windows spotlight on lock screen' is set to 'Disabled'

- **GPO Path:** `User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Configure Windows spotlight on lock screen`
- **Setting:** Configure Windows spotlight on lock screen
- **Value:** Disabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKCU\Software\Policies\Microsoft\Windows\CloudContent\ConfigureWindowsSpotlight` = `2` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKCU\Software\Policies\Microsoft\Windows\CloudContent" `
  -ValueName "ConfigureWindowsSpotlight" `
  -Type DWord `
  -Value 2
```

### 19.7.8.2 - 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'

- **GPO Path:** `User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Do not suggest third-party content in Windows spotlight`
- **Setting:** Do not suggest third-party content in Windows spotlight
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKCU\Software\Policies\Microsoft\Windows\CloudContent\DisableThirdPartySuggestions` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKCU\Software\Policies\Microsoft\Windows\CloudContent" `
  -ValueName "DisableThirdPartySuggestions" `
  -Type DWord `
  -Value 1
```

### 19.7.26.1 - 'Prevent users from sharing files within their profile.' is set to 'Enabled'

- **GPO Path:** `User Configuration\Policies\Administrative Templates\Windows Components\Network Sharing\Prevent users from sharing files within their profile.`
- **Setting:** Prevent users from sharing files within their profile.
- **Value:** Enabled
- **Applies to:** Member Servers + Domain Controllers
- **Registry:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoInplaceSharing` = `1` (REG_DWORD)

```powershell
Set-GPRegistryValue `
  -Name $Gpo.DisplayName `
  -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
  -ValueName "NoInplaceSharing" `
  -Type DWord `
  -Value 1
```
