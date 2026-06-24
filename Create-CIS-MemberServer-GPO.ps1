<#
.SYNOPSIS
  Build and configure the domain GPO "CIS - Windows Server 2025 - Member Servers - Level 1"
  (CIS Microsoft Windows Server 2025 Benchmark v2.0.0 - Level 1, Member Servers).
.DESCRIPTION
  Idempotent. Run from a domain-joined management host (or DC) with RSAT installed,
  as a user with GPO create/link rights. All files must stay in the same folder.

  SAFE BY DEFAULT: building the GPO affects NO servers. The GPO only goes live when it is
  LINKED, which happens only if you pass -TargetOU (and not -NoLink). Omit -TargetOU to build
  and review the GPO first, then link it deliberately to a pilot OU.

  Delivery per setting type:
    * Administrative Templates / registry  -> Set-GPRegistryValue           (native)
    * Windows Firewall profiles (section 9)-> Set-NetFirewallProfile         (native)
    * Security template (INF) + Advanced Audit -> staged into SYSVOL with the
      Client-Side-Extension (CSE) registration and version bookkeeping that GPMC
      performs internally (the part that must be exact, done here and verified).

  TESTING TIP: to validate the INF on a standalone box before trusting the GPO, use
  Microsoft LGPO.exe (Security Compliance Toolkit) against LOCAL policy:
      LGPO.exe /s "CIS_Server2025_Member_Level1.inf"        # applies the template locally
      auditpol /get /category:*    # confirm audit; secedit /export to confirm the rest
.PARAMETER TargetOU
  Distinguished name of the OU to link, e.g. "OU=Servers,DC=company,DC=com".
  LINKING IS OPT-IN: if you omit -TargetOU the GPO is built and configured but NOT linked
  (it affects no servers until you link it deliberately). Linking is the only step that makes
  the baseline go live, so it is intentionally separate.
.PARAMETER NoLink
  Force build-only: never link, even if -TargetOU is supplied. Belt-and-braces for change windows.
.PARAMETER LogPath
  Transcript log file. Defaults to .\Logs\Create-CIS-<scope>-<timestamp>.log next to the script.
  The full run (every action, warning, and error) is captured there.
.PARAMETER WhatIf
  Preview everything (create/registry/firewall/INF/audit/link) and change nothing.
.EXAMPLE
  .\Create-CIS-MemberServer-GPO.ps1 -WhatIf                                  # preview, no changes
.EXAMPLE
  .\Create-CIS-MemberServer-GPO.ps1                                          # build + configure, do NOT link
.EXAMPLE
  .\Create-CIS-MemberServer-GPO.ps1 -TargetOU "OU=Servers,DC=company,DC=com"                       # build + configure + link (goes live)
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $TargetOU,                  # omit to build without linking (safe default)
    [switch] $NoLink,                    # never link, even if -TargetOU is given
    [string] $LogPath,                   # log file; default: .\Logs\Create-CIS-<scope>-<timestamp>.log
    [string] $ScriptRoot = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'

# ---- Logging: full transcript of this run ---------------------------------
if (-not $LogPath) {
    $LogPath = Join-Path $ScriptRoot ("Logs\Create-CIS-Member-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
}
try {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LogPath) | Out-Null
    Start-Transcript -Path $LogPath -Force | Out-Null
    $script:Transcribing = $true
} catch { $script:Transcribing = $false; Write-Warning "Could not start transcript: $($_.Exception.Message)" }
Write-Host "Log file: $LogPath" -ForegroundColor DarkCyan
Write-Host ("Run by {0} on {1} at {2:u}" -f $env:USERNAME, $env:COMPUTERNAME, (Get-Date)) -ForegroundColor DarkCyan

Import-Module GroupPolicy    -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

$GpoName  = "CIS - Windows Server 2025 - Member Servers - Level 1"
$Scope    = "Member"                       # 'Member' or 'DC'
$InfFile  = Join-Path $ScriptRoot "CIS_Server2025_Member_Level1.inf"
$AuditCsv = Join-Path $ScriptRoot "CIS_AuditPolicy_Member.csv"
$RegMod   = Join-Path $ScriptRoot "RegistrySettings.ps1"

# ---- Preflight -------------------------------------------------------------
foreach ($f in @($InfFile, $AuditCsv, $RegMod)) {
    if (-not (Test-Path -LiteralPath $f)) { throw "Required file not found next to this script: $f" }
}
$Domain  = Get-ADDomain
$DnsRoot = $Domain.DNSRoot

# ---- 1) Create or reuse the GPO -------------------------------------------
#       With -WhatIf the GPO is NOT created; later steps print their plan and skip.
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if ($gpo) {
    Write-Host "[=] Reusing existing GPO '$GpoName'  {$($gpo.Id)}" -ForegroundColor Yellow
} elseif ($PSCmdlet.ShouldProcess($GpoName, 'Create new GPO')) {
    $gpo = New-GPO -Name $GpoName -Comment "CIS Server 2025 v2.0.0 L1 ($Scope). Managed by Create-CIS script."
    Write-Host "[+] Created GPO '$GpoName'  {$($gpo.Id)}" -ForegroundColor Green
} else {
    Write-Host "[WhatIf] Would create GPO '$GpoName'." -ForegroundColor Yellow
}

# ---- 2) Administrative Templates / registry (native; honours -WhatIf) ------
. $RegMod
Set-CISRegistrySettings -GpoName $GpoName -Scope $Scope

# ---- 3) Windows Firewall profiles, section 9 (native) ---------------------
if ($PSCmdlet.ShouldProcess("Firewall profiles for '$GpoName'", 'Configure 9.1-9.3')) {
    try {
        Set-NetFirewallProfile -PolicyStore "$DnsRoot\$GpoName" -Profile Domain,Private,Public `
            -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow `
            -NotifyOnListen False -LogMaxSizeKilobytes 16384 -LogAllowed True -LogBlocked True `
            -LogFileName "%SystemRoot%\System32\logfiles\firewall\pfirewall.log"
        Write-Host "[+] Firewall profiles configured (9.1-9.3)" -ForegroundColor Green
    } catch {
        Write-Warning "Firewall GPO step failed - configure section 9 manually: $($_.Exception.Message)"
    }
}

# ---- CSE merge helper (used by the security-template/audit injection) ------
function Merge-Cse {
    param([string]$Existing, [object[]]$Needed)
    $blocks = @{}
    if ($Existing) {
        foreach ($m in [regex]::Matches($Existing, '\[([^\]]+)\]')) {
            $g = @([regex]::Matches($m.Groups[1].Value, '\{[0-9A-Fa-f-]+\}') | ForEach-Object { $_.Value.ToUpper() })
            if ($g.Count -ge 1) { $blocks[$g[0]] = New-Object System.Collections.Generic.List[string]
                for ($i=1; $i -lt $g.Count; $i++) { [void]$blocks[$g[0]].Add($g[$i]) } }
        }
    }
    foreach ($n in $Needed) {
        $cse = $n.Cse.ToUpper(); $tool = $n.Tool.ToUpper()
        if (-not $blocks.ContainsKey($cse)) { $blocks[$cse] = New-Object System.Collections.Generic.List[string] }
        if ($blocks[$cse] -notcontains $tool) { [void]$blocks[$cse].Add($tool) }
    }
    $sb = ''
    foreach ($cse in ($blocks.Keys | Sort-Object)) {
        $tools = (($blocks[$cse] | Sort-Object -Unique) -join '')
        $sb += "[$cse$tools]"
    }
    return $sb
}
# ---- 4-7) Stage INF + audit, register CSEs, sync version (skipped on -WhatIf)
$needed = @(
    [pscustomobject]@{ Cse='{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'; Tool='{D02B1F72-3407-48AE-BA88-E8213C6761F1}' }  # Registry
    [pscustomobject]@{ Cse='{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'; Tool='{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}' }  # Security
    [pscustomobject]@{ Cse='{F3CCC681-B74C-4060-9F26-CD84525DCA2A}'; Tool='{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}' }  # Audit Policy
)
if (-not $gpo) {
    Write-Host "[WhatIf] Would stage GptTmpl.inf + audit.csv into SYSVOL, register Registry/Security/Audit CSEs, and sync the GPO version." -ForegroundColor Yellow
} elseif ($PSCmdlet.ShouldProcess("GPO '$GpoName'", 'Stage INF + audit.csv, register CSEs, sync version')) {
    $guid    = $gpo.Id.Guid
    $polPath = "\\$DnsRoot\SYSVOL\$DnsRoot\Policies\{$guid}"
    $gpoDn   = "CN={$guid},CN=Policies,CN=System,$($Domain.DistinguishedName)"
    $secDir  = Join-Path $polPath 'Machine\Microsoft\Windows NT\SecEdit'
    $audDir  = Join-Path $polPath 'Machine\Microsoft\Windows NT\Audit'
    New-Item -ItemType Directory -Force -Path $secDir, $audDir | Out-Null
    Copy-Item -LiteralPath $InfFile  -Destination (Join-Path $secDir 'GptTmpl.inf') -Force
    Copy-Item -LiteralPath $AuditCsv -Destination (Join-Path $audDir 'audit.csv')  -Force
    Write-Host "[+] Staged GptTmpl.inf and audit.csv into SYSVOL" -ForegroundColor Green

    $obj    = Get-ADObject -Identity $gpoDn -Properties gPCMachineExtensionNames, versionNumber
    $merged = Merge-Cse -Existing $obj.gPCMachineExtensionNames -Needed $needed
    Set-ADObject -Identity $gpoDn -Replace @{ gPCMachineExtensionNames = $merged }
    Write-Host "[+] CSE registration: $merged" -ForegroundColor Green

    $newVer = [int]$obj.versionNumber + 1
    Set-ADObject -Identity $gpoDn -Replace @{ versionNumber = $newVer }
    $gptIni = Join-Path $polPath 'GPT.INI'
    if (Test-Path -LiteralPath $gptIni) {
        $c = Get-Content -LiteralPath $gptIni
        if ($c -match '^Version=') { $c = $c -replace '^Version=\d+', "Version=$newVer" }
        else                       { $c += "Version=$newVer" }
        Set-Content -LiteralPath $gptIni -Value $c -Encoding Ascii
    } else {
        Set-Content -LiteralPath $gptIni -Value @('[General]', "Version=$newVer") -Encoding Ascii
    }
    Write-Host "[+] Version synced (AD versionNumber = GPT.INI Version = $newVer)" -ForegroundColor Green

    $chk    = Get-ADObject -Identity $gpoDn -Properties gPCMachineExtensionNames, versionNumber
    $infOk  = Test-Path -LiteralPath (Join-Path $secDir 'GptTmpl.inf')
    $audOk  = Test-Path -LiteralPath (Join-Path $audDir 'audit.csv')
    $secReg = $chk.gPCMachineExtensionNames -match '827D319E-6EAC-11D2-A4EA-00C04F79F83A'
    $audReg = $chk.gPCMachineExtensionNames -match 'F3CCC681-B74C-4060-9F26-CD84525DCA2A'
    $verOk  = ([int]$chk.versionNumber -eq $newVer)
    Write-Host "`n--- Verification ---" -ForegroundColor Cyan
    Write-Host ("  GptTmpl.inf staged ....... {0}" -f $infOk)
    Write-Host ("  audit.csv staged ......... {0}" -f $audOk)
    Write-Host ("  Security CSE registered .. {0}" -f [bool]$secReg)
    Write-Host ("  Audit CSE registered ..... {0}" -f [bool]$audReg)
    Write-Host ("  Version in sync .......... {0}" -f $verOk)
    if (-not ($infOk -and $audOk -and $secReg -and $audReg -and $verOk)) {
        Write-Warning "One or more checks failed - inspect the GPO in GPMC before linking. FALLBACK: open the GPO editor -> Security Settings -> right-click -> 'Import Policy...' to import $InfFile manually (always reliable)."
    }
}

# ---- 8) Link to the target OU (OPT-IN: only with -TargetOU, never with -NoLink) ----
if ($NoLink) {
    Write-Host "[i] -NoLink set: GPO built and configured but NOT linked (affects no servers)." -ForegroundColor Yellow
} elseif (-not $TargetOU) {
    Write-Host "[i] No -TargetOU: GPO built but NOT linked (affects no servers)." -ForegroundColor Yellow
    Write-Host "    When ready, link it deliberately - to a PILOT OU first:" -ForegroundColor Yellow
    Write-Host "      New-GPLink -Name '$GpoName' -Target '<OU distinguished name>' -LinkEnabled Yes" -ForegroundColor Yellow
} else {
    $ouOk = Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$TargetOU)" -ErrorAction SilentlyContinue
    if (-not $ouOk) {
        Write-Warning "Target OU '$TargetOU' not found - GPO was NOT linked. Verify the DN."
    } else {
        $already = (Get-GPInheritance -Target $TargetOU).GpoLinks.DisplayName -contains $GpoName
        if ($already) {
            Write-Host "[=] GPO already linked to $TargetOU" -ForegroundColor Yellow
        } elseif ($PSCmdlet.ShouldProcess($TargetOU, "LINK GPO '$GpoName' - goes LIVE for all servers in this OU at next gpupdate")) {
            New-GPLink -Name $GpoName -Target $TargetOU -LinkEnabled Yes | Out-Null
            Write-Host "[+] Linked GPO to $TargetOU - applies at next gpupdate/reboot." -ForegroundColor Green
            Write-Host "    Undo: .\Rollback-CIS-GPO.ps1 -Scope $Scope -Action DisableLink" -ForegroundColor Cyan
        }
    }
}

Write-Host "`n=== '$GpoName' build complete ===" -ForegroundColor Cyan
Write-Host "Next: gpupdate /force + reboot on a PILOT node, then validate against" -ForegroundColor Cyan
Write-Host "PotentiallyDisruptiveSettings.md and run a CIS-CAT assessment before widening scope." -ForegroundColor Cyan
Write-Host "Full log: $LogPath" -ForegroundColor DarkCyan
if ($script:Transcribing) { try { Stop-Transcript | Out-Null } catch {} }
