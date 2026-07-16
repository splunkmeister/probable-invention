<#
.SYNOPSIS
  Apply the CIS Windows Server 2025 Level 1 baseline to the LOCAL machine at build time.
.DESCRIPTION
  For host provisioning (golden image, MDT/SCCM task sequence, Packer, Ansible/DSC step).
  Applies everything locally and synchronously - NO domain GPO, NO SYSVOL, NO AD changes:

    1. Security template (INF)      -> secedit /configure   (System Access, Privilege Rights,
                                                              Registry Values, Services)
    2. Administrative Templates      -> writes the 173 registry values directly (HKLM)
    3. Advanced Audit Policy (sec.17)-> auditpol  (via Set-CIS-AuditPolicy.ps1 -Mode Local)
    4. Windows Firewall (section 9)  -> Set-NetFirewallProfile (local store)

  Deterministic, returns an exit code, and transcribes to a log. Supports -WhatIf.

  Re-enforcement note: a build-time apply sets a known-good baseline but does NOT self-heal
  drift. Pair with a domain GPO (Create-CIS-*-GPO.ps1) for ongoing enforcement if desired;
  where both touch a setting, the GPO wins (applied after local).

  For a STANDALONE (workgroup) server this script is the ONLY delivery mechanism - there is no
  domain GPO to link, so -Scope Standalone plus a scheduled re-run is the whole story.
.PARAMETER Scope
  Member | DC | Standalone - selects the matching INF, setting tables, and audit set.

  Standalone implements a DIFFERENT BENCHMARK, not a variant of Member: CIS Microsoft Windows
  Server 2025 Stand-alone Benchmark v1.0.0, Level 1 (307 recommendations). It has its own
  numbering - standalone 2.2.16/2.2.20 are the settings Member calls 2.2.21/2.2.26 - and its
  own data files (RegistrySettings-Standalone.ps1, CIS-Standalone-Data.ps1). It is applied
  verbatim; there are no local deviations. See CIS-Scope.ps1.
.PARAMETER IncludeCurrentUser
  Also apply the per-user (HKCU, section 19) settings to the CURRENT user's hive.
  Off by default: at build time HKCU is the build account, not end users. For all future
  users, deliver section 19 via GPO or by applying to the Default User hive instead.
.PARAMETER SkipAudit / -SkipFirewall
  Omit those stages (e.g. if handled elsewhere in the build).
.PARAMETER BackupPath
  Folder for the pre-apply state capture (default: %windir%\Temp\CIS-Backup-<scope>-<timestamp>).
  A local apply has no GPO to unlink, so Rollback-CIS-GPO.ps1 cannot undo it - this capture is
  the undo path. Taken BEFORE anything is written; the restore commands are printed at the end
  and land in the transcript.
.PARAMETER SkipBackup
  Skip the pre-apply capture. Only sensible when imaging a throwaway VM you would rebuild
  rather than restore.
.PARAMETER Force
  Skip the domain-membership preflight that refuses a profile mismatched to this host.
.EXAMPLE
  .\Apply-CIS-Local.ps1 -Scope Member -WhatIf      # preview, change nothing
.EXAMPLE
  .\Apply-CIS-Local.ps1 -Scope Member              # apply the Member baseline locally
.EXAMPLE
  .\Apply-CIS-Local.ps1 -Scope Standalone          # workgroup host (Stand-alone v1.0.0 L1)
.NOTES
  Run ELEVATED. Account/lockout policy (section 1) applies to LOCAL accounts on member servers;
  for domain accounts it must live in the Default Domain Policy (not a local apply). On a
  standalone host section 1 governs the SAM directly, so it is fully in force - including
  1.2.3 AllowAdministratorLockout, which CAN lock out the built-in Administrator. Keep a second
  admin account or console access. See PotentiallyDisruptiveSettings.md.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('Member','DC','Standalone')][string] $Scope,
    [string]  $ScriptRoot = $PSScriptRoot,
    [string]  $LogPath = "$env:windir\Temp\CIS-Apply-$Scope.log",
    [switch]  $IncludeCurrentUser,
    [switch]  $SkipAudit,
    [switch]  $SkipFirewall,
    [string]  $BackupPath,
    [switch]  $SkipBackup,
    [switch]  $Force
)

$ErrorActionPreference = 'Stop'

# ---- Preflight -------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run elevated - secedit/auditpol/firewall require administrator." }

$ScopeMod = Join-Path $ScriptRoot 'CIS-Scope.ps1'
if (-not (Test-Path -LiteralPath $ScopeMod)) { throw "Missing required file: $ScopeMod" }
. $ScopeMod

# Applying the wrong profile is silent and expensive: the Member profile on a workgroup host
# denies RDP to every account, and the Standalone profile on a domain member drops hardening
# that domain accounts rely on. Check the host's actual role before secedit writes anything.
$hostRole = try { Get-CISHostRole } catch { 'Unknown' }
if ($hostRole -ne 'Unknown' -and $hostRole -ne $Scope) {
    $msg = "Profile mismatch: -Scope $Scope requested, but this host is '$hostRole' (Win32_ComputerSystem.DomainRole)."
    if ($Force) { Write-Warning "$msg Continuing because -Force was passed." }
    else {
        throw @"
$msg
  Standalone = workgroup / not domain-joined   Member = domain-joined   DC = domain controller
Applying the Member profile to a workgroup host denies RDP to every administrator: it denies
S-1-5-113 'Local account', which on a workgroup host is every account (Member benchmark 2.2.26).
Re-run with -Scope $hostRole, or pass -Force if the role is about to change (e.g. imaging a
golden image that will be domain-joined later).
"@
    }
}

$InfFile = Join-Path $ScriptRoot ("CIS_Server2025_{0}_Level1.inf" -f $Scope)
$AudMod  = Join-Path $ScriptRoot 'Set-CIS-AuditPolicy.ps1'
# Standalone is a separate benchmark with its own numbering, so it has its own data files.
if ($Scope -eq 'Standalone') {
    $RegMod  = Join-Path $ScriptRoot 'RegistrySettings-Standalone.ps1'
    $DataMod = Join-Path $ScriptRoot 'CIS-Standalone-Data.ps1'
} else {
    $RegMod  = Join-Path $ScriptRoot 'RegistrySettings.ps1'
    $DataMod = $null
}
foreach ($f in @($InfFile, $RegMod)) { if (-not (Test-Path -LiteralPath $f)) { throw "Missing required file: $f" } }
if ($DataMod -and -not (Test-Path -LiteralPath $DataMod)) { throw "Missing required file: $DataMod" }

try { Start-Transcript -Path $LogPath -Append | Out-Null } catch {}
$pi = Get-CISProfileInfo -Scope $Scope
Write-Host ("CIS local apply - Scope={0}  (log: {1})" -f $Scope, $LogPath) -ForegroundColor Cyan
Write-Host ("  Benchmark: {0} {1}, {2}" -f $pi.Benchmark, $pi.Version, $pi.Profile) -ForegroundColor Cyan
$summary = [ordered]@{ Backup='skipped'; INF='skipped'; Registry='skipped'; Audit='skipped'; Firewall='skipped'; Review='-' }

# The standalone benchmark leaves a handful of recommendations that cannot be encoded as a single
# value (site-specific banner text, registry path lists, SDDL, ASR rule GUIDs). They are listed
# up front and land in the transcript, so nobody mistakes this run for full coverage.
if ($Scope -eq 'Standalone') {
    . $DataMod
    Write-Host ""
    Write-Host ("  This profile applies the Stand-alone benchmark verbatim - there are no deviations.") -ForegroundColor Cyan
    Write-Host ("  {0} recommendation(s) are NOT auto-applied and need a decision (see" -f $CISStandaloneReview.Count) -ForegroundColor Yellow
    Write-Host  "  ExceptionsAndManualSteps.md section 4):" -ForegroundColor Yellow
    foreach ($r in $CISStandaloneReview) {
        Write-Host ("    [REVIEW] {0,-14} {1}" -f $r.Id, $r.Title) -ForegroundColor DarkYellow
    }
    $summary.Review = "$($CISStandaloneReview.Count) manual"
    Write-Host ""
}

# ---- 0) Pre-apply state capture -------------------------------------------
# A local apply writes straight to the host: there is no GPO to unlink, so Rollback-CIS-GPO.ps1
# cannot undo it. Capture the two areas that have first-class backup/restore verbs BEFORE
# anything is written. This matters most for Standalone, where section 1 governs the SAM
# directly and a bad account-policy value can lock out the only administrator.
if (-not $BackupPath) {
    $BackupPath = Join-Path $env:windir ("Temp\CIS-Backup-{0}-{1:yyyyMMdd-HHmmss}" -f $Scope, (Get-Date))
}
$secBak = Join-Path $BackupPath 'security-policy.inf'
$audBak = Join-Path $BackupPath 'audit-policy.csv'
if ($SkipBackup) {
    Write-Warning "-SkipBackup: no pre-apply state captured. This apply will not be undoable."
    $summary.Backup = 'skipped'
} elseif ($PSCmdlet.ShouldProcess($BackupPath, 'capture current security + audit policy before applying')) {
    try {
        New-Item -ItemType Directory -Force -Path $BackupPath | Out-Null
        & secedit.exe /export /cfg $secBak /quiet
        $secOk = ($LASTEXITCODE -eq 0) -and (Test-Path -LiteralPath $secBak)
        & auditpol.exe /backup /file:$audBak | Out-Null
        $audOk = ($LASTEXITCODE -eq 0) -and (Test-Path -LiteralPath $audBak)
        if ($secOk -and $audOk) {
            Write-Host "[+] Pre-apply state captured -> $BackupPath" -ForegroundColor Green
            $summary.Backup = $BackupPath
        } else {
            # Do not proceed silently: without a capture there is no way back.
            throw "capture incomplete (secedit=$secOk auditpol=$audOk)"
        }
    } catch {
        Write-Warning "Pre-apply capture FAILED: $($_.Exception.Message)"
        Write-Warning "Re-run with -SkipBackup only if you accept that this apply cannot be undone."
        throw
    }
} else {
    Write-Host "[WhatIf] Would capture current security + audit policy to $BackupPath." -ForegroundColor Yellow
    $summary.Backup = 'whatif'
}

# ---- 1) Security template via secedit /configure --------------------------
if ($PSCmdlet.ShouldProcess($InfFile, 'secedit /configure (SECURITYPOLICY USER_RIGHTS SERVICES)')) {
    $db     = Join-Path $env:windir "security\database\CIS-$Scope.sdb"
    $secLog = Join-Path $env:windir "Temp\CIS-secedit-$Scope.log"
    & secedit.exe /configure /db $db /cfg $InfFile /areas SECURITYPOLICY USER_RIGHTS SERVICES /log $secLog /quiet
    $rc = $LASTEXITCODE
    if ($rc -eq 0) { Write-Host "[+] Security template applied (secedit rc=0)" -ForegroundColor Green; $summary.INF = 'applied' }
    else { Write-Warning "secedit returned $rc - see $secLog"; $summary.INF = "rc=$rc" }
} else { Write-Host "[WhatIf] Would apply $InfFile via secedit /configure." -ForegroundColor Yellow; $summary.INF = 'whatif' }

# ---- 2) Administrative Template registry settings (local) -----------------
. $RegMod   # loads $CISRegistrySettings or $CISStandaloneRegistry (no GroupPolicy dependency)
if ($Scope -eq 'Standalone') {
    # The standalone data file contains exactly its own profile, so there is nothing to filter.
    $want = $CISStandaloneRegistry
} else {
    $scopeFilter = Get-CISScopeFilter -Scope $Scope
    $want = $CISRegistrySettings | Where-Object { $_.Scope -in $scopeFilter }
}

$machine = $want | Where-Object { $_.Key -like 'HKLM\*' }
$user    = $want | Where-Object { $_.Key -like 'HKCU\*' }

function Set-LocalRegistry {
    param([object[]]$Items)
    $ok = 0; $fail = 0
    foreach ($s in $Items) {
        $prov = $s.Key -replace '^HKLM\\', 'HKLM:\' -replace '^HKCU\\', 'HKCU:\'
        try {
            if (-not (Test-Path -LiteralPath $prov)) { New-Item -Path $prov -Force | Out-Null }
            # Honour the declared type. Collapsing everything to String/DWord would write the
            # wrong type for MultiString/ExpandString settings, which then never take effect.
            $pt = switch ($s.Type) {
                'String'       { 'String' }
                'ExpandString' { 'ExpandString' }
                'MultiString'  { 'MultiString' }
                default        { 'DWord' }
            }
            New-ItemProperty -Path $prov -Name $s.Name -Value $s.Value -PropertyType $pt -Force -ErrorAction Stop | Out-Null
            $ok++
        } catch { Write-Warning "[$($s.Id)] $($s.Key)\$($s.Name): $($_.Exception.Message)"; $fail++ }
    }
    return [pscustomobject]@{ Ok = $ok; Fail = $fail }
}

if ($PSCmdlet.ShouldProcess("local machine registry", "apply $($machine.Count) HKLM settings")) {
    $r = Set-LocalRegistry -Items $machine
    Write-Host "[+] Registry (HKLM): $($r.Ok) applied, $($r.Fail) failed." -ForegroundColor Green
    $summary.Registry = "$($r.Ok)/$($machine.Count)"
} else { Write-Host "[WhatIf] Would apply $($machine.Count) HKLM registry settings." -ForegroundColor Yellow; $summary.Registry = 'whatif' }

if ($IncludeCurrentUser -and $user.Count) {
    if ($PSCmdlet.ShouldProcess("current user's HKCU hive", "apply $($user.Count) section-19 settings")) {
        $ru = Set-LocalRegistry -Items $user
        Write-Host "[+] Registry (HKCU, current user): $($ru.Ok) applied, $($ru.Fail) failed." -ForegroundColor Green
    }
} elseif ($user.Count) {
    Write-Host "[i] Skipped $($user.Count) per-user (HKCU/section 19) settings. Deliver via GPO or Default User hive, or pass -IncludeCurrentUser." -ForegroundColor Yellow
}

# ---- 3) Advanced Audit Policy (local, via auditpol) -----------------------
if (-not $SkipAudit) {
    if (Test-Path -LiteralPath $AudMod) {
        if ($PSCmdlet.ShouldProcess('local audit policy', 'apply section 17 subcategories')) {
            & $AudMod -Scope $Scope -Mode Local
            $summary.Audit = 'applied'
        } else { Write-Host "[WhatIf] Would apply Advanced Audit Policy locally." -ForegroundColor Yellow; $summary.Audit = 'whatif' }
    } else { Write-Warning "Set-CIS-AuditPolicy.ps1 not found - audit policy NOT applied."; $summary.Audit = 'missing' }
}

# ---- 4) Windows Firewall profiles (local store) ---------------------------
# The Stand-alone benchmark defines section 9 for the PRIVATE and PUBLIC profiles only (14 L1
# settings, 9.2.x / 9.3.x). It has no Domain-profile recommendations because a workgroup host
# never uses that profile, so configuring it here would be applying a setting no benchmark asks
# for. Member/DC keep all three (9.1-9.3).
$fwProfiles = if ($Scope -eq 'Standalone') { @('Private','Public') } else { @('Domain','Private','Public') }
if (-not $SkipFirewall) {
    if ($PSCmdlet.ShouldProcess(('local firewall profiles: ' + ($fwProfiles -join ',')), 'configure section 9')) {
        try {
            Set-NetFirewallProfile -Profile $fwProfiles `
                -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow `
                -NotifyOnListen False -LogMaxSizeKilobytes 16384 -LogAllowed True -LogBlocked True `
                -LogFileName "%SystemRoot%\System32\logfiles\firewall\pfirewall.log"
            Write-Host ("[+] Firewall profiles configured: {0}" -f ($fwProfiles -join ', ')) -ForegroundColor Green
            $summary.Firewall = ($fwProfiles -join ',')
        } catch { Write-Warning "Firewall step failed: $($_.Exception.Message)"; $summary.Firewall = 'failed' }
    } else { Write-Host ("[WhatIf] Would configure firewall profiles: {0}" -f ($fwProfiles -join ', ')) -ForegroundColor Yellow; $summary.Firewall = 'whatif' }
}

# ---- Summary ---------------------------------------------------------------
Write-Host "`n--- Local apply summary ($Scope) ---" -ForegroundColor Cyan
$summary.GetEnumerator() | ForEach-Object { Write-Host ("  {0,-10}: {1}" -f $_.Key, $_.Value) }
Write-Host ("Verify with:  .\Test-CIS-Compliance.ps1 -Scope {0}" -f $Scope) -ForegroundColor Cyan

# The undo path, printed where an operator will actually find it (and captured in the transcript).
if (-not $SkipBackup -and $summary.Backup -notin 'skipped','whatif','failed') {
    Write-Host "`nTo undo this apply (there is no GPO to unlink):" -ForegroundColor Cyan
    Write-Host ("  secedit /configure /db `$env:windir\security\database\CIS-restore.sdb /cfg `"{0}`" /areas SECURITYPOLICY USER_RIGHTS SERVICES" -f $secBak) -ForegroundColor DarkCyan
    Write-Host ("  auditpol /restore /file:`"{0}`"" -f $audBak) -ForegroundColor DarkCyan
    Write-Host "  Administrative-Template values (sections 18-19) are NOT covered by the above -" -ForegroundColor DarkYellow
    Write-Host "  they are policy registry values; revert them via GPO, by re-imaging, or by hand." -ForegroundColor DarkYellow
}

if ($Scope -eq 'Standalone') {
    Write-Host "Reminder: section 1 governs the local SAM directly on a workgroup host, including" -ForegroundColor Yellow
    Write-Host "          1.2.3 AllowAdministratorLockout - the built-in Administrator CAN now be locked" -ForegroundColor Yellow
    Write-Host "          out by 5 bad passwords. Confirm you have a second admin account or console access." -ForegroundColor Yellow
}
Write-Host "A reboot is recommended so all security-template + audit settings fully settle." -ForegroundColor Cyan
try { Stop-Transcript | Out-Null } catch {}
