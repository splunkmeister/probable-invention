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
.PARAMETER Scope
  Member or DC - selects the matching INF, registry scope, and audit set.
.PARAMETER IncludeCurrentUser
  Also apply the 6 per-user (HKCU, section 19) settings to the CURRENT user's hive.
  Off by default: at build time HKCU is the build account, not end users. For all future
  users, deliver section 19 via GPO or by applying to the Default User hive instead.
.PARAMETER SkipAudit / -SkipFirewall
  Omit those stages (e.g. if handled elsewhere in the build).
.EXAMPLE
  .\Apply-CIS-Local.ps1 -Scope Member -WhatIf      # preview, change nothing
.EXAMPLE
  .\Apply-CIS-Local.ps1 -Scope Member              # apply the Member baseline locally
.NOTES
  Run ELEVATED. Account/lockout policy (section 1) applies to LOCAL accounts on member servers;
  for domain accounts it must live in the Default Domain Policy (not a local apply).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('Member','DC')][string] $Scope,
    [string]  $ScriptRoot = $PSScriptRoot,
    [string]  $LogPath = "$env:windir\Temp\CIS-Apply-$Scope.log",
    [switch]  $IncludeCurrentUser,
    [switch]  $SkipAudit,
    [switch]  $SkipFirewall
)

$ErrorActionPreference = 'Stop'

# ---- Preflight -------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run elevated - secedit/auditpol/firewall require administrator." }

$InfFile = Join-Path $ScriptRoot ("CIS_Server2025_{0}_Level1.inf" -f ($(if ($Scope -eq 'DC') {'DC'} else {'Member'})))
$RegMod  = Join-Path $ScriptRoot 'RegistrySettings.ps1'
$AudMod  = Join-Path $ScriptRoot 'Set-CIS-AuditPolicy.ps1'
foreach ($f in @($InfFile, $RegMod)) { if (-not (Test-Path -LiteralPath $f)) { throw "Missing required file: $f" } }

try { Start-Transcript -Path $LogPath -Append | Out-Null } catch {}
Write-Host "CIS Server 2025 L1 local apply - Scope=$Scope  (log: $LogPath)" -ForegroundColor Cyan
$summary = [ordered]@{ INF='skipped'; Registry='skipped'; Audit='skipped'; Firewall='skipped' }

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
. $RegMod   # loads $CISRegistrySettings (no GroupPolicy dependency at load time)
$scopeFilter = if ($Scope -eq 'DC') { @('Both','DC') } else { @('Both','MS') }
$want = $CISRegistrySettings | Where-Object { $_.Scope -in $scopeFilter }
$machine = $want | Where-Object { $_.Key -like 'HKLM\*' }
$user    = $want | Where-Object { $_.Key -like 'HKCU\*' }

function Set-LocalRegistry {
    param([object[]]$Items)
    $ok = 0; $fail = 0
    foreach ($s in $Items) {
        $prov = $s.Key -replace '^HKLM\\', 'HKLM:\' -replace '^HKCU\\', 'HKCU:\'
        try {
            if (-not (Test-Path -LiteralPath $prov)) { New-Item -Path $prov -Force | Out-Null }
            $pt = if ($s.Type -eq 'String') { 'String' } else { 'DWord' }
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
if (-not $SkipFirewall) {
    if ($PSCmdlet.ShouldProcess('local firewall profiles', 'configure 9.1-9.3')) {
        try {
            Set-NetFirewallProfile -Profile Domain,Private,Public `
                -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow `
                -NotifyOnListen False -LogMaxSizeKilobytes 16384 -LogAllowed True -LogBlocked True `
                -LogFileName "%SystemRoot%\System32\logfiles\firewall\pfirewall.log"
            Write-Host "[+] Firewall profiles configured." -ForegroundColor Green
            $summary.Firewall = 'applied'
        } catch { Write-Warning "Firewall step failed: $($_.Exception.Message)"; $summary.Firewall = 'failed' }
    } else { Write-Host "[WhatIf] Would configure local firewall profiles." -ForegroundColor Yellow; $summary.Firewall = 'whatif' }
}

# ---- Summary ---------------------------------------------------------------
Write-Host "`n--- Local apply summary ($Scope) ---" -ForegroundColor Cyan
$summary.GetEnumerator() | ForEach-Object { Write-Host ("  {0,-9}: {1}" -f $_.Key, $_.Value) }
Write-Host "Verify with:  .\Test-CIS-Compliance.ps1 -Scope $Scope" -ForegroundColor Cyan
Write-Host "A reboot is recommended so all security-template + audit settings fully settle." -ForegroundColor Cyan
try { Stop-Transcript | Out-Null } catch {}
