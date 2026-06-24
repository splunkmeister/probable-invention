<#
.SYNOPSIS
  Safe rollback / undo for the CIS Windows Server 2025 Level 1 GPOs during piloting.
.DESCRIPTION
  Provides four levels of undo, from instantly-reversible to full removal:

    DisableLink (default) : disables every link to the GPO so it stops applying immediately.
                            Nothing is deleted; re-enable by re-running Create-*.ps1 or in GPMC.
    Unlink                : removes the GPO's links from the OUs (GPO object is kept intact).
    Remove                : backs the GPO up first, removes all links, then deletes the GPO.
                            High-impact - prompts for confirmation.
    Restore               : re-imports the GPO from a previous backup (Import-GPO) and, if
                            -TargetOU is given, re-links it.

  Always run on a domain-joined host with RSAT (GroupPolicy + ActiveDirectory) as a user with
  rights to edit/link/delete the GPO. Linked SITES (Configuration NC) are not auto-discovered.
.PARAMETER Scope
  Member or DC - selects the CIS GPO name. Ignored if -GpoName is supplied.
.PARAMETER GpoName
  Explicit GPO display name (overrides -Scope).
.PARAMETER Action
  DisableLink | Unlink | Remove | Restore   (default: DisableLink)
.PARAMETER BackupPath
  Folder used by Remove (backup target) and Restore (backup source). Default: .\GPO-Backups
.PARAMETER TargetOU
  For Restore: OU to re-link after import. Optional.
.EXAMPLE
  .\Rollback-CIS-GPO.ps1 -Scope Member                      # disable links (safe, reversible)
.EXAMPLE
  .\Rollback-CIS-GPO.ps1 -Scope DC -Action Unlink           # remove links, keep the GPO
.EXAMPLE
  .\Rollback-CIS-GPO.ps1 -Scope Member -Action Remove       # backup + delete (asks to confirm)
.EXAMPLE
  .\Rollback-CIS-GPO.ps1 -Scope Member -Action Restore -BackupPath .\GPO-Backups -TargetOU "OU=Pilot,DC=corp,DC=com"
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Member','DC')][string] $Scope = 'Member',
    [string] $GpoName,
    [ValidateSet('DisableLink','Unlink','Remove','Restore')][string] $Action = 'DisableLink',
    [string] $BackupPath = (Join-Path $PSScriptRoot 'GPO-Backups'),
    [string] $TargetOU,
    [string] $LogPath
)

$ErrorActionPreference = 'Stop'

# ---- Logging ---------------------------------------------------------------
if (-not $LogPath) {
    $LogPath = Join-Path $PSScriptRoot ("Logs\Rollback-CIS-{0}-{1:yyyyMMdd-HHmmss}.log" -f $Scope, (Get-Date))
}
try {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LogPath) | Out-Null
    Start-Transcript -Path $LogPath -Force | Out-Null; $script:Transcribing = $true
} catch { $script:Transcribing = $false; Write-Warning "Could not start transcript: $($_.Exception.Message)" }
Write-Host "Log file: $LogPath" -ForegroundColor DarkCyan
Write-Host ("Run by {0} on {1} at {2:u}" -f $env:USERNAME, $env:COMPUTERNAME, (Get-Date)) -ForegroundColor DarkCyan

Import-Module GroupPolicy     -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

if (-not $GpoName) {
    $GpoName = if ($Scope -eq 'DC') { 'CIS - Windows Server 2025 - Domain Controllers - Level 1' }
               else                 { 'CIS - Windows Server 2025 - Member Servers - Level 1' }
}
$domainDN = (Get-ADDomain).DistinguishedName
Write-Host "Target GPO : $GpoName" -ForegroundColor Cyan
Write-Host "Action     : $Action`n" -ForegroundColor Cyan

function Get-LinkedContainers {
    param([string]$Guid)
    # gPLink stores [LDAP://cn={GUID},...;<flags>]; DirectoryString match is case-insensitive.
    Get-ADObject -LDAPFilter "(gPLink=*{$Guid}*)" -SearchBase $domainDN -SearchScope Subtree `
        -Properties distinguishedName, gPLink |
        Select-Object -ExpandProperty distinguishedName
}

# ---------------- Restore (GPO may not currently exist) ----------------
if ($Action -eq 'Restore') {
    if (-not (Test-Path -LiteralPath $BackupPath)) { throw "BackupPath not found: $BackupPath" }
    if ($PSCmdlet.ShouldProcess($GpoName, "Import-GPO from $BackupPath")) {
        Import-GPO -BackupGpoName $GpoName -Path $BackupPath -TargetName $GpoName -CreateIfNeeded | Out-Null
        Write-Host "[+] Restored GPO '$GpoName' from backup." -ForegroundColor Green
        if ($TargetOU) {
            if (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$TargetOU)" -ErrorAction SilentlyContinue) {
                $already = (Get-GPInheritance -Target $TargetOU).GpoLinks.DisplayName -contains $GpoName
                if (-not $already) { New-GPLink -Name $GpoName -Target $TargetOU -LinkEnabled Yes | Out-Null }
                Write-Host "[+] Linked to $TargetOU" -ForegroundColor Green
            } else { Write-Warning "TargetOU '$TargetOU' not found - link manually." }
        }
    }
    return
}

# ---------------- Locate the GPO ----------------
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) { Write-Warning "GPO '$GpoName' not found - nothing to do."; return }
$guid  = $gpo.Id.Guid
$links = @(Get-LinkedContainers -Guid $guid)
if ($links.Count) {
    Write-Host "Currently linked at:" -ForegroundColor Yellow
    $links | ForEach-Object { Write-Host "   $_" }
} else {
    Write-Host "GPO is not linked anywhere." -ForegroundColor Yellow
}
Write-Host ""

switch ($Action) {

    'DisableLink' {
        foreach ($ou in $links) {
            if ($PSCmdlet.ShouldProcess($ou, "Disable link to '$GpoName'")) {
                Set-GPLink -Name $GpoName -Target $ou -LinkEnabled No | Out-Null
                Write-Host "[+] Disabled link at $ou" -ForegroundColor Green
            }
        }
        if (-not $links.Count) { Write-Host "No links to disable." -ForegroundColor Yellow }
        Write-Host "`nGPO is preserved and no longer applies. Re-enable via Create-*.ps1 or GPMC." -ForegroundColor Cyan
    }

    'Unlink' {
        foreach ($ou in $links) {
            if ($PSCmdlet.ShouldProcess($ou, "Remove link to '$GpoName'")) {
                Remove-GPLink -Name $GpoName -Target $ou | Out-Null
                Write-Host "[+] Removed link at $ou" -ForegroundColor Green
            }
        }
        if (-not $links.Count) { Write-Host "No links to remove." -ForegroundColor Yellow }
        Write-Host "`nGPO object kept. Re-link with New-GPLink or Create-*.ps1." -ForegroundColor Cyan
    }

    'Remove' {
        # Always back up before deletion.
        New-Item -ItemType Directory -Force -Path $BackupPath | Out-Null
        $stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
        $backup = Backup-GPO -Name $GpoName -Path $BackupPath -Comment "Pre-removal backup $stamp"
        Write-Host "[+] Backed up to $BackupPath  (BackupId $($backup.Id))" -ForegroundColor Green

        foreach ($ou in $links) {
            if ($PSCmdlet.ShouldProcess($ou, "Remove link to '$GpoName'")) {
                Remove-GPLink -Name $GpoName -Target $ou | Out-Null
                Write-Host "[+] Removed link at $ou" -ForegroundColor Green
            }
        }
        if ($PSCmdlet.ShouldProcess($GpoName, "DELETE GPO (restorable from $BackupPath)")) {
            Remove-GPO -Name $GpoName | Out-Null
            Write-Host "[+] GPO '$GpoName' deleted." -ForegroundColor Green
            Write-Host "    Restore with: .\Rollback-CIS-GPO.ps1 -GpoName '$GpoName' -Action Restore -BackupPath '$BackupPath'" -ForegroundColor Cyan
        }
    }
}

Write-Host "`nDone. Run 'gpupdate /force' on affected hosts to pull the change." -ForegroundColor Cyan
Write-Host "Full log: $LogPath" -ForegroundColor DarkCyan
if ($script:Transcribing) { try { Stop-Transcript | Out-Null } catch {} }
