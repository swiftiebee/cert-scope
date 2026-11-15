#requires -Version 5.1
#requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Grant')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Grant')]
    [Parameter(ParameterSetName = 'Domain')]
    [ValidateNotNullOrEmpty()]
    [string]$ReaderGroup,

    [Parameter(ParameterSetName = 'Workgroup')]
    [string]$Account,

    [Parameter(ParameterSetName = 'Workgroup')]
    [Parameter(ParameterSetName = 'Domain')]
    [string]$ClientIPv4,

    [Parameter(Mandatory, ParameterSetName = 'Workgroup')]
    [switch]$PrepareWorkgroup,

    [Parameter(Mandatory, ParameterSetName = 'Domain')]
    [switch]$PrepareDomain,

    [ValidateNotNullOrEmpty()]
    [string[]]$RegistryBranches = @('HKLM\SOFTWARE\Microsoft\SystemCertificates\MY'),

    [Parameter(ParameterSetName = 'Grant')]
    [switch]$GrantWinreg,
    [switch]$Undo
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Run this script in Windows PowerShell 5.1.'
}

$access = [System.Security.AccessControl.AccessControlSections]::Access
$writeDacl = [System.Security.AccessControl.RegistryRights]::ReadPermissions -bor
    [System.Security.AccessControl.RegistryRights]::ChangePermissions
$registryView = if ([Environment]::Is64BitOperatingSystem) { 'Registry64' } else { 'Default' }
$winreg = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg'
$customSidPattern = 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[1-9][0-9]{3,}'
$storePattern = '^(?:HKLM|HKU\\' + $customSidPattern +
    ')\\SOFTWARE\\(?:Policies\\)?Microsoft\\SystemCertificates\\[A-Za-z0-9_.-]+(?<certificates>\\Certificates)?$'

function Get-ReaderSid([string]$Group) {
    if ($Group -match "^$customSidPattern$") {
        return [System.Security.Principal.SecurityIdentifier]::new($Group)
    }
    if ($Group -notmatch '^[^\\]+\\[^\\]+$') {
        throw 'Specify the reader group as DOMAIN\Group or supply its SID.'
    }
    $account = [System.Security.Principal.NTAccount]::new($Group)
    $result = $account.Translate([System.Security.Principal.SecurityIdentifier])
    if ($result.Value -notmatch "^$customSidPattern$") {
        throw 'Specify a dedicated reader group. Built-in identities are not accepted.'
    }
    return $result
}

function Get-GrantPlan([string[]]$Branches, [bool]$IncludeGateway) {
    $plan = [ordered]@{}
    foreach ($branch in $Branches) {
        if ($branch -notmatch $storePattern) {
            throw "Use an explicit Windows certificate store or its Certificates subkey: $branch"
        }
        if ($Matches['certificates']) {
            $plan[$branch] = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
        } else {
            # Let the scanner open the store itself. Inherit only inside Certificates.
            $plan[$branch] = [System.Security.AccessControl.InheritanceFlags]::None
            $plan["$branch\Certificates"] = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
        }
    }
    if ($IncludeGateway) {
        $plan[$winreg] = [System.Security.AccessControl.InheritanceFlags]::None
    }
    return $plan
}

function Open-AclKey([string]$Path) {
    if ($Path -ne $winreg -and $Path -notmatch $storePattern) {
        throw "Unexpected key: $Path"
    }
    $prefix, $subkey = $Path -split '\\', 2
    $hive = if ($prefix -eq 'HKLM') { 'LocalMachine' } else { 'Users' }
    $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $registryView)
    try {
        $key = $root.OpenSubKey($subkey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $writeDacl)
        if ($null -eq $key) {
            throw "Key missing: $Path. For a test store, import a certificate first. For HKU, load the profile by signing in."
        }
        return $key
    } finally {
        $root.Dispose()
    }
}

function Get-PlannedChanges($Plan, [System.Security.Principal.SecurityIdentifier]$Sid) {
    foreach ($path in $Plan.Keys) {
        $key = Open-AclKey $path
        try {
            $acl = $key.GetAccessControl($access)
            $before = $acl.GetSecurityDescriptorSddlForm($access)
            $rule = [System.Security.AccessControl.RegistryAccessRule]::new(
                $Sid, 'ReadKey', $Plan[$path], 'None', 'Allow')
            $acl.AddAccessRule($rule)
            [pscustomobject]@{
                Path = $path
                Before = $before
                After = $acl.GetSecurityDescriptorSddlForm($access)
            }
        } finally {
            $key.Dispose()
        }
    }
}

function Get-ComparableDacl([string]$Sddl) {
    # Windows sets auto-inheritance flags when persisting registry ACLs.
    # Keep the protection flag and every ACE in the comparison.
    return $Sddl -creplace '^D:(P?)(?:AR|AI)+(?=\(|$)', 'D:$1'
}

function Set-SavedAccess($Changes, [bool]$Restore, [bool]$Preview = $false) {
    foreach ($change in $Changes) {
        if ($change.Before -ceq $change.After) { continue }
        $expected = if ($Restore) { $change.After } else { $change.Before }
        $desired = if ($Restore) { $change.Before } else { $change.After }

        $key = Open-AclKey $change.Path
        try {
            $acl = $key.GetAccessControl($access)
            $current = Get-ComparableDacl ($acl.GetSecurityDescriptorSddlForm($access))
            if ($current -ceq (Get-ComparableDacl $desired)) { continue }
            if ($current -cne (Get-ComparableDacl $expected)) {
                throw "Permissions changed outside this script on $($change.Path). Resolve the conflict before proceeding."
            }
            if (-not $Preview) {
                $acl.SetSecurityDescriptorSddlForm($desired, $access)
                $key.SetAccessControl($acl)
            }
        } finally {
            $key.Dispose()
        }
    }
}

function Initialize-BackupDirectory([string]$Path, [bool]$Create) {
    $admins = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    if (-not [System.IO.Directory]::Exists($Path)) {
        if (-not $Create) { throw "Backup directory not found: $Path" }
        $acl = [System.Security.AccessControl.DirectorySecurity]::new()
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            $owner = if ($identity.User -eq $system) { $system } else { $admins }
            $acl.SetOwner($owner)
        } finally {
            $identity.Dispose()
        }
        $acl.SetAccessRuleProtection($true, $false)
        $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        foreach ($trustedSid in $admins, $system) {
            $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
                $trustedSid, 'FullControl', $inherit, 'None', 'Allow'))
        }
        [void][System.IO.Directory]::CreateDirectory($Path, $acl)
    }
    if ([System.IO.File]::GetAttributes($Path) -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Backup directory must not be a link: $Path"
    }
    $acl = [System.IO.Directory]::GetAccessControl($Path)
    $sidType = [System.Security.Principal.SecurityIdentifier]
    $trusted = @($admins.Value, $system.Value)
    $otherRules = @($acl.GetAccessRules($true, $true, $sidType) | Where-Object {
        $_.IdentityReference.Value -notin $trusted
    })
    if ($acl.GetOwner($sidType).Value -notin $trusted -or -not $acl.AreAccessRulesProtected -or $otherRules.Count) {
        throw "Backup directory must be owned and accessible only by Administrators and SYSTEM: $Path"
    }
}

function Read-Backup([string]$Path, [System.Security.Principal.SecurityIdentifier]$Sid) {
    $stored = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($stored.Version -ne 1 -or $stored.Computer -ne $env:COMPUTERNAME -or $stored.GroupSid -ne $Sid.Value) {
        throw "Backup does not match this computer and group: $Path"
    }
    return $stored
}

$preparing = $PrepareWorkgroup -or $PrepareDomain
$target = $null
$profile = $null
if ($preparing) {
    . (Join-Path $PSScriptRoot 'CertScopeTargetTransport.ps1')
    if ($PrepareWorkgroup) {
        if (-not $Account) { $Account = Read-Host "Existing local reader on $env:COMPUTERNAME (name or COMPUTER\name)" }
        $ReaderGroup = (Get-LocalReader $Account -Undo:$Undo).SID.Value
        $profile = 'Private'
    } else {
        if (-not $ReaderGroup) { $ReaderGroup = Read-Host 'Existing domain security group (DOMAIN\Group or SID)' }
        if ($ReaderGroup -like "$env:COMPUTERNAME\*") { throw 'Provide a domain reader group.' }
        $profile = 'Domain'
    }
    if (-not $ClientIPv4) { $ClientIPv4 = Read-Host 'Scanner IPv4 address' }
    if (-not $Undo -and -not $PSBoundParameters.ContainsKey('RegistryBranches')) {
        $entered = Read-Host 'Certificate stores, separated by ; (Enter for HKLM\SOFTWARE\Microsoft\SystemCertificates\MY)'
        if (-not [string]::IsNullOrWhiteSpace($entered)) {
            $RegistryBranches = @($entered.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if ($RegistryBranches.Count -eq 0) { throw 'Specify at least one certificate store.' }
        }
    }
    $target = Get-TargetTransport -ClientIPv4 $ClientIPv4 -Profile $profile -Undo:$Undo
    $GrantWinreg = $true
    Write-Host "TCP 445: scanner $ClientIPv4, firewall profile $profile."
    if ($target) { Write-Host "Target IPv4: $target. Planned Remote Registry startup: Automatic." }
}

$sid = Get-ReaderSid $ReaderGroup
$stateDirectory = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'CertScopeRegistryAccess'
$backupName = if ($preparing) { 'target-setup.json' } else { $sid.Value + '.json' }
$backupPath = Join-Path $stateDirectory $backupName
$plan = $null
if (-not $Undo) {
    $plan = Get-GrantPlan $RegistryBranches $GrantWinreg.IsPresent
    Write-Host "Computer: $env:COMPUTERNAME. Reader: $ReaderGroup ($sid)."
    foreach ($path in $plan.Keys) {
        Write-Host "  ReadKey: $path ($($plan[$path]))"
    }
}

$action = if ($Undo) { 'Restore recorded settings' } elseif ($preparing) {
    'Configure Remote Registry, scoped TCP 445, and the listed read permissions'
} else { 'Grant the listed registry permissions' }
if (-not $PSCmdlet.ShouldProcess("$env:COMPUTERNAME / $ReaderGroup", $action)) {
    if ($WhatIfPreference -and -not $Undo) {
        Get-PlannedChanges $plan $sid | Select-Object Path, @{Name='WouldChange'; Expression={$_.Before -cne $_.After}}
    }
    return
}

Initialize-BackupDirectory $stateDirectory (-not $Undo)
$lockPath = Join-Path $stateDirectory 'access.lock'
$lock = [System.IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
try {
    $newBackup = -not [System.IO.File]::Exists($backupPath)
    if ($Undo) {
        if ($newBackup) { throw "Backup not found: $backupPath" }
        $saved = Read-Backup $backupPath $sid
        if ($preparing) { Assert-TransportBackup $saved.Transport $ClientIPv4 $profile }
        Set-SavedAccess $saved.Keys $true $true
        if ($preparing) { Restore-TargetTransport $saved.Transport }
        Set-SavedAccess $saved.Keys $true
        [System.IO.File]::Delete($backupPath)
        Write-Host 'Recorded settings restored.'
        return
    }

    if ($newBackup) {
        $changes = @(Get-PlannedChanges $plan $sid)
        if (-not $preparing -and -not ($changes | Where-Object { $_.Before -cne $_.After })) {
            Write-Host 'The requested rules are already present.'
            return
        }
        $saved = [pscustomobject]@{
            Version = 1
            Computer = $env:COMPUTERNAME
            GroupSid = $sid.Value
            Keys = $changes
        }
        if ($preparing) { $saved | Add-Member NoteProperty Transport (New-TransportBackup $ClientIPv4 $profile) }
        $temporary = Join-Path $stateDirectory ([guid]::NewGuid().ToString('N') + '.tmp')
        try {
            $saved | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $temporary -Encoding UTF8
            [System.IO.File]::Move($temporary, $backupPath)
        } finally {
            [System.IO.File]::Delete($temporary)
        }
    } else {
        $saved = Read-Backup $backupPath $sid
        if ($preparing) { Assert-TransportBackup $saved.Transport $ClientIPv4 $profile }
        if (@($saved.Keys).Count -ne $plan.Count -or ($saved.Keys | Where-Object { -not $plan.Contains($_.Path) })) {
            throw "This group has a different saved grant. Run -Undo before changing the branch list: $backupPath"
        }
    }

    try {
        Set-SavedAccess $saved.Keys $false $true
        Set-SavedAccess $saved.Keys $false
        if ($preparing) { Set-TargetTransport $saved.Transport }
    } catch {
        if ($newBackup) {
            try {
                Set-SavedAccess $saved.Keys $true $true
                if ($preparing) { Restore-TargetTransport $saved.Transport }
                Set-SavedAccess $saved.Keys $true
                [System.IO.File]::Delete($backupPath)
            } catch {
                Write-Warning "Rollback incomplete. Backup: $backupPath. $($_.Exception.Message)"
            }
        }
        throw
    }
    Write-Host "Settings applied. Backup: $backupPath"
    if ($preparing) {
        Write-Host "Verify from CertScope on the scanner using the selected reader. Target: $target."
    }
} finally {
    $lock.Dispose()
}
