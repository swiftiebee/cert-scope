#requires -Version 5.1
#requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ReaderGroup,
    [string]$ClientIPv4,
    [string[]]$RegistryBranches,
    [switch]$Undo
)

& (Join-Path $PSScriptRoot 'Grant-CertScopeRegistryRead.ps1') -PrepareDomain @PSBoundParameters
