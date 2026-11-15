param(
	[Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ServerInstance,
	[Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ExistingTestDatabase,
	[string]$ApplicationPath = (Join-Path $PSScriptRoot '..\artifacts\CertScope.exe'),
	[switch]$TrustServerCertificate
)

# Runs a compiled .NET Framework process; no dynamic assembly loading by PowerShell.
# Writes only to the explicitly supplied EXISTING EMPTY user database.
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$assemblyPath = [IO.Path]::GetFullPath($ApplicationPath)
if ($ExistingTestDatabase -in @('master', 'model', 'msdb', 'tempdb')) { throw 'A system database cannot be used for integration tests.' }
if (-not (Test-Path -LiteralPath $assemblyPath)) { throw 'Build the application first: build.ps1.' }
$testRoot = Join-Path $projectRoot ('artifacts\sql-integration-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
Copy-Item -LiteralPath $assemblyPath -Destination (Join-Path $testRoot 'CertScope.exe')
Copy-Item -LiteralPath ($assemblyPath + '.config') -Destination (Join-Path $testRoot 'CertScope.exe.config')
$entrySource = @'
using System;
public static class SqlIntegrationEntry
{
	public static int Main(string[] args)
	{
		return StorageRegression.RunSql(args[0], args[1], args[2], args[3], Boolean.Parse(args[4]));
	}
}
'@
$entryPath = Join-Path $testRoot 'SqlIntegrationEntry.cs'
[IO.File]::WriteAllText($entryPath, $entrySource, [Text.UTF8Encoding]::new($false))
$referenceDirectory = Join-Path $projectRoot 'tools\net45\build\.NETFramework\v4.5'
$compilerPath = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compilerPath)) { $compilerPath = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
$runner = Join-Path $testRoot 'CertScope.SqlIntegration.exe'
$compilerArguments = @('/nologo', '/noconfig', '/nostdlib+', '/langversion:5', '/target:exe', ('/out:' + $runner), ('/reference:' + $assemblyPath))
foreach ($assemblyName in @('mscorlib', 'System', 'System.Core', 'System.Data', 'System.Xml', 'System.Runtime.Serialization')) {
	$compilerArguments += '/reference:' + (Join-Path $referenceDirectory ($assemblyName + '.dll'))
}
$compilerArguments += (Join-Path $PSScriptRoot 'StorageRegression.cs')
$compilerArguments += $entryPath
& $compilerPath $compilerArguments
if ($LASTEXITCODE -ne 0) { throw 'SQL integration runner compilation failed.' }
Write-Output ('SQL integration output: ' + $testRoot)
$trustArgument = ([bool]$TrustServerCertificate).ToString()
& $runner $ServerInstance $ExistingTestDatabase $projectRoot $testRoot $trustArgument
if ($LASTEXITCODE -ne 0) { throw ('SQL integration tests failed. See ' + (Join-Path $testRoot 'results.txt')) }
Write-Output ('SQL integration tests passed. Data and evidence retained: ' + $testRoot)
