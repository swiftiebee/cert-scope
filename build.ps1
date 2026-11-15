param([switch]$Test, [switch]$BuildTests, [string]$OutputDirectory = 'artifacts')
$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$referenceDirectory = Join-Path $projectRoot 'tools\net45\build\.NETFramework\v4.5'
if (-not (Test-Path -LiteralPath (Join-Path $referenceDirectory 'mscorlib.dll'))) {
	throw 'Нет reference assemblies .NET Framework 4.5. Запустите tools\prepare.ps1 либо установите targeting pack 4.5 и исправьте путь.'
}
$compilerPath = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compilerPath)) { $compilerPath = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
$artifactDirectory = Join-Path $projectRoot $OutputDirectory
New-Item -ItemType Directory -Force -Path $artifactDirectory,(Join-Path $artifactDirectory 'samples') | Out-Null
$references = @('mscorlib','System','System.Core','System.Data','System.Drawing','System.Windows.Forms','System.Runtime.Serialization','System.Security','System.Xml','System.Xml.Linq','System.IO.Compression','System.IO.Compression.FileSystem')
$compilerArguments = @('/nologo','/noconfig','/nostdlib+','/langversion:5','/target:winexe','/platform:anycpu','/optimize+','/debug:pdbonly',('/out:' + (Join-Path $artifactDirectory 'CertScope.exe')))
foreach ($assemblyName in $references) { $compilerArguments += '/reference:' + (Join-Path $referenceDirectory ($assemblyName + '.dll')) }
if (Test-Path -LiteralPath (Join-Path $projectRoot 'sql\schema.sql')) { $compilerArguments += '/resource:' + (Join-Path $projectRoot 'sql\schema.sql') + ',CertScope.Schema.sql' }
$compilerArguments += '/win32icon:' + (Join-Path $projectRoot 'src\Assets\CertScope.ico')
$compilerArguments += '/resource:' + (Join-Path $projectRoot 'src\Assets\CertScope.ico') + ',CertScope.Icon'
$compilerArguments += @(Get-ChildItem -LiteralPath (Join-Path $projectRoot 'src') -Filter '*.cs' | ForEach-Object FullName)
& $compilerPath $compilerArguments
if ($LASTEXITCODE -ne 0) { throw 'Сборка приложения завершилась с ошибкой.' }
Copy-Item -LiteralPath (Join-Path $projectRoot 'src\App.config') -Destination (Join-Path $artifactDirectory 'CertScope.exe.config') -Force
Get-ChildItem -LiteralPath (Join-Path $projectRoot 'inputs') -Filter 'organizer-*.cer' | Copy-Item -Destination (Join-Path $artifactDirectory 'samples') -Force
if ($Test -or $BuildTests) {
	$testArguments = @('/nologo','/noconfig','/nostdlib+','/langversion:5','/target:exe','/platform:anycpu','/optimize+',('/out:' + (Join-Path $artifactDirectory 'CertScope.Tests.exe')),('/reference:' + (Join-Path $artifactDirectory 'CertScope.exe')))
	foreach ($assemblyName in $references) { $testArguments += '/reference:' + (Join-Path $referenceDirectory ($assemblyName + '.dll')) }
	$testArguments += @(Get-ChildItem -LiteralPath (Join-Path $projectRoot 'tests') -Filter '*.cs' | ForEach-Object FullName)
	& $compilerPath $testArguments
	if ($LASTEXITCODE -ne 0) { throw 'Сборка тестов завершилась с ошибкой.' }
	Copy-Item -LiteralPath (Join-Path $projectRoot 'src\App.config') -Destination (Join-Path $artifactDirectory 'CertScope.Tests.exe.config') -Force
	if ($Test) {
		& (Join-Path $artifactDirectory 'CertScope.Tests.exe') $projectRoot
		if ($LASTEXITCODE -ne 0) { throw 'Тесты выявили ошибки. См. artifacts\test-results.txt.' }
	}
}
Write-Output ('Готово: ' + (Join-Path $artifactDirectory 'CertScope.exe'))
