$ErrorActionPreference = 'Stop'
$packagePath = Join-Path $PSScriptRoot 'net45.nupkg'
$targetPath = Join-Path $PSScriptRoot 'net45'
if (Test-Path -LiteralPath (Join-Path $targetPath 'build\.NETFramework\v4.5\mscorlib.dll')) { Write-Output 'Reference assemblies уже доступны.'; exit 0 }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -Uri 'https://api.nuget.org/v3-flatcontainer/microsoft.netframework.referenceassemblies.net45/1.0.3/microsoft.netframework.referenceassemblies.net45.1.0.3.nupkg' -OutFile $packagePath
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::ExtractToDirectory($packagePath, $targetPath)
Write-Output 'Microsoft.NETFramework.ReferenceAssemblies.net45 1.0.3 подготовлен локально. Системное ПО не устанавливалось.'
