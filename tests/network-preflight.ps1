#requires -Version 5.1
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)][string[]]$ComputerName,
	[string[]]$RegistryBranches = @('HKLM\SOFTWARE\Microsoft\SystemCertificates'),
	[ValidateSet('Registry64', 'Registry32')][string[]]$RegistryViews = @('Registry64'),
	[switch]$AlternateCredential,
	[ValidateRange(1, 30)][int]$ConnectTimeoutSeconds = 3,
	[string]$ReportPath = (Join-Path $PSScriptRoot '..\verification\network-preflight.json')
)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -eq 'Core') {
	throw 'Запустите сценарий через Windows PowerShell 5.1: powershell.exe -NoProfile -File tests\network-preflight.ps1 ...'
}
foreach ($computer in $ComputerName) {
	if ($computer -notmatch '^[\p{L}\p{N}_.:-]+$') { throw 'Имя ПК содержит недопустимые символы.' }
}
foreach ($branch in $RegistryBranches) {
	if ($branch -notmatch '^(?i:HKLM|HKU)(\\.*)?$') { throw 'Разрешены только явные ветки HKLM и HKU.' }
}

# This type uses a temporary outbound logon session. The password is never a command argument,
# a managed string, or a report field. No service/registry/security setting is modified.
if ($AlternateCredential -and -not ('CertScopePreflight.NetworkIdentity' -as [type])) {
	Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
namespace CertScopePreflight
{
	public sealed class NetworkIdentity : IDisposable
	{
		private IntPtr token;
		private WindowsImpersonationContext context;
		public NetworkIdentity(string account, SecureString password)
		{
			string domain = null, name = account;
			int separator = account.IndexOf('\\');
			if (separator >= 0) { domain = account.Substring(0, separator); name = account.Substring(separator + 1); }
			IntPtr secret = Marshal.SecureStringToGlobalAllocUnicode(password);
			try
			{
				if (!LogonUser(name, domain, secret, 9, 3, out token)) throw new Win32Exception(Marshal.GetLastWin32Error());
				try { context = WindowsIdentity.Impersonate(token); }
				catch { CloseHandle(token); token = IntPtr.Zero; throw; }
			}
			finally { Marshal.ZeroFreeGlobalAllocUnicode(secret); }
		}
		public void Dispose()
		{
			try { if (context != null) { context.Dispose(); context = null; } }
			finally { if (token != IntPtr.Zero) { CloseHandle(token); token = IntPtr.Zero; } }
		}
		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool LogonUser(string user, string domain, IntPtr password, int type, int provider, out IntPtr token);
		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
	}
}
'@
}

$credential = $null
if ($AlternateCredential) {
	$credential = Get-Credential -Message 'Тестовая сетевая учётная запись (DOMAIN\user или user@domain). Пароль не записывается в отчёт.'
	if ($null -eq $credential) { throw 'Ввод учётной записи отменён.' }
}
$results = New-Object 'System.Collections.Generic.List[object]'
function Add-Result([string]$computer, [string]$check, [string]$status, [string]$detail, [int]$errorCode = 0) {
	$results.Add([pscustomobject]@{
		TimeUtc = [DateTime]::UtcNow.ToString('o'); Computer = $computer; Check = $check
		Status = $status; Detail = $detail; ErrorCode = $errorCode
		AccountMode = $(if ($AlternateCredential) { 'ExplicitNetworkCredential' } else { 'CurrentProcess' })
	})
	Write-Host ('{0} | {1} | {2} | {3}' -f $computer, $check, $status, $detail)
}

try {
	foreach ($computer in $ComputerName) {
		try {
			$addresses = [Net.Dns]::GetHostAddresses($computer)
			Add-Result $computer 'DNS' 'Success' (($addresses | ForEach-Object { $_.IPAddressToString }) -join ', ')
		} catch { Add-Result $computer 'DNS' 'Error' $_.Exception.Message $_.Exception.HResult }
		foreach ($port in @(445, 135)) {
			$client = New-Object Net.Sockets.TcpClient
			try {
				$connect = $client.BeginConnect($computer, $port, $null, $null)
				try {
					if (-not $connect.AsyncWaitHandle.WaitOne($ConnectTimeoutSeconds * 1000)) {
						Add-Result $computer ('TCP/' + $port) 'Timeout' 'Соединение не установлено в заданный срок.'
					} else {
						$client.EndConnect($connect)
						Add-Result $computer ('TCP/' + $port) 'Success' 'TCP-соединение установлено; права и доступность Remote Registry этим не доказаны.'
					}
				} finally { $connect.AsyncWaitHandle.Close() }
			} catch { Add-Result $computer ('TCP/' + $port) 'Error' $_.Exception.Message $_.Exception.HResult }
			finally { $client.Close() }
		}

		$identity = $null
		try {
			if ($credential) { $identity = New-Object CertScopePreflight.NetworkIdentity($credential.UserName, $credential.Password) }
			foreach ($view in $RegistryViews) {
				foreach ($branch in $RegistryBranches) {
					$base = $null; $key = $null
					try {
						$parts = $branch -split '\\', 2
						$hive = if ($parts[0] -eq 'HKLM') { [Microsoft.Win32.RegistryHive]::LocalMachine } else { [Microsoft.Win32.RegistryHive]::Users }
						$path = if ($parts.Length -eq 2) { $parts[1] } else { '' }
						$base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hive, $computer, [Microsoft.Win32.RegistryView]::$view)
						$key = $base.OpenSubKey($path, $false)
						if ($null -eq $key) { Add-Result $computer ($view + '/' + $branch) 'NotConfigured' 'Ветка отсутствует либо её наличие не подтверждено.' }
						else {
							# Enumerate names/counts only: do not read certificate contents or private key values.
							$subkeys = $key.GetSubKeyNames().Length; $values = $key.GetValueNames().Length
							Add-Result $computer ($view + '/' + $branch) 'Success' ('Открыто только для чтения. Подветок: {0}; значений: {1}. ACL вложенных ключей проверяются отдельным сканированием.' -f $subkeys, $values)
						}
					} catch { Add-Result $computer ($view + '/' + $branch) 'Error' $_.Exception.Message $_.Exception.HResult }
					finally { if ($key) { $key.Dispose() }; if ($base) { $base.Dispose() } }
				}
			}
		} catch { Add-Result $computer 'NetworkIdentity' 'Error' $_.Exception.Message $_.Exception.HResult }
		finally { if ($identity) { $identity.Dispose() } }
	}
} finally {
	if ($credential) { $credential.Password.Dispose(); $credential = $null }
	$directory = Split-Path -Parent ([IO.Path]::GetFullPath($ReportPath))
	[IO.Directory]::CreateDirectory($directory) | Out-Null
	ConvertTo-Json -InputObject @($results.ToArray()) -Depth 4 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
}
Write-Host ('Отчёт: ' + [IO.Path]::GetFullPath($ReportPath))
Write-Host 'Удалённые RPC-вызовы Windows могут ожидать системный тайм-аут; приложение CertScope дополнительно ограничивает их отдельным worker-процессом.'
if (@($results | Where-Object { $_.Status -ne 'Success' }).Count -gt 0) { exit 1 }
exit 0
