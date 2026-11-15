using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using CertScope;
using Microsoft.Win32;

internal static class ScannerRegression
{
	internal static void Run(Action<string, Action> run, string root, string output)
	{
		run("Certificate scan excludes key metadata, CRLs and CTLs", () =>
		{
			string testPath = @"Software\CertScopeRegression_" + Guid.NewGuid().ToString("N");
			try
			{
				byte[] der = File.ReadAllBytes(Path.Combine(root, "inputs", "organizer-1.cer"));
				foreach (string area in new[] { "Certificates", "Keys", "CRLs", "CTLs" })
					using (RegistryKey key = Registry.CurrentUser.CreateSubKey(testPath + @"\SystemCertificates\My\" + area + @"\sample")) key.SetValue("Blob", der, RegistryValueKind.Binary);
				var settings = FileSettings();
				settings.RegistryViews = new List<string> { Environment.Is64BitProcess ? "Registry64" : "Registry32" };
				settings.RegistryBranches.Add("HKU\\" + WindowsIdentity.GetCurrent().User.Value + "\\" + testPath);
				var result = Scanner.Run(settings, null, CancellationToken.None, null, null);
				Require(result.Observations.Count == 1 && result.Observations[0].Source.Contains("\\Certificates\\"), "Non-certificate store areas were read as certificates");
				Require(result.Sources.All(s => s.Status == SourceStatus.Success), "Unexpected coverage error");
			}
			finally { Registry.CurrentUser.DeleteSubKeyTree(testPath, false); }
		});
		run("Invalid source entries return configuration errors", () =>
		{
			foreach (string value in new string[] { null, "", " " })
			{
				var settings = FileSettings(); settings.Directories.Add(value); Invalid(settings);
				settings = FileSettings(); settings.RegistryBranches.Add(value); Invalid(settings);
				settings = FileSettings(); settings.SelectedSids.Add(value); Invalid(settings);
			}
			var badSid = FileSettings(); badSid.SelectedSids.Add("S-1-5-99999999999999999999"); Invalid(badSid);
		});
		run("CryptoPro scan opt-out and old configuration compatibility", () =>
		{
			var settings = FileSettings();
			var scan = Scanner.Run(settings, null, CancellationToken.None, null, null);
			Require(scan.Sources.Count == 1 && scan.Sources[0].Status == SourceStatus.NotConfigured, "Unselected sources were accessed");
			string legacy = Json.Serialize(ScanSettings.Default()).Replace(",\"IncludeCryptoPro\":true", "");
			Require(Json.Deserialize<ScanSettings>(legacy).IncludeCryptoPro, "Legacy v1 default changed");
			Require(!Json.Clone(settings).IncludeCryptoPro, "Explicit opt-out lost during snapshot");
		});
		run("File traversal limit reports partial coverage", () =>
		{
			string folder = Path.Combine(output, "limited-files"); Directory.CreateDirectory(folder);
			byte[] der = File.ReadAllBytes(Path.Combine(root, "inputs", "organizer-1.cer"));
			File.WriteAllBytes(Path.Combine(folder, "first.cer"), der); File.WriteAllBytes(Path.Combine(folder, "second.cer"), der);
			var settings = FileSettings(); settings.Directories.Add(folder); settings.MaxRegistryValues = 1;
			var scan = Scanner.Run(settings, null, CancellationToken.None, null, null);
			Require(scan.Observations.Count == 1, "Limit must stop after one file");
			Require(scan.Sources.Any(s => s.Source == folder && s.Status == SourceStatus.Partial), "Truncated directory was marked complete");
		});
		run("Registry value limit reports partial coverage", () =>
		{
			string relative = @"Software\CertScopeRegression\" + Guid.NewGuid().ToString("N");
			string sid = WindowsIdentity.GetCurrent().User.Value;
			try
			{
				using (RegistryKey key = Registry.CurrentUser.CreateSubKey(relative))
				{
					byte[] der = File.ReadAllBytes(Path.Combine(root, "inputs", "organizer-1.cer"));
					key.SetValue("First", der, RegistryValueKind.Binary); key.SetValue("Second", der, RegistryValueKind.Binary);
				}
				string branch = "HKU\\" + sid + "\\" + relative;
				var settings = FileSettings(); settings.RegistryBranches.Add(branch); settings.MaxRegistryValues = 1;
				var scan = Scanner.Run(settings, null, CancellationToken.None, null, null);
				Require(scan.Observations.Count == 1, "Limit must stop after one registry value");
				Require(scan.Sources.Any(s => s.Source == branch && s.Status == SourceStatus.Partial), "Truncated registry key was marked complete");
			}
			finally { Registry.CurrentUser.DeleteSubKeyTree(relative, false); }
		});
		run("Explicit SID scan does not enumerate other profiles", () =>
		{
			var settings = FileSettings(); settings.IncludeUsers = true;
			settings.SelectedSids.Add(WindowsIdentity.GetCurrent().User.Value);
			var scan = Scanner.Run(settings, null, CancellationToken.None, null, null);
			Require(!scan.Sources.Any(s => s.Source.StartsWith("ProfileList") || s.Source.StartsWith("HKU: ")), "Unselected profile enumeration occurred");
			Require(scan.Sources.All(s => s.Source == "Компьютер" || s.Source == "Профили пользователей" || s.Source.Contains(settings.SelectedSids[0])), "Unexpected source outside selected user");
		});
		run("Worker deadline includes blocked request pipe", () =>
		{
			Environment.SetEnvironmentVariable("CERTSCOPE_TEST_SLOW_WORKER", "1");
			try
			{
				var settings = FileSettings(); settings.IncludeCryptoPro = true; settings.TimeoutSeconds = 1;
				settings.OutputDirectory = new string('x', 200000);
				var clock = Stopwatch.StartNew();
				var scan = Scanner.Run(settings, null, CancellationToken.None, null, null);
				Require(clock.Elapsed.TotalSeconds < 8, "Request pipe ignored deadline");
				Require(scan.Sources.Any(s => s.Status == SourceStatus.Timeout), "Stalled worker did not report timeout");
			}
			finally { Environment.SetEnvironmentVariable("CERTSCOPE_TEST_SLOW_WORKER", null); }
		});
	}
	private static ScanSettings FileSettings()
	{
		var settings = ScanSettings.Default();
		settings.IncludeMachine = settings.IncludeUsers = settings.IncludeUserFiles = settings.IncludeCryptoPro = false;
		settings.RegistryViews = new List<string> { "Registry64" }; settings.RetryCount = 0; settings.TimeoutSeconds = 8;
		return settings;
	}
	private static void Invalid(ScanSettings settings)
	{
		try { settings.Validate(); } catch (InvalidDataException) { return; }
		throw new Exception("Invalid configuration accepted");
	}
	private static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
}
