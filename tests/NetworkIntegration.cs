using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Threading;
using CertScope;

/// <summary>Explicitly selected test host only. Never changes services, ACL, certificates or firewall.</summary>
public static class NetworkIntegration
{
	public static int Run(string root, string host, string username, string domain, string password)
	{
		if (password == null) { Console.Error.WriteLine("NETWORK TEST NOT STARTED: standard input closed before password was supplied. Use an interactive console or a secure stdin launcher."); return 2; }
		string folder = Path.Combine(root, "artifacts", "network-test-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N").Substring(0, 6));
		Directory.CreateDirectory(folder);
		var lines = new List<string>();
		Action<string> log = text => { string line = DateTime.UtcNow.ToString("O") + " " + text; lines.Add(line); Console.WriteLine(line); };
		string callerIdentity = WindowsIdentity.GetCurrent().Name;
		var credentials = new ScanCredentials { Domain = domain, UserName = username, Password = password };
		password = null;
		try
		{
			var limited = ScanSettings.Default();
			limited.Computers = new List<string> { host };
			limited.IncludeMachine = limited.IncludeUsers = limited.IncludeUserFiles = limited.IncludeCryptoPro = false;
			limited.RegistryBranches.Add(@"HKLM\SOFTWARE\Microsoft\SystemCertificates\MY");
			limited.MaxHosts = 1; limited.MaxSourcesPerHost = 2; limited.MaxWorkers = 3;
			limited.TimeoutSeconds = 12; limited.RetryCount = 0;
			limited.Validate();
			log("NETWORK TARGET " + host + "; read-only test; explicit credential is not saved.");
			try { log("DNS " + String.Join(", ", Dns.GetHostAddresses(host).Select(a => a.ToString()))); }
			catch (Exception error) { log("DNS ERROR " + error.GetType().Name + ": " + error.Message); }
			foreach (int port in new[] { 445, 135 }) ProbePort(host, port, log);

			ScanResult selected = Scan("01-selected-MY", limited, credentials, folder, log);
			var standard = Json.Clone(limited);
			standard.TimeoutSeconds = 60;
			standard.RegistryBranches.Clear();
			standard.IncludeMachine = standard.IncludeUsers = standard.IncludeUserFiles = standard.IncludeCryptoPro = true;
			ScanResult comprehensive = Scan("02-standard-sources", standard, credentials, folder, log);

			// A fresh worker without explicit credentials checks reset; successful/failed access depends on
			// the actual current user's permissions. No deliberately wrong password or account-lockout test.
			Scan("03-current-account-after-explicit", limited, null, folder, log);
			bool identityRestored = String.Equals(callerIdentity, WindowsIdentity.GetCurrent().Name, StringComparison.OrdinalIgnoreCase);
			log("LOCAL IDENTITY RESTORED: " + identityRestored);
			bool readable = selected.Sources.Concat(comprehensive.Sources).Any(s =>
				s.Source.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase) &&
				(s.Status == SourceStatus.Success || s.Status == SourceStatus.Empty));
			log("REMOTE REGISTRY SOURCE READABLE: " + readable);
			log("Executed integration scenario. Each source status is recorded; domain delegation and offline profiles are not inferred from this result.");
			return readable && identityRestored ? 0 : 1;
		}
		catch (Exception error) { log("NETWORK SCENARIO ERROR " + error); return 1; }
		finally
		{
			credentials.Password = null;
			File.WriteAllLines(Path.Combine(folder, "summary.txt"), lines, new UTF8Encoding(true));
			Console.WriteLine("NETWORK REPORT: " + folder);
		}
	}

	private static ScanResult Scan(string name, ScanSettings settings, ScanCredentials credentials, string folder, Action<string> log)
	{
		log("START " + name);
		var watch = Stopwatch.StartNew();
		var repository = new LocalRepository(Path.Combine(folder, name + "-data"));
		var result = Scanner.Run(settings, credentials, CancellationToken.None, repository.SaveObservation, repository.SaveReport);
		Json.Save(Path.Combine(folder, name + "-settings.json"), settings);
		Json.Save(Path.Combine(folder, name + "-results.json"), result);
		foreach (SourceReport source in result.Sources)
			log(name + " | " + source.Status + " | " + source.Source + " | count=" + source.Count + " | code=" + source.ErrorCode + " | " + source.Message);
		log("END " + name + "; seconds=" + watch.Elapsed.TotalSeconds.ToString("F1", System.Globalization.CultureInfo.InvariantCulture) + "; observations=" + result.Observations.Count);
		return result;
	}

	private static void ProbePort(string host, int port, Action<string> log)
	{
		using (var client = new TcpClient())
		{
			try
			{
				IAsyncResult connection = client.BeginConnect(host, port, null, null);
				using (WaitHandle wait = connection.AsyncWaitHandle)
				{
					if (!wait.WaitOne(3000)) { log("TCP " + port + " TIMEOUT"); return; }
					client.EndConnect(connection);
					log("TCP " + port + " OPEN (transport only)");
				}
			}
			catch (Exception error) { log("TCP " + port + " ERROR " + error.GetType().Name + ": " + error.Message); }
		}
	}
}
