using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace CertScope
{
	[DataContract]
	public sealed class DnAttribute
	{
		[DataMember] public int Rdn { get; set; }
		[DataMember] public string Oid { get; set; }
		[DataMember] public string Value { get; set; }
	}
	[DataContract]
	public sealed class ExtensionRecord
	{
		[DataMember] public string Oid { get; set; }
		[DataMember] public bool Critical { get; set; }
		[DataMember] public string RawBase64 { get; set; }
		[DataMember] public string Description { get; set; }
	}
	[DataContract]
	public sealed class CertificateRecord
	{
		[DataMember] public string Sha256 { get; set; }
		[DataMember] public string SerialNumber { get; set; }
		[DataMember] public string Subject { get; set; }
		[DataMember] public string Issuer { get; set; }
		[DataMember] public string DisplayName { get; set; }
		[DataMember] public string DisplayNameSource { get; set; }
		[DataMember] public DateTime NotBeforeUtc { get; set; }
		[DataMember] public DateTime NotAfterUtc { get; set; }
		[DataMember] public string PublicKeyAlgorithm { get; set; }
		[DataMember] public string SignatureAlgorithm { get; set; }
		[DataMember] public string PublicKeyParameters { get; set; }
		[DataMember] public string SignatureParameters { get; set; }
		[DataMember] public string LicenseStatus { get; set; }
		[DataMember] public string LicenseVersion { get; set; }
		[DataMember] public string LicenseEvidence { get; set; }
		[DataMember] public byte[] Der { get; set; }
		[DataMember] public List<ExtensionRecord> Extensions { get; set; }
		[DataMember] public List<DnAttribute> SubjectAttributes { get; set; }
		[DataMember] public List<DnAttribute> IssuerAttributes { get; set; }
	}
	[DataContract]
	public sealed class Observation
	{
		[DataMember] public Guid Id { get; set; }
		[DataMember] public Guid ScanId { get; set; }
		[DataMember] public string Computer { get; set; }
		[DataMember] public string Source { get; set; }
		[DataMember] public string UserSid { get; set; }
		[DataMember] public string RegistryView { get; set; }
		[DataMember] public DateTime FoundUtc { get; set; }
		[DataMember] public CertificateRecord Certificate { get; set; }
	}
	public enum SourceStatus { Success, Empty, Partial, Unreachable, AccessDenied, Timeout, Cancelled, NotConfigured, Unsupported, Error }
	[DataContract]
	public sealed class SourceReport
	{
		[DataMember] public Guid ScanId { get; set; }
		[DataMember] public string Computer { get; set; }
		[DataMember] public string Source { get; set; }
		[DataMember] public string UserSid { get; set; }
		[DataMember] public SourceStatus Status { get; set; }
		[DataMember] public string Message { get; set; }
		[DataMember] public DateTime StartedUtc { get; set; }
		[DataMember] public DateTime FinishedUtc { get; set; }
		[DataMember] public int Count { get; set; }
		[DataMember] public int ErrorCode { get; set; }
		[DataMember] public string StackTrace { get; set; }
	}
	public sealed class ScanResult
	{
		public Guid ScanId { get; set; }
		public List<Observation> Observations { get; set; }
		public List<SourceReport> Sources { get; set; }
		public ScanResult() { Observations = new List<Observation>(); Sources = new List<SourceReport>(); }
	}
	[DataContract]
	public sealed class ScanCredentials
	{
		[DataMember] public string Domain { get; set; }
		[DataMember] public string UserName { get; set; }
		[DataMember] public string Password { get; set; }
	}
	[DataContract]
	public sealed class ScanSettings
	{
		[DataMember] public int Version { get; set; }
		[DataMember] public List<string> Computers { get; set; }
		[DataMember] public List<string> RegistryBranches { get; set; }
		[DataMember] public List<string> Directories { get; set; }
		[DataMember] public List<string> SelectedSids { get; set; }
		[DataMember] public List<string> RegistryViews { get; set; }
		[DataMember] public bool IncludeMachine { get; set; }
		[DataMember] public bool IncludeUsers { get; set; }
		[DataMember] public bool IncludeUserFiles { get; set; }
		[DataMember] public bool IncludeCryptoPro { get; set; }
		[DataMember] public bool FullRegistry { get; set; }
		[DataMember] public int MaxHosts { get; set; }
		[DataMember] public int MaxSourcesPerHost { get; set; }
		[DataMember] public int MaxWorkers { get; set; }
		[DataMember] public int TimeoutSeconds { get; set; }
		[DataMember] public int MaxFileBytes { get; set; }
		[DataMember] public int MaxRegistryValues { get; set; }
		[DataMember] public int RetryCount { get; set; }
		[DataMember] public string SqlConnectionString { get; set; }
		[DataMember] public string OutputDirectory { get; set; }
		[DataMember] public string LogDirectory { get; set; }
		public static ScanSettings Default()
		{
			return new ScanSettings { Version = 1, Computers = new List<string> { Environment.MachineName }, RegistryBranches = new List<string>(), Directories = new List<string>(), SelectedSids = new List<string>(), RegistryViews = new List<string> { "Registry64", "Registry32" }, IncludeMachine = true, IncludeUsers = true, IncludeUserFiles = true, IncludeCryptoPro = true, MaxHosts = 3, MaxSourcesPerHost = 2, MaxWorkers = 4, TimeoutSeconds = 60, MaxFileBytes = 16 * 1024 * 1024, MaxRegistryValues = 200000, RetryCount = 1, SqlConnectionString = "Data Source=localhost;Initial Catalog=CertScope;Integrated Security=True;Encrypt=True;TrustServerCertificate=False;Connect Timeout=5", OutputDirectory = "data", LogDirectory = "logs" };
		}
		// Existing v1 configurations retain the previously implicit product metadata scan.
		[OnDeserializing]
		private void BeforeDeserialize(StreamingContext context) { IncludeCryptoPro = true; }
		/// <summary>Проверяет конфигурацию до запуска; пароли в ней запрещены.</summary>
		public void Validate()
		{
			if (Version != 1) throw new InvalidDataException("Неподдерживаемая версия конфигурации.");
			if (Computers == null || Computers.Count == 0 || Computers.Count > 10000 || Computers.Any(x => String.IsNullOrWhiteSpace(x) || x.Length > 255 || !System.Text.RegularExpressions.Regex.IsMatch(x, @"^[\p{L}\p{N}_.:-]+$"))) throw new InvalidDataException("Укажите корректные имена компьютеров без пробелов и путей.");
			if (MaxHosts < 1 || MaxHosts > 32 || MaxSourcesPerHost < 1 || MaxSourcesPerHost > 16 || MaxWorkers < 1 || MaxWorkers > 32 || TimeoutSeconds < 1 || TimeoutSeconds > 3600 || RetryCount < 0 || RetryCount > 3 || MaxFileBytes < 1024 || MaxFileBytes > 64 * 1024 * 1024 || MaxRegistryValues < 1 || MaxRegistryValues > 10000000) throw new InvalidDataException("Параметры нагрузки выходят за допустимые пределы.");
			if (RegistryBranches == null || Directories == null || SelectedSids == null || RegistryViews == null || RegistryViews.Count == 0 || RegistryViews.Any(v => v != "Registry32" && v != "Registry64")) throw new InvalidDataException("Некорректные списки источников или представления реестра.");
			if (RegistryBranches.Any(b => String.IsNullOrWhiteSpace(b) || (!b.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase) && !b.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase) && !b.Equals("HKLM", StringComparison.OrdinalIgnoreCase) && !b.Equals("HKU", StringComparison.OrdinalIgnoreCase)))) throw new InvalidDataException("Ветки должны начинаться с HKLM или HKU.");
			if (Directories.Any(String.IsNullOrWhiteSpace)) throw new InvalidDataException("Каталоги не должны содержать пустые пути.");
			if (SelectedSids.Any(s => String.IsNullOrWhiteSpace(s) || !System.Text.RegularExpressions.Regex.IsMatch(s, @"^S-1-[0-9]+(-[0-9]+)+$"))) throw new InvalidDataException("Некорректный SID пользователя.");
			// Windows can normalize overflowing numeric subauthorities; reject them before native parsing.
			foreach (string sid in SelectedSids)
			{
				string[] parts = sid.Split('-'); ulong authority;
				if (parts.Length > 18 || !UInt64.TryParse(parts[2], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out authority) || authority > 0xFFFFFFFFFFFFUL)
					throw new InvalidDataException("Некорректный SID пользователя: недопустимый идентификатор центра или число частей.");
				for (int part = 3; part < parts.Length; part++)
				{
					uint component;
					if (!UInt32.TryParse(parts[part], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out component))
						throw new InvalidDataException("Некорректный SID пользователя: числовая часть превышает 32 бита.");
				}
			}
			try { foreach (string sid in SelectedSids) new System.Security.Principal.SecurityIdentifier(sid); }
			catch (ArgumentException error) { throw new InvalidDataException("Некорректный SID пользователя.", error); }
			if (String.IsNullOrWhiteSpace(OutputDirectory) || String.IsNullOrWhiteSpace(LogDirectory)) throw new InvalidDataException("Укажите каталог данных и журналов.");
			if (!String.IsNullOrWhiteSpace(SqlConnectionString)) { var cs = new System.Data.SqlClient.SqlConnectionStringBuilder(SqlConnectionString); if (!cs.IntegratedSecurity || !String.IsNullOrEmpty(cs.Password) || !String.IsNullOrEmpty(cs.UserID)) throw new InvalidDataException("Конфигурация SQL должна использовать Windows-аутентификацию без пароля."); }
		}
	}
	public static class Json
	{
		public static string Serialize<T>(T value) { using (var stream = new MemoryStream()) { new DataContractJsonSerializer(typeof(T)).WriteObject(stream, value); return Encoding.UTF8.GetString(stream.ToArray()); } }
		public static T Deserialize<T>(string text) { using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(text))) return (T)new DataContractJsonSerializer(typeof(T)).ReadObject(stream); }
		public static T Clone<T>(T value) { return Deserialize<T>(Serialize(value)); }
		public static void Save<T>(string path, T value)
		{
			string full = Path.GetFullPath(path); Directory.CreateDirectory(Path.GetDirectoryName(full)); string temp = full + "." + Guid.NewGuid().ToString("N") + ".tmp";
			try { using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) { var bytes = Encoding.UTF8.GetBytes(Serialize(value)); file.Write(bytes, 0, bytes.Length); file.Flush(true); } if (File.Exists(full)) File.Replace(temp, full, null); else File.Move(temp, full); }
			finally { if (File.Exists(temp)) File.Delete(temp); }
		}
	}
}
