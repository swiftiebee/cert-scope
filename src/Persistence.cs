using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace CertScope
{
	[DataContract]
	internal sealed class StoredEvent
	{
		[DataMember] public int Version { get; set; }
		[DataMember] public Guid EventId { get; set; }
		[DataMember] public Observation Observation { get; set; }
		[DataMember] public SourceReport Report { get; set; }
	}

	/// <summary>Неизменяемый журнал является рабочим хранилищем и устойчивой очередью доставки.</summary>
	public sealed class LocalRepository
	{
		private readonly string root;
		private readonly string eventsDirectory;
		private readonly string acknowledgementsDirectory;
		private readonly string mutexName;
		private readonly object gate = new object();
		public string LastSynchronizationError { get; private set; }
		public string RootDirectory { get { return root; } }

		public LocalRepository(string root)
		{
			if (String.IsNullOrWhiteSpace(root)) throw new ArgumentException("Не задан каталог рабочего хранилища.");
			var fullPath = Path.GetFullPath(root);
			// Directory names with and without a trailing separator must use the same mutex.
			this.root = fullPath.Length > Path.GetPathRoot(fullPath).Length
				? fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) : fullPath;
			eventsDirectory = Path.Combine(this.root, "events");
			acknowledgementsDirectory = Path.Combine(this.root, "acks");
			Directory.CreateDirectory(eventsDirectory);
			Directory.CreateDirectory(acknowledgementsDirectory);
			mutexName = "Local\\CertScope_" + Hash(Encoding.UTF8.GetBytes(this.root.ToUpperInvariant())).Substring(0, 32);
		}

		/// <summary>Сначала фиксирует весь результат на диске; только после этого событие доступно для SQL.</summary>
		public void SaveObservation(Observation observation)
		{
			if (observation == null || observation.Certificate == null) throw new ArgumentNullException("observation");
			if (observation.Id == Guid.Empty) observation.Id = Guid.NewGuid();
			ValidateObservation(observation);
			SaveEvent(new StoredEvent { Version = 1, EventId = observation.Id, Observation = observation });
		}

		private static void ValidateObservation(Observation observation)
		{
			if (observation.Certificate == null || observation.Id == Guid.Empty) throw new InvalidDataException("Неверное наблюдение.");
			NormalizeSerial(observation.Certificate.SerialNumber);
			if (observation.Certificate.Der == null || observation.Certificate.Der.Length == 0) throw new InvalidDataException("Пустой DER сертификата.");
			if (!String.Equals(Hash(observation.Certificate.Der), observation.Certificate.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("SHA-256 не соответствует DER сертификата.");
			ValidateLength(observation.Computer, 255, "Имя компьютера");
			ValidateLength(observation.UserSid, 256, "SID пользователя");
			ValidateLength(observation.RegistryView, 32, "Представление реестра");
		}

		private static void ValidateLength(string value, int maximum, string field)
		{
			if (value != null && value.Length > maximum) throw new InvalidDataException(field + ": превышено ограничение " + maximum + " символов. Событие не добавлено в очередь; данные не усечены.");
		}

		/// <summary>Сохраняет ошибки и сведения о полноте охвата наравне с успешными наблюдениями.</summary>
		public void SaveReport(SourceReport report)
		{
			if (report == null) throw new ArgumentNullException("report");
			ValidateLength(report.Computer, 255, "Имя компьютера");
			SaveEvent(new StoredEvent { Version = 1, EventId = ReportId(report), Report = report });
		}

		private static Guid ReportId(SourceReport report)
		{
			byte[] digest;
			using (var algorithm = SHA256.Create()) digest = algorithm.ComputeHash(Serialize(report));
			var guidBytes = new byte[16];
			Array.Copy(digest, guidBytes, guidBytes.Length);
			return new Guid(guidBytes);
		}

		private void SaveEvent(StoredEvent value)
		{
			var bytes = Serialize(value);
			WithLock(delegate
			{
				var path = EventPath(value.EventId);
				if (File.Exists(path))
				{
					if (!File.ReadAllBytes(path).SequenceEqual(bytes)) throw new InvalidDataException("Один EventId соответствует разным данным: " + value.EventId);
					return;
				}
				AtomicNewFile(path, bytes);
			});
		}

		public List<Observation> LoadObservations()
		{
			return ReadEvents().Where(e => e.Observation != null).Select(e => e.Observation).OrderBy(e => e.FoundUtc).ToList();
		}

		public List<SourceReport> LoadReports()
		{
			return ReadEvents().Where(e => e.Report != null).Select(e => e.Report).OrderBy(e => e.StartedUtc).ToList();
		}

		public List<string> GetSerialConflicts()
		{
			return LoadObservations().GroupBy(o => NormalizeSerial(o.Certificate.SerialNumber), StringComparer.Ordinal)
				.Where(g => g.Select(o => o.Certificate.Sha256).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1)
				.Select(g => "Серийный номер " + g.Key + ": " + String.Join(", ", g.Select(o => o.Certificate.Sha256).Distinct(StringComparer.OrdinalIgnoreCase))).ToList();
		}

		public int PendingCount
		{
			get
			{
				int count = 0;
				WithLock(delegate { count = Directory.GetFiles(eventsDirectory, "*.json").Count(p => !File.Exists(AckPath(Path.GetFileNameWithoutExtension(p)))); });
				return count;
			}
		}

		/// <summary>Доставляет события транзакционно. Повтор после commit безопасен благодаря AppliedEvents.</summary>
		public int Synchronize(string connectionString, CancellationToken cancellationToken)
		{
			LastSynchronizationError = null;
			int synchronized = 0;
			try
			{
				cancellationToken.ThrowIfCancellationRequested();
				var builder = new SqlConnectionStringBuilder(connectionString);
				if (!builder.IntegratedSecurity || !String.IsNullOrEmpty(builder.Password) || !String.IsNullOrEmpty(builder.UserID)) throw new ArgumentException("SQL использует Windows-аутентификацию. Удалите User ID/Password и включите Integrated Security.");
				if (String.IsNullOrWhiteSpace(builder.InitialCatalog)) throw new ArgumentException("Укажите существующую базу SQL в Initial Catalog.");
				builder.ConnectTimeout = Math.Min(builder.ConnectTimeout == 0 ? 15 : builder.ConnectTimeout, 15);
				builder.ApplicationName = "CertScope";
				var destination = Hash(Serialize(new[] { builder.DataSource.ToUpperInvariant(), builder.InitialCatalog.ToUpperInvariant() }));
				WithLock(delegate
				{
					var destinationPath = Path.Combine(root, "sql-destination.txt");
					if (File.Exists(destinationPath) && File.ReadAllText(destinationPath) != destination)
						throw new InvalidOperationException("Очередь привязана к другой базе SQL. Для доставки в новую базу используйте копию каталога events в новом рабочем каталоге без acks и sql-destination.txt. Исходные данные не изменены.");
				});
				using (var connection = new SqlConnection(builder.ConnectionString))
				{
					cancellationToken.ThrowIfCancellationRequested();
					connection.Open();
					EnsureSchema(connection, cancellationToken);
					WithLock(delegate
					{
						var destinationPath = Path.Combine(root, "sql-destination.txt");
						if (!File.Exists(destinationPath)) AtomicNewFile(destinationPath, Encoding.UTF8.GetBytes(destination));
						else if (File.ReadAllText(destinationPath) != destination) throw new InvalidOperationException("Другой процесс уже привязал очередь к другой базе SQL.");
					});
					foreach (var value in ReadEvents())
					{
						cancellationToken.ThrowIfCancellationRequested();
						if (File.Exists(AckPath(value.EventId.ToString("N")))) continue;
						for (int attempt = 0; ; attempt++)
						{
							try { ApplyEvent(connection, value, cancellationToken); break; }
							catch (SqlException ex)
							{
								if (ex.Number != 1205 || attempt >= 2) throw;
								if (cancellationToken.WaitHandle.WaitOne(100 * (attempt + 1))) cancellationToken.ThrowIfCancellationRequested();
							}
						}
						WithLock(delegate
						{
							var ackPath = AckPath(value.EventId.ToString("N"));
							if (!File.Exists(ackPath)) AtomicNewFile(ackPath, Encoding.UTF8.GetBytes(DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture)));
						});
						synchronized++;
					}
				}
				return synchronized;
			}
			catch (Exception ex)
			{
				// Connection strings and credentials are deliberately not included in diagnostics.
				LastSynchronizationError = ex.GetType().Name + ": " + ex.Message;
				throw;
			}
		}

		private List<StoredEvent> ReadEvents()
		{
			var values = new List<StoredEvent>();
			WithLock(delegate
			{
				foreach (var path in Directory.GetFiles(eventsDirectory, "*.json").OrderBy(p => p, StringComparer.Ordinal))
				{
					try
					{
						var value = Deserialize<StoredEvent>(File.ReadAllBytes(path));
						if (value == null || value.Version != 1 || value.EventId == Guid.Empty || (value.Observation == null) == (value.Report == null) || Path.GetFileNameWithoutExtension(path) != value.EventId.ToString("N")) throw new InvalidDataException("Неверная структура события.");
						if (value.Observation != null)
						{
							ValidateObservation(value.Observation);
							if (value.Observation.Id != value.EventId) throw new InvalidDataException("EventId наблюдения не совпадает с конвертом.");
						}
						else if (ReportId(value.Report) != value.EventId) throw new InvalidDataException("Контрольная сумма отчёта не совпадает с EventId.");
						values.Add(value);
					}
					catch (Exception ex) { throw new InvalidDataException("Повреждено событие " + Path.GetFileName(path) + ". Исходный файл сохранён; восстановите его из резервной копии.", ex); }
				}
			});
			return values;
		}

		private void WithLock(Action action)
		{
			lock (gate)
			using (var mutex = new Mutex(false, mutexName))
			{
				bool acquired = false;
				try
				{
					try { acquired = mutex.WaitOne(TimeSpan.FromSeconds(30)); }
					catch (AbandonedMutexException) { acquired = true; }
					if (!acquired) throw new TimeoutException("Рабочее хранилище занято другим процессом более 30 секунд.");
					action();
				}
				finally { if (acquired) mutex.ReleaseMutex(); }
			}
		}

		private string EventPath(Guid id) { return Path.Combine(eventsDirectory, id.ToString("N") + ".json"); }
		private string AckPath(string id) { return Path.Combine(acknowledgementsDirectory, id + ".ack"); }

		internal static byte[] Serialize<T>(T value)
		{
			using (var stream = new MemoryStream())
			{
				new DataContractJsonSerializer(typeof(T)).WriteObject(stream, value);
				return stream.ToArray();
			}
		}

		internal static T Deserialize<T>(byte[] bytes)
		{
			using (var stream = new MemoryStream(bytes)) return (T)new DataContractJsonSerializer(typeof(T)).ReadObject(stream);
		}

		internal static void AtomicNewFile(string path, byte[] content)
		{
			var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
			try
			{
				using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough))
				{
					stream.Write(content, 0, content.Length);
					stream.Flush(true);
				}
				File.Move(temporary, path);
			}
			finally { if (File.Exists(temporary)) File.Delete(temporary); }
		}

		public static string NormalizeSerial(string value)
		{
			if (String.IsNullOrWhiteSpace(value)) throw new InvalidDataException("Серийный номер отсутствует.");
			var normalized = new string(value.Where(c => !Char.IsWhiteSpace(c) && c != ':' && c != '-').ToArray()).ToUpperInvariant();
			if (normalized.Length == 0 || normalized.Any(c => !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))) throw new InvalidDataException("Серийный номер должен быть шестнадцатеричным.");
			normalized = normalized.TrimStart('0');
			if (normalized.Length == 0) normalized = "0";
			if (normalized.Length > 512) throw new InvalidDataException("Серийный номер превышает поддерживаемые 512 символов; запись не усечена.");
			return normalized;
		}

		internal static string Hash(byte[] bytes)
		{
			using (var algorithm = SHA256.Create()) return BitConverter.ToString(algorithm.ComputeHash(bytes)).Replace("-", "");
		}

		private static void EnsureSchema(SqlConnection connection, CancellationToken token)
		{
			using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
			using (var command = new SqlCommand(SchemaSql, connection, transaction))
			{
				command.CommandTimeout = 30;
				using (token.Register(command.Cancel)) { command.ExecuteNonQuery(); token.ThrowIfCancellationRequested(); transaction.Commit(); }
			}
		}

		private static void ApplyEvent(SqlConnection connection, StoredEvent value, CancellationToken token)
		{
			using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
			using (var command = new SqlCommand(value.Observation == null ? ReportSql : ObservationSql, connection, transaction))
			{
				command.CommandTimeout = 30;
				Add(command, "@EventId", SqlDbType.UniqueIdentifier, value.EventId);
				var payloadBytes = Serialize(value);
				Add(command, "@Payload", SqlDbType.NVarChar, Encoding.UTF8.GetString(payloadBytes), -1);
				Add(command, "@PayloadHash", SqlDbType.Char, Hash(payloadBytes), 64);
				if (value.Observation != null)
				{
					var observation = value.Observation;
					var certificate = observation.Certificate;
					var location = new[] { certificate.Sha256.ToUpperInvariant(), (observation.Computer ?? "").ToUpperInvariant(), observation.Source ?? "", observation.UserSid ?? "", observation.RegistryView ?? "" };
					Add(command, "@Serial", SqlDbType.NVarChar, NormalizeSerial(certificate.SerialNumber), 512);
					Add(command, "@Sha", SqlDbType.Char, certificate.Sha256.ToUpperInvariant(), 64);
					Add(command, "@Der", SqlDbType.VarBinary, certificate.Der, -1);
					Add(command, "@Metadata", SqlDbType.NVarChar, Encoding.UTF8.GetString(Serialize(certificate)), -1);
					Add(command, "@OwnerName", SqlDbType.NVarChar, certificate.DisplayName ?? "", -1);
					Add(command, "@Subject", SqlDbType.NVarChar, certificate.Subject ?? "", -1);
					Add(command, "@Issuer", SqlDbType.NVarChar, certificate.Issuer ?? "", -1);
					Add(command, "@NotBefore", SqlDbType.DateTime2, certificate.NotBeforeUtc.ToUniversalTime());
					Add(command, "@NotAfter", SqlDbType.DateTime2, certificate.NotAfterUtc.ToUniversalTime());
					Add(command, "@LicenseStatus", SqlDbType.NVarChar, certificate.LicenseStatus ?? "", -1);
					Add(command, "@LicenseVersion", SqlDbType.NVarChar, certificate.LicenseVersion ?? "", -1);
					Add(command, "@Location", SqlDbType.Char, Hash(Serialize(location)), 64);
					Add(command, "@ScanId", SqlDbType.UniqueIdentifier, observation.ScanId);
					Add(command, "@Computer", SqlDbType.NVarChar, observation.Computer ?? "", 255);
					Add(command, "@Source", SqlDbType.NVarChar, observation.Source ?? "", -1);
					Add(command, "@Sid", SqlDbType.NVarChar, observation.UserSid ?? "", 256);
					Add(command, "@View", SqlDbType.NVarChar, observation.RegistryView ?? "", 32);
					Add(command, "@Found", SqlDbType.DateTime2, observation.FoundUtc.ToUniversalTime());
				}
				else
				{
					var report = value.Report;
					Add(command, "@ScanId", SqlDbType.UniqueIdentifier, report.ScanId);
					Add(command, "@Computer", SqlDbType.NVarChar, report.Computer ?? "", 255);
					Add(command, "@Source", SqlDbType.NVarChar, report.Source ?? "", -1);
					Add(command, "@Status", SqlDbType.NVarChar, report.Status.ToString(), 64);
				}
				using (token.Register(command.Cancel)) { token.ThrowIfCancellationRequested(); command.ExecuteNonQuery(); token.ThrowIfCancellationRequested(); transaction.Commit(); }
			}
		}

		private static void Add(SqlCommand command, string name, SqlDbType type, object value, int size = 0)
		{
			if (size > 0 && value is string && ((string)value).Length > size) throw new InvalidDataException(name + ": значение длиннее ограничения SQL; запись не усечена.");
			var parameter = size == 0 ? command.Parameters.Add(name, type) : command.Parameters.Add(name, type, size);
			parameter.Value = value ?? DBNull.Value;
		}

		private const string EventPrefix = @"
SET XACT_ABORT ON;
DECLARE @lockResult int;
EXEC @lockResult = sys.sp_getapplock @Resource=N'CertScope.Import', @LockMode=N'Exclusive', @LockOwner=N'Transaction', @LockTimeout=25000;
IF @lockResult < 0 THROW 51001, N'Не удалось получить блокировку импорта CertScope.', 1;
IF EXISTS (SELECT 1 FROM dbo.CS_AppliedEvents WITH (UPDLOCK,HOLDLOCK) WHERE EventId=@EventId AND PayloadSha256<>@PayloadHash)
 THROW 51005, N'Один EventId содержит разные данные. Импорт отклонён без потери очереди.', 1;
IF NOT EXISTS (SELECT 1 FROM dbo.CS_AppliedEvents WITH (UPDLOCK,HOLDLOCK) WHERE EventId=@EventId)
BEGIN
DECLARE @now datetime2(7)=SYSUTCDATETIME();
";
		private const string ObservationSql = EventPrefix + @"
IF NOT EXISTS (SELECT 1 FROM dbo.CS_CertificateVariants WHERE Sha256=@Sha)
 INSERT dbo.CS_CertificateVariants(Sha256,Der,OwnerName,Subject,Issuer,NotBeforeUtc,NotAfterUtc,LicenseStatus,LicenseVersion,MetadataJson,CreatedUtc) VALUES(@Sha,@Der,@OwnerName,@Subject,@Issuer,@NotBefore,@NotAfter,@LicenseStatus,@LicenseVersion,@Metadata,@now);
ELSE
 UPDATE dbo.CS_CertificateVariants SET OwnerName=@OwnerName,Subject=@Subject,Issuer=@Issuer,NotBeforeUtc=@NotBefore,NotAfterUtc=@NotAfter,LicenseStatus=@LicenseStatus,LicenseVersion=@LicenseVersion,MetadataJson=@Metadata WHERE Sha256=@Sha;
IF NOT EXISTS (SELECT 1 FROM dbo.CS_Certificates WHERE SerialNumber=@Serial)
 INSERT dbo.CS_Certificates(SerialNumber,CanonicalSha256,CreatedUtc,UpdatedUtc) VALUES(@Serial,@Sha,@now,@now);
ELSE
BEGIN
 DECLARE @canonical char(64)=(SELECT CanonicalSha256 FROM dbo.CS_Certificates WHERE SerialNumber=@Serial);
 UPDATE dbo.CS_Certificates SET UpdatedUtc=@now WHERE SerialNumber=@Serial;
 IF @canonical<>@Sha AND NOT EXISTS (SELECT 1 FROM dbo.CS_SerialConflicts WHERE SerialNumber=@Serial AND IncomingSha256=@Sha)
  INSERT dbo.CS_SerialConflicts(SerialNumber,CanonicalSha256,IncomingSha256,DetectedUtc) VALUES(@Serial,@canonical,@Sha,@now);
END;
IF NOT EXISTS (SELECT 1 FROM dbo.CS_SerialVariants WHERE SerialNumber=@Serial AND Sha256=@Sha)
 INSERT dbo.CS_SerialVariants(SerialNumber,Sha256) VALUES(@Serial,@Sha);
IF NOT EXISTS (SELECT 1 FROM dbo.CS_Locations WHERE LocationKey=@Location)
 INSERT dbo.CS_Locations(LocationKey,Sha256,Computer,Source,UserSid,RegistryView,FirstSeenUtc,LastSeenUtc) VALUES(@Location,@Sha,@Computer,@Source,@Sid,@View,@Found,@Found);
ELSE
 UPDATE dbo.CS_Locations SET FirstSeenUtc=CASE WHEN FirstSeenUtc>@Found THEN @Found ELSE FirstSeenUtc END, LastSeenUtc=CASE WHEN LastSeenUtc<@Found THEN @Found ELSE LastSeenUtc END WHERE LocationKey=@Location;
INSERT dbo.CS_Observations(EventId,ScanId,SerialNumber,Sha256,LocationKey,FoundUtc,PayloadJson) VALUES(@EventId,@ScanId,@Serial,@Sha,@Location,@Found,@Payload);
INSERT dbo.CS_AppliedEvents(EventId,EventKind,PayloadSha256,AppliedUtc) VALUES(@EventId,'O',@PayloadHash,@now);
END;";
		private const string ReportSql = EventPrefix + @"
INSERT dbo.CS_SourceReports(EventId,ScanId,Computer,Source,Status,PayloadJson) VALUES(@EventId,@ScanId,@Computer,@Source,@Status,@Payload);
INSERT dbo.CS_AppliedEvents(EventId,EventKind,PayloadSha256,AppliedUtc) VALUES(@EventId,'R',@PayloadHash,@now);
END;";

		// This migration is intentionally self-contained: the EXE can initialize an existing empty database.
		internal const string SchemaSql = @"
SET XACT_ABORT ON;
DECLARE @schemaLock int;
EXEC @schemaLock=sys.sp_getapplock @Resource=N'CertScope.Schema', @LockMode=N'Exclusive', @LockOwner=N'Transaction', @LockTimeout=25000;
IF @schemaLock<0 THROW 51002, N'Не удалось получить блокировку схемы CertScope.', 1;
IF OBJECT_ID(N'dbo.CS_SchemaVersion',N'U') IS NOT NULL
BEGIN
 IF EXISTS(SELECT 1 FROM dbo.CS_SchemaVersion WHERE Version<>1) THROW 51003, N'Неподдерживаемая версия схемы CertScope.',1;
END;
IF OBJECT_ID(N'dbo.CS_SchemaVersion',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_Certificates',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_CertificateVariants',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_SerialVariants',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_SerialConflicts',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_Locations',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_Observations',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_SourceReports',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_AppliedEvents',N'U') IS NULL
BEGIN
 IF ISNULL(HAS_PERMS_BY_NAME(DB_NAME(),'DATABASE','CREATE TABLE'),0)<>1 OR ISNULL(HAS_PERMS_BY_NAME(N'dbo','SCHEMA','ALTER'),0)<>1
  THROW 51004,N'Для первичной миграции нужны CREATE TABLE в базе и ALTER схемы dbo. Администратор может применить sql/schema.sql заранее.',1;
END;
IF OBJECT_ID(N'dbo.CS_SchemaVersion',N'U') IS NULL
 CREATE TABLE dbo.CS_SchemaVersion(Version int NOT NULL CONSTRAINT PK_CS_SchemaVersion PRIMARY KEY, AppliedUtc datetime2(7) NOT NULL);
IF OBJECT_ID(N'dbo.CS_CertificateVariants',N'U') IS NULL
 CREATE TABLE dbo.CS_CertificateVariants(Sha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT PK_CS_CertificateVariants PRIMARY KEY, Der varbinary(max) NOT NULL,OwnerName nvarchar(max) NOT NULL,Subject nvarchar(max) NOT NULL,Issuer nvarchar(max) NOT NULL,NotBeforeUtc datetime2(7) NOT NULL,NotAfterUtc datetime2(7) NOT NULL,LicenseStatus nvarchar(max) NOT NULL,LicenseVersion nvarchar(max) NOT NULL, MetadataJson nvarchar(max) NOT NULL, CreatedUtc datetime2(7) NOT NULL);
IF OBJECT_ID(N'dbo.CS_Certificates',N'U') IS NULL
 CREATE TABLE dbo.CS_Certificates(SerialNumber nvarchar(512) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT PK_CS_Certificates PRIMARY KEY NONCLUSTERED, CanonicalSha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_Certificates_Variant REFERENCES dbo.CS_CertificateVariants(Sha256),CreatedUtc datetime2(7) NOT NULL,UpdatedUtc datetime2(7) NOT NULL);
IF OBJECT_ID(N'dbo.CS_SerialVariants',N'U') IS NULL
 CREATE TABLE dbo.CS_SerialVariants(SerialNumber nvarchar(512) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_SerialVariants_Certificate REFERENCES dbo.CS_Certificates(SerialNumber),Sha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_SerialVariants_Variant REFERENCES dbo.CS_CertificateVariants(Sha256),CONSTRAINT PK_CS_SerialVariants PRIMARY KEY NONCLUSTERED(SerialNumber,Sha256));
IF OBJECT_ID(N'dbo.CS_SerialConflicts',N'U') IS NULL
 CREATE TABLE dbo.CS_SerialConflicts(SerialNumber nvarchar(512) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_SerialConflicts_Certificate REFERENCES dbo.CS_Certificates(SerialNumber),CanonicalSha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_SerialConflicts_Canonical REFERENCES dbo.CS_CertificateVariants(Sha256),IncomingSha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_SerialConflicts_Incoming REFERENCES dbo.CS_CertificateVariants(Sha256),DetectedUtc datetime2(7) NOT NULL,CONSTRAINT PK_CS_SerialConflicts PRIMARY KEY NONCLUSTERED(SerialNumber,IncomingSha256));
IF OBJECT_ID(N'dbo.CS_Locations',N'U') IS NULL
 CREATE TABLE dbo.CS_Locations(LocationKey char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT PK_CS_Locations PRIMARY KEY,Sha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_Locations_Variant REFERENCES dbo.CS_CertificateVariants(Sha256),Computer nvarchar(255) NOT NULL,Source nvarchar(max) NOT NULL,UserSid nvarchar(256) NOT NULL,RegistryView nvarchar(32) NOT NULL,FirstSeenUtc datetime2(7) NOT NULL,LastSeenUtc datetime2(7) NOT NULL);
IF OBJECT_ID(N'dbo.CS_Observations',N'U') IS NULL
 CREATE TABLE dbo.CS_Observations(EventId uniqueidentifier NOT NULL CONSTRAINT PK_CS_Observations PRIMARY KEY,ScanId uniqueidentifier NOT NULL,SerialNumber nvarchar(512) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_Observations_Certificate REFERENCES dbo.CS_Certificates(SerialNumber),Sha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_Observations_Variant REFERENCES dbo.CS_CertificateVariants(Sha256),LocationKey char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_Observations_Location REFERENCES dbo.CS_Locations(LocationKey),FoundUtc datetime2(7) NOT NULL,PayloadJson nvarchar(max) NOT NULL);
IF OBJECT_ID(N'dbo.CS_SourceReports',N'U') IS NULL
 CREATE TABLE dbo.CS_SourceReports(EventId uniqueidentifier NOT NULL CONSTRAINT PK_CS_SourceReports PRIMARY KEY,ScanId uniqueidentifier NOT NULL,Computer nvarchar(255) NOT NULL,Source nvarchar(max) NOT NULL,Status nvarchar(64) NOT NULL,PayloadJson nvarchar(max) NOT NULL);
IF OBJECT_ID(N'dbo.CS_AppliedEvents',N'U') IS NULL
 CREATE TABLE dbo.CS_AppliedEvents(EventId uniqueidentifier NOT NULL CONSTRAINT PK_CS_AppliedEvents PRIMARY KEY,EventKind char(1) NOT NULL,PayloadSha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL,AppliedUtc datetime2(7) NOT NULL);
IF NOT EXISTS(SELECT 1 FROM dbo.CS_SchemaVersion) INSERT dbo.CS_SchemaVersion(Version,AppliedUtc) VALUES(1,SYSUTCDATETIME());
";
	}
}
