using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CertScope;

/// <summary>Regression checks without a Main; also compiled into the common test suite.</summary>
public static class StorageRegression
{
	public static void RunLocal(string projectRoot, string output)
	{
		Directory.CreateDirectory(output);
		var certificate = CertificateParser.Parse(File.ReadAllBytes(Path.Combine(projectRoot, "inputs", "organizer-1.cer"))).Single();
		var location = Path.Combine(output, "same-directory");
		var repository = new LocalRepository(location);
		var withSlash = new LocalRepository(location + Path.DirectorySeparatorChar);
		Assert(repository.RootDirectory == withSlash.RootDirectory, "Repository aliases must use the same lock identity.");
		var observation = Observe(certificate);
		Parallel.For(0, 32, i => (i % 2 == 0 ? repository : withSlash).SaveObservation(observation));
		Assert(repository.LoadObservations().Count == 1, "Concurrent replay duplicates an event.");
		var invalid = Observe(certificate); invalid.Computer = new string('X', 256);
		Expect<InvalidDataException>(() => repository.SaveObservation(invalid));
		Expect<InvalidDataException>(() => repository.SaveReport(new SourceReport { Computer = new string('X', 256), ScanId = Guid.NewGuid() }));
		Assert(repository.PendingCount == 1, "Invalid event poisoned the queue.");
		using (var cancel = new CancellationTokenSource()) { cancel.Cancel(); Expect<OperationCanceledException>(() => repository.Synchronize("invalid connection string", cancel.Token)); }
		var duplicate = Json.Clone(certificate); duplicate.Der = new byte[] { 1, 2, 3 };
		var cerDirectory = Path.Combine(output, "invalid-cer");
		Expect<InvalidDataException>(() => ExportService.ExportCer(cerDirectory, new[] { observation, Observe(duplicate) }));
		Assert(!Directory.Exists(cerDirectory), "CER export wrote files before input validation.");
		ExportService.ExportCer(Path.Combine(output, "valid-cer"), new[] { observation, observation });
		Assert(Directory.GetFiles(Path.Combine(output, "valid-cer"), "*.cer").Length == 1, "CER duplicate exported twice.");
		var target = Path.Combine(output, "existing.txt"); File.WriteAllText(target, "Existing report", Encoding.UTF8);
		Expect<InvalidDataException>(() => ExportService.ExportText(target, new[] { new Observation() }));
		Assert(File.ReadAllText(target, Encoding.UTF8) == "Existing report", "Failed export overwrote the previous report.");
	}

	/// <summary>Only writes to an explicitly supplied existing, empty SQL Server 2019 database.</summary>
	public static int RunSql(string server, string database, string projectRoot, string output, bool trustCertificate)
	{
		Directory.CreateDirectory(output);
		var log = new List<string>();
		Action<string> pass = name => { string line = "PASS " + name; Console.WriteLine(line); log.Add(DateTime.UtcNow.ToString("o") + " " + line); };
		try
		{
			Assert(!new[] { "master", "model", "msdb", "tempdb" }.Contains(database, StringComparer.OrdinalIgnoreCase), "System databases are forbidden.");
			var builder = new SqlConnectionStringBuilder { DataSource = server, InitialCatalog = database, IntegratedSecurity = true, Encrypt = true, TrustServerCertificate = trustCertificate, ConnectTimeout = 5 };
			using (var connection = new SqlConnection(builder.ConnectionString))
			{
				connection.Open();
				Assert(Convert.ToInt32(Scalar(connection, "SELECT CAST(SERVERPROPERTY('ProductMajorVersion') AS int)")) == 15, "SQL Server 2019 required.");
				Assert(Convert.ToInt32(Scalar(connection, "SELECT COUNT(*) FROM sys.tables WHERE is_ms_shipped=0")) == 0, "An EMPTY test database is required; no data was deleted.");
				pass("SQL Server 2019 and empty isolated database verified");
				var firstBytes = File.ReadAllBytes(Path.Combine(projectRoot, "inputs", "organizer-1.cer"));
				var secondBytes = File.ReadAllBytes(Path.Combine(projectRoot, "inputs", "organizer-2.cer"));
				var certificate = CertificateParser.Parse(firstBytes).Single();
				var repository = new LocalRepository(Path.Combine(output, "main"));
				var first = Observe(certificate); repository.SaveObservation(first); repository.Synchronize(builder.ConnectionString, CancellationToken.None);
				Assert(Count(connection, "CS_Certificates") == 1, "First certificate missing.");
				Assert(Convert.ToInt32(Scalar(connection, "SELECT COUNT(*) FROM dbo.CS_Certificates WHERE CreatedUtc=UpdatedUtc")) == 1, "Initial timestamps differ.");
				var created = (DateTime)Scalar(connection, "SELECT CreatedUtc FROM dbo.CS_Certificates");
				var updated = (DateTime)Scalar(connection, "SELECT UpdatedUtc FROM dbo.CS_Certificates");
				pass("Schema migration and initial CreatedUtc=UpdatedUtc");
				repository.SaveObservation(first); repository.Synchronize(builder.ConnectionString, CancellationToken.None);
				Assert(Count(connection, "CS_Observations") == 1 && (DateTime)Scalar(connection, "SELECT UpdatedUtc FROM dbo.CS_Certificates") == updated, "Replay changed data/time.");
				pass("Duplicate EventId remains idempotent");
				File.Move(Path.Combine(repository.RootDirectory, "acks", first.Id.ToString("N") + ".ack"), Path.Combine(output, "simulated-lost-ack.txt"));
				repository = new LocalRepository(repository.RootDirectory); Assert(repository.PendingCount == 1, "Lost ack did not requeue event.");
				repository.Synchronize(builder.ConnectionString, CancellationToken.None);
				Assert(repository.PendingCount == 0 && Count(connection, "CS_Observations") == 1 && (DateTime)Scalar(connection, "SELECT UpdatedUtc FROM dbo.CS_Certificates") == updated, "Commit/ack recovery changed data.");
				pass("Restart after commit before acknowledgement does not duplicate data");
				Thread.Sleep(25); repository.SaveObservation(Observe(certificate)); repository.Synchronize(builder.ConnectionString, CancellationToken.None);
				Assert((DateTime)Scalar(connection, "SELECT CreatedUtc FROM dbo.CS_Certificates") == created && (DateTime)Scalar(connection, "SELECT UpdatedUtc FROM dbo.CS_Certificates") > updated && Count(connection, "CS_Locations") == 1, "Reimport timestamps/location wrong.");
				pass("New observation updates time while preserving creation date/location");
				var parallelRoots = Enumerable.Range(0, 6).Select(i => Path.Combine(output, "parallel-" + i)).ToArray();
				foreach (var path in parallelRoots) new LocalRepository(path).SaveObservation(Observe(certificate));
				Parallel.ForEach(parallelRoots, new ParallelOptions { MaxDegreeOfParallelism = 4 }, path => new LocalRepository(path).Synchronize(builder.ConnectionString, CancellationToken.None));
				Assert(Count(connection, "CS_Certificates") == 1 && Count(connection, "CS_CertificateVariants") == 1 && Count(connection, "CS_Observations") == 8 && Count(connection, "CS_Locations") == 1, "Concurrent counts/uniqueness wrong.");
				pass("Six concurrent SQL clients preserve events and unique serial/location");
				var reusedRepository = new LocalRepository(Path.Combine(output, "event-id-collision"));
				var reused = Observe(certificate); reused.Id = first.Id; reused.Source = "SYNTHETIC changed payload with reused EventId"; reusedRepository.SaveObservation(reused);
				int failure = 0; try { reusedRepository.Synchronize(builder.ConnectionString, CancellationToken.None); } catch (SqlException ex) { failure = ex.Number; }
				Assert(failure == 51005 && reusedRepository.PendingCount == 1 && Count(connection, "CS_Observations") == 8, "Payload collision not rejected atomically.");
				pass("Changed payload with reused EventId is rejected without loss");
				var collisionBytes = CopySerial(secondBytes, firstBytes); File.WriteAllBytes(Path.Combine(output, "SYNTHETIC-invalid-signature-serial-collision.cer"), collisionBytes);
				var collision = CertificateParser.Parse(collisionBytes).Single(); Assert(collision.SerialNumber == certificate.SerialNumber && collision.Sha256 != certificate.Sha256, "Invalid fixture.");
				var colliding = Observe(collision); colliding.Source = "SYNTHETIC metadata test, invalid signature"; repository.SaveObservation(colliding); repository.Synchronize(builder.ConnectionString, CancellationToken.None);
				Assert(Count(connection, "CS_Certificates") == 1 && Count(connection, "CS_CertificateVariants") == 2 && Count(connection, "CS_SerialConflicts") == 1, "Collision did not preserve DER variants.");
				Assert((string)Scalar(connection, "SELECT CanonicalSha256 FROM dbo.CS_Certificates") == certificate.Sha256 && (DateTime)Scalar(connection, "SELECT CreatedUtc FROM dbo.CS_Certificates") == created, "Collision overwrote original.");
				pass("Serial collision retains original, both DER variants and explicit conflict");
				var report = new SourceReport { ScanId = first.ScanId, Computer = "CERTSCOPE-LAB", Source = "SQL integration coverage", Status = SourceStatus.Partial, StartedUtc = DateTime.UtcNow, FinishedUtc = DateTime.UtcNow, Message = "Synthetic coverage test" };
				repository.SaveReport(report); repository.SaveReport(report); repository.Synchronize(builder.ConnectionString, CancellationToken.None);
				Assert(Count(connection, "CS_SourceReports") == 1, "Report replay duplicated coverage."); pass("Coverage delivery is idempotent");
				File.WriteAllLines(Path.Combine(output, "database-counts.txt"), new[] { "Server=" + server, "Database=" + database, "CS_Certificates=" + Count(connection, "CS_Certificates"), "CS_CertificateVariants=" + Count(connection, "CS_CertificateVariants"), "CS_Observations=" + Count(connection, "CS_Observations"), "CS_SourceReports=" + Count(connection, "CS_SourceReports"), "CS_AppliedEvents=" + Count(connection, "CS_AppliedEvents"), "CS_SerialConflicts=" + Count(connection, "CS_SerialConflicts") }, Encoding.UTF8);
			}
			return 0;
		}
		catch (Exception ex) { Console.Error.WriteLine(ex); log.Add("FAIL " + ex); return 1; }
		finally
		{
			File.WriteAllLines(Path.Combine(output, "results.txt"), log, Encoding.UTF8);
			File.WriteAllText(Path.Combine(output, "README.txt"), "Existing databases were not changed. Test data remains in the supplied test database.\r\nSynthetic collision DER has an invalid signature and is only a metadata fixture.\r\n", Encoding.UTF8);
		}
	}

	private static int Count(SqlConnection connection, string table) { return Convert.ToInt32(Scalar(connection, "SELECT COUNT(*) FROM dbo." + table)); }
	private static object Scalar(SqlConnection connection, string query) { using (var command = new SqlCommand(query, connection)) { command.CommandTimeout = 30; return command.ExecuteScalar(); } }
	private static Observation Observe(CertificateRecord certificate) { return new Observation { Id = Guid.NewGuid(), ScanId = Guid.NewGuid(), Computer = "CERTSCOPE-LAB", Source = "SQL integration test", UserSid = "", RegistryView = "Test", FoundUtc = DateTime.UtcNow, Certificate = certificate }; }
	private static void Assert(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
	private static void Expect<T>(Action action) where T : Exception { try { action(); } catch (T) { return; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
	private static byte[] CopySerial(byte[] template, byte[] source)
	{
		int offset, length, sourceOffset, sourceLength; SerialRange(template, out offset, out length); SerialRange(source, out sourceOffset, out sourceLength);
		Assert(length == sourceLength, "Fixtures have different serial lengths."); var result = (byte[])template.Clone(); Buffer.BlockCopy(source, sourceOffset, result, offset, length); return result;
	}
	private static void SerialRange(byte[] bytes, out int content, out int length)
	{
		int end; ReadHeader(bytes, 0, 0x30, out content, out length, out end); ReadHeader(bytes, content, 0x30, out content, out length, out end);
		if (bytes[content] == 0xA0) { int ignored; ReadHeader(bytes, content, 0xA0, out ignored, out length, out end); content = end; }
		ReadHeader(bytes, content, 0x02, out content, out length, out end);
	}
	private static void ReadHeader(byte[] bytes, int offset, int tag, out int content, out int length, out int end)
	{
		Assert(offset >= 0 && offset + 2 <= bytes.Length && bytes[offset++] == tag, "Invalid fixture ASN.1."); int first = bytes[offset++]; length = first;
		if ((first & 128) != 0) { int count = first & 127; Assert(count > 0 && count <= 4 && offset + count <= bytes.Length, "Invalid ASN.1 length."); length = 0; for (int i = 0; i < count; i++) length = checked(length * 256 + bytes[offset++]); }
		content = offset; end = checked(content + length); Assert(end <= bytes.Length, "Truncated ASN.1 fixture.");
	}
}
