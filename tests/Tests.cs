using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using CertScope;
using Microsoft.Win32;

internal static class Tests
{
	private static int passed, failed, skipped;
	private static readonly List<string> log = new List<string>();
	private static string root, output;
	private static byte[] der;
	private static CertificateRecord certificate;
	[STAThread]
	private static int Main(string[] args)
	{
		if (args.Length > 0 && args[0] == "--worker") { if (Environment.GetEnvironmentVariable("CERTSCOPE_TEST_SLOW_WORKER") == "1") Thread.Sleep(15000); return Scanner.RunWorker(); }
		if (args.Length > 0 && args[0] == "--network")
		{
			if (args.Length != 5) { Console.Error.WriteLine("Usage: CertScope.Tests.exe --network projectRoot computer user domain; password from standard input."); return 2; }
			string networkPassword = Console.ReadLine();
			if (networkPassword == null) { Console.Error.WriteLine("No password supplied on standard input; no network authentication attempted."); return 2; }
			try { return NetworkIntegration.Run(args[1], args[2], args[3], args[4], networkPassword); }
			finally { networkPassword = null; }
		}
		root = args.Length > 0 ? args[0] : Path.GetFullPath("..");
		output = Path.Combine(root, "artifacts", "test-run-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss")); Directory.CreateDirectory(output);
		der = File.ReadAllBytes(Path.Combine(root, "inputs", "organizer-1.cer"));
		Run("Exact target .NET Framework 4.5", () => Equal(".NETFramework,Version=v4.5", ((TargetFrameworkAttribute)Attribute.GetCustomAttribute(typeof(CertificateParser).Assembly, typeof(TargetFrameworkAttribute))).FrameworkName));
		Run("Organizer DER, SHA-256, serial and dates", () => { certificate = CertificateParser.Parse(der).Single(); var native = new X509Certificate2(der); try { Equal(LocalRepository.NormalizeSerial(native.SerialNumber), certificate.SerialNumber); Equal(native.NotAfter.ToUniversalTime(), certificate.NotAfterUtc); Equal(native.NotBefore.ToUniversalTime(), certificate.NotBeforeUtc); } finally { native.Reset(); } using(var hash=SHA256.Create()) Equal(BitConverter.ToString(hash.ComputeHash(der)).Replace("-",""),certificate.Sha256); True(certificate.Der.SequenceEqual(der)); True(certificate.SubjectAttributes.Count>0); });
		Run("Organizer second certificate distinct", () => True(CertificateParser.Parse(File.ReadAllBytes(Path.Combine(root,"inputs","organizer-2.cer"))).Single().Sha256 != certificate.Sha256));
		Run("PEM content detection and multiple blocks dedup", () => { var pem = "-----BEGIN CERTIFICATE-----\n"+Convert.ToBase64String(der)+"\n-----END CERTIFICATE-----\n"; Equal(certificate.Sha256,CertificateParser.Parse(Encoding.UTF8.GetBytes(pem+pem)).Single().Sha256); });
		Run("Serialized Windows certificate exact DER", () => True(CertificateParser.Parse(NativeExport(X509ContentType.SerializedCert)).Single().Der.SequenceEqual(der)));
		Run("PKCS7 and serialized Windows store", () => { var collection = new X509Certificate2Collection(new X509Certificate2(der)); foreach(var type in new[]{X509ContentType.Pkcs7,X509ContentType.SerializedStore}) True(CertificateParser.Parse(collection.Export(type)).Single().Der.SequenceEqual(der)); });
		Run("PKCS12 rejected without key import", () => Throws<NotSupportedException>(()=>CertificateParser.Parse(NativeExport(X509ContentType.Pfx))));
		Run("Private key PEM rejected", () => Throws<NotSupportedException>(()=>CertificateParser.Parse(Encoding.ASCII.GetBytes("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"))));
		Run("Empty/truncated/corrupt certificate rejected", () => { Throws<CryptographicException>(()=>CertificateParser.Parse(new byte[0])); Throws<CryptographicException>(()=>CertificateParser.Parse(der.Take(der.Length-5).ToArray())); Throws<CryptographicException>(()=>CertificateParser.Parse(new byte[]{1,2,3})); });
		Run("DER trailing garbage rejected", () => Throws<CryptographicException>(()=>CertificateParser.Parse(der.Concat(new byte[]{0,0}).ToArray())));
		Run("Serial normalization and invalid input", () => { Equal("AB01",LocalRepository.NormalizeSerial(" 00:ab:01 ")); Throws<InvalidDataException>(()=>LocalRepository.NormalizeSerial("xyz")); });
		Run("Synthetic RDN, unknown extension and license marker", SyntheticCertificate);
		Run("Local journal idempotency, replay collision and restart", () => {var store=new LocalRepository(Path.Combine(output,"journal"));var observation=Observe(certificate);store.SaveObservation(observation);store.SaveObservation(observation);Equal(1,store.LoadObservations().Count);Equal(1,new LocalRepository(store.RootDirectory).PendingCount);var changed=Json.Clone(observation);changed.Computer="Changed";Throws<InvalidDataException>(()=>store.SaveObservation(changed));var corrupt=Json.Clone(observation);corrupt.Id=Guid.NewGuid();corrupt.Certificate.Sha256="BAD";Throws<InvalidDataException>(()=>store.SaveObservation(corrupt));});
		Run("Concurrent local journal writes", () => {var path=Path.Combine(output,"parallel");Parallel.For(0,24,i=>new LocalRepository(path).SaveObservation(Observe(certificate)));Equal(24,new LocalRepository(path).LoadObservations().Count);Equal(24,new LocalRepository(path).PendingCount);});
		Run("Same serial/different DER conflict retained", () => {var store=new LocalRepository(Path.Combine(output,"conflict"));store.SaveObservation(Observe(certificate));var second=CertificateParser.Parse(File.ReadAllBytes(Path.Combine(root,"inputs","organizer-2.cer"))).Single();second.SerialNumber=certificate.SerialNumber;store.SaveObservation(Observe(second));Equal(2,store.LoadObservations().Count);True(store.GetSerialConflicts().Count>0);});
		Run("Interrupted temporary file ignored, corrupt event diagnosed", () => {var path=Path.Combine(output,"recovery");var store=new LocalRepository(path);store.SaveObservation(Observe(certificate));File.WriteAllText(Path.Combine(path,"events","unfinished.tmp-dead"),"{");Equal(1,new LocalRepository(path).LoadObservations().Count);File.WriteAllText(Path.Combine(path,"events",Guid.NewGuid().ToString("N")+".json"),"broken");Throws<InvalidDataException>(()=>store.LoadObservations());});
		Run("SQL unavailable preserves pending queue", () => {var store=new LocalRepository(Path.Combine(output,"sql-offline"));store.SaveObservation(Observe(certificate));try {store.Synchronize("Data Source=tcp:127.0.0.1,1;Initial Catalog=CertScopeTest;Integrated Security=True;Connect Timeout=1;Encrypt=True",CancellationToken.None);throw new Exception("Unexpected SQL server");}catch(System.Data.SqlClient.SqlException){} Equal(1,store.PendingCount);});
		Run("XLSX valid XML, safe strings, exact serial, long values", ExportXlsx);
		Run("TXT Cyrillic and CER byte equality", () => {var items=new[]{Observe(certificate)};string path=Path.Combine(output,"report.txt");ExportService.ExportText(path,items);True(File.ReadAllText(path,Encoding.UTF8).Contains(certificate.DisplayName));string folder=Path.Combine(output,"cer");ExportService.ExportCer(folder,items);True(File.ReadAllBytes(Directory.GetFiles(folder,"*.cer").Single()).SequenceEqual(der));});
		Run("Config roundtrip/version/limits/no secrets", () => {var s=ScanSettings.Default();s.Validate();string path=Path.Combine(output,"settings.json");Json.Save(path,s);var loaded=Json.Deserialize<ScanSettings>(File.ReadAllText(path));loaded.Validate();Equal(s.MaxWorkers,loaded.MaxWorkers);True(!File.ReadAllText(path).Contains("Password"));loaded.Version=99;Throws<InvalidDataException>(()=>loaded.Validate());loaded.Version=1;loaded.MaxWorkers=0;Throws<InvalidDataException>(()=>loaded.Validate());loaded.MaxWorkers=1;loaded.SqlConnectionString="Server=x;Database=x;User ID=a;Password=secret";Throws<InvalidDataException>(()=>loaded.Validate());});
		Run("Real file scan: extensionless/PEM/error, concurrent hosts and sources", ScanFiles);
		Run("Read-only local registry scan and coverage", ScanLocalRegistry);
		Run("Actual Windows registry serialized Blob", RegistryBlob);
		Run("Hard worker timeout bounds stalled native work", () => {Environment.SetEnvironmentVariable("CERTSCOPE_TEST_SLOW_WORKER","1");try {var s=FileSettings();s.TimeoutSeconds=1;var watch=Stopwatch.StartNew();var result=Scanner.Run(s,null,CancellationToken.None,null,null);True(watch.Elapsed.TotalSeconds<10);True(result.Sources.Any(r=>r.Status==SourceStatus.Timeout));}finally{Environment.SetEnvironmentVariable("CERTSCOPE_TEST_SLOW_WORKER",null);}});
		Run("In-flight cancellation stops workers", () => {Environment.SetEnvironmentVariable("CERTSCOPE_TEST_SLOW_WORKER","1");try {using(var cancel=new CancellationTokenSource()) {cancel.CancelAfter(300);var watch=Stopwatch.StartNew();var result=Scanner.Run(FileSettings(),null,cancel.Token,null,null);True(watch.Elapsed.TotalSeconds<8);True(result.Sources.Any(r=>r.Status==SourceStatus.Cancelled));}}finally{Environment.SetEnvironmentVariable("CERTSCOPE_TEST_SLOW_WORKER",null);}});
		ParserRegression.Run(Run, root, output);
		ScannerRegression.Run(Run, root, output);
		Run("Storage validation, atomic exports and concurrent path aliases", () => StorageRegression.RunLocal(root, Path.Combine(output, "storage-regression")));
		Skip("Domain/non-admin delegated ACL controlled comparison: no domain test environment provided. Real remote test is a separate --network scenario.");
		Skip("SQL integration is a separate suite; see docs/TESTING.md and tests/sql-integration.ps1.");
		Skip("Windows 10 runtime certification not performed; host OS build " + Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber", "unknown") + "; exact 4.5 target compiled.");
		string summary="RESULT: "+passed+" passed, "+failed+" failed, "+skipped+" skipped";Console.WriteLine(summary);log.Add(summary);File.WriteAllLines(Path.Combine(root,"artifacts","test-results.txt"),log,Encoding.UTF8);return failed==0?0:1;
	}
	private static void Run(string name,Action action) {try{action();passed++;Print("PASS "+name);}catch(SkipException ex){Skip(name+": "+ex.Message);}catch(Exception ex){failed++;Print("FAIL "+name+": "+ex);}}
	private static void Print(string text){Console.WriteLine(text);log.Add(DateTime.UtcNow.ToString("O")+" "+text);}
	private static void Skip(string text){skipped++;Print("SKIP "+text);}
	private static void True(bool value){if(!value)throw new Exception("Assertion failed");}
	private static void Equal<T>(T a,T b){if(!Object.Equals(a,b))throw new Exception("Expected: "+a+"; actual: "+b);}
	private static void Throws<T>(Action a) where T:Exception {try{a();}catch(T){return;}throw new Exception("Expected "+typeof(T).Name);}
	private sealed class SkipException:Exception{public SkipException(string value):base(value){}}
	private static Observation Observe(CertificateRecord c){return new Observation{Id=Guid.NewGuid(),ScanId=Guid.NewGuid(),Computer="TEST-PC",Source="Synthetic test location",UserSid="",RegistryView="File",FoundUtc=DateTime.UtcNow,Certificate=c};}
	private static ScanSettings FileSettings(){var s=ScanSettings.Default();s.IncludeMachine=s.IncludeUsers=s.IncludeUserFiles=false;s.RegistryViews=new List<string>{"Registry64"};s.TimeoutSeconds=8;s.RetryCount=0;return s;}
	private static void ScanFiles()
	{
		string path=Path.Combine(output,"scan-files");Directory.CreateDirectory(path);File.WriteAllBytes(Path.Combine(path,"no-extension"),der);File.WriteAllText(Path.Combine(path,"corrupt.cer"),"broken");File.WriteAllText(Path.Combine(path,"same.pem"),"-----BEGIN CERTIFICATE-----\n"+Convert.ToBase64String(der)+"\n-----END CERTIFICATE-----");var s=FileSettings();s.Computers=new List<string>{"localhost",Environment.MachineName};s.Directories.Add(path);s.Directories.Add(Path.Combine(output,"does-not-exist"));var result=Scanner.Run(s,null,CancellationToken.None,null,null);Equal(4,result.Observations.Count);True(result.Sources.Any(r=>r.Status==SourceStatus.Partial));True(result.Sources.Any(r=>r.Status==SourceStatus.Error));True(result.Sources.Any(r=>r.Status==SourceStatus.NotConfigured));Json.Save(Path.Combine(output,"file-scan.json"),result.Sources);
	}
	private static void ScanLocalRegistry()
	{
		var s=FileSettings();s.RegistryBranches.Add(@"HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates");var result=Scanner.Run(s,null,CancellationToken.None,null,null);Json.Save(Path.Combine(output,"registry-reports.json"),result.Sources);if(result.Observations.Count==0&&result.Sources.Any(r=>r.Status==SourceStatus.AccessDenied))throw new SkipException("Sandbox denies registry access; detailed source reports verified.");True(result.Observations.Count>0);True(result.Observations.All(o=>o.Certificate.Der.Length>0));
	}
	private static void RegistryBlob()
	{
		try{using(var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates")){if(key==null)throw new SkipException("ROOT store missing");foreach(var name in key.GetSubKeyNames()){using(var sub=key.OpenSubKey(name)){var blob=sub.GetValue("Blob") as byte[];if(blob==null)continue;True(CertificateParser.Parse(blob).Count>0);return;}}throw new SkipException("No serialized registry blob");}}catch(System.Security.SecurityException){throw new SkipException("Sandbox registry permission");}catch(UnauthorizedAccessException){throw new SkipException("Registry permission");}
	}
	private static void ExportXlsx()
	{
		var o=Observe(Json.Clone(certificate));o.Certificate.DisplayName="=HYPERLINK(\"x\")";o.Certificate.Subject=new string('Я',35000);string path=Path.Combine(output,"report.xlsx");ExportService.ExportXlsx(path,new[]{o});using(var zip=ZipFile.OpenRead(path)){True(zip.GetEntry("[Content_Types].xml")!=null);var texts=new List<string>();foreach(var entry in zip.Entries.Where(e=>e.FullName.EndsWith(".xml")||e.FullName.EndsWith(".rels"))){using(var input=entry.Open()){var doc=XDocument.Load(input);True(!doc.Descendants().Any(e=>e.Name.LocalName=="f"));texts.AddRange(doc.Descendants().Where(e=>e.Name.LocalName=="t").Select(e=>e.Value));}}True(texts.Contains(certificate.SerialNumber));True(texts.Contains("=HYPERLINK(\"x\")"));True(texts.Where(t=>t.Length>1000&&t.All(c=>c=='Я')).Sum(t=>t.Length)==35000);}
	}
	// Deliberately unsigned, synthetic ASN.1 fixture: tests metadata only, never claims a real licence.
	private static void SyntheticCertificate()
	{
		byte[] oidCn=Wrap(6,new byte[]{0x55,4,3}),oidOrg=Wrap(6,new byte[]{0x55,4,10});
		byte[] firstCn=Seq(oidCn,Wrap(12,Encoding.UTF8.GetBytes("Иванов, Иван")));
		byte[] org=Seq(oidOrg,Wrap(12,Encoding.UTF8.GetBytes("Тест + лаборатория")));
		byte[] secondCn=Seq(oidCn,Wrap(12,Encoding.UTF8.GetBytes("Второе значение")));
		byte[] name=Seq(Wrap(0x31,Concat(firstCn,org)),Wrap(0x31,secondCn));
		byte[] algorithm=Seq(Wrap(6,new byte[]{0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,0x0b}),Wrap(5,new byte[0]));
		byte[] publicAlgorithm=Seq(Wrap(6,new byte[]{0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1}),Wrap(5,new byte[0]));
		byte[] licenseValue=Wrap(12,Encoding.UTF8.GetBytes("SYNTHETIC NOT A LICENSE"));
		byte[] license=Seq(Wrap(6,new byte[]{0x2a,0x85,0x03,2,2,49,2}),Wrap(4,licenseValue));
		byte[] unknown=Seq(Wrap(6,new byte[]{0x2a,3,4,5}),Wrap(4,new byte[]{1,2,3,4}));
		byte[] tbs=Seq(Wrap(0xa0,Wrap(2,new byte[]{2})),Wrap(2,new byte[]{0,0x80}),algorithm,name,Seq(Wrap(23,Encoding.ASCII.GetBytes("240101000000Z")),Wrap(23,Encoding.ASCII.GetBytes("290101000000Z"))),name,Seq(publicAlgorithm,Wrap(3,new byte[]{0,1,2,3})),Wrap(0xa3,Seq(license,unknown)));
		byte[] fixture=Seq(tbs,algorithm,Wrap(3,new byte[]{0,1,2,3}));File.WriteAllBytes(Path.Combine(output,"SYNTHETIC-metadata-only.cer"),fixture);var c=CertificateParser.Parse(fixture).Single();Equal("80",c.SerialNumber);Equal(2,c.SubjectAttributes.Count(a=>a.Oid=="2.5.4.3"));Equal(2,c.SubjectAttributes.Count(a=>a.Rdn==0));True(c.SubjectAttributes.Any(a=>a.Value=="Иванов, Иван"));True(c.Extensions.Any(e=>e.Oid=="1.2.3.4.5"&&e.RawBase64==Convert.ToBase64String(new byte[]{1,2,3,4})));True(c.LicenseStatus.Contains("Обнаруж")||c.LicenseStatus.Contains("обнаруж"));True(c.LicenseVersion.Contains("не определена"));
	}
	private static byte[] Concat(params byte[][] values){return values.SelectMany(v=>v).ToArray();}
	private static byte[] NativeExport(X509ContentType type){var native=new X509Certificate2(der);try{return native.Export(type);}finally{native.Reset();}}
	private static byte[] Seq(params byte[][] values){return Wrap(0x30,Concat(values));}
	private static byte[] Wrap(int tag,byte[] value){var bytes=new List<byte>{(byte)tag};if(value.Length<128)bytes.Add((byte)value.Length);else if(value.Length<256){bytes.Add(0x81);bytes.Add((byte)value.Length);}else{bytes.Add(0x82);bytes.Add((byte)(value.Length>>8));bytes.Add((byte)value.Length);}bytes.AddRange(value);return bytes.ToArray();}
}
