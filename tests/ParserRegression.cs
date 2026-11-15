using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using CertScope;

/// <summary>Дополнительные проверки метаданных. Синтетические DER не имеют действительной подписи.</summary>
internal static class ParserRegression
{
	public static void Run(Action<string, Action> run, string root, string output)
	{
		run("Parser: organizer public certificates match supplied archives", () =>
		{
			Check(CertificateParser.Parse(File.ReadAllBytes(Path.Combine(root, "inputs", "organizer-1.cer"))).Single().Sha256 == "A5249A7F9AAECF7140F1BD4D8CE389B0264AFB1618E441A5A219CF227D49FF3A");
			Check(CertificateParser.Parse(File.ReadAllBytes(Path.Combine(root, "inputs", "organizer-2.cer"))).Single().Sha256 == "59483F26CE12F81751B726E54B54BD89E6A77A2643472E23E4E84700D66DC7A8");
		});
		run("Parser: synthetic GOST public key OIDs without CryptoPro", () =>
		{
			CheckPublicKeyOid("1.2.643.2.2.19", new byte[] { 42, 133, 3, 2, 2, 19 });
			CheckPublicKeyOid("1.2.643.7.1.1.1.1", new byte[] { 42, 133, 3, 7, 1, 1, 1, 1 });
			CheckPublicKeyOid("1.2.643.7.1.1.1.2", new byte[] { 42, 133, 3, 7, 1, 1, 1, 2 });
		});
		run("Parser: UTF-8 BOM PEM preserves public DER", () =>
		{
			byte[] der = File.ReadAllBytes(Path.Combine(root, "inputs", "organizer-1.cer"));
			byte[] pem = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes("\r\n-----BEGIN CERTIFICATE-----\r\n" + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks) + "\r\n-----END CERTIFICATE-----\r\n")).ToArray();
			Check(CertificateParser.Parse(pem).Single().Der.SequenceEqual(der));
		});
		run("Parser: PEM rejects mixed private-key block and external garbage", () =>
		{
			byte[] der = File.ReadAllBytes(Path.Combine(root, "inputs", "organizer-1.cer"));
			string pem = "-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(der) + "\n-----END CERTIFICATE-----\n";
			Reject<NotSupportedException>(() => CertificateParser.Parse(Encoding.UTF8.GetBytes(pem + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----")));
			Reject<CryptographicException>(() => CertificateParser.Parse(Encoding.UTF8.GetBytes(pem + "garbage")));
		});
		run("Parser: surname and givenName take priority over CN", () =>
		{
			byte[] name = Seq(Set(Attribute(4, "Иванов")), Set(Attribute(42, "Иван Иванович")), Set(Attribute(3, "Другое CN")));
			var certificate = CertificateParser.Parse(Certificate(name, null, null, null, null)).Single();
			Check(certificate.DisplayName == "Иванов Иван Иванович");
			Check(certificate.DisplayNameSource.Contains("surname"));
			Check(certificate.SubjectAttributes.Count == 3);
		});
		run("Parser: UTCTime pivot and GeneralizedTime remain UTC", () =>
		{
			var old = CertificateParser.Parse(Certificate(null, null, "500101000000Z", "491231235959Z", null)).Single();
			Check(old.NotBeforeUtc == new DateTime(1950, 1, 1, 0, 0, 0, DateTimeKind.Utc));
			Check(old.NotAfterUtc == new DateTime(2049, 12, 31, 23, 59, 59, DateTimeKind.Utc));
			var future = CertificateParser.Parse(Certificate(null, null, "20500101000000Z", "20511231235959Z", null)).Single();
			Check(future.NotBeforeUtc.Kind == DateTimeKind.Utc && future.NotAfterUtc.Year == 2051);
			Reject<CryptographicException>(() => CertificateParser.Parse(Certificate(null, null, "250230000000Z", "260101000000Z", null)));
			Reject<CryptographicException>(() => CertificateParser.Parse(Certificate(null, null, "270101000000Z", "260101000000Z", null)));
		});
		run("Parser: unknown critical and malformed known extensions retain original value", () =>
		{
			byte[] unknown = Extension(new byte[] { 42, 3, 4, 5 }, new byte[] { 255, 0, 15 }, true);
			byte[] malformedSan = Extension(new byte[] { 85, 29, 17 }, new byte[] { 48, 1, 0 }, false);
			var certificate = CertificateParser.Parse(Certificate(null, new[] { unknown, malformedSan }, null, null, null)).Single();
			Check(certificate.Extensions.Count == 2);
			Check(certificate.Extensions[0].Critical && certificate.Extensions[0].RawBase64 == "/wAP");
			Check(certificate.Extensions[1].Description.Contains("Не удалось разобрать"));
			Check(Convert.FromBase64String(certificate.Extensions[1].RawBase64).SequenceEqual(new byte[] { 48, 1, 0 }));
		});
		run("Parser: duplicate extensions and nonminimal serial rejected", () =>
		{
			byte[] extension = Extension(new byte[] { 42, 3, 4, 5 }, new byte[] { 1, 2 }, false);
			Reject<CryptographicException>(() => CertificateParser.Parse(Certificate(null, new[] { extension, extension }, null, null, null)));
			Reject<CryptographicException>(() => CertificateParser.Parse(Certificate(null, null, null, null, new byte[] { 0, 1 })));
			Reject<CryptographicException>(() => CertificateParser.Parse(Certificate(null, null, null, null, new byte[] { 128 })));
		});
		run("Parser: malformed UTF-8 name rejected without replacement characters", () =>
		{
			byte[] name = Seq(Set(Seq(Wrap(6, new byte[] { 85, 4, 3 }), Wrap(12, new byte[] { 0xc3, 0x28 }))));
			Reject<CryptographicException>(() => CertificateParser.Parse(Certificate(name, null, null, null, null)));
		});
		run("Parser: deeply nested CRL extension diagnosed while retaining certificate", () =>
		{
			byte[] value = Wrap(0x86, Encoding.ASCII.GetBytes("https://example.invalid/crl"));
			for (int depth = 0; depth < 40; depth++) value = Seq(value);
			var certificate = CertificateParser.Parse(Certificate(null, new[] { Extension(new byte[] { 85, 29, 31 }, value, false) }, null, null, null)).Single();
			Check(certificate.Extensions[0].Description.Contains("Не удалось разобрать"));
			Check(Convert.FromBase64String(certificate.Extensions[0].RawBase64).SequenceEqual(value));
		});
	}

	private static void CheckPublicKeyOid(string expected, byte[] encodedOid)
	{
		var certificate = CertificateParser.Parse(Certificate(null, null, null, null, null, encodedOid)).Single();
		Check(certificate.PublicKeyAlgorithm == expected);
	}

	private static byte[] Certificate(byte[] name, byte[][] extensions, string before, string after, byte[] serial, byte[] publicKeyOid = null)
	{
		name = name ?? Seq(Set(Attribute(3, "SYNTHETIC metadata fixture")));
		before = before ?? "250101000000Z";
		after = after ?? "290101000000Z";
		byte[] algorithm = Seq(Wrap(6, new byte[] { 42, 134, 72, 134, 247, 13, 1, 1, 11 }), Wrap(5, new byte[0]));
		byte[] keyAlgorithm = Seq(Wrap(6, publicKeyOid ?? new byte[] { 42, 134, 72, 134, 247, 13, 1, 1, 1 }), Wrap(5, new byte[0]));
		var fields = new List<byte[]> { Wrap(0xa0, Wrap(2, new byte[] { 2 })), Wrap(2, serial ?? new byte[] { 1 }), algorithm, name,
			Seq(Wrap(before.Length == 15 ? 24 : 23, Encoding.ASCII.GetBytes(before)), Wrap(after.Length == 15 ? 24 : 23, Encoding.ASCII.GetBytes(after))), name,
			Seq(keyAlgorithm, Wrap(3, new byte[] { 0, 1, 2, 3 })) };
		if (extensions != null) fields.Add(Wrap(0xa3, Seq(extensions)));
		return Seq(Seq(fields.ToArray()), algorithm, Wrap(3, new byte[] { 0, 1, 2, 3 }));
	}

	private static byte[] Attribute(byte lastOidArc, string value) { return Seq(Wrap(6, new byte[] { 85, 4, lastOidArc }), Wrap(12, Encoding.UTF8.GetBytes(value))); }
	private static byte[] Extension(byte[] oid, byte[] value, bool critical) { return critical ? Seq(Wrap(6, oid), Wrap(1, new byte[] { 255 }), Wrap(4, value)) : Seq(Wrap(6, oid), Wrap(4, value)); }
	private static byte[] Seq(params byte[][] values) { return Wrap(48, values.SelectMany(value => value).ToArray()); }
	private static byte[] Set(byte[] value) { return Wrap(49, value); }
	private static byte[] Wrap(int tag, byte[] value)
	{
		var bytes = new List<byte> { (byte)tag };
		if (value.Length < 128) bytes.Add((byte)value.Length);
		else if (value.Length < 256) { bytes.Add(129); bytes.Add((byte)value.Length); }
		else { bytes.Add(130); bytes.Add((byte)(value.Length >> 8)); bytes.Add((byte)value.Length); }
		bytes.AddRange(value);
		return bytes.ToArray();
	}
	private static void Check(bool condition) { if (!condition) throw new InvalidOperationException("Parser regression assertion failed."); }
	private static void Reject<T>(Action action) where T : Exception
	{
		try { action(); }
		catch (T) { return; }
		throw new InvalidOperationException("Expected " + typeof(T).Name);
	}
}
