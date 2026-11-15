using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace CertScope
{
	/// <summary>Читает только открытые сертификаты. Не импортирует PFX, ключи или данные в системные хранилища.</summary>
	public static class CertificateParser
	{
		public const int MaximumInputBytes = 64 * 1024 * 1024;
		private const int MaximumCertificates = 10000;
		private const string LicenseOid = "1.2.643.2.2.49.2";
		private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);
		private static readonly Encoding StrictBmp = new UnicodeEncoding(true, false, true);
		private static readonly Encoding StrictUniversal = new UTF32Encoding(true, false, true);

		/// <summary>Возвращает уникальные DER-сертификаты из DER, PEM, PKCS#7 и сериализованных форматов Windows.</summary>
		public static List<CertificateRecord> Parse(byte[] bytes)
		{
			if (bytes == null || bytes.Length == 0) throw Bad("Пустые данные сертификата.");
			if (bytes.Length > MaximumInputBytes) throw new InvalidDataException("Данные превышают предел парсера 64 МиБ.");
			try
			{
				List<CertificateRecord> result;
				if (LooksLikePem(bytes)) result = ParsePem(bytes);
				else result = ParseBinary(bytes);
				return result.GroupBy(c => c.Sha256, StringComparer.Ordinal).Select(g => g.First()).ToList();
			}
			catch (DecoderFallbackException e) { throw new CryptographicException("Некорректная кодировка ASN.1 или PEM.", e); }
			catch (FormatException e) { throw new CryptographicException("Некорректное значение ASN.1 или Base64.", e); }
			catch (OverflowException e) { throw new CryptographicException("Число ASN.1 выходит за допустимый предел.", e); }
		}

		/// <summary>Нормализует шестнадцатеричный serial без изменения его числового значения.</summary>
		public static string NormalizeSerial(string serial)
		{
			if (String.IsNullOrWhiteSpace(serial)) throw new FormatException("Серийный номер пуст.");
			var text = new StringBuilder();
			foreach (char c in serial.Trim())
			{
				if (Char.IsWhiteSpace(c) || c == ':' || c == '-') continue;
				if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) throw new FormatException("Серийный номер должен быть hex.");
				text.Append(Char.ToUpperInvariant(c));
			}
			if (text.Length == 0) throw new FormatException("Серийный номер пуст.");
			string normalized = text.ToString().TrimStart('0');
			return normalized.Length == 0 ? "0" : normalized;
		}

		private static bool LooksLikePem(byte[] bytes)
		{
			int p = bytes.Length >= 3 && bytes[0] == 239 && bytes[1] == 187 && bytes[2] == 191 ? 3 : 0;
			while (p < bytes.Length && (bytes[p] == 32 || bytes[p] == 9 || bytes[p] == 10 || bytes[p] == 13)) p++;
			return p + 11 <= bytes.Length && Encoding.ASCII.GetString(bytes, p, 11) == "-----BEGIN ";
		}

		private static List<CertificateRecord> ParsePem(byte[] bytes)
		{
			string text = StrictUtf8.GetString(bytes).TrimStart('\uFEFF');
			var result = new List<CertificateRecord>();
			int position = 0;
			while (position < text.Length)
			{
				while (position < text.Length && Char.IsWhiteSpace(text[position])) position++;
				if (position == text.Length) break;
				if (text.IndexOf("-----BEGIN ", position, StringComparison.Ordinal) != position) throw Bad("Лишние данные вне PEM-блока.");
				int labelEnd = text.IndexOf("-----", position + 11, StringComparison.Ordinal);
				if (labelEnd < 0 || labelEnd - position > 80) throw Bad("Повреждённый заголовок PEM.");
				string label = text.Substring(position + 11, labelEnd - position - 11);
				if (label.IndexOf("PRIVATE KEY", StringComparison.Ordinal) >= 0 || label == "PKCS12" || label == "PFX") throw new NotSupportedException("PFX/PKCS#12 и закрытые ключи не импортируются. Требуется открытый CER/PEM.");
				if (label != "CERTIFICATE" && label != "X509 CERTIFICATE" && label != "PKCS7" && label != "CMS") throw new NotSupportedException("Неподдерживаемый PEM-блок: " + label + ".");
				string ending = "-----END " + label + "-----";
				int end = text.IndexOf(ending, labelEnd + 5, StringComparison.Ordinal);
				if (end < 0) throw Bad("Не найден конец PEM-блока.");
				byte[] binary = Convert.FromBase64String(text.Substring(labelEnd + 5, end - labelEnd - 5));
				// Тип определяется содержимым: даже PFX с ошибочной меткой CERTIFICATE должен быть отклонён.
				result.AddRange(ParseBinary(binary));
				if (result.Count > MaximumCertificates) throw new InvalidDataException("В контейнере более 10000 сертификатов.");
				position = end + ending.Length;
			}
			if (result.Count == 0) throw Bad("PEM не содержит сертификатов.");
			return result;
		}

		private static List<CertificateRecord> ParseBinary(byte[] bytes)
		{
			// Сначала исследуется ASN.1, без загрузки криптопровайдера или закрытого ключа.
			DerNode root = null; int consumed = 0;
			try { root = DerNode.First(bytes, out consumed); } catch (CryptographicException) { }
			if (root != null && root.Tag == 0x30)
			{
				List<DerNode> children = root.Children();
				if (children.Count >= 2 && children[0].Tag == 0x02 && children[1].Tag == 0x30)
				{
					List<DerNode> contentInfo = children[1].Children();
					if (children[0].Length == 1 && children[0].ValueByte(0) == 3 && contentInfo.Count > 0 && contentInfo[0].Tag == 0x06 && Oid(contentInfo[0]) == "1.2.840.113549.1.7.1")
						throw new NotSupportedException("Обнаружен PFX/PKCS#12: контейнер с ключами не импортируется. Предоставьте открытый CER.");
				}
				if (children.Count == 3 && children[0].Tag == 0x30 && children[1].Tag == 0x30 && children[2].Tag == 0x03)
				{
					// CryptoAPI терпимо относится к хвосту DER; не позволяем fallback скрыть повреждение.
					if (consumed != bytes.Length) throw Bad("Лишние байты после DER-сертификата.");
					return new List<CertificateRecord> { ParseDer(bytes) };
				}
			}
			return ParseNative(bytes);
		}

		/// <summary>Строго разбирает структуру X.509; математическую подпись и доверие цепочке не проверяет.</summary>
		private static CertificateRecord ParseDer(byte[] bytes)
		{
			if (bytes.Length == 0 || bytes.Length > MaximumInputBytes) throw Bad("Недопустимый размер DER.");
			DerNode certificate = DerNode.Root(bytes);
			certificate.Require(0x30);
			List<DerNode> parts = certificate.Children();
			if (parts.Count != 3) throw Bad("Certificate должен содержать три элемента.");
			parts[0].Require(0x30);
			ValidateBitString(parts[2]);
			List<DerNode> tbs = parts[0].Children();
			int p = 0;
			int version = 0;
			if (tbs.Count > 0 && tbs[0].Tag == 0xA0)
			{
				List<DerNode> explicitVersion = tbs[p++].Children();
				if (explicitVersion.Count != 1 || explicitVersion[0].Tag != 2 || explicitVersion[0].Length != 1 || explicitVersion[0].ValueByte(0) > 2) throw Bad("Некорректная версия X.509.");
				version = explicitVersion[0].ValueByte(0);
			}
			if (tbs.Count - p < 6) throw Bad("TBSCertificate не содержит обязательных полей.");
			DerNode serial = tbs[p++];
			serial.Require(2);
			ValidatePositiveInteger(serial);
			DerNode innerAlgorithm = tbs[p++];
			string signatureOid, signatureParameters;
			ReadAlgorithm(parts[1], out signatureOid, out signatureParameters);
			string innerOid, innerParameters;
			ReadAlgorithm(innerAlgorithm, out innerOid, out innerParameters);
			if (signatureOid != innerOid || signatureParameters != innerParameters) throw Bad("Алгоритмы подписи Certificate и TBSCertificate различаются.");
			List<DnAttribute> issuer = ReadName(tbs[p++]);
			DerNode validity = tbs[p++]; validity.Require(0x30);
			List<DerNode> times = validity.Children();
			if (times.Count != 2) throw Bad("Validity должен содержать две даты.");
			List<DnAttribute> subject = ReadName(tbs[p++]);
			DerNode key = tbs[p++]; key.Require(0x30);
			List<DerNode> keyParts = key.Children();
			if (keyParts.Count != 2) throw Bad("Некорректный SubjectPublicKeyInfo.");
			string keyOid, keyParameters;
			ReadAlgorithm(keyParts[0], out keyOid, out keyParameters);
			ValidateBitString(keyParts[1]);
			var extensions = new List<ExtensionRecord>();
			int lastOptional = 0;
			while (p < tbs.Count)
			{
				DerNode field = tbs[p++];
				int optional = field.Tag == 0x81 ? 1 : field.Tag == 0x82 ? 2 : field.Tag == 0xA3 ? 3 : 0;
				if (optional == 0 || optional <= lastOptional || version == 0 || (optional == 3 && version != 2)) throw Bad("Недопустимое optional-поле X.509.");
				lastOptional = optional;
				if (optional == 3) extensions = ReadExtensions(field);
				else ValidateBitStringContent(field);
			}
			string displayName, displaySource;
			SelectDisplayName(subject, out displayName, out displaySource);
			ExtensionRecord license = extensions.FirstOrDefault(e => e.Oid == LicenseOid);
			var record = new CertificateRecord
			{
				Der = (byte[])bytes.Clone(), SerialNumber = NormalizeSerial(Hex(serial.ValueBytes())),
				SubjectAttributes = subject, IssuerAttributes = issuer,
				Subject = FormatName(subject), Issuer = FormatName(issuer),
				DisplayName = displayName, DisplayNameSource = displaySource,
				NotBeforeUtc = ReadTime(times[0]), NotAfterUtc = ReadTime(times[1]),
				PublicKeyAlgorithm = keyOid, PublicKeyParameters = keyParameters,
				SignatureAlgorithm = signatureOid, SignatureParameters = signatureParameters,
				Extensions = extensions,
				LicenseStatus = license == null ? "Признак отсутствует" : "Обнаружено",
				LicenseVersion = license == null ? "Не применимо" : "Версия не определена",
				LicenseEvidence = license == null ? "Расширение " + LicenseOid + " отсутствует; лицензия установленного CSP не проверялась."
					: "Присутствует расширение " + LicenseOid + "; его исходное значение сохранено. Нет подтверждённого контракта декодирования версии. Действительность лицензии не проверялась."
			};
			if (record.NotAfterUtc < record.NotBeforeUtc) throw Bad("Окончание действия предшествует началу.");
			using (SHA256 hash = SHA256.Create()) record.Sha256 = Hex(hash.ComputeHash(bytes));
			return record;
		}

		private static void ReadAlgorithm(DerNode node, out string oid, out string parameters)
		{
			node.Require(0x30);
			List<DerNode> parts = node.Children();
			if (parts.Count < 1 || parts.Count > 2) throw Bad("Некорректный AlgorithmIdentifier.");
			oid = Oid(parts[0]);
			parameters = parts.Count == 2 ? Convert.ToBase64String(parts[1].FullBytes()) : null;
		}

		private static List<DnAttribute> ReadName(DerNode name)
		{
			name.Require(0x30);
			var result = new List<DnAttribute>();
			int rdn = 0;
			foreach (DerNode set in name.Children())
			{
				set.Require(0x31);
				List<DerNode> attributes = set.Children();
				if (attributes.Count == 0) throw Bad("Пустой RelativeDistinguishedName.");
				foreach (DerNode attribute in attributes)
				{
					attribute.Require(0x30);
					List<DerNode> pair = attribute.Children();
					if (pair.Count != 2) throw Bad("Некорректный атрибут DN.");
					result.Add(new DnAttribute { Rdn = rdn, Oid = Oid(pair[0]), Value = ReadDirectoryString(pair[1]) });
				}
				rdn++;
			}
			return result;
		}

		private static string ReadDirectoryString(DerNode value)
		{
			byte[] data = value.ValueBytes();
			if (value.Tag == 12) return StrictUtf8.GetString(data);
			if (value.Tag == 30) return StrictBmp.GetString(data);
			if (value.Tag == 28) return StrictUniversal.GetString(data);
			if (value.Tag == 18 || value.Tag == 19 || value.Tag == 22 || value.Tag == 26)
			{
				if (data.Any(b => b > 127)) throw Bad("Не-ASCII символ в ASN.1 ASCII-строке.");
				return Encoding.ASCII.GetString(data);
			}
			// TeletexString не подменяется недоказанной кодировкой Windows-1251/Latin-1.
			return "[ASN.1 tag=" + value.Tag.ToString("X2", CultureInfo.InvariantCulture) + "; Base64=" + Convert.ToBase64String(value.FullBytes()) + "]";
		}

		private static void SelectDisplayName(List<DnAttribute> subject, out string name, out string source)
		{
			string surname = String.Join(" ", subject.Where(a => a.Oid == "2.5.4.4").Select(a => a.Value));
			string given = String.Join(" ", subject.Where(a => a.Oid == "2.5.4.42").Select(a => a.Value));
			if (surname.Length > 0 && given.Length > 0) { name = surname + " " + given; source = "Subject: surname (2.5.4.4) + givenName (2.5.4.42)"; return; }
			name = String.Join(" / ", subject.Where(a => a.Oid == "2.5.4.3").Select(a => a.Value));
			source = name.Length > 0 ? "Subject: commonName (2.5.4.3); не обязательно ФИО" : "В Subject отсутствуют CN и полная пара surname/givenName";
		}

		private static string FormatName(List<DnAttribute> attributes)
		{
			return String.Join(", ", attributes.GroupBy(a => a.Rdn).Select(group => String.Join(" + ", group.Select(a => DnLabel(a.Oid) + "=" + EscapeDn(a.Value)))));
		}

		private static string DnLabel(string oid)
		{
			switch (oid)
			{
				case "2.5.4.3": return "CN"; case "2.5.4.4": return "SN"; case "2.5.4.42": return "G";
				case "2.5.4.6": return "C"; case "2.5.4.7": return "L"; case "2.5.4.8": return "ST";
				case "2.5.4.9": return "STREET"; case "2.5.4.10": return "O"; case "2.5.4.11": return "OU";
				case "1.2.840.113549.1.9.1": return "E"; default: return oid;
			}
		}

		private static string EscapeDn(string value)
		{
			var result = new StringBuilder();
			for (int i = 0; i < value.Length; i++)
			{
				char c = value[i];
				if (c < 32 || c == 127) { result.Append("\\u" + ((int)c).ToString("X4", CultureInfo.InvariantCulture)); continue; }
				if (",+\"\\<>;=".IndexOf(c) >= 0 || (i == 0 && c == '#') || (c == ' ' && (i == 0 || i == value.Length - 1))) result.Append('\\');
				result.Append(c);
			}
			return result.ToString();
		}

		private static DateTime ReadTime(DerNode node)
		{
			string text = Encoding.ASCII.GetString(node.ValueBytes());
			if (node.Tag == 23 && text.Length == 13 && text[12] == 'Z')
			{
				int year;
				if (!Int32.TryParse(text.Substring(0, 2), NumberStyles.None, CultureInfo.InvariantCulture, out year)) throw Bad("Некорректный год UTCTime.");
				text = (year >= 50 ? "19" : "20") + text;
			}
			else if (node.Tag != 24 || text.Length != 15 || text[14] != 'Z') throw Bad("Дата X.509 должна быть UTCTime/GeneralizedTime UTC с секундами.");
			DateTime result;
			if (!DateTime.TryParseExact(text, "yyyyMMddHHmmss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out result)) throw Bad("Недопустимая календарная дата X.509.");
			return result;
		}

		private static List<ExtensionRecord> ReadExtensions(DerNode field)
		{
			List<DerNode> wrapper = field.Children();
			if (wrapper.Count != 1) throw Bad("Некорректная оболочка Extensions.");
			wrapper[0].Require(0x30);
			var result = new List<ExtensionRecord>();
			var seen = new HashSet<string>(StringComparer.Ordinal);
			foreach (DerNode node in wrapper[0].Children())
			{
				node.Require(0x30);
				List<DerNode> parts = node.Children();
				if (parts.Count < 2 || parts.Count > 3) throw Bad("Некорректная структура Extension.");
				string oid = Oid(parts[0]);
				if (!seen.Add(oid)) throw Bad("Повторное расширение X.509: " + oid + ".");
				bool critical = parts.Count == 3 && ReadBoolean(parts[1]);
				DerNode value = parts[parts.Count - 1]; value.Require(4);
				byte[] raw = value.ValueBytes();
				string description;
				try { description = DescribeExtension(oid, raw); }
				catch (Exception e)
				{
					if (!(e is CryptographicException) && !(e is FormatException) && !(e is DecoderFallbackException) && !(e is OverflowException)) throw;
					description = "Не удалось разобрать содержимое расширения: " + e.Message + " Исходное значение сохранено.";
				}
				result.Add(new ExtensionRecord { Oid = oid, Critical = critical, RawBase64 = Convert.ToBase64String(raw), Description = description });
			}
			return result;
		}

		private static string DescribeExtension(string oid, byte[] raw)
		{
			if (oid == LicenseOid) return "Признак ограниченной лицензии КриптоПро; версия и работоспособность не определялись. Исходное значение сохранено.";
			if (oid != "2.5.29.14" && oid != "2.5.29.15" && oid != "2.5.29.17" && oid != "2.5.29.19" && oid != "2.5.29.31" && oid != "2.5.29.32" && oid != "2.5.29.35" && oid != "2.5.29.37" && oid != "1.3.6.1.5.5.7.1.1")
				return "Неизвестное расширение; исходное значение сохранено без изменений.";
			DerNode node = DerNode.Root(raw);
			if (oid == "2.5.29.14") { node.Require(4); return "Subject Key Identifier: " + Hex(node.ValueBytes()); }
			if (oid == "2.5.29.15")
			{
				ValidateBitString(node);
				string[] labels = { "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly" };
				var selected = new List<string>();
				for (int i = 0; i < labels.Length; i++) if (1 + i / 8 < node.Length && (node.ValueByte(1 + i / 8) & (128 >> (i % 8))) != 0) selected.Add(labels[i]);
				return "Key Usage: " + String.Join(", ", selected);
			}
			node.Require(0x30);
			List<DerNode> items = node.Children();
			if (oid == "2.5.29.19")
			{
				int p = 0; bool ca = false;
				if (items.Count > 0 && items[0].Tag == 1) { ca = ReadBoolean(items[0]); p++; }
				string path = "не задан";
				if (p < items.Count) { items[p].Require(2); ValidatePositiveInteger(items[p]); path = "0x" + NormalizeSerial(Hex(items[p++].ValueBytes())); }
				if (p != items.Count) throw Bad("Лишние поля Basic Constraints.");
				return "Basic Constraints: CA=" + (ca ? "true" : "false") + "; pathLen=" + path;
			}
			if (oid == "2.5.29.37") return "Extended Key Usage: " + String.Join(", ", items.Select(Oid));
			if (oid == "2.5.29.17") return "Subject Alternative Name: " + String.Join("; ", items.Select(GeneralName));
			if (oid == "2.5.29.35") return "Authority Key Identifier: " + String.Join("; ", items.Select(n => n.Tag == 0x80 ? Hex(n.ValueBytes()) : "tag " + n.Tag.ToString("X2", CultureInfo.InvariantCulture) + "=" + Convert.ToBase64String(n.FullBytes())));
			if (oid == "2.5.29.32")
			{
				var policies = new List<string>();
				foreach (DerNode policy in items) { policy.Require(0x30); List<DerNode> values = policy.Children(); if (values.Count < 1) throw Bad("Пустая Certificate Policy."); policies.Add(Oid(values[0])); }
				return "Certificate Policies: " + String.Join(", ", policies) + "; qualifiers сохранены в RawBase64";
			}
			if (oid == "1.3.6.1.5.5.7.1.1")
			{
				var access = new List<string>();
				foreach (DerNode item in items) { item.Require(0x30); List<DerNode> pair = item.Children(); if (pair.Count != 2) throw Bad("Некорректный AccessDescription."); access.Add(Oid(pair[0]) + ": " + GeneralName(pair[1])); }
				return "Authority Information Access: " + String.Join("; ", access);
			}
			var uris = new List<string>();
			CollectUris(node, uris);
			return "CRL Distribution Points: " + (uris.Count > 0 ? String.Join("; ", uris) : "URI не обнаружены; полная структура сохранена");
		}

		private static string GeneralName(DerNode node)
		{
			if (node.Tag == 0x81 || node.Tag == 0x82 || node.Tag == 0x86)
			{
				byte[] bytes = node.ValueBytes();
				if (bytes.Any(b => b > 127)) throw Bad("Не-ASCII GeneralName.");
				return (node.Tag == 0x81 ? "email=" : node.Tag == 0x82 ? "DNS=" : "URI=") + Encoding.ASCII.GetString(bytes);
			}
			if (node.Tag == 0x87 && (node.Length == 4 || node.Length == 16)) return "IP=" + new IPAddress(node.ValueBytes());
			if (node.Tag == 0xA4) { List<DerNode> names = node.Children(); if (names.Count != 1) throw Bad("Некорректный directoryName."); return "DN=" + FormatName(ReadName(names[0])); }
			return "tag " + node.Tag.ToString("X2", CultureInfo.InvariantCulture) + "=" + Convert.ToBase64String(node.FullBytes());
		}

		private static void CollectUris(DerNode node, List<string> result)
		{
			if (node.Tag == 0x86) { result.Add(GeneralName(node)); return; }
			if ((node.Tag & 0x20) != 0) foreach (DerNode child in node.Children()) CollectUris(child, result);
		}

		private static bool ReadBoolean(DerNode node)
		{
			node.Require(1);
			if (node.Length != 1 || (node.ValueByte(0) != 0 && node.ValueByte(0) != 255)) throw Bad("Некорректный DER BOOLEAN.");
			return node.ValueByte(0) != 0;
		}

		private static void ValidatePositiveInteger(DerNode node)
		{
			if (node.Length == 0 || (node.ValueByte(0) & 128) != 0 || (node.Length > 1 && node.ValueByte(0) == 0 && (node.ValueByte(1) & 128) == 0)) throw Bad("Некорректное неотрицательное DER INTEGER.");
		}

		private static void ValidateBitString(DerNode node) { node.Require(3); ValidateBitStringContent(node); }
		private static void ValidateBitStringContent(DerNode node)
		{
			if (node.Length < 1 || node.ValueByte(0) > 7 || (node.Length == 1 && node.ValueByte(0) != 0)) throw Bad("Некорректный BIT STRING.");
			if (node.Length > 1 && (node.ValueByte(node.Length - 1) & ((1 << node.ValueByte(0)) - 1)) != 0) throw Bad("Ненулевые неиспользуемые биты BIT STRING.");
		}

		private static string Oid(DerNode node)
		{
			node.Require(6);
			if (node.Length == 0 || node.Length > 256) throw Bad("Некорректная длина OID.");
			var arcs = new List<ulong>(); ulong current = 0; bool firstByte = true;
			for (int i = 0; i < node.Length; i++)
			{
				byte b = node.ValueByte(i);
				if (firstByte && b == 128) throw Bad("Неминимальное кодирование OID.");
				if (current > (UInt64.MaxValue >> 7)) throw Bad("Слишком большая дуга OID.");
				current = (current << 7) | (uint)(b & 127);
				if ((b & 128) == 0) { arcs.Add(current); current = 0; firstByte = true; }
				else firstByte = false;
			}
			if (!firstByte || arcs.Count == 0) throw Bad("Незавершённый OID.");
			ulong first = arcs[0];
			string prefix = first < 40 ? "0." + first : first < 80 ? "1." + (first - 40) : "2." + (first - 80);
			return prefix + (arcs.Count > 1 ? "." + String.Join(".", arcs.Skip(1).Select(a => a.ToString(CultureInfo.InvariantCulture))) : "");
		}

		private static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", ""); }
		private static CryptographicException Bad(string message) { return new CryptographicException(message); }

		/// <summary>Ограниченный DER reader: definite/minimal lengths, не более 32 уровней и 10000 siblings.</summary>
		private sealed class DerNode
		{
			private readonly byte[] bytes;
			private readonly int start, valueStart, depth;
			public int Tag { get; private set; }
			public int Length { get; private set; }
			private int End { get { return valueStart + Length; } }
			private DerNode(byte[] data, int tag, int begin, int value, int length, int level) { bytes = data; Tag = tag; start = begin; valueStart = value; Length = length; depth = level; }
			public static DerNode Root(byte[] bytes)
			{
				int p; DerNode result = First(bytes, out p);
				if (p != bytes.Length) throw Bad("Лишние байты после DER-объекта.");
				return result;
			}
			public static DerNode First(byte[] bytes, out int consumed)
			{
				consumed = 0; return Read(bytes, ref consumed, bytes.Length, 0);
			}
			private static DerNode Read(byte[] bytes, ref int p, int end, int depth)
			{
				if (depth > 32 || p < 0 || end > bytes.Length || end - p < 2) throw Bad("Повреждённая или слишком глубокая структура DER.");
				int start = p; int tag = bytes[p++];
				if (tag == 0 || (tag & 31) == 31) throw Bad("Неподдерживаемый ASN.1 tag.");
				int lead = bytes[p++]; int length;
				if ((lead & 128) == 0) length = lead;
				else
				{
					int count = lead & 127;
					if (count == 0 || count > 4 || count > end - p || bytes[p] == 0) throw Bad("Некорректная definite length DER.");
					long value = 0; for (int i = 0; i < count; i++) value = (value << 8) | bytes[p++];
					if (value < 128 || value > MaximumInputBytes) throw Bad("Неминимальная или слишком большая длина DER.");
					length = (int)value;
				}
				if (length > end - p) throw Bad("DER-объект обрезан.");
				DerNode result = new DerNode(bytes, tag, start, p, length, depth); p += length; return result;
			}
			public void Require(int expected) { if (Tag != expected) throw Bad("Неожиданный ASN.1 tag: " + Tag.ToString("X2", CultureInfo.InvariantCulture) + ", ожидался " + expected.ToString("X2", CultureInfo.InvariantCulture) + "."); }
			public byte ValueByte(int index) { if (index < 0 || index >= Length) throw Bad("Выход за границу ASN.1."); return bytes[valueStart + index]; }
			public byte[] ValueBytes() { var result = new byte[Length]; Buffer.BlockCopy(bytes, valueStart, result, 0, Length); return result; }
			public byte[] FullBytes() { var result = new byte[End - start]; Buffer.BlockCopy(bytes, start, result, 0, result.Length); return result; }
			public List<DerNode> Children()
			{
				if ((Tag & 32) == 0) throw Bad("Primitive ASN.1 не имеет дочерних узлов.");
				var result = new List<DerNode>(); int p = valueStart;
				while (p < End) { if (result.Count >= 10000) throw Bad("Слишком много ASN.1 элементов."); result.Add(Read(bytes, ref p, End, depth + 1)); }
				return result;
			}
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct CryptoBlob { public uint Length; public IntPtr Data; }
		[StructLayout(LayoutKind.Sequential)]
		private struct CertContext { public uint Encoding; public IntPtr Data; public uint Length; public IntPtr Info; public IntPtr Store; }
		[DllImport("crypt32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool CryptQueryObject(uint objectType, ref CryptoBlob data, uint expectedContentFlags, uint expectedFormatFlags, uint flags, out uint encoding, out uint content, out uint format, out IntPtr store, out IntPtr message, out IntPtr context);
		[DllImport("crypt32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool PFXIsPFXBlob(ref CryptoBlob data);
		[DllImport("crypt32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool CertAddSerializedElementToStore(IntPtr store, byte[] bytes, uint length, uint disposition, uint flags, uint contextFlags, out uint contextType, out IntPtr context);
		[DllImport("crypt32.dll", SetLastError = true)]
		private static extern IntPtr CertEnumCertificatesInStore(IntPtr store, IntPtr previous);
		[DllImport("crypt32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool CertFreeCertificateContext(IntPtr context);
		[DllImport("crypt32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool CertCloseStore(IntPtr store, uint flags);
		[DllImport("crypt32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool CryptMsgClose(IntPtr message);

		/// <summary>Десериализация только в памяти; флаги PFX_AND_LOAD и API импорта PFX намеренно отсутствуют.</summary>
		private static List<CertificateRecord> ParseNative(byte[] bytes)
		{
			var result = new List<CertificateRecord>();
			IntPtr store = IntPtr.Zero, message = IntPtr.Zero, context = IntPtr.Zero, current = IntPtr.Zero;
			GCHandle pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
			try
			{
				var blob = new CryptoBlob { Length = (uint)bytes.Length, Data = pinned.AddrOfPinnedObject() };
				if (PFXIsPFXBlob(ref blob)) throw new NotSupportedException("Обнаружен PFX/PKCS#12: импорт контейнеров закрытых ключей отключён. Требуется открытый CER.");
				uint encoding, content, format;
				const uint supported = (1u << 1) | (1u << 4) | (1u << 5) | (1u << 8) | (1u << 9);
				if (CryptQueryObject(2, ref blob, supported, 14, 0, out encoding, out content, out format, out store, out message, out context))
				{
					if (context != IntPtr.Zero) result.Add(ReadContext(context));
					if (store != IntPtr.Zero)
					{
						while (true)
						{
							// Enum освобождает previous; после вызова нельзя освобождать его повторно.
							current = CertEnumCertificatesInStore(store, current);
							if (current == IntPtr.Zero)
							{
								int error = Marshal.GetLastWin32Error();
								if (error != unchecked((int)0x80092004) && error != 0) throw new CryptographicException("Ошибка перечисления сертификатов контейнера.", new Win32Exception(error));
								break;
							}
							if (result.Count >= MaximumCertificates) throw new InvalidDataException("В контейнере более 10000 сертификатов.");
							result.Add(ReadContext(current));
						}
					}
					return result;
				}
				// Registry Blob может быть отдельным Windows serialized certificate, а не DER.
				uint type; IntPtr serialized = IntPtr.Zero;
				try
				{
					if (CertAddSerializedElementToStore(IntPtr.Zero, bytes, (uint)bytes.Length, 4, 0, 2, out type, out serialized))
					{
						if (type != 1 || serialized == IntPtr.Zero) throw Bad("Сериализованный элемент не является сертификатом.");
						result.Add(ReadContext(serialized)); return result;
					}
					int error = Marshal.GetLastWin32Error();
					throw new CryptographicException("Формат не распознан либо данные повреждены. Поддерживаются X.509 DER/PEM, PKCS#7 и сериализованные сертификаты/хранилища Windows.", new Win32Exception(error));
				}
				finally { if (serialized != IntPtr.Zero) CertFreeCertificateContext(serialized); }
			}
			finally
			{
				if (current != IntPtr.Zero) CertFreeCertificateContext(current);
				if (context != IntPtr.Zero) CertFreeCertificateContext(context);
				if (store != IntPtr.Zero) CertCloseStore(store, 0);
				if (message != IntPtr.Zero) CryptMsgClose(message);
				pinned.Free();
			}
		}

		private static CertificateRecord ReadContext(IntPtr pointer)
		{
			CertContext context = (CertContext)Marshal.PtrToStructure(pointer, typeof(CertContext));
			if (context.Data == IntPtr.Zero || context.Length == 0 || context.Length > MaximumInputBytes) throw Bad("Недопустимый размер CERT_CONTEXT.");
			var bytes = new byte[(int)context.Length]; Marshal.Copy(context.Data, bytes, 0, bytes.Length);
			return ParseDer(bytes);
		}
	}
}
