using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace CertScope
{
	/// <summary>Экспорт открытых данных без Excel, выполнения формул или обращения к закрытым ключам.</summary>
	public static class ExportService
	{
		private const string SpreadsheetNamespace = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
		private const string RelationshipNamespace = "http://schemas.openxmlformats.org/package/2006/relationships";
		private const string OfficeRelationshipNamespace = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
		private static readonly string[] Headers = {
			"EventId", "ScanId", "Компьютер", "Источник", "SID пользователя", "Представление реестра", "Обнаружен UTC",
			"Серийный номер", "SHA-256 DER", "Владелец", "Источник имени", "Subject", "Удостоверяющий центр / Issuer",
			"Действует с UTC", "Действует до UTC", "Алгоритм открытого ключа", "Параметры открытого ключа",
			"Алгоритм подписи", "Параметры подписи", "Признак лицензии", "Версия встроенной лицензии", "Основание вывода",
			"Subject: атрибуты DN", "Issuer: атрибуты DN", "Проверка доверия"
		};

		/// <summary>Создаёт ZIP-пакет SpreadsheetML: серийные номера и все входные значения являются текстом.</summary>
		public static void ExportXlsx(string path, IEnumerable<Observation> observations)
		{
			ExportXlsx(path, observations, null);
		}

		public static void ExportXlsx(string path, IEnumerable<Observation> observations, IEnumerable<SourceReport> reports)
		{
			if (observations == null) throw new ArgumentNullException("observations");
			var items = observations.ToList();
			var sheets = new List<Sheet>();
			var certificateSheet = new Sheet("Сертификаты", Headers);
			foreach (var item in items) certificateSheet.Rows.Add(ToRow(item));
			sheets.Add(certificateSheet);
			var extensionsSheet = new Sheet("Расширения", new[] { "SHA-256 DER", "OID", "Критичное", "Описание", "Исходное значение Base64" });
			foreach (var certificate in items.Select(o => o.Certificate).GroupBy(c => c.Sha256).Select(g => g.First()))
				foreach (var extension in certificate.Extensions ?? new List<ExtensionRecord>())
					extensionsSheet.Rows.Add(new[] { certificate.Sha256, extension.Oid, extension.Critical ? "Да" : "Нет", extension.Description, extension.RawBase64 });
			sheets.Add(extensionsSheet);
			if (reports != null) sheets.Add(ReportSheet(reports));
			PrepareLongValues(sheets);
			WriteWorkbook(path, sheets);
		}

		public static void ExportReportsXlsx(string path, IEnumerable<SourceReport> reports)
		{
			var sheets = new List<Sheet> { ReportSheet(reports) };
			PrepareLongValues(sheets);
			WriteWorkbook(path, sheets);
		}

		/// <summary>Сохраняет читаемый UTF-8 TXT и полные JSON-данные без потери расширений и DER.</summary>
		public static void ExportText(string path, IEnumerable<Observation> observations)
		{
			ExportText(path, observations, null);
		}

		public static void ExportText(string path, IEnumerable<Observation> observations, IEnumerable<SourceReport> reports)
		{
			AtomicExport(path, delegate(string temporary)
			{
				using (var writer = new StreamWriter(temporary, false, new UTF8Encoding(true)))
				{
					writer.WriteLine("CertScope — открытые сертификаты и места обнаружения");
					writer.WriteLine("Время экспорта UTC: " + Utc(DateTime.UtcNow));
					writer.WriteLine("Разбор метаданных не подтверждает доверие цепочке, подпись или статус отзыва.");
					foreach (var item in observations)
					{
						writer.WriteLine();
						writer.WriteLine(new string('─', 64));
						var values = ToRow(item);
						for (int i = 0; i < Headers.Length; i++) writer.WriteLine(Headers[i] + ": " + values[i]);
						writer.WriteLine("Полные данные JSON (включая открытый DER и неизвестные расширения):");
						writer.WriteLine(Encoding.UTF8.GetString(LocalRepository.Serialize(item)));
					}
					if (reports != null)
					{
						writer.WriteLine();
						writer.WriteLine("ОХВАТ И ОШИБКИ (JSON):");
						foreach (var report in reports) writer.WriteLine(Encoding.UTF8.GetString(LocalRepository.Serialize(report)));
					}
				}
			});
		}

		public static void ExportReportsText(string path, IEnumerable<SourceReport> reports)
		{
			ExportText(path, new Observation[0], reports);
		}

		/// <summary>Имя CER задаётся SHA-256. Повтор не изменяет файл, если байты уже совпадают.</summary>
		public static void ExportCer(string directory, IEnumerable<Observation> observations)
		{
			if (observations == null) throw new ArgumentNullException("observations");
			var certificates = observations.Select(o => o == null ? null : o.Certificate).ToList();
			// Validate before deduplication: a malformed duplicate must not be silently discarded.
			foreach (var certificate in certificates)
				if (certificate == null || certificate.Der == null || certificate.Der.Length == 0 || !String.Equals(LocalRepository.Hash(certificate.Der), certificate.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("SHA-256 не соответствует экспортируемому DER.");
			Directory.CreateDirectory(directory);
			foreach (var certificate in certificates.GroupBy(c => c.Sha256, StringComparer.OrdinalIgnoreCase).Select(g => g.First()))
			{
				var path = Path.Combine(directory, certificate.Sha256.ToUpperInvariant() + ".cer");
				if (File.Exists(path))
				{
					if (File.ReadAllBytes(path).SequenceEqual(certificate.Der)) continue;
					throw new IOException("Файл с именем SHA-256 уже существует, но содержит другие байты: " + path);
				}
				LocalRepository.AtomicNewFile(path, certificate.Der);
			}
		}

		private static string[] ToRow(Observation item)
		{
			if (item == null || item.Certificate == null) throw new InvalidDataException("Наблюдение не содержит сертификат.");
			var c = item.Certificate;
			return new[] {
				item.Id.ToString(), item.ScanId.ToString(), item.Computer, item.Source, item.UserSid, item.RegistryView, Utc(item.FoundUtc),
				LocalRepository.NormalizeSerial(c.SerialNumber), c.Sha256, c.DisplayName, c.DisplayNameSource, c.Subject, c.Issuer,
				Utc(c.NotBeforeUtc), Utc(c.NotAfterUtc), c.PublicKeyAlgorithm, c.PublicKeyParameters,
				c.SignatureAlgorithm, c.SignatureParameters, c.LicenseStatus, c.LicenseVersion, c.LicenseEvidence,
				Encoding.UTF8.GetString(LocalRepository.Serialize(c.SubjectAttributes)), Encoding.UTF8.GetString(LocalRepository.Serialize(c.IssuerAttributes)),
				"Не выполнялась: подпись / цепочка / CRL / OCSP"
			};
		}

		private static Sheet ReportSheet(IEnumerable<SourceReport> reports)
		{
			var sheet = new Sheet("Охват и ошибки", new[] { "ScanId", "Компьютер", "Источник", "SID", "Статус", "Сообщение", "Начало UTC", "Окончание UTC", "Найдено", "Код ошибки", "Стек исключения" });
			foreach (var report in reports)
				sheet.Rows.Add(new[] { report.ScanId.ToString(), report.Computer, report.Source, report.UserSid, report.Status.ToString(), report.Message, Utc(report.StartedUtc), Utc(report.FinishedUtc), report.Count.ToString(CultureInfo.InvariantCulture), report.ErrorCode.ToString(CultureInfo.InvariantCulture), report.StackTrace });
			return sheet;
		}

		private sealed class Sheet
		{
			public string Name;
			public List<string[]> Rows = new List<string[]>();
			public Sheet(string name, string[] headers) { Name = name; Rows.Add(headers); }
		}

		/// <summary>Длинные значения сохраняются целиком частями на отдельном листе с указанием исходной ячейки.</summary>
		private static void PrepareLongValues(List<Sheet> sheets)
		{
			var longValues = new Sheet("Длинные значения", new[] { "Лист", "Ячейка", "Часть", "Значение — соединить части по порядку" });
			foreach (var sheet in sheets)
			{
				if (sheet.Rows.Count > 1048576) throw new InvalidDataException("Превышен предел XLSX: 1 048 576 строк на лист. Экспортируйте отфильтрованные данные или TXT.");
				for (int row = 0; row < sheet.Rows.Count; row++)
					for (int column = 0; column < sheet.Rows[row].Length; column++)
					{
						var value = sheet.Rows[row][column] ?? "";
						if (value.Length <= 30000) continue;
						var address = Cell(column, row + 1);
						int offset = 0, part = 1;
						while (offset < value.Length)
						{
							int length = Math.Min(30000, value.Length - offset);
							if (offset + length < value.Length && Char.IsHighSurrogate(value[offset + length - 1])) length--;
							longValues.Rows.Add(new[] { sheet.Name, address, (part++).ToString(CultureInfo.InvariantCulture), value.Substring(offset, length) });
							offset += length;
						}
						sheet.Rows[row][column] = "Полное значение сохранено на листе «Длинные значения»: " + sheet.Name + "!" + address;
					}
			}
			if (longValues.Rows.Count > 1048576) throw new InvalidDataException("Слишком много частей длинных значений для XLSX. Используйте TXT.");
			if (longValues.Rows.Count > 1) sheets.Add(longValues);
		}

		private static void WriteWorkbook(string path, List<Sheet> sheets)
		{
			AtomicExport(path, delegate(string temporary)
			{
				using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
				using (var archive = new ZipArchive(file, ZipArchiveMode.Create))
				{
					WriteXml(archive, "[Content_Types].xml", delegate(XmlWriter writer)
					{
						writer.WriteStartElement("Types", "http://schemas.openxmlformats.org/package/2006/content-types");
						EmptyElement(writer, "Default", "Extension", "rels", "ContentType", "application/vnd.openxmlformats-package.relationships+xml");
						EmptyElement(writer, "Default", "Extension", "xml", "ContentType", "application/xml");
						EmptyElement(writer, "Override", "PartName", "/xl/workbook.xml", "ContentType", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml");
						EmptyElement(writer, "Override", "PartName", "/xl/styles.xml", "ContentType", "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml");
						for (int i = 0; i < sheets.Count; i++) EmptyElement(writer, "Override", "PartName", "/xl/worksheets/sheet" + (i + 1) + ".xml", "ContentType", "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml");
						writer.WriteEndElement();
					});
					WriteXml(archive, "_rels/.rels", delegate(XmlWriter writer)
					{
						writer.WriteStartElement("Relationships", RelationshipNamespace);
						EmptyElement(writer, "Relationship", "Id", "rId1", "Type", OfficeRelationshipNamespace + "/officeDocument", "Target", "xl/workbook.xml");
						writer.WriteEndElement();
					});
					WriteXml(archive, "xl/workbook.xml", delegate(XmlWriter writer)
					{
						writer.WriteStartElement("workbook", SpreadsheetNamespace);
						writer.WriteAttributeString("xmlns", "r", null, OfficeRelationshipNamespace);
						writer.WriteStartElement("sheets");
						for (int i = 0; i < sheets.Count; i++)
						{
							writer.WriteStartElement("sheet"); writer.WriteAttributeString("name", sheets[i].Name);
							writer.WriteAttributeString("sheetId", (i + 1).ToString(CultureInfo.InvariantCulture));
							writer.WriteAttributeString("r", "id", OfficeRelationshipNamespace, "rId" + (i + 1)); writer.WriteEndElement();
						}
						writer.WriteEndElement(); writer.WriteEndElement();
					});
					WriteXml(archive, "xl/_rels/workbook.xml.rels", delegate(XmlWriter writer)
					{
						writer.WriteStartElement("Relationships", RelationshipNamespace);
						for (int i = 0; i < sheets.Count; i++) EmptyElement(writer, "Relationship", "Id", "rId" + (i + 1), "Type", OfficeRelationshipNamespace + "/worksheet", "Target", "worksheets/sheet" + (i + 1) + ".xml");
						EmptyElement(writer, "Relationship", "Id", "rIdStyles", "Type", OfficeRelationshipNamespace + "/styles", "Target", "styles.xml");
						writer.WriteEndElement();
					});
					WriteStyles(archive);
					for (int i = 0; i < sheets.Count; i++) WriteSheet(archive, i + 1, sheets[i]);
				}
			});
		}

		private static void WriteSheet(ZipArchive archive, int number, Sheet sheet)
		{
			WriteXml(archive, "xl/worksheets/sheet" + number + ".xml", delegate(XmlWriter writer)
			{
				writer.WriteStartElement("worksheet", SpreadsheetNamespace);
				EmptyElement(writer, "dimension", "ref", "A1:" + Cell(sheet.Rows[0].Length - 1, sheet.Rows.Count));
				writer.WriteStartElement("sheetViews"); writer.WriteStartElement("sheetView"); writer.WriteAttributeString("workbookViewId", "0");
				EmptyElement(writer, "pane", "ySplit", "1", "topLeftCell", "A2", "activePane", "bottomLeft", "state", "frozen");
				writer.WriteEndElement(); writer.WriteEndElement();
				EmptyElement(writer, "sheetFormatPr", "defaultRowHeight", "15");
				writer.WriteStartElement("cols");
				EmptyElement(writer, "col", "min", "1", "max", sheet.Rows[0].Length.ToString(CultureInfo.InvariantCulture), "width", "28", "customWidth", "1");
				writer.WriteEndElement();
				writer.WriteStartElement("sheetData");
				for (int row = 0; row < sheet.Rows.Count; row++)
				{
					writer.WriteStartElement("row"); writer.WriteAttributeString("r", (row + 1).ToString(CultureInfo.InvariantCulture));
					for (int column = 0; column < sheet.Rows[row].Length; column++)
					{
						writer.WriteStartElement("c"); writer.WriteAttributeString("r", Cell(column, row + 1)); writer.WriteAttributeString("t", "inlineStr");
						if (row == 0) writer.WriteAttributeString("s", "1");
						writer.WriteStartElement("is"); writer.WriteStartElement("t"); writer.WriteAttributeString("xml", "space", "http://www.w3.org/XML/1998/namespace", "preserve");
						writer.WriteString(ExcelEscape(sheet.Rows[row][column] ?? ""));
						writer.WriteEndElement(); writer.WriteEndElement(); writer.WriteEndElement();
					}
					writer.WriteEndElement();
				}
				writer.WriteEndElement();
				EmptyElement(writer, "autoFilter", "ref", "A1:" + Cell(sheet.Rows[0].Length - 1, sheet.Rows.Count));
				writer.WriteEndElement();
			});
		}

		private static void WriteStyles(ZipArchive archive)
		{
			WriteXml(archive, "xl/styles.xml", delegate(XmlWriter writer)
			{
				writer.WriteStartElement("styleSheet", SpreadsheetNamespace);
				writer.WriteStartElement("fonts"); writer.WriteAttributeString("count", "2");
				writer.WriteStartElement("font"); EmptyElement(writer, "sz", "val", "11"); EmptyElement(writer, "name", "val", "Calibri"); writer.WriteEndElement();
				writer.WriteStartElement("font"); EmptyElement(writer, "b"); EmptyElement(writer, "color", "rgb", "FFFFFFFF"); EmptyElement(writer, "sz", "val", "11"); EmptyElement(writer, "name", "val", "Calibri"); writer.WriteEndElement(); writer.WriteEndElement();
				writer.WriteStartElement("fills"); writer.WriteAttributeString("count", "3");
				writer.WriteStartElement("fill"); EmptyElement(writer, "patternFill", "patternType", "none"); writer.WriteEndElement();
				writer.WriteStartElement("fill"); EmptyElement(writer, "patternFill", "patternType", "gray125"); writer.WriteEndElement();
				writer.WriteStartElement("fill"); writer.WriteStartElement("patternFill"); writer.WriteAttributeString("patternType", "solid"); EmptyElement(writer, "fgColor", "rgb", "FF15364A"); EmptyElement(writer, "bgColor", "indexed", "64"); writer.WriteEndElement(); writer.WriteEndElement(); writer.WriteEndElement();
				writer.WriteStartElement("borders"); writer.WriteAttributeString("count", "1"); writer.WriteStartElement("border"); EmptyElement(writer, "left"); EmptyElement(writer, "right"); EmptyElement(writer, "top"); EmptyElement(writer, "bottom"); EmptyElement(writer, "diagonal"); writer.WriteEndElement(); writer.WriteEndElement();
				writer.WriteStartElement("cellStyleXfs"); writer.WriteAttributeString("count", "1"); EmptyElement(writer, "xf", "numFmtId", "0", "fontId", "0", "fillId", "0", "borderId", "0"); writer.WriteEndElement();
				writer.WriteStartElement("cellXfs"); writer.WriteAttributeString("count", "2");
				EmptyElement(writer, "xf", "numFmtId", "49", "fontId", "0", "fillId", "0", "borderId", "0", "xfId", "0", "applyNumberFormat", "1");
				EmptyElement(writer, "xf", "numFmtId", "49", "fontId", "1", "fillId", "2", "borderId", "0", "xfId", "0", "applyFont", "1", "applyFill", "1", "applyNumberFormat", "1"); writer.WriteEndElement();
				writer.WriteStartElement("cellStyles"); writer.WriteAttributeString("count", "1"); EmptyElement(writer, "cellStyle", "name", "Normal", "xfId", "0", "builtinId", "0"); writer.WriteEndElement();
				writer.WriteEndElement();
			});
		}

		private static void WriteXml(ZipArchive archive, string path, Action<XmlWriter> write)
		{
			using (var stream = archive.CreateEntry(path, CompressionLevel.Optimal).Open())
			using (var writer = XmlWriter.Create(stream, new XmlWriterSettings { Encoding = new UTF8Encoding(false), CloseOutput = false }))
			{
				writer.WriteStartDocument(); write(writer); writer.WriteEndDocument();
			}
		}

		private static void EmptyElement(XmlWriter writer, string element, params string[] attributes)
		{
			writer.WriteStartElement(element);
			for (int i = 0; i < attributes.Length; i += 2) writer.WriteAttributeString(attributes[i], attributes[i + 1]);
			writer.WriteEndElement();
		}

		private static string Cell(int column, int row)
		{
			string name = "";
			for (int value = column + 1; value > 0; value = (value - 1) / 26) name = (char)('A' + (value - 1) % 26) + name;
			return name + row.ToString(CultureInfo.InvariantCulture);
		}

		private static string ExcelEscape(string value)
		{
			value = Regex.Replace(value, @"_x[0-9A-Fa-f]{4}_", m => "_x005F_" + m.Value.Substring(1));
			var result = new StringBuilder();
			for (int i = 0; i < value.Length; i++)
			{
				char c = value[i];
				if (Char.IsHighSurrogate(c) && i + 1 < value.Length && Char.IsLowSurrogate(value[i + 1])) { result.Append(c); result.Append(value[++i]); }
				else if (Char.IsSurrogate(c) || !XmlConvert.IsXmlChar(c) || c == '\r') result.Append("_x" + ((int)c).ToString("X4", CultureInfo.InvariantCulture) + "_");
				else result.Append(c);
			}
			return result.ToString();
		}

		private static string Utc(DateTime value) { return value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture); }

		private static void AtomicExport(string path, Action<string> write)
		{
			path = Path.GetFullPath(path);
			Directory.CreateDirectory(Path.GetDirectoryName(path));
			var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
			try
			{
				write(temporary);
				using (var stream = new FileStream(temporary, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) stream.Flush(true);
				if (File.Exists(path)) File.Replace(temporary, path, null); else File.Move(temporary, path);
			}
			finally { if (File.Exists(temporary)) File.Delete(temporary); }
		}
	}
}
