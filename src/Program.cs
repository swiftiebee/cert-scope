using System;
using System.IO;
using System.Text;
using System.Windows.Forms;
using System.Runtime.Versioning;
using System.Reflection;

[assembly: TargetFramework(".NETFramework,Version=v4.5", FrameworkDisplayName = ".NET Framework 4.5")]
[assembly: AssemblyTitle("CertScope — Инвентаризация сертификатов")]
[assembly: AssemblyVersion("1.0.0.0")]
namespace CertScope
{
	internal static class Program
	{
		[STAThread]
		private static int Main(string[] args)
		{
			if (args.Length > 0 && args[0] == "--worker") return Scanner.RunWorker();
			Application.EnableVisualStyles();
			Application.SetCompatibleTextRenderingDefault(false);
			Application.ThreadException += (s, e) => { AppLog.Error(e.Exception, "UI"); MessageBox.Show(e.Exception.Message, "CertScope", MessageBoxButtons.OK, MessageBoxIcon.Error); };
			AppDomain.CurrentDomain.UnhandledException += (s, e) => AppLog.Error(e.ExceptionObject as Exception, "Unhandled");
			try { Application.Run(new MainForm()); return 0; }
			catch (Exception ex) { AppLog.Error(ex, "Startup"); MessageBox.Show(ex.Message, "Ошибка запуска CertScope"); return 1; }
		}
	}
	public static class AppLog
	{
		private static readonly object Gate = new object();
		public static string DirectoryPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
		public static void Error(Exception ex, string stage)
		{
			if (ex == null) return;
			Write(DateTime.UtcNow.ToString("O") + "\tScanId=-\tPC=" + Environment.MachineName + "\tSource=Application\tStage=" + stage + "\tCode=" + ex.HResult + "\t" + ex.GetType().FullName + "\t" + ex.Message + "\t" + ex.StackTrace);
		}
		public static void Report(SourceReport report)
		{
			Write(DateTime.UtcNow.ToString("O") + "\tScanId=" + report.ScanId + "\tPC=" + report.Computer + "\tSource=" + report.Source + "\tStage=Collection\tStatus=" + report.Status + "\tCode=" + report.ErrorCode + "\t" + report.Message + "\t" + report.StackTrace);
		}
		private static void Write(string line)
		{
			try { lock (Gate) { Directory.CreateDirectory(DirectoryPath); File.AppendAllText(Path.Combine(DirectoryPath, "certscope-" + DateTime.UtcNow.ToString("yyyyMMdd") + ".log"), line.Replace("\r", "\\r").Replace("\n", "\\n") + Environment.NewLine, Encoding.UTF8); } }
			catch (IOException) { System.Diagnostics.Debug.WriteLine("Не удалось записать журнал."); }
			catch (UnauthorizedAccessException) { System.Diagnostics.Debug.WriteLine("Недостаточно прав для записи журнала."); }
		}
	}
}
