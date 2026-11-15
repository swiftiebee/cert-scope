using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace CertScope
{
	/// <summary>Read-only collection. Each potentially blocking source lives in a disposable local process.</summary>
	public static class Scanner
	{
		[DataContract]
		private sealed class Job
		{
			[DataMember] public string Kind;
			[DataMember] public string Computer;
			[DataMember] public string Path;
			[DataMember] public string UserSid;
			[DataMember] public string View;
			[DataMember] public bool CertificateArea;
		}

		[DataContract]
		private sealed class Request
		{
			[DataMember] public Guid ScanId;
			[DataMember] public Job Job;
			[DataMember] public ScanSettings Settings;
			[DataMember] public string Domain;
			[DataMember] public string UserName;
			[DataMember] public string Password;
		}

		[DataContract]
		private sealed class Message
		{
			[DataMember] public Observation Observation;
			[DataMember] public SourceReport Report;
			[DataMember] public Job Discovered;
		}

		private sealed class JobOutcome
		{
			public readonly List<Job> Jobs = new List<Job>();
			public SourceStatus Status = SourceStatus.Error;
			public int Count;
		}

		private sealed class CallbackFailure : Exception
		{
			internal CallbackFailure(Exception cause) : base("Не удалось сохранить/обработать результат. Сканирование остановлено; проверьте доступность локального хранилища.", cause) { }
		}

		/// <summary>Take an immutable settings snapshot and collect bounded hosts and sources.</summary>
		public static ScanResult Run(ScanSettings settings, ScanCredentials credentials, CancellationToken cancellation,
			Action<Observation> onObservation, Action<SourceReport> onReport)
		{
			if (settings == null) throw new ArgumentNullException("settings");
			settings.Validate();
			ScanSettings snapshot = Decode<ScanSettings>(Encode(settings));
			var result = new ScanResult();
			Guid scanId = Guid.NewGuid();
			result.ScanId = scanId;
			object gate = new object();
			var seen = new HashSet<string>(StringComparer.Ordinal);
			var failureCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
			CancellationToken effectiveCancellation = failureCancellation.Token;
			string domain = credentials == null ? null : credentials.Domain;
			string username = credentials == null ? null : credentials.UserName;
			string password = credentials == null ? null : credentials.Password;
			Action<Observation> observation = item =>
			{
				string key = item.Computer.ToUpperInvariant() + "\n" + item.Source + "\n" + item.UserSid + "\n" + item.RegistryView + "\n" + item.Certificate.Sha256;
				lock (gate)
				{
					if (!seen.Add(key)) return;
					result.Observations.Add(item);
					try { if (onObservation != null) onObservation(item); }
					catch (Exception error) { failureCancellation.Cancel(); throw new CallbackFailure(error); }
				}
			};
			Action<SourceReport> report = item =>
			{
				lock (gate)
				{
					result.Sources.Add(item);
					try { if (onReport != null) onReport(item); }
					catch (Exception error) { failureCancellation.Cancel(); throw new CallbackFailure(error); }
				}
			};
			try
			{
			using (var global = new SemaphoreSlim(Math.Max(1, snapshot.MaxWorkers)))
			{
				Parallel.ForEach(snapshot.Computers.Distinct(StringComparer.OrdinalIgnoreCase),
					new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, snapshot.MaxHosts) }, computer =>
				{
					DateTime started = DateTime.UtcNow;
					var statuses = new List<SourceStatus>();
					int total = 0;
					var jobs = BuildFixedJobs(snapshot, computer);
					if (snapshot.IncludeUsers || snapshot.IncludeUserFiles || snapshot.FullRegistry)
					{
						var discover = Execute(new Request { ScanId = scanId, Settings = snapshot, Domain = domain,
							UserName = username, Password = password,
							Job = new Job { Computer = computer, Kind = "Discover", Path = "Профили пользователей", View = "Registry64" } },
							global, effectiveCancellation, observation, report);
						jobs.AddRange(discover.Jobs);
						statuses.Add(discover.Status);
					}
					Parallel.ForEach(jobs, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, snapshot.MaxSourcesPerHost) }, job =>
					{
						JobOutcome outcome = Execute(new Request { ScanId = scanId, Job = job, Settings = snapshot,
							Domain = domain, UserName = username, Password = password }, global, effectiveCancellation, observation, report);
						lock (statuses) { statuses.Add(outcome.Status); total += outcome.Count; }
					});
					SourceStatus aggregate = Aggregate(statuses, total, effectiveCancellation.IsCancellationRequested);
					report(new SourceReport { ScanId = scanId, Computer = computer, Source = "Компьютер", UserSid = "",
						Status = aggregate, StartedUtc = started, FinishedUtc = DateTime.UtcNow, Count = total,
						Message = "Завершено источников: " + statuses.Count + ". Смотрите отдельные статусы; успех не означает охват недоступных профилей." });
				});
			}
			}
			finally { password = null; failureCancellation.Dispose(); }
			return result;
		}

		private static SourceStatus Aggregate(IList<SourceStatus> states, int count, bool cancelled)
		{
			if (cancelled) return SourceStatus.Cancelled;
			if (states.Count == 0) return SourceStatus.NotConfigured;
			if (states.All(s => s == SourceStatus.Success || s == SourceStatus.Empty)) return count == 0 ? SourceStatus.Empty : SourceStatus.Success;
			if (states.Distinct().Count() == 1) return states[0];
			return SourceStatus.Partial;
		}

		private static List<Job> BuildFixedJobs(ScanSettings settings, string computer)
		{
			var jobs = new List<Job>();
			foreach (string view in settings.RegistryViews)
			{
				if (settings.IncludeCryptoPro) jobs.Add(new Job { Computer = computer, Kind = "CryptoPro", Path = "CryptoProInstallation / " + view, View = view, UserSid = "" });
				if (settings.FullRegistry)
				{
					jobs.Add(RegistryJob(computer, "HKLM", view, false, ""));
					if (settings.SelectedSids.Count == 0) jobs.Add(RegistryJob(computer, "HKU", view, false, ""));
					else foreach (string sid in settings.SelectedSids) jobs.Add(RegistryJob(computer, "HKU\\" + sid, view, false, sid));
				}
				else
				{
					if (settings.IncludeMachine)
					{
						jobs.Add(RegistryJob(computer, @"HKLM\SOFTWARE\Microsoft\SystemCertificates", view, true, ""));
						jobs.Add(RegistryJob(computer, @"HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates", view, true, ""));
					}
					foreach (string path in settings.RegistryBranches)
						jobs.Add(RegistryJob(computer, path.Trim(), view, false, ""));
				}
			}
			foreach (string path in settings.Directories)
				jobs.Add(new Job { Computer = computer, Kind = "Files", Path = path.Trim(), UserSid = "", View = "" });
			return jobs.GroupBy(j => j.Kind + "\n" + j.Path + "\n" + j.View, StringComparer.OrdinalIgnoreCase).Select(g => g.First()).ToList();
		}

		private static Job RegistryJob(string computer, string path, string view, bool certificates, string sid)
		{
			return new Job { Kind = "Registry", Computer = computer, Path = path, View = view, CertificateArea = certificates, UserSid = sid };
		}

		/// <summary>Dispose the entire worker at deadline; CancellationToken alone cannot stop RPC.</summary>
		private static JobOutcome Execute(Request request, SemaphoreSlim global, CancellationToken cancellation,
			Action<Observation> observation, Action<SourceReport> report)
		{
			var outcome = new JobOutcome();
			DateTime started = DateTime.UtcNow;
			bool acquired = false;
			try
			{
				global.Wait(cancellation);
				acquired = true;
				for (int attempt = 0; attempt <= request.Settings.RetryCount; attempt++)
				{
					cancellation.ThrowIfCancellationRequested();
					bool finalReceived = false;
					using (var process = new Process())
					{
						process.StartInfo = new ProcessStartInfo
						{
							FileName = System.Windows.Forms.Application.ExecutablePath,
							Arguments = "--worker", UseShellExecute = false, CreateNoWindow = true,
							RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
							StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
						};
						try
						{
							process.Start();
							var reader = Task.Run(() =>
							{
								string line;
								while ((line = process.StandardOutput.ReadLine()) != null)
								{
									Message message = Decode<Message>(line);
									if (message.Observation != null) { observation(message.Observation); outcome.Count++; }
									if (message.Discovered != null) outcome.Jobs.Add(message.Discovered);
									if (message.Report != null)
									{
										report(message.Report);
										if (message.Report.Source == request.Job.Path)
										{
											outcome.Status = message.Report.Status;
											finalReceived = true;
										}
									}
								}
							});
							var errors = Task.Run(() => { while (process.StandardError.ReadLine() != null) { } });
							var timer = Stopwatch.StartNew();
							// Pipe writes can block too: include sending a large request in the worker deadline.
							// UTF-8 is explicit at both ends. Credentials never appear in process arguments.
							var inputWriter = Task.Run(() =>
							{
								using (var input = new StreamWriter(process.StandardInput.BaseStream, new UTF8Encoding(false)))
									input.WriteLine(Encode(request));
							});
							bool timeout = false;
							while (!process.WaitForExit(100))
							{
								if (reader.IsFaulted || inputWriter.IsFaulted || cancellation.IsCancellationRequested || timer.Elapsed.TotalSeconds >= request.Settings.TimeoutSeconds)
								{
									timeout = !cancellation.IsCancellationRequested && timer.Elapsed.TotalSeconds >= request.Settings.TimeoutSeconds;
									process.Kill();
									process.WaitForExit();
									break;
								}
							}
							Task.WaitAll(reader, errors);
							try { inputWriter.Wait(); }
							catch (AggregateException) { if (!timeout && !cancellation.IsCancellationRequested) throw; }
							if (cancellation.IsCancellationRequested) throw new OperationCanceledException(cancellation);
							if (timeout)
							{
								outcome.Status = SourceStatus.Timeout;
								report(CreateReport(request, started, SourceStatus.Timeout, "Лимит времени источника; локальный worker остановлен. Полученные до остановки результаты сохранены.", outcome.Count, null));
							}
							else if (!finalReceived || process.ExitCode != 0)
							{
								outcome.Status = SourceStatus.Error;
								report(CreateReport(request, started, SourceStatus.Error, "Worker завершился без успешного окончания протокола; код " + process.ExitCode + ".", outcome.Count, null));
							}
						}
						finally
						{
							try { if (!process.HasExited) { process.Kill(); process.WaitForExit(); } } catch (InvalidOperationException) { }
						}
					}
					if (outcome.Status != SourceStatus.Unreachable) break;
					if (attempt < request.Settings.RetryCount && cancellation.WaitHandle.WaitOne(250 * (attempt + 1)))
						throw new OperationCanceledException(cancellation);
				}
			}
			catch (OperationCanceledException)
			{
				outcome.Status = SourceStatus.Cancelled;
				report(CreateReport(request, started, SourceStatus.Cancelled, "Сканирование отменено; частичные результаты сохранены.", outcome.Count, null));
			}
			catch (Exception error)
			{
				if (ContainsCallbackFailure(error)) throw;
				outcome.Status = Classify(error);
				report(CreateReport(request, started, outcome.Status, error.Message, outcome.Count, error));
			}
			finally { if (acquired) global.Release(); }
			return outcome;
		}

		private static bool ContainsCallbackFailure(Exception error)
		{
			if (error is CallbackFailure) return true;
			var aggregate = error as AggregateException;
			if (aggregate != null) return aggregate.Flatten().InnerExceptions.Any(ContainsCallbackFailure);
			return error.InnerException != null && ContainsCallbackFailure(error.InnerException);
		}

		/// <summary>Called by Program for --worker. No asynchronous work crosses impersonation.</summary>
		public static int RunWorker()
		{
			using (var input = new StreamReader(Console.OpenStandardInput(), Encoding.UTF8))
			using (var output = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true })
			{
				Request request = null;
				DateTime started = DateTime.UtcNow;
				try
				{
					request = Decode<Request>(input.ReadLine());
					using (var identity = new NetworkIdentity(request.Domain, request.UserName, request.Password))
					{
						request.Password = null;
						var collector = new Collector(request, m => output.WriteLine(Encode(m)));
						collector.Run();
					}
					return 0;
				}
				catch (Exception error)
				{
					if (request != null)
						output.WriteLine(Encode(new Message { Report = CreateReport(request, started, Classify(error), error.Message, 0, error) }));
					return request == null ? 2 : 0;
				}
			}
		}

		private sealed class Collector
		{
			private readonly Request request;
			private readonly Action<Message> send;
			private readonly DateTime started = DateTime.UtcNow;
			private int count, examined, unknown, skipped;
			private bool partial;

			internal Collector(Request request, Action<Message> send) { this.request = request; this.send = send; }

			internal void Run()
			{
				if (request.Job.Kind == "Discover") Discover();
				else if (request.Job.Kind == "Registry") Registry();
				else if (request.Job.Kind == "Files") Files();
				else if (request.Job.Kind == "CryptoPro") { CryptoPro(); return; }
				else throw new NotSupportedException("Неизвестный тип источника.");
				SourceStatus status = partial ? SourceStatus.Partial : count == 0 ? SourceStatus.Empty : SourceStatus.Success;
				if (request.Job.Kind == "Discover" && !partial) status = SourceStatus.Success;
				send(new Message { Report = CreateReport(request, started, status,
					"Проверено значений/файлов: " + examined + "; сертификатов: " + count + "; данных другого/неизвестного формата: " + unknown + "; пропусков: " + skipped + ".", count, null) });
			}

			private RegistryKey OpenRoot(RegistryHive hive, string view)
			{
				RegistryView selected = view == "Registry32" ? RegistryView.Registry32 : RegistryView.Registry64;
				return IsLocal(request.Job.Computer) ? RegistryKey.OpenBaseKey(hive, selected) : RegistryKey.OpenRemoteBaseKey(hive, request.Job.Computer, selected);
			}

			private void Discover()
			{
				var loaded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
				var profiles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
				if (request.Settings.SelectedSids.Count == 0) try
				{
					using (RegistryKey users = OpenRoot(RegistryHive.Users, "Registry64"))
						foreach (string sid in users.GetSubKeyNames()) if (IsSid(sid)) loaded.Add(sid);
				}
				catch (Exception e) { Issue("HKU: перечисление загруженных SID", Classify(e), e.Message, e); }
				// Explicit SIDs do not require enumerating other users or unrelated ProfileList entries.
				if (request.Settings.SelectedSids.Count == 0 || request.Settings.IncludeUserFiles) try
				{
					using (RegistryKey machine = OpenRoot(RegistryHive.LocalMachine, "Registry64"))
					{
						const string profileRoot = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
						IEnumerable<string> profileSids = request.Settings.SelectedSids;
						if (request.Settings.SelectedSids.Count == 0)
						{
							using (RegistryKey list = machine.OpenSubKey(profileRoot, false))
							{
								if (list == null) Issue("ProfileList", SourceStatus.NotConfigured, "Список профилей не найден; охват пользователей неизвестен.", null);
								else profileSids = list.GetSubKeyNames();
							}
						}
						foreach (string sid in profileSids)
						{
							if (!IsSid(sid)) continue;
							try { using (RegistryKey profile = machine.OpenSubKey(profileRoot + "\\" + sid, false))
							{
								object raw = profile == null ? null : profile.GetValue("ProfileImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
								profiles[sid] = raw as string;
							} }
							catch (Exception e) { Issue("ProfileList\\" + sid, Classify(e), e.Message, e); }
						}
					}
				}
				catch (Exception e) { Issue("ProfileList: перечисление профилей", Classify(e), e.Message, e); }
				IEnumerable<string> candidates = request.Settings.SelectedSids.Count > 0 ? request.Settings.SelectedSids : loaded.Union(profiles.Keys);
				foreach (string sid in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
				{
					if (!IsSid(sid)) { Issue("SID " + sid, SourceStatus.Unsupported, "Некорректный SID пользователя.", null); continue; }
					if (request.Settings.IncludeUsers || request.Settings.FullRegistry)
					{
						if (loaded.Contains(sid) || request.Settings.SelectedSids.Contains(sid))
						{
							if (!request.Settings.FullRegistry)
							foreach (string view in request.Settings.RegistryViews)
							{
								send(new Message { Discovered = RegistryJob(request.Job.Computer, "HKU\\" + sid + @"\Software\Microsoft\SystemCertificates", view, true, sid) });
								send(new Message { Discovered = RegistryJob(request.Job.Computer, "HKU\\" + sid + @"\Software\Policies\Microsoft\SystemCertificates", view, true, sid) });
							}
						}
						else Issue("HKU\\" + sid, SourceStatus.NotConfigured, "Профиль не загружен или его загрузку не удалось подтвердить. NTUSER.DAT не подключается автоматически.", null);
					}
					if (!request.Settings.IncludeUserFiles) continue;
					if (!loaded.Contains(sid) && !request.Settings.SelectedSids.Contains(sid))
					{
						Issue("MY файлы / " + sid, SourceStatus.NotConfigured,
							"Невозможно подтвердить AppData незагруженного профиля и перенаправление папок. Добавьте известный каталог в настройки; профиль не подключается.", null);
						continue;
					}
					try
					{
						string appData;
						using (RegistryKey users = OpenRoot(RegistryHive.Users, "Registry64"))
						using (RegistryKey shell = users.OpenSubKey(sid + @"\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", false))
							appData = shell == null ? null : shell.GetValue("AppData", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
						if (String.IsNullOrWhiteSpace(appData))
						{
							Issue("MY файлы / " + sid, SourceStatus.NotConfigured, "AppData не задан в User Shell Folders; путь оператора не подставляется.", null);
							continue;
						}
						string profilePath;
						if (profiles.TryGetValue(sid, out profilePath) && !String.IsNullOrWhiteSpace(profilePath) && profilePath.IndexOf('%') < 0)
							appData = ReplaceInsensitive(appData, "%USERPROFILE%", profilePath);
						if (appData.IndexOf('%') >= 0)
						{
							Issue("MY файлы / " + sid, SourceStatus.NotConfigured, "Путь AppData содержит неразрешённые переменные удалённого пользователя: " + appData + ". Задайте каталог явно.", null);
							continue;
						}
						string directory = ResolveDirectory(request.Job.Computer, Path.Combine(appData, @"Microsoft\SystemCertificates\My\Certificates"));
						if (!IsPermittedDiscoveredPath(directory))
						{
							Issue("MY файлы / " + sid, SourceStatus.NotConfigured, "Перенаправленный AppData указывает на другой сервер: " + directory + ". Добавьте разрешённый UNC-каталог явно; автоматическая передача credentials на новый сервер отключена.", null);
							continue;
						}
						send(new Message { Discovered = new Job { Kind = "Files", Computer = request.Job.Computer, UserSid = sid, View = "", Path = directory, CertificateArea = true } });
					}
					catch (Exception e) { Issue("MY файлы / " + sid, Classify(e), e.Message, e); }
				}
			}

			private bool IsPermittedDiscoveredPath(string path)
			{
				if (!path.StartsWith(@"\\", StringComparison.Ordinal)) return true;
				string server = path.Substring(2).Split('\\')[0];
				if (server.Equals(request.Job.Computer, StringComparison.OrdinalIgnoreCase) || (IsLocal(request.Job.Computer) && IsLocal(server))) return true;
				return request.Settings.Directories.Any(allowed =>
				{
					string expanded = ReplaceInsensitive(allowed.Trim(), "{computer}", request.Job.Computer).TrimEnd('\\');
					return expanded.StartsWith(@"\\", StringComparison.Ordinal) && (path.Equals(expanded, StringComparison.OrdinalIgnoreCase) || path.StartsWith(expanded + "\\", StringComparison.OrdinalIgnoreCase));
				});
			}

			private void Registry()
			{
				string branch = request.Job.Path;
				RegistryHive hive;
				if (branch.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)) hive = RegistryHive.Users;
				else if (branch.Equals("HKLM", StringComparison.OrdinalIgnoreCase) || branch.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase))
				{ hive = RegistryHive.LocalMachine; branch = branch.Length == 4 ? "" : branch.Substring(5); }
				else if (branch.Equals("HKU", StringComparison.OrdinalIgnoreCase) || branch.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase))
				{ hive = RegistryHive.Users; branch = branch.Length == 3 ? "" : branch.Substring(4); }
				else throw new NotSupportedException("Поддерживаются явные ветки HKLM\\... и HKU\\SID\\...; удалённый HKCU неоднозначен.");
				using (RegistryKey root = OpenRoot(hive, request.Job.View))
				{
					var pending = new Stack<string>();
					pending.Push(branch);
					int keys = 0;
					while (pending.Count > 0)
					{
						string path = pending.Pop();
						// SystemCertificates also contains key metadata, revocation lists and trust lists.
						// These are not public certificates; skip before opening or reading their values.
						if (IsNonCertificateStoreBranch(path)) continue;
						if (++keys > request.Settings.MaxRegistryValues || examined >= request.Settings.MaxRegistryValues)
						{ Issue(request.Job.Path + " / лимит", SourceStatus.Partial, "Достигнут лимит ключей/значений " + request.Settings.MaxRegistryValues + "; оставшиеся ветки не проверены.", null); break; }
						try
						{
							using (RegistryKey key = root.OpenSubKey(path, false))
							{
								if (key == null) { Issue(path, SourceStatus.NotConfigured, "Ветка отсутствует либо недоступна.", null); continue; }
								foreach (string name in key.GetValueNames())
								{
									if (examined >= request.Settings.MaxRegistryValues) { Issue(request.Job.Path + " / лимит", SourceStatus.Partial, "Достигнут лимит значений; оставшиеся значения не проверены.", null); break; }
									examined++;
									string location = (hive == RegistryHive.Users ? "HKU\\" : "HKLM\\") + path + "\\@" + name;
									try
									{
										byte[] data = ReadRegistryData(key, name, request.Settings.MaxFileBytes);
										if (data == null) { unknown++; continue; }
										if (data.Length > request.Settings.MaxFileBytes) { Issue(location, SourceStatus.Partial, "Значение превышает лимит байт; не разобрано.", null); continue; }
										Parse(data, location, request.Job.CertificateArea && path.IndexOf("\\Certificates\\", StringComparison.OrdinalIgnoreCase) >= 0 && name.Equals("Blob", StringComparison.OrdinalIgnoreCase));
									}
									catch (Exception e) { Issue(location, Classify(e), e.Message, e); }
								}
								foreach (string child in key.GetSubKeyNames())
								{
									if (pending.Count >= request.Settings.MaxRegistryValues) { Issue(path, SourceStatus.Partial, "Лимит ожидающих веток; часть подветок не добавлена.", null); break; }
									pending.Push(path.Length == 0 ? child : path + "\\" + child);
								}
							}
						}
						catch (Exception e) { Issue(path, Classify(e), e.Message, e); }
					}
				}
			}

			private static bool IsNonCertificateStoreBranch(string path)
			{
				string[] parts = path.Split('\\');
				for (int i = 0; i + 2 < parts.Length; i++)
				{
					if (!parts[i].Equals("SystemCertificates", StringComparison.OrdinalIgnoreCase)) continue;
					string area = parts[i + 2];
					return area.Equals("Keys", StringComparison.OrdinalIgnoreCase) || area.Equals("CRLs", StringComparison.OrdinalIgnoreCase) || area.Equals("CTLs", StringComparison.OrdinalIgnoreCase);
				}
				return false;
			}

			/// <summary>Read installed-product metadata only; do not infer a certificate licence from it.</summary>
			private void CryptoPro()
			{
				var versions = new List<string>();
				using (RegistryKey machine = OpenRoot(RegistryHive.LocalMachine, request.Job.View))
				{
					foreach (string path in new[] { @"SOFTWARE\Crypto Pro\Cryptography\CurrentVersion", @"SOFTWARE\Crypto Pro\Cryptography" })
					{
						try
						{
							using (RegistryKey key = machine.OpenSubKey(path, false))
							{
								if (key == null) continue;
								foreach (string name in new[] { "Version", "ProductVersion", "DisplayVersion", "Build" })
								{
									object value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
									if (value != null) versions.Add("HKLM\\" + path + " @" + name + " = " + Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture));
								}
							}
						}
						catch (Exception e) { Issue(path, Classify(e), e.Message, e); }
					}
					try
					{
						using (RegistryKey uninstall = machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", false))
						{
							if (uninstall != null) foreach (string name in uninstall.GetSubKeyNames())
							{
								try
								{
									using (RegistryKey item = uninstall.OpenSubKey(name, false))
									{
										if (item == null) continue;
										string display = item.GetValue("DisplayName", "", RegistryValueOptions.DoNotExpandEnvironmentNames) as string ?? "";
										if ((display.IndexOf("CryptoPro", StringComparison.OrdinalIgnoreCase) >= 0 || display.IndexOf("Crypto Pro", StringComparison.OrdinalIgnoreCase) >= 0 || display.IndexOf("КриптоПро", StringComparison.OrdinalIgnoreCase) >= 0) && display.IndexOf("CSP", StringComparison.OrdinalIgnoreCase) >= 0)
											versions.Add(display + ": " + Convert.ToString(item.GetValue("DisplayVersion", "Версия не указана", RegistryValueOptions.DoNotExpandEnvironmentNames)) + " [Uninstall\\" + name + "]");
									}
								}
								catch (Exception e) { Issue("Uninstall\\" + name, Classify(e), e.Message, e); }
							}
						}
					}
					catch (Exception e) { Issue("Uninstall", Classify(e), e.Message, e); }
				}
				send(new Message { Report = CreateReport(request, started, partial ? SourceStatus.Partial : versions.Count == 0 ? SourceStatus.Empty : SourceStatus.Success,
					versions.Count == 0 ? "Сведения о версии установленного КриптоПро CSP не найдены в доступных исследованных ветках. Это не проверка встроенной лицензии." : String.Join("; ", versions) + ". Версия установленного продукта; действительность лицензии не проверялась.", 0, null) });
			}

			private void Files()
			{
				string start = ResolveDirectory(request.Job.Computer, request.Job.Path);
				if (start.IndexOf('%') >= 0) throw new NotSupportedException("Путь содержит неразрешённые переменные. Задайте абсолютный путь целевого компьютера.");
				if (File.Exists(start)) { ReadFile(start); return; }
				var pending = new Stack<string>();
				pending.Push(start);
				int directories = 0;
				while (pending.Count > 0)
				{
					string path = pending.Pop();
					if (++directories > request.Settings.MaxRegistryValues || examined >= request.Settings.MaxRegistryValues)
					{ Issue(path, SourceStatus.Partial, "Лимит количества каталогов/файлов; обход не завершён.", null); break; }
					try
					{
						if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
						{ Issue(path, SourceStatus.Unsupported, "Точка повторной обработки/ссылка не обходится автоматически; задайте фактический каталог явно.", null); continue; }
						foreach (string file in Directory.EnumerateFiles(path))
						{
							if (examined >= request.Settings.MaxRegistryValues) { Issue(path + " / лимит", SourceStatus.Partial, "Достигнут лимит файлов; оставшиеся файлы не проверены.", null); break; }
							ReadFile(file);
						}
						foreach (string directory in Directory.EnumerateDirectories(path))
						{
							if (pending.Count >= request.Settings.MaxRegistryValues) { Issue(path, SourceStatus.Partial, "Лимит очереди каталогов; не все подкаталоги добавлены.", null); break; }
							pending.Push(directory);
						}
					}
					catch (Exception e) { Issue(path, Classify(e), e.Message, e); }
				}
			}

			private void ReadFile(string path)
			{
				examined++;
				try
				{
					if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
					{ Issue(path, SourceStatus.Unsupported, "Файл-ссылка пропущен.", null); return; }
					using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
					{
						if (file.Length > request.Settings.MaxFileBytes) { Issue(path, SourceStatus.Partial, "Размер файла превышает лимит; файл не прочитан.", null); return; }
						using (var buffer = new MemoryStream())
						{
							byte[] block = new byte[8192];
							int read;
							while ((read = file.Read(block, 0, block.Length)) != 0)
							{
								if (buffer.Length + read > request.Settings.MaxFileBytes) { Issue(path, SourceStatus.Partial, "Файл вырос сверх лимита во время чтения.", null); return; }
								buffer.Write(block, 0, read);
							}
							Parse(buffer.ToArray(), path, true);
						}
					}
				}
				catch (Exception e) { Issue(path, Classify(e), e.Message, e); }
			}

			private void Parse(byte[] bytes, string source, bool expected)
			{
				try
				{
					List<CertificateRecord> certificates = CertificateParser.Parse(bytes);
					if (certificates.Count == 0)
					{
						unknown++;
						if (expected) Issue(source, SourceStatus.Unsupported, "Открытый X.509 не найден; неизвестный формат либо контейнер, не разрешённый для импорта ключей.", null);
					}
					foreach (CertificateRecord certificate in certificates)
					{
						count++;
						send(new Message { Observation = new Observation { Id = Guid.NewGuid(), ScanId = request.ScanId, Computer = request.Job.Computer,
							Source = source, UserSid = request.Job.UserSid ?? "", RegistryView = request.Job.View ?? "", FoundUtc = DateTime.UtcNow, Certificate = certificate } });
					}
				}
				catch (Exception e)
				{
					unknown++;
					if (expected) Issue(source, e is NotSupportedException ? SourceStatus.Unsupported : SourceStatus.Error, e.Message, e);
				}
			}

			private void Issue(string source, SourceStatus status, string message, Exception error)
			{
				partial = true; skipped++;
				SourceReport report = CreateReport(request, started, status, message, 0, error);
				report.Source = source;
				send(new Message { Report = report });
			}
		}

		private static SourceReport CreateReport(Request request, DateTime started, SourceStatus status, string message, int count, Exception error)
		{
			return new SourceReport { ScanId = request.ScanId, Computer = request.Job.Computer, Source = request.Job.Path,
				UserSid = request.Job.UserSid ?? "", Status = status, Message = message, StartedUtc = started, FinishedUtc = DateTime.UtcNow,
				Count = count, ErrorCode = error == null ? 0 : error is Win32Exception ? ((Win32Exception)error).NativeErrorCode : error.HResult, StackTrace = error == null ? "" : error.ToString() };
		}

		private static SourceStatus Classify(Exception error)
		{
			if (error is UnauthorizedAccessException || error is SecurityException) return SourceStatus.AccessDenied;
			if (error is FileNotFoundException || error is DirectoryNotFoundException) return SourceStatus.NotConfigured;
			if (error is NotSupportedException) return SourceStatus.Unsupported;
			int code = error is Win32Exception ? ((Win32Exception)error).NativeErrorCode : error.HResult & 0xffff;
			if (code == 5 || code == 1326 || code == 1314 || code == 1385) return SourceStatus.AccessDenied;
			if (code == 53 || code == 64 || code == 67 || code == 121 || code == 1231 || code == 1722 || code == 1727 || code == 1753) return SourceStatus.Unreachable;
			return SourceStatus.Error;
		}

		private static bool IsSid(string sid)
		{
			if (String.IsNullOrEmpty(sid) || !sid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase) || sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) return false;
			try { new SecurityIdentifier(sid); return true; } catch (ArgumentException) { return false; }
		}

		/// <summary>Query size before allocation, then read into a bounded buffer even if the value changes.</summary>
		private static byte[] ReadRegistryData(RegistryKey key, string name, int maximum)
		{
			uint type, length = 0;
			int status = RegQueryValueEx(key.Handle, name, IntPtr.Zero, out type, null, ref length);
			if (status != 0) throw new Win32Exception(status);
			if (type != 1 && type != 2 && type != 3) return null;
			if (length > maximum) throw new InvalidDataException("Значение превышает лимит байт; не прочитано.");
			byte[] buffer = new byte[(int)length];
			status = RegQueryValueEx(key.Handle, name, IntPtr.Zero, out type, buffer, ref length);
			if (status != 0) throw new Win32Exception(status);
			if (length != buffer.Length) Array.Resize(ref buffer, (int)length);
			if (type == 1 || type == 2) return Encoding.UTF8.GetBytes(Encoding.Unicode.GetString(buffer).TrimEnd('\0'));
			return type == 3 ? buffer : null;
		}

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
		private static extern int RegQueryValueEx(Microsoft.Win32.SafeHandles.SafeRegistryHandle key, string name, IntPtr reserved, out uint type, byte[] data, ref uint length);

		private static bool IsLocal(string computer)
		{
			return computer == "." || computer.Equals("localhost", StringComparison.OrdinalIgnoreCase) || computer.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase);
		}

		private static string ResolveDirectory(string computer, string path)
		{
			path = ReplaceInsensitive(path, "{computer}", computer);
			if (IsLocal(computer) || path.StartsWith(@"\\", StringComparison.Ordinal)) return path;
			if (path.Length >= 3 && Char.IsLetter(path[0]) && path[1] == ':' && (path[2] == '\\' || path[2] == '/'))
				return @"\\" + computer + "\\" + path[0] + "$" + path.Substring(2);
			throw new NotSupportedException("Для удалённого компьютера нужен абсолютный путь диска или UNC-путь общей папки.");
		}

		private static string ReplaceInsensitive(string input, string from, string to)
		{
			int offset = input.IndexOf(from, StringComparison.OrdinalIgnoreCase);
			while (offset >= 0) { input = input.Substring(0, offset) + to + input.Substring(offset + from.Length); offset = input.IndexOf(from, offset + to.Length, StringComparison.OrdinalIgnoreCase); }
			return input;
		}

		private static string Encode<T>(T value)
		{
			using (var stream = new MemoryStream()) { new DataContractJsonSerializer(typeof(T)).WriteObject(stream, value); return Encoding.UTF8.GetString(stream.ToArray()); }
		}

		private static T Decode<T>(string value)
		{
			using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(value))) return (T)new DataContractJsonSerializer(typeof(T)).ReadObject(stream);
		}

		private sealed class NetworkIdentity : IDisposable
		{
			private IntPtr token;
			private WindowsImpersonationContext context;
			internal NetworkIdentity(string domain, string username, string password)
			{
				if (String.IsNullOrWhiteSpace(username)) return;
				if (!LogonUser(username, String.IsNullOrWhiteSpace(domain) ? null : domain, password ?? "", 9, 3, out token))
					throw new Win32Exception(Marshal.GetLastWin32Error());
				try { context = WindowsIdentity.Impersonate(token); }
				catch { CloseHandle(token); token = IntPtr.Zero; throw; }
			}
			public void Dispose()
			{
				try { if (context != null) { context.Dispose(); context = null; } }
				finally { if (token != IntPtr.Zero) { CloseHandle(token); token = IntPtr.Zero; } }
			}
			[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)] private static extern bool LogonUser(string username, string domain, string password, int type, int provider, out IntPtr token);
			[DllImport("kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
		}
	}
}
