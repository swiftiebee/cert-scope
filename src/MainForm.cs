using System;
using System.Collections.Generic;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace CertScope
{
	/// <summary>Рабочее место оператора: реальные результаты, настройки и проверяемый охват.</summary>
	public sealed class MainForm : Form
	{
		private readonly Color Navy = Theme.Blue, Teal = Theme.Teal, Pale = Theme.Canvas;
		private readonly string basePath = AppDomain.CurrentDomain.BaseDirectory;
		private ScanSettings settings;
		private LocalRepository repository;
		private readonly List<Observation> observations = new List<Observation>();
		private readonly List<SourceReport> reports = new List<SourceReport>();
		private readonly DataGridView certificateGrid = Grid(), reportGrid = Grid(), computerGrid = Grid();
		private List<string> activeComputers = new List<string>();
		private DateTime activeSince = DateTime.MinValue;
		private readonly TextBox search = new TextBox(), computers = Lines(), directories = Lines(), branches = Lines(), sids = Lines(), sql = new TextBox(), user = new TextBox(), domain = new TextBox(), password = new TextBox();
		private readonly CheckBox machine = new CheckBox(), users = new CheckBox(), userFiles = new CheckBox(), cryptoPro = new CheckBox(), full = new CheckBox(), view32 = new CheckBox(), view64 = new CheckBox();
		private readonly NumericUpDown hosts = Number(1,32), perHost = Number(1,16), workers = Number(1,32), timeout = Number(1,3600), retries = Number(0,3), maxBytes = Number(1,64), maxValues = Number(1,10000000);
		private readonly TextBox dataPath = new TextBox(), logPath = new TextBox();
		private readonly Label totalLabel = new Label(), warningLabel = new Label(), queueLabel = new Label(), status = new Label(), identity = new Label();
		private readonly ActionButton start = new ActionButton(), cancel = new ActionButton(), sync = new ActionButton();
		private readonly ComboBox expiry = new ComboBox();
		private readonly WorkspaceTabs tabs = new WorkspaceTabs();
		private readonly Label resultCount = new Label();
		private readonly ProgressBar activity = new ProgressBar();
		private Panel statusDot;
		private CancellationTokenSource cancellation;
		private bool running, syncing;
		private readonly System.Windows.Forms.Timer refresh = new System.Windows.Forms.Timer();
		private bool dirty;
		public MainForm()
		{
			Text = "CertScope | Инвентаризация сертификатов"; Size = new Size(1440, 940); MinimumSize = new Size(1120, 800); StartPosition = FormStartPosition.CenterScreen;
			Font = new Font("Segoe UI", 10); ForeColor = Theme.Ink; BackColor = Pale; AutoScaleDimensions = new SizeF(96, 96); AutoScaleMode = AutoScaleMode.Dpi; DoubleBuffered = true;
			using (var iconStream = typeof(MainForm).Assembly.GetManifestResourceStream("CertScope.Icon"))
                if (iconStream != null) using (var icon = new Icon(iconStream)) Icon = (Icon)icon.Clone();
            KeyPreview = true;
            KeyDown += (s, e) => { if (e.Control && e.KeyCode == Keys.F) { tabs.SelectedIndex = 0; search.Focus(); e.SuppressKeyPress = true; } };
            settings = ScanSettings.Default();
			string configPath = Path.Combine(basePath, "settings.json");
			if (File.Exists(configPath)) { try { settings = Json.Deserialize<ScanSettings>(File.ReadAllText(configPath, Encoding.UTF8)); settings.Validate(); } catch (Exception ex) { AppLog.Error(ex,"Configuration"); MessageBox.Show("Настройки не прочитаны; загружены стандартные.\n" + ex.Message); settings = ScanSettings.Default(); } }
			BuildLayout(); PopulateSettings(); OpenRepository();
			refresh.Interval = 500; refresh.Tick += (s,e) => { if (dirty) { dirty = false; RefreshResults(); } }; refresh.Start();
			FormClosing += (s,e) => { if (running || syncing) { e.Cancel = true; if (cancellation != null) cancellation.Cancel(); status.Text = "Отмена операции… После завершения окно можно закрыть."; } };
		}
		private static TextBox Lines()
        {
            return new TextBox { Multiline = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill,
                AcceptsReturn = true, BorderStyle = BorderStyle.FixedSingle, BackColor = Color.FromArgb(246, 248, 252),
                ForeColor = Theme.Ink, Margin = new Padding(0, 5, 0, 8) };
        }
        private static NumericUpDown Number(int min, int max)
        {
            return new NumericUpDown { Minimum = min, Maximum = max, Width = 100, Margin = new Padding(6),
                ThousandsSeparator = true, BorderStyle = BorderStyle.FixedSingle, BackColor = Color.FromArgb(246, 248, 252), ForeColor = Theme.Ink };
        }
        private static DataGridView Grid()
        {
            return new DataGridView { Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false,
                AllowUserToDeleteRows = false, AutoGenerateColumns = false, BackgroundColor = Color.White,
                BorderStyle = BorderStyle.None, CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal,
                GridColor = Color.FromArgb(233, 238, 246), ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None,
                RowHeadersVisible = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect, MultiSelect = true,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill, AllowUserToResizeRows = false,
                RowTemplate = { Height = 48 }, EnableHeadersVisualStyles = false, ColumnHeadersHeight = 46,
                ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing,
                ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle { BackColor = Color.FromArgb(243, 246, 252),
                    ForeColor = Theme.Blue, Font = new Font("Segoe UI", 9, FontStyle.Bold), Padding = new Padding(12, 0, 8, 0),
                    SelectionBackColor = Color.FromArgb(243, 246, 252) },
                AlternatingRowsDefaultCellStyle = new DataGridViewCellStyle { BackColor = Color.FromArgb(250, 251, 254) },
                DefaultCellStyle = new DataGridViewCellStyle { ForeColor = Theme.Ink, Font = new Font("Segoe UI", 10),
                    SelectionBackColor = Color.FromArgb(221, 231, 252), SelectionForeColor = Theme.Blue,
                    Padding = new Padding(12, 0, 8, 0) } };
        }
        private Button ActionButton(string text, EventHandler action, bool primary = false)
        {
            var button = new ActionButton { Text = text, Kind = primary ? ButtonKind.Primary : ButtonKind.Secondary,
                AutoSize = true, MinimumSize = new Size(105, 38), Height = 38, Padding = new Padding(14, 6, 14, 6),
                Margin = new Padding(0, 4, 8, 4) };
            button.Click += action;
            return button;
        }
        private static Label TextLabel(string text, float size, Color color, FontStyle style = FontStyle.Regular)
        {
            return new Label { Text = text, AutoSize = false, Dock = DockStyle.Fill, Margin = Padding.Empty,
                TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI", size, style), ForeColor = color };
        }
        private static Panel IconTile(UiIcon icon, Color background, Color foreground, int size)
        {
            var tile = new SurfacePanel { Size = new Size(size, size), FillColor = background,
                BorderColor = background, Radius = 10, Margin = Padding.Empty };
            tile.Paint += (s, e) => Theme.DrawIcon(e.Graphics, icon,
                new RectangleF(tile.Width * .25f, tile.Height * .25f, tile.Width * .5f, tile.Height * .5f), foreground, 1.7f);
            return tile;
        }
        private void BuildLayout()
        {
            SuspendLayout();
            var body = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 6, ColumnCount = 1,
                Padding = new Padding(28, 0, 28, 0), Margin = Padding.Empty, BackColor = Pale };
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            body.RowStyles.Add(new RowStyle(SizeType.Absolute, 76));
            body.RowStyles.Add(new RowStyle(SizeType.Absolute, 98));
            body.RowStyles.Add(new RowStyle(SizeType.Absolute, 124));
            body.RowStyles.Add(new RowStyle(SizeType.Absolute, 18));
            body.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            body.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
            Controls.Add(body);

            var top = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1,
                Margin = Padding.Empty, Padding = new Padding(0, 14, 0, 12) };
            top.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 48));
            top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            top.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 260));
            top.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            top.Controls.Add(new BrandMark { Dock = DockStyle.Fill, Margin = new Padding(0, 4, 8, 4) }, 0, 0);
            top.Controls.Add(TextLabel("CertScope", 20, Navy, FontStyle.Bold), 1, 0);
            var project = TextLabel("ГРЧЦ   /   КЕЙС 03", 9, Theme.Muted);
            project.TextAlign = ContentAlignment.MiddleRight;
            top.Controls.Add(project, 2, 0);
            top.Paint += (s, e) => { using (var pen = new Pen(Theme.Border)) e.Graphics.DrawLine(pen, 0, top.Height - 1, top.Width, top.Height - 1); };
            body.Controls.Add(top, 0, 0);

            var header = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1,
                Margin = Padding.Empty, Padding = new Padding(0, 12, 0, 16) };
            header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            header.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 302));
            header.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var heading = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
            heading.RowStyles.Add(new RowStyle(SizeType.Percent, 60));
            heading.RowStyles.Add(new RowStyle(SizeType.Percent, 40));
            heading.Controls.Add(TextLabel("Инвентаризация сертификатов", 23, Navy, FontStyle.Bold), 0, 0);
            heading.Controls.Add(TextLabel("Сертификаты, источники и история обнаружений", 10, Theme.Muted), 0, 1);
            header.Controls.Add(heading, 0, 0);
            var commands = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft,
                WrapContents = false, Margin = Padding.Empty, Padding = new Padding(0, 14, 0, 0) };
            start.Text = "Сканировать"; start.Icon = UiIcon.Play; start.Kind = ButtonKind.Primary;
            start.Size = new Size(174, 44); start.Margin = new Padding(10, 0, 0, 0); start.Click += StartScan;
            start.AccessibleName = "Начать сканирование";
            cancel.Text = "Отменить"; cancel.Icon = UiIcon.Stop; cancel.Kind = ButtonKind.Secondary;
            cancel.Size = new Size(118, 44); cancel.Margin = Padding.Empty; cancel.Enabled = false;
            cancel.Click += (s, e) => { if (cancellation != null) cancellation.Cancel(); };
            commands.Controls.Add(start); commands.Controls.Add(cancel);
            header.Controls.Add(commands, 1, 0); body.Controls.Add(header, 0, 1);

            var cards = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, Margin = Padding.Empty };
            cards.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            for (int i = 0; i < 3; i++) cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / 3));
            Card(cards, totalLabel, "Сертификаты", "Уникальные / места обнаружения", UiIcon.Certificate, 0);
            Card(cards, warningLabel, "Ограничения сбора", "Источники, требующие внимания", UiIcon.Shield, 1);
            Card(cards, queueLabel, "Очередь SQL", "События для синхронизации", UiIcon.Database, 2);
            body.Controls.Add(cards, 0, 2);

            var workspace = new SurfacePanel { Dock = DockStyle.Fill, FillColor = Color.White, BorderColor = Theme.Border,
                Radius = 14, Padding = new Padding(8, 6, 8, 8), Margin = Padding.Empty };
            tabs.Dock = DockStyle.Fill; tabs.Font = new Font("Segoe UI", 10);
            var resultsTab = new TabPage("Сертификаты") { BackColor = Color.White, Padding = new Padding(8, 4, 8, 0) };
            var coverageTab = new TabPage("Охват и ошибки") { BackColor = Color.White, Padding = new Padding(8, 10, 8, 0) };
            var settingsTab = new TabPage("Настройки") { BackColor = Color.White };
            var computersTab = new TabPage("Прогресс по ПК") { BackColor = Color.White, Padding = new Padding(8, 10, 8, 0) };
            tabs.TabPages.AddRange(new[] { resultsTab, coverageTab, settingsTab, computersTab });
            workspace.Controls.Add(tabs); body.Controls.Add(workspace, 0, 4);
            var results = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Margin = Padding.Empty };
            results.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            results.RowStyles.Add(new RowStyle(SizeType.Absolute, 68));
            results.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            results.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
            resultsTab.Controls.Add(results);
            results.Controls.Add(BuildToolbar(), 0, 0);
            AddColumn(certificateGrid, "Владелец", 27); AddColumn(certificateGrid, "Серийный номер", 23);
            AddColumn(certificateGrid, "Компьютер", 15); AddColumn(certificateGrid, "Действует до (UTC)", 19); AddColumn(certificateGrid, "Лицензия", 16);
            certificateGrid.CellDoubleClick += (s, e) => { if (e.RowIndex >= 0) ShowDetails(); };
            certificateGrid.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { ShowDetails(); e.Handled = true; e.SuppressKeyPress = true; } };
            certificateGrid.Paint += (s, e) => PaintEmpty(e.Graphics, certificateGrid, UiIcon.Certificate,
                search.TextLength > 0 || expiry.SelectedIndex > 0 ? "Нет совпадений" : "Сертификатов пока нет",
                search.TextLength > 0 || expiry.SelectedIndex > 0 ? "Измените поиск или срок действия" : "Импортируйте файлы или запустите сканирование");
            results.Controls.Add(certificateGrid, 0, 1);
            var resultsFooter = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
            resultsFooter.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            resultsFooter.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            resultsFooter.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
            resultsFooter.Controls.Add(TextLabel("Двойной щелчок или Enter — карточка сертификата", 9, Theme.Muted), 0, 0);
            resultCount.Dock = DockStyle.Fill; resultCount.ForeColor = Theme.Muted; resultCount.TextAlign = ContentAlignment.MiddleRight;
            resultCount.Font = new Font("Segoe UI", 9); resultsFooter.Controls.Add(resultCount, 1, 0); results.Controls.Add(resultsFooter, 0, 2);
            AddColumn(reportGrid, "Компьютер", 14); AddColumn(reportGrid, "Источник", 25);
            AddColumn(reportGrid, "Статус", 15); AddColumn(reportGrid, "Результат / причина", 46);
            reportGrid.CellDoubleClick += (s, e) => { if (e.RowIndex >= 0 && reportGrid.CurrentRow != null) DetailText("Диагностика источника", PrettyReport((SourceReport)reportGrid.CurrentRow.Tag)); };
            reportGrid.Paint += (s, e) => PaintEmpty(e.Graphics, reportGrid, UiIcon.Shield, "Источники ещё не проверены", "Результаты появятся после сканирования");
            coverageTab.Controls.Add(reportGrid);
            AddColumn(computerGrid, "Компьютер", 22); AddColumn(computerGrid, "Состояние", 24);
            AddColumn(computerGrid, "Найдено", 14); AddColumn(computerGrid, "Последний источник", 40);
            computerGrid.Paint += (s, e) => PaintEmpty(e.Graphics, computerGrid, UiIcon.Computers, "Нет активного сканирования", "Список компьютеров задаётся в настройках");
            computersTab.Controls.Add(computerGrid);
            BuildSettings(settingsTab);

            var footer = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, Margin = Padding.Empty };
            footer.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 20));
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 112));
            statusDot = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty };
            statusDot.Paint += (s, e) => { float scale = e.Graphics.DpiX / 96f; using (var brush = new SolidBrush(running || syncing ? Theme.Blue : Theme.Teal)) e.Graphics.FillEllipse(brush, scale, statusDot.Height / 2f - 3 * scale, 6 * scale, 6 * scale); };
            footer.Controls.Add(statusDot, 0, 0);
            status.Dock = DockStyle.Fill; status.ForeColor = Theme.Muted; status.TextAlign = ContentAlignment.MiddleLeft;
            status.AutoEllipsis = true; status.Font = new Font("Segoe UI", 9); status.Text = "Готово к работе";
            footer.Controls.Add(status, 1, 0);
            activity.Style = ProgressBarStyle.Marquee; activity.MarqueeAnimationSpeed = 30;
            activity.Dock = DockStyle.Fill; activity.Margin = new Padding(12, 17, 0, 17); activity.Visible = false;
            footer.Controls.Add(activity, 2, 0); body.Controls.Add(footer, 0, 5);
            ResumeLayout(true);
        }
        private Control BuildToolbar()
        {
            var tools = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 6, RowCount = 1,
                Margin = Padding.Empty, Padding = new Padding(0, 12, 0, 12) };
            tools.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            tools.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 194));
            tools.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 12));
            tools.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
            tools.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 122));
            tools.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 194));
            tools.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var searchBox = new SurfacePanel { Dock = DockStyle.Fill, FillColor = Color.FromArgb(246, 248, 253),
                BorderColor = Theme.Border, Radius = 8, Margin = new Padding(0, 0, 12, 0), Padding = new Padding(36, 10, 10, 8) };
            searchBox.Paint += (s, e) => { float scale = e.Graphics.DpiX / 96f; Theme.DrawIcon(e.Graphics, UiIcon.Search, new RectangleF(12 * scale, 13 * scale, 17 * scale, 17 * scale), Theme.Steel); };
            search.BorderStyle = BorderStyle.None; search.BackColor = searchBox.FillColor; search.ForeColor = Theme.Ink;
            search.Dock = DockStyle.Fill; search.AccessibleName = "Поиск сертификатов";
            search.TextChanged += (s, e) => RefreshResults(); searchBox.Controls.Add(search);
            // The visible label is a real input hint, not text that enters the search query.
            var hint = new Label { Text = "Поиск сертификатов", AutoSize = true, BackColor = searchBox.FillColor,
                ForeColor = Theme.Muted, Location = new Point(36, 11), Cursor = Cursors.IBeam };
            hint.Click += (s, e) => search.Focus(); searchBox.Controls.Add(hint); hint.BringToFront();
            search.TextChanged += (s, e) => hint.Visible = search.TextLength == 0 && !search.Focused;
            search.GotFocus += (s, e) => { hint.Visible = false; searchBox.BorderColor = Theme.Steel; searchBox.Invalidate(); };
            search.LostFocus += (s, e) => { hint.Visible = search.TextLength == 0; searchBox.BorderColor = Theme.Border; searchBox.Invalidate(); };
            tools.Controls.Add(searchBox, 0, 0);
            var expiryBox = new SurfacePanel { Dock = DockStyle.Fill, FillColor = Color.FromArgb(246, 248, 253),
                BorderColor = Theme.Border, Radius = 8, Padding = new Padding(8, 9, 8, 6), Margin = Padding.Empty };
            expiry.DropDownStyle = ComboBoxStyle.DropDownList; expiry.FlatStyle = FlatStyle.Flat;
            expiry.BackColor = expiryBox.FillColor; expiry.ForeColor = Theme.Blue; expiry.Dock = DockStyle.Fill;
            expiry.AccessibleName = "Фильтр по сроку действия";
            expiry.Items.AddRange(new object[] { "Все сроки", "Действующие", "Истекают ≤ 30 дней", "Истёкшие" });
            expiry.SelectedIndex = 0; expiry.SelectedIndexChanged += (s, e) => RefreshResults();
            expiryBox.Controls.Add(expiry); tools.Controls.Add(expiryBox, 1, 0);
            var import = new ActionButton { Text = "Импорт", Icon = UiIcon.Import, Kind = ButtonKind.Secondary,
                Dock = DockStyle.Fill, Margin = new Padding(0, 0, 8, 0) };
            import.Click += ImportCertificates; tools.Controls.Add(import, 3, 0);
            var export = new ActionButton { Text = "Экспорт", Icon = UiIcon.Export, Kind = ButtonKind.Secondary,
                Dock = DockStyle.Fill, Margin = new Padding(0, 0, 8, 0) };
            export.Click += Export; tools.Controls.Add(export, 4, 0);
            sync.Text = "Синхронизация SQL"; sync.Icon = UiIcon.Sync; sync.Kind = ButtonKind.Accent;
            sync.Dock = DockStyle.Fill; sync.Margin = Padding.Empty; sync.Click += Synchronize; tools.Controls.Add(sync, 5, 0);
            return tools;
        }
        private void Card(TableLayoutPanel parent, Label value, string caption, string detail, UiIcon icon, int column)
        {
            bool primary = column == 0;
            var panel = new SurfacePanel { Dock = DockStyle.Fill, FillColor = primary ? Theme.Blue : Color.White,
                BorderColor = primary ? Theme.Blue : Theme.Border, Radius = 12,
                Padding = new Padding(22, 12, 18, 12), Margin = new Padding(column == 0 ? 0 : 8, 0, column == 2 ? 0 : 8, 0) };
            var content = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 3,
                Margin = Padding.Empty, BackColor = panel.FillColor };
            content.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            content.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 44));
            content.RowStyles.Add(new RowStyle(SizeType.Absolute, 25));
            content.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            content.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
            content.Controls.Add(TextLabel(caption, 10, primary ? Theme.BlueSoft : Theme.Muted), 0, 0);
            value.Text = "0"; value.Dock = DockStyle.Fill; value.Margin = Padding.Empty;
            value.Font = new Font("Segoe UI", 27, FontStyle.Bold); value.ForeColor = primary ? Color.White : Theme.Blue;
            value.TextAlign = ContentAlignment.MiddleLeft; content.Controls.Add(value, 0, 1);
            content.Controls.Add(TextLabel(detail, 9, primary ? Theme.BlueSoft : Theme.Muted), 0, 2);
            var tile = IconTile(icon, primary ? Color.FromArgb(65, 94, 134) : column == 2 ? Theme.Green : Color.FromArgb(232, 239, 253),
                primary ? Theme.Green : Theme.Blue, 42);
            content.Controls.Add(tile, 1, 0); content.SetRowSpan(tile, 2);
            panel.Controls.Add(content); parent.Controls.Add(panel, column, 0);
        }
        private void PaintEmpty(Graphics graphics, DataGridView grid, UiIcon icon, string title, string subtitle)
        {
            if (grid.Rows.Count != 0) return;
            float scale = graphics.DpiX / 96f;
            int available = grid.ClientSize.Height - grid.ColumnHeadersHeight;
            if (available < 140 * scale) return;
            int centerX = grid.ClientSize.Width / 2;
            int centerY = grid.ColumnHeadersHeight + available / 2 - (int)(20 * scale);
            using (var brush = new SolidBrush(Color.FromArgb(239, 244, 254)))
            using (var path = Theme.RoundedRect(new RectangleF(centerX - 30 * scale, centerY - 48 * scale, 60 * scale, 60 * scale), 16 * scale))
                graphics.FillPath(brush, path);
            Theme.DrawIcon(graphics, icon, new RectangleF(centerX - 14 * scale, centerY - 32 * scale, 28 * scale, 28 * scale), Theme.Steel, 1.8f);
            using (var font = new Font("Segoe UI", 13, FontStyle.Bold))
                TextRenderer.DrawText(graphics, title, font, new Rectangle(0, centerY + (int)(24 * scale), grid.Width, (int)(28 * scale)), Theme.Blue, TextFormatFlags.HorizontalCenter);
            using (var font = new Font("Segoe UI", 10))
                TextRenderer.DrawText(graphics, subtitle, font, new Rectangle(0, centerY + (int)(58 * scale), grid.Width, (int)(28 * scale)), Theme.Muted, TextFormatFlags.HorizontalCenter);
        }
		private static void AddColumn(DataGridView grid,string caption,float weight) { grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText=caption,FillWeight=weight,SortMode=DataGridViewColumnSortMode.Automatic }); }
        private void BuildSettings(TabPage page)
        {
            page.AutoScroll = true;
            page.BackColor = Color.White;
            var table = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 2, RowCount = 0,
                Padding = new Padding(22, 0, 22, 20), BackColor = Color.White };
            table.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 245));
            table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            page.Controls.Add(table);
            SettingsSection(table, "Источники сканирования", UiIcon.Computers);
            SettingsRow(table, "Компьютеры\nОдно имя на строку", computers, 88);
            var pcButtons = new FlowLayoutPanel { Dock = DockStyle.Fill, Margin = Padding.Empty };
            var import = (ActionButton)ActionButton("Импорт списка ПК", (s, e) => {
                using (var dialog = new OpenFileDialog { Filter = "Текстовый список|*.txt|Все файлы|*.*" })
                    if (dialog.ShowDialog() == DialogResult.OK) computers.Text = File.ReadAllText(dialog.FileName, Encoding.UTF8);
            }); import.Icon = UiIcon.Import; pcButtons.Controls.Add(import);
            pcButtons.Controls.Add(ActionButton("Демо: файлы организаторов", (s, e) => DemoSettings()));
            SettingsRow(table, "Быстрая настройка", pcButtons, 52);
            var sources = new FlowLayoutPanel { Dock = DockStyle.Fill, Margin = Padding.Empty };
            machine.Text = "LocalMachine"; users.Text = "Профили / HKU"; userFiles.Text = "Файлы MY";
            cryptoPro.Text = "КриптоПро CSP"; full.Text = "Полный реестр";
            foreach (var check in new[] { machine, users, userFiles, cryptoPro, full })
            { check.AutoSize = true; check.ForeColor = Theme.Ink; check.Margin = new Padding(0, 8, 18, 4); sources.Controls.Add(check); }
            SettingsRow(table, "Области сбора", sources, 76);
            SettingsRow(table, "Каталоги\nПуть / UNC / {computer}", directories, 78);
            SettingsRow(table, "Дополнительные ветки\nHKLM\\… или HKU\\…", branches, 78);
            SettingsRow(table, "Выбранные SID\nПусто — доступные профили", sids, 68);
            var views = new FlowLayoutPanel { Dock = DockStyle.Fill, Margin = Padding.Empty };
            view32.Text = "32 бита"; view64.Text = "64 бита";
            foreach (var check in new[] { view32, view64 })
            { check.AutoSize = true; check.Margin = new Padding(0, 7, 22, 0); views.Controls.Add(check); }
            SettingsRow(table, "Представления реестра", views, 42);

            SettingsSection(table, "Учётная запись", UiIcon.Shield);
            var auth = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 2, Margin = Padding.Empty };
            for (int i = 0; i < 3; i++) auth.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / 3));
            auth.RowStyles.Add(new RowStyle(SizeType.Absolute, 27));
            auth.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            auth.Controls.Add(TextLabel("Домен", 9, Theme.Muted), 0, 0);
            auth.Controls.Add(TextLabel("Пользователь", 9, Theme.Muted), 1, 0);
            auth.Controls.Add(TextLabel("Пароль · только в памяти", 9, Theme.Muted), 2, 0);
            int col = 0;
            foreach (var field in new[] { domain, user, password })
            { StyleInput(field); field.Dock = DockStyle.Fill; field.Margin = new Padding(0, 3, 10, 8); auth.Controls.Add(field, col++, 1); }
            password.UseSystemPasswordChar = true;
            SettingsRow(table, "Сетевой доступ\nПусто — текущий пользователь", auth, 72);
            identity.AutoSize = true; identity.ForeColor = Theme.Teal;
            identity.Text = "Текущий процесс: " + WindowsIdentity.GetCurrent().Name;
            SettingsRow(table, "Активная идентичность", identity, 38);

            SettingsSection(table, "Параметры сбора", UiIcon.Settings);
            var limits = new FlowLayoutPanel { Dock = DockStyle.Fill, Margin = Padding.Empty };
            Limit(limits, "ПК", hosts); Limit(limits, "на ПК", perHost); Limit(limits, "всего", workers); Limit(limits, "секунд", timeout);
            SettingsRow(table, "Параллельность / тайм-аут", limits, 50);
            var bounds = new FlowLayoutPanel { Dock = DockStyle.Fill, Margin = Padding.Empty };
            Limit(bounds, "повторы", retries); Limit(bounds, "МБ/файл", maxBytes); Limit(bounds, "значений", maxValues);
            SettingsRow(table, "Ограничения обхода", bounds, 50);

            SettingsSection(table, "Хранилище и конфигурация", UiIcon.Database);
            foreach (var field in new[] { sql, dataPath, logPath }) { StyleInput(field); field.Dock = DockStyle.Fill; }
            SettingsRow(table, "Подключение к SQL Server\nWindows-аутентификация", sql, 58);
            SettingsRow(table, "Рабочие данные", dataPath, 46);
            SettingsRow(table, "Журналы", logPath, 46);
            var configButtons = new FlowLayoutPanel { Dock = DockStyle.Fill, Margin = Padding.Empty };
            var save = (ActionButton)ActionButton("Сохранить настройки", (s, e) => Guard(() => ApplySettings(true)), true);
            save.Icon = UiIcon.Settings; configButtons.Controls.Add(save);
            configButtons.Controls.Add(ActionButton("Импорт конфига", ImportSettings));
            configButtons.Controls.Add(ActionButton("Экспорт конфига", ExportSettings));
            SettingsRow(table, "Конфигурация v1", configButtons, 54);
            var guidance = new Label { Text = "Remote Registry и права доступа настраивает администратор. Незагруженные профили и недоступные источники отражаются в отчёте. Программа не проверяет доверие цепочки, подпись и отзыв сертификата.",
                AutoSize = false, Dock = DockStyle.Fill, ForeColor = Theme.Muted, Font = new Font("Segoe UI", 9), Padding = new Padding(0, 8, 0, 0) };
            int noteRow = table.RowCount++;
            table.RowStyles.Add(new RowStyle(SizeType.Absolute, 66)); table.Controls.Add(guidance, 0, noteRow); table.SetColumnSpan(guidance, 2);
        }
        private static void StyleInput(TextBox field)
        {
            field.BorderStyle = BorderStyle.FixedSingle; field.BackColor = Color.FromArgb(246, 248, 252);
            field.ForeColor = Theme.Ink; field.Margin = new Padding(0, 7, 0, 8);
        }
        private static void SettingsSection(TableLayoutPanel table, string title, UiIcon icon)
        {
            int row = table.RowCount++;
            table.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
            var section = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty, Padding = new Padding(32, 0, 0, 0) };
            section.Controls.Add(TextLabel(title, 11, Theme.Blue, FontStyle.Bold));
            section.Paint += (s, e) => {
                using (var line = new Pen(Theme.Border)) e.Graphics.DrawLine(line, 0, 0, section.Width, 0);
                float scale = e.Graphics.DpiX / 96f;
                Theme.DrawIcon(e.Graphics, icon, new RectangleF(0, 19 * scale, 20 * scale, 20 * scale), Theme.Teal);
            };
            table.Controls.Add(section, 0, row); table.SetColumnSpan(section, 2);
        }
        private static void SettingsRow(TableLayoutPanel table, string title, Control control, int height)
        {
            int row = table.RowCount++;
            table.RowStyles.Add(new RowStyle(SizeType.Absolute, height));
            var label = TextLabel(title, 9.5f, Theme.Muted);
            label.Padding = new Padding(0, 5, 12, 0); label.TextAlign = ContentAlignment.TopLeft;
            table.Controls.Add(label, 0, row); table.Controls.Add(control, 1, row);
        }
        private static void Limit(FlowLayoutPanel panel, string title, Control control)
        {
            panel.Controls.Add(new Label { Text = title, AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(0, 11, 0, 0) });
            panel.Controls.Add(control);
        }
		private static List<string> ReadLines(TextBox box) {return box.Lines.Select(x=>x.Trim()).Where(x=>x.Length>0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();}
		private void PopulateSettings()
		{
			computers.Lines=settings.Computers.ToArray();directories.Lines=settings.Directories.ToArray();branches.Lines=settings.RegistryBranches.ToArray();sids.Lines=settings.SelectedSids.ToArray();machine.Checked=settings.IncludeMachine;users.Checked=settings.IncludeUsers;userFiles.Checked=settings.IncludeUserFiles;cryptoPro.Checked=settings.IncludeCryptoPro;full.Checked=settings.FullRegistry;view32.Checked=settings.RegistryViews.Contains("Registry32");view64.Checked=settings.RegistryViews.Contains("Registry64");hosts.Value=settings.MaxHosts;perHost.Value=settings.MaxSourcesPerHost;workers.Value=settings.MaxWorkers;timeout.Value=settings.TimeoutSeconds;retries.Value=settings.RetryCount;maxBytes.Value=Math.Max(1,settings.MaxFileBytes/1024/1024);maxValues.Value=settings.MaxRegistryValues;sql.Text=settings.SqlConnectionString;dataPath.Text=settings.OutputDirectory;logPath.Text=settings.LogDirectory;
		}
		private ScanSettings ReadSettings()
		{
			var value=Json.Clone(settings);value.Computers=ReadLines(computers);value.Directories=ReadLines(directories);value.RegistryBranches=ReadLines(branches);value.SelectedSids=ReadLines(sids);value.IncludeMachine=machine.Checked;value.IncludeUsers=users.Checked;value.IncludeUserFiles=userFiles.Checked;value.IncludeCryptoPro=cryptoPro.Checked;value.FullRegistry=full.Checked;value.RegistryViews=new List<string>();if(view32.Checked)value.RegistryViews.Add("Registry32");if(view64.Checked)value.RegistryViews.Add("Registry64");value.MaxHosts=(int)hosts.Value;value.MaxSourcesPerHost=(int)perHost.Value;value.MaxWorkers=(int)workers.Value;value.TimeoutSeconds=(int)timeout.Value;value.RetryCount=(int)retries.Value;value.MaxFileBytes=(int)maxBytes.Value*1024*1024;value.MaxRegistryValues=(int)maxValues.Value;value.SqlConnectionString=sql.Text;value.OutputDirectory=dataPath.Text;value.LogDirectory=logPath.Text;value.Validate();return value;
		}
		private string Resolve(string path) { return Path.IsPathRooted(path)?path:Path.Combine(basePath,path); }
		private void ApplySettings(bool save)
		{
			if (running || syncing) throw new InvalidOperationException("Дождитесь завершения операции перед изменением хранилища.");
			CommitSettings(ReadSettings(), save);
			status.Text = "Настройки проверены и сохранены. Пароль не включён в конфигурацию.";
		}
		/// <summary>Проверяет новое хранилище до замены работающей конфигурации.</summary>
		private void CommitSettings(ScanSettings next, bool save)
		{
			next.Validate();
			LocalRepository nextRepository = repository;
			List<Observation> nextObservations = null;
			List<SourceReport> nextReports = null;
			if (repository == null || !String.Equals(Resolve(settings.OutputDirectory), Resolve(next.OutputDirectory), StringComparison.OrdinalIgnoreCase))
			{
				nextRepository = new LocalRepository(Resolve(next.OutputDirectory));
				nextObservations = nextRepository.LoadObservations();
				nextReports = nextRepository.LoadReports();
			}
			if (save) Json.Save(Path.Combine(basePath, "settings.json"), next);
			settings = next;
			AppLog.DirectoryPath = Resolve(settings.LogDirectory);
			repository = nextRepository;
			if (nextObservations != null)
			{
				observations.Clear(); observations.AddRange(nextObservations);
				reports.Clear(); reports.AddRange(nextReports);
				activeComputers.Clear(); RefreshResults();
			}
		}
		private void OpenRepository() { repository=new LocalRepository(Resolve(settings.OutputDirectory));observations.Clear();observations.AddRange(repository.LoadObservations());reports.Clear();reports.AddRange(repository.LoadReports());AppLog.DirectoryPath=Resolve(settings.LogDirectory);RefreshResults(); }
		private async void StartScan(object sender,EventArgs args)
		{
			if(running||syncing)return;
			ScanSettings snapshot;try { ApplySettings(true);snapshot=Json.Clone(settings);snapshot.Directories=snapshot.Directories.Select(x=>x.Contains("{computer}")||Path.IsPathRooted(x)?x:Resolve(x)).ToList(); } catch(Exception ex) { ShowError(ex);return; }
			var credentials=new ScanCredentials {Domain=domain.Text.Trim(),UserName=user.Text.Trim(),Password=password.Text};password.Clear();identity.Text="Сетевой доступ: "+(String.IsNullOrEmpty(credentials.UserName)?WindowsIdentity.GetCurrent().Name:(credentials.Domain+"\\"+credentials.UserName))+" · текущий запуск";
			cancellation=new CancellationTokenSource();running=true;activeComputers=snapshot.Computers.ToList();activeSince=DateTime.UtcNow;SetBusy();RefreshResults();status.Text="Сбор данных… Частичные результаты сохраняются по мере поступления.";tabs.SelectedIndex=0;
			try
			{
				var result=await Task.Run(()=>Scanner.Run(snapshot,credentials,cancellation.Token,observation=> {repository.SaveObservation(observation);Post(()=> {observations.Add(observation);dirty=true;});},report=> {repository.SaveReport(report);AppLog.Report(report);Post(()=> {reports.Add(report);dirty=true;status.Text=report.Computer+" · "+StatusName(report.Status)+" · "+report.Source;});}));
				status.Text = (cancellation.IsCancellationRequested ? "Сканирование отменено: " : "Сканирование завершено: ") + result.Observations.Count + " обнаружений, " + result.Sources.Count + " отчётов. Данные сохранены локально.";
			}
			catch(OperationCanceledException) {status.Text="Сканирование отменено. Полученные результаты сохранены.";}
			catch(Exception ex) {ShowError(ex);}
			finally {credentials.Password=null;running=false;cancellation.Dispose();cancellation=null;SetBusy();RefreshResults();}
		}
		private void Post(Action action) {if(!IsDisposed&&IsHandleCreated)BeginInvoke(action);}
		private void SetBusy()
        {
            start.Enabled = !running && !syncing; cancel.Enabled = running || syncing;
            sync.Enabled = !running && !syncing; tabs.TabPages[2].Enabled = !running && !syncing;
            activity.Visible = running || syncing; statusDot.Invalidate();
        }
		/// <summary>Одна строка на сертификат и место; история повторных запусков остаётся в журнале.</summary>
		private List<Observation> LatestObservations()
		{
			return observations.Where(o => o.Certificate != null)
				.GroupBy(o => new { o.Certificate.Sha256, Computer = (o.Computer ?? "").ToUpperInvariant(), Source = (o.Source ?? "").ToUpperInvariant(), o.UserSid, o.RegistryView })
				.Select(g => g.OrderByDescending(o => o.FoundUtc).First()).ToList();
		}
		private List<Observation> VisibleObservations()
		{
			string query=search.Text.Trim();DateTime now=DateTime.UtcNow;return LatestObservations().Where(o=>query.Length==0||(o.Certificate.DisplayName+" "+o.Certificate.SerialNumber+" "+o.Certificate.Subject+" "+o.Certificate.Issuer+" "+o.Computer+" "+o.Source+" "+o.Certificate.Sha256).IndexOf(query,StringComparison.OrdinalIgnoreCase)>=0).Where(o=>expiry.SelectedIndex==0||(expiry.SelectedIndex==1&&o.Certificate.NotBeforeUtc<=now&&o.Certificate.NotAfterUtc>=now)||(expiry.SelectedIndex==2&&o.Certificate.NotAfterUtc>=now&&o.Certificate.NotAfterUtc<=now.AddDays(30))||(expiry.SelectedIndex==3&&o.Certificate.NotAfterUtc<now)).ToList();
		}
		private void RefreshResults()
		{
			if(repository==null)return;certificateGrid.Rows.Clear();foreach(var o in VisibleObservations()) {var c=o.Certificate;int i=certificateGrid.Rows.Add(c.DisplayName,c.SerialNumber,o.Computer,c.NotAfterUtc.ToString("yyyy-MM-dd HH:mm"),c.LicenseStatus);certificateGrid.Rows[i].Tag=o;if(c.NotAfterUtc<DateTime.UtcNow)certificateGrid.Rows[i].DefaultCellStyle.ForeColor=Color.FromArgb(158, 75, 65);}
			reportGrid.Rows.Clear();foreach(var r in reports.AsEnumerable().Reverse()) {int i=reportGrid.Rows.Add(r.Computer,r.Source,StatusName(r.Status),r.Message);reportGrid.Rows[i].Tag=r;if(r.Status!=SourceStatus.Success&&r.Status!=SourceStatus.Empty)reportGrid.Rows[i].DefaultCellStyle.ForeColor=Color.FromArgb(158, 75, 65);}
			totalLabel.Text=observations.Where(o=>o.Certificate!=null).Select(o=>o.Certificate.Sha256).Distinct().Count()+" / "+LatestObservations().Count;warningLabel.Text=reports.Count(r=>r.Status!=SourceStatus.Success&&r.Status!=SourceStatus.Empty).ToString();queueLabel.Text=repository.PendingCount.ToString();
			resultCount.Text = "Строк: " + certificateGrid.Rows.Count;
			certificateGrid.Invalidate(); reportGrid.Invalidate();
			computerGrid.Rows.Clear();foreach(var pc in activeComputers) {var latest=reports.Where(r=>r.Computer.Equals(pc,StringComparison.OrdinalIgnoreCase)&&r.StartedUtc>=activeSince).LastOrDefault();int found=observations.Count(o=>o.Computer.Equals(pc,StringComparison.OrdinalIgnoreCase)&&o.FoundUtc>=activeSince);computerGrid.Rows.Add(pc,latest!=null&&latest.Source=="Компьютер"?StatusName(latest.Status):running?(latest==null?"Ожидание / подключение":"Сканируется"):"Завершено",found,latest==null?"—":latest.Source);}
		}
		public static string StatusName(SourceStatus status) {switch(status) {case SourceStatus.Success:return "Проверен";case SourceStatus.Empty:return "Не найдены";case SourceStatus.Partial:return "Частично";case SourceStatus.Unreachable:return "Недоступен";case SourceStatus.AccessDenied:return "Отказ в доступе";case SourceStatus.Timeout:return "Тайм-аут";case SourceStatus.Cancelled:return "Отменено";case SourceStatus.NotConfigured:return "Не настроен";case SourceStatus.Unsupported:return "Не поддерживается";default:return "Ошибка";}}
		private void ShowDetails()
		{
			if(certificateGrid.CurrentRow==null)return;var o=(Observation)certificateGrid.CurrentRow.Tag;var c=o.Certificate;var t=new StringBuilder();t.AppendLine(c.DisplayName).AppendLine("Источник имени: "+c.DisplayNameSource).AppendLine("\nСерийный номер: "+c.SerialNumber).AppendLine("SHA-256 DER: "+c.Sha256).AppendLine("Subject: "+c.Subject).AppendLine("Issuer: "+c.Issuer).AppendLine("Действует с: "+c.NotBeforeUtc.ToString("O")).AppendLine("Действует до: "+c.NotAfterUtc.ToString("O")).AppendLine("Алгоритм ключа: "+c.PublicKeyAlgorithm).AppendLine("Алгоритм подписи: "+c.SignatureAlgorithm).AppendLine("Параметры ключа (DER): "+c.PublicKeyParameters).AppendLine("Параметры подписи (DER): "+c.SignatureParameters).AppendLine("\nЛицензия: "+c.LicenseStatus).AppendLine("Версия лицензии: "+c.LicenseVersion).AppendLine("Основание: "+c.LicenseEvidence).AppendLine("\nКомпьютер: "+o.Computer).AppendLine("Источник: "+o.Source).AppendLine("SID: "+o.UserSid).AppendLine("Представление: "+o.RegistryView).AppendLine("Обнаружен (UTC): "+o.FoundUtc.ToString("O")).AppendLine("ScanId: "+o.ScanId).AppendLine("\nРасширения:");foreach(var e in c.Extensions)t.AppendLine(e.Oid+(e.Critical?" [critical]":"")).AppendLine(e.Description).AppendLine("Raw Base64: "+e.RawBase64).AppendLine();t.AppendLine("Успешный разбор не является проверкой подписи, доверия или отзыва.");DetailText("Карточка сертификата",t.ToString());
		}
		private static string PrettyReport(SourceReport r) {return "ScanId: "+r.ScanId+"\r\nКомпьютер: "+r.Computer+"\r\nИсточник: "+r.Source+"\r\nSID: "+r.UserSid+"\r\nСтатус: "+StatusName(r.Status)+"\r\nНачало: "+r.StartedUtc.ToString("O")+"\r\nКонец: "+r.FinishedUtc.ToString("O")+"\r\nНайдено: "+r.Count+"\r\nКод: "+r.ErrorCode+"\r\n\r\n"+r.Message+"\r\n\r\n"+r.StackTrace;}
        private void DetailText(string title, string value)
        {
            using (var form = new Form { Text = title, Size = new Size(1000, 760), MinimumSize = new Size(700, 520),
                StartPosition = FormStartPosition.CenterParent, Font = Font, BackColor = Theme.Canvas,
                ShowInTaskbar = false, MinimizeBox = false, Icon = Icon,
                AutoScaleDimensions = new SizeF(96, 96), AutoScaleMode = AutoScaleMode.Dpi })
            {
                var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3,
                    Padding = new Padding(24, 12, 24, 8) };
                layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
                layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));
                layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
                layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
                layout.Controls.Add(TextLabel(title, 18, Theme.Blue, FontStyle.Bold), 0, 0);
                var surface = new SurfacePanel { Dock = DockStyle.Fill, Radius = 12, FillColor = Color.White,
                    BorderColor = Theme.Border, Padding = new Padding(16), Margin = Padding.Empty };
                var text = new TextBox { Text = value, Multiline = true, ReadOnly = true,
                    ScrollBars = ScrollBars.Both, Dock = DockStyle.Fill, Font = new Font("Consolas", 10),
                    WordWrap = false, BorderStyle = BorderStyle.None, BackColor = Color.White, ForeColor = Theme.Ink };
                surface.Controls.Add(text); layout.Controls.Add(surface, 0, 1);
                var commands = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft,
                    Margin = Padding.Empty, Padding = new Padding(0, 10, 0, 0) };
                var close = new ActionButton { Text = "Закрыть", Kind = ButtonKind.Primary, Size = new Size(120, 38), DialogResult = DialogResult.OK };
                var copy = new ActionButton { Text = "Копировать", Kind = ButtonKind.Secondary, Size = new Size(140, 38) };
                copy.Click += (s, e) => Guard(() => Clipboard.SetText(value));
                commands.Controls.Add(close); commands.Controls.Add(copy); layout.Controls.Add(commands, 0, 2);
                form.Controls.Add(layout); form.AcceptButton = close; form.CancelButton = close;
                form.Shown += (s, e) => { text.SelectionStart = 0; text.SelectionLength = 0; close.Focus(); };
                form.ShowDialog(this);
            }
        }
		/// <summary>Импортирует только открытые сертификаты с отменой между файлами.</summary>
		private async void ImportCertificates(object sender, EventArgs args)
		{
			if (running || syncing) return;
			string[] paths;
			using (var dialog = new OpenFileDialog { Title = "Открытые сертификаты и хранилища", Filter = "Все файлы|*.*", Multiselect = true })
			{
				if (dialog.ShowDialog() != DialogResult.OK) return;
				paths = dialog.FileNames;
			}
			try { ApplySettings(true); } catch (Exception ex) { ShowError(ex); return; }
			var snapshot = Json.Clone(settings);
			cancellation = new CancellationTokenSource();
			var token = cancellation.Token;
			running = true; SetBusy();
			var scanId = Guid.NewGuid();
			status.Text = "Импорт открытых сертификатов…";
			try
			{
				await Task.Run(() =>
				{
					foreach (var path in paths)
					{
						token.ThrowIfCancellationRequested();
						var report = new SourceReport { ScanId = scanId, Computer = Environment.MachineName, Source = path, StartedUtc = DateTime.UtcNow };
						try
						{
							if (new FileInfo(path).Length > snapshot.MaxFileBytes) throw new InvalidDataException("Файл превышает лимит.");
							var parsed = CertificateParser.Parse(File.ReadAllBytes(path));
							foreach (var certificate in parsed)
							{
								var observation = new Observation { Id = Guid.NewGuid(), ScanId = scanId, Computer = Environment.MachineName, Source = path, FoundUtc = DateTime.UtcNow, Certificate = certificate, UserSid = "", RegistryView = "File" };
								repository.SaveObservation(observation);
								Post(() => { observations.Add(observation); dirty = true; });
							}
							report.Count = parsed.Count;
							report.Status = parsed.Count > 0 ? SourceStatus.Success : SourceStatus.Empty;
							report.Message = "Импорт открытых сертификатов: " + parsed.Count;
						}
						catch (Exception ex)
						{
							report.Status = ex is NotSupportedException ? SourceStatus.Unsupported : SourceStatus.Error;
							report.Message = ex.Message; report.ErrorCode = ex.HResult; report.StackTrace = ex.StackTrace;
						}
						report.FinishedUtc = DateTime.UtcNow;
						repository.SaveReport(report); AppLog.Report(report);
						Post(() => { reports.Add(report); dirty = true; });
					}
				});
				status.Text = "Импорт завершён. Результаты и диагностика сохранены локально.";
			}
			catch (OperationCanceledException) { status.Text = "Импорт отменён. Полученные результаты сохранены."; }
			catch (Exception ex) { ShowError(ex); }
			finally { running = false; cancellation.Dispose(); cancellation = null; SetBusy(); RefreshResults(); }
		}
		private async void Synchronize(object sender,EventArgs args)
		{
			if(running||syncing)return;try {ApplySettings(true);}catch(Exception ex){ShowError(ex);return;}cancellation=new CancellationTokenSource();syncing=true;SetBusy();status.Text="Синхронизация с SQL Server…";
			try {int count=await Task.Run(()=>repository.Synchronize(settings.SqlConnectionString,cancellation.Token));status.Text="SQL: подтверждено событий — "+count+". "+repository.LastSynchronizationError;}catch(OperationCanceledException){status.Text="Синхронизация отменена; неподтверждённые события остались в очереди.";}catch(Exception ex){ShowError(ex);}finally{syncing=false;cancellation.Dispose();cancellation=null;SetBusy();RefreshResults();}
		}
		private void Export(object sender,EventArgs args)
		{
			Guard(()=> {using(var d=new SaveFileDialog {Filter="Excel workbook (*.xlsx)|*.xlsx|Текст UTF-8 (*.txt)|*.txt|Открытые сертификаты (папка)|*.cer",FileName="CertScope-"+DateTime.Now.ToString("yyyyMMdd-HHmm")}) {if(d.ShowDialog()!=DialogResult.OK)return;var visible=VisibleObservations();if(d.FilterIndex==1) {ExportService.ExportXlsx(d.FileName,visible);ExportService.ExportReportsXlsx(Path.Combine(Path.GetDirectoryName(d.FileName),Path.GetFileNameWithoutExtension(d.FileName)+"-coverage.xlsx"),reports);}else if(d.FilterIndex==2) {ExportService.ExportText(d.FileName,visible);ExportService.ExportReportsText(Path.Combine(Path.GetDirectoryName(d.FileName),Path.GetFileNameWithoutExtension(d.FileName)+"-coverage.txt"),reports);}else ExportService.ExportCer(Path.Combine(Path.GetDirectoryName(d.FileName),Path.GetFileNameWithoutExtension(d.FileName)),visible);status.Text="Экспорт сохранён: "+d.FileName;}});
		}
		private void ImportSettings(object sender,EventArgs args) {Guard(()=> {using(var d=new OpenFileDialog {Filter="Конфигурация JSON|*.json"})if(d.ShowDialog()==DialogResult.OK) {var next=Json.Deserialize<ScanSettings>(File.ReadAllText(d.FileName,Encoding.UTF8));CommitSettings(next,true);user.Clear();domain.Clear();password.Clear();PopulateSettings();status.Text="Конфигурация импортирована. Сетевая учётная запись сброшена на текущую.";}});}
		private void ExportSettings(object sender,EventArgs args) {Guard(()=> {var next=ReadSettings();using(var d=new SaveFileDialog {Filter="Конфигурация JSON|*.json",FileName="CertScope-settings.json"})if(d.ShowDialog()==DialogResult.OK)Json.Save(d.FileName,next);});}
		private void DemoSettings() {computers.Text=Environment.MachineName;directories.Text=Directory.Exists(Path.Combine(basePath,"samples"))?Path.Combine(basePath,"samples"):Path.GetFullPath(Path.Combine(basePath,"..","inputs"));branches.Clear();sids.Clear();machine.Checked=users.Checked=userFiles.Checked=cryptoPro.Checked=full.Checked=false;user.Clear();domain.Clear();password.Clear();status.Text="Настроено сканирование файлов организаторов. Нажмите «Сканировать».";}
		private void Guard(Action action) {try{action();}catch(Exception ex){ShowError(ex);}}
		private void ShowError(Exception ex) {AppLog.Error(ex,"OperatorAction");status.Text="Ошибка: "+ex.Message;MessageBox.Show(this,ex.Message,"CertScope",MessageBoxButtons.OK,MessageBoxIcon.Warning);}
	}
}
