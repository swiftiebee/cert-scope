using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace CertScope
{
    internal enum ButtonKind { Primary, Secondary, Quiet, Accent }
    internal enum UiIcon { None, Search, Import, Export, Sync, Play, Stop, Certificate, Shield, Database, Settings, Computers, Chevron, Cross }

    internal static class Theme
    {
        public static readonly Color Blue = Color.FromArgb(41, 69, 104);
        public static readonly Color BlueSoft = Color.FromArgb(167, 187, 236);
        public static readonly Color Steel = Color.FromArgb(119, 147, 174);
        public static readonly Color Teal = Color.FromArgb(71, 106, 111);
        public static readonly Color Mint = Color.FromArgb(176, 221, 210);
        public static readonly Color Green = Color.FromArgb(181, 238, 197);
        public static readonly Color Ink = Color.FromArgb(32, 52, 75);
        public static readonly Color Muted = Color.FromArgb(104, 122, 143);
        public static readonly Color Canvas = Color.FromArgb(242, 245, 250);
        public static readonly Color Border = Color.FromArgb(223, 230, 239);
        public static readonly Color White = Color.White;

        public static GraphicsPath RoundedRect(RectangleF rectangle, float radius)
        {
            var path = new GraphicsPath();
            float diameter = Math.Max(0, Math.Min(radius * 2, Math.Min(rectangle.Width, rectangle.Height)));
            if (diameter < 1)
            {
                path.AddRectangle(rectangle);
                path.CloseFigure();
                return path;
            }
            path.AddArc(rectangle.X, rectangle.Y, diameter, diameter, 180, 90);
            path.AddArc(rectangle.Right - diameter, rectangle.Y, diameter, diameter, 270, 90);
            path.AddArc(rectangle.Right - diameter, rectangle.Bottom - diameter, diameter, diameter, 0, 90);
            path.AddArc(rectangle.X, rectangle.Bottom - diameter, diameter, diameter, 90, 90);
            path.CloseFigure();
            return path;
        }

        public static void DrawIcon(Graphics graphics, UiIcon icon, RectangleF bounds, Color color, float stroke = 1.6f)
        {
            if (icon == UiIcon.None || bounds.Width <= 0 || bounds.Height <= 0) return;
            GraphicsState saved = graphics.Save();
            try
            {
                graphics.SmoothingMode = SmoothingMode.AntiAlias;
                float scale = Math.Min(bounds.Width, bounds.Height) / 24f;
                graphics.TranslateTransform(bounds.X + (bounds.Width - scale * 24) / 2, bounds.Y + (bounds.Height - scale * 24) / 2);
                graphics.ScaleTransform(scale, scale);
                using (var pen = new Pen(color, stroke) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
                using (var brush = new SolidBrush(color))
                {
                    switch (icon)
                    {
                        case UiIcon.Search:
                            graphics.DrawEllipse(pen, 4, 3.5f, 12.5f, 12.5f);
                            graphics.DrawLine(pen, 15, 15, 20.5f, 20.5f);
                            break;
                        case UiIcon.Import:
                            graphics.DrawLine(pen, 12, 3, 12, 14);
                            graphics.DrawLines(pen, new[] { new PointF(8, 10), new PointF(12, 14), new PointF(16, 10) });
                            graphics.DrawLines(pen, new[] { new PointF(4, 14), new PointF(4, 20), new PointF(20, 20), new PointF(20, 14) });
                            break;
                        case UiIcon.Export:
                            graphics.DrawLine(pen, 12, 14, 12, 3);
                            graphics.DrawLines(pen, new[] { new PointF(8, 7), new PointF(12, 3), new PointF(16, 7) });
                            graphics.DrawLines(pen, new[] { new PointF(4, 14), new PointF(4, 20), new PointF(20, 20), new PointF(20, 14) });
                            break;
                        case UiIcon.Sync:
                            graphics.DrawArc(pen, 4, 4, 16, 16, 207, 149);
                            graphics.DrawLines(pen, new[] { new PointF(20, 4), new PointF(20, 10), new PointF(14, 10) });
                            graphics.DrawArc(pen, 4, 4, 16, 16, 27, 149);
                            graphics.DrawLines(pen, new[] { new PointF(4, 20), new PointF(4, 14), new PointF(10, 14) });
                            break;
                        case UiIcon.Play:
                            using (var triangle = new GraphicsPath())
                            {
                                triangle.AddPolygon(new[] { new PointF(8, 5), new PointF(19, 12), new PointF(8, 19) });
                                graphics.FillPath(brush, triangle);
                            }
                            break;
                        case UiIcon.Stop:
                            using (var square = RoundedRect(new RectangleF(6, 6, 12, 12), 2)) graphics.FillPath(brush, square);
                            break;
                        case UiIcon.Certificate:
                            graphics.DrawLines(pen, new[] { new PointF(15, 19), new PointF(5, 19), new PointF(5, 3), new PointF(19, 3), new PointF(19, 13) });
                            graphics.DrawLine(pen, 8, 7, 16, 7);
                            graphics.DrawLine(pen, 8, 10.5f, 13, 10.5f);
                            graphics.DrawEllipse(pen, 13, 12.5f, 7, 7);
                            graphics.DrawLines(pen, new[] { new PointF(14.5f, 19), new PointF(14, 22), new PointF(16.5f, 20.7f), new PointF(19, 22), new PointF(18.5f, 19) });
                            break;
                        case UiIcon.Shield:
                            using (var shield = new GraphicsPath())
                            {
                                shield.AddLines(new[] { new PointF(12, 2.5f), new PointF(20, 6), new PointF(19, 14) });
                                shield.AddBezier(19, 14, 18, 17.5f, 14, 20, 12, 21.5f);
                                shield.AddBezier(12, 21.5f, 10, 20, 6, 17.5f, 5, 14);
                                shield.AddLines(new[] { new PointF(5, 14), new PointF(4, 6), new PointF(12, 2.5f) });
                                graphics.DrawPath(pen, shield);
                            }
                            graphics.DrawLines(pen, new[] { new PointF(8, 11.5f), new PointF(11, 14.5f), new PointF(16, 9.5f) });
                            break;
                        case UiIcon.Database:
                            graphics.DrawEllipse(pen, 4, 3, 16, 6);
                            graphics.DrawLine(pen, 4, 6, 4, 18);
                            graphics.DrawLine(pen, 20, 6, 20, 18);
                            graphics.DrawArc(pen, 4, 9, 16, 6, 0, 180);
                            graphics.DrawArc(pen, 4, 15, 16, 6, 0, 180);
                            break;
                        case UiIcon.Settings:
                            graphics.DrawEllipse(pen, 8, 8, 8, 8);
                            for (int i = 0; i < 8; i++)
                            {
                                double angle = i * Math.PI / 4;
                                graphics.DrawLine(pen, 12 + 7 * (float)Math.Cos(angle), 12 + 7 * (float)Math.Sin(angle), 12 + 10 * (float)Math.Cos(angle), 12 + 10 * (float)Math.Sin(angle));
                            }
                            graphics.DrawEllipse(pen, 5, 5, 14, 14);
                            break;
                        case UiIcon.Computers:
                            using (var screen = RoundedRect(new RectangleF(3, 4, 18, 12), 2)) graphics.DrawPath(pen, screen);
                            graphics.DrawLine(pen, 12, 16, 12, 20);
                            graphics.DrawLine(pen, 7, 20, 17, 20);
                            break;
                        case UiIcon.Chevron:
                            graphics.DrawLines(pen, new[] { new PointF(9, 6), new PointF(15, 12), new PointF(9, 18) });
                            break;
                        case UiIcon.Cross:
                            graphics.DrawLine(pen, 6, 6, 18, 18);
                            graphics.DrawLine(pen, 18, 6, 6, 18);
                            break;
                    }
                }
            }
            finally { graphics.Restore(saved); }
        }
    }

    internal sealed class SurfacePanel : Panel
    {
        private Color fillColor = Theme.White, borderColor = Theme.Border, accentColor = Color.Empty;
        private int radius = 14;
        public Color FillColor { get { return fillColor; } set { fillColor = value; Invalidate(); } }
        public Color BorderColor { get { return borderColor; } set { borderColor = value; Invalidate(); } }
        public Color AccentColor { get { return accentColor; } set { accentColor = value; Invalidate(); } }
        public int Radius { get { return radius; } set { radius = Math.Max(0, value); Invalidate(); } }

        public SurfacePanel()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
            BackColor = Color.Transparent;
            Padding = new Padding(16);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            if (ClientSize.Width < 2 || ClientSize.Height < 2) return;
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            float scale = e.Graphics.DpiX / 96f;
            RectangleF rectangle = new RectangleF(.5f, .5f, ClientSize.Width - 1, ClientSize.Height - 1);
            using (var path = Theme.RoundedRect(rectangle, radius * scale))
            using (var background = new SolidBrush(fillColor))
            {
                e.Graphics.FillPath(background, path);
                if (!borderColor.IsEmpty && borderColor.A > 0)
                    using (var border = new Pen(borderColor, 1)) e.Graphics.DrawPath(border, path);
            }
            if (!accentColor.IsEmpty && accentColor.A > 0)
                using (var accent = new SolidBrush(accentColor))
                using (var mark = Theme.RoundedRect(new RectangleF(1, 16 * scale, 3 * scale, Math.Max(1, Height - 32 * scale)), 1.5f * scale)) e.Graphics.FillPath(accent, mark);
            base.OnPaint(e);
        }
    }

    internal sealed class ActionButton : Button
    {
        private bool hovered, pressed, keyboardPressed;
        private ButtonKind kind = ButtonKind.Secondary;
        private UiIcon icon = UiIcon.None;
        private int radius = 9;
        public ButtonKind Kind { get { return kind; } set { kind = value; Invalidate(); } }
        public UiIcon Icon { get { return icon; } set { icon = value; Invalidate(); if (AutoSize) PerformLayout(); } }
        public int Radius { get { return radius; } set { radius = Math.Max(0, value); Invalidate(); } }

        public ActionButton()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
            BackColor = Color.Transparent;
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            UseVisualStyleBackColor = false;
            Cursor = Cursors.Hand;
            Padding = new Padding(14, 7, 14, 7);
            MinimumSize = new Size(0, 38);
            Height = 40;
            Margin = new Padding(4);
        }

        public override Size GetPreferredSize(Size proposedSize)
        {
            using (Graphics graphics = CreateGraphics())
            {
                Size text = TextRenderer.MeasureText(graphics, Text, Font, Size.Empty, TextFormatFlags.SingleLine);
                int iconWidth = icon == UiIcon.None ? 0 : (int)Math.Ceiling(27 * graphics.DpiX / 96f);
                return new Size(Math.Max(MinimumSize.Width, text.Width + Padding.Horizontal + iconWidth), Math.Max(MinimumSize.Height, text.Height + Padding.Vertical));
            }
        }

        protected override void OnMouseEnter(EventArgs e) { hovered = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hovered = false; pressed = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { if (e.Button == MouseButtons.Left) pressed = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { pressed = false; Invalidate(); base.OnMouseUp(e); }
        protected override void OnKeyDown(KeyEventArgs e) { if (e.KeyCode == Keys.Space) keyboardPressed = true; Invalidate(); base.OnKeyDown(e); }
        protected override void OnKeyUp(KeyEventArgs e) { keyboardPressed = false; Invalidate(); base.OnKeyUp(e); }
        protected override void OnGotFocus(EventArgs e) { Invalidate(); base.OnGotFocus(e); }
        protected override void OnLostFocus(EventArgs e) { keyboardPressed = false; Invalidate(); base.OnLostFocus(e); }
        protected override void OnEnabledChanged(EventArgs e) { hovered = pressed = keyboardPressed = false; Invalidate(); base.OnEnabledChanged(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            if (Width < 2 || Height < 2) return;
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            float scale = e.Graphics.DpiX / 96f;
            bool down = pressed || keyboardPressed;
            Color background = Theme.White, foreground = Theme.Blue, border = Theme.Border;
            if (kind == ButtonKind.Primary)
            {
                background = down ? Color.FromArgb(29, 50, 79) : hovered ? Color.FromArgb(53, 83, 122) : Theme.Blue;
                foreground = Theme.White; border = Color.Empty;
            }
            else if (kind == ButtonKind.Accent)
            {
                background = down ? Color.FromArgb(150, 213, 178) : hovered ? Color.FromArgb(166, 226, 188) : Theme.Green;
                foreground = Theme.Ink; border = Color.Empty;
            }
            else if (kind == ButtonKind.Quiet)
            {
                background = down ? Color.FromArgb(223, 232, 246) : hovered ? Color.FromArgb(234, 240, 249) : Color.Transparent;
                border = Color.Empty;
            }
            else if (down) background = Color.FromArgb(228, 236, 248);
            else if (hovered) { background = Color.FromArgb(242, 246, 252); border = Theme.Steel; }
            if (!Enabled)
            {
                background = kind == ButtonKind.Quiet ? Color.Transparent : Color.FromArgb(235, 239, 245);
                foreground = Color.FromArgb(159, 173, 189);
                border = kind == ButtonKind.Secondary ? Theme.Border : Color.Empty;
            }
            if (Parent != null)
                using (var canvas = new SolidBrush(Parent.BackColor)) e.Graphics.FillRectangle(canvas, ClientRectangle);
            using (var path = Theme.RoundedRect(new RectangleF(.5f, .5f, Width - 1, Height - 1), radius * scale))
            {
                if (background.A > 0) using (var fill = new SolidBrush(background)) e.Graphics.FillPath(fill, path);
                if (!border.IsEmpty) using (var line = new Pen(border)) e.Graphics.DrawPath(line, path);
            }
            Rectangle content = Rectangle.FromLTRB(Padding.Left, Padding.Top, Width - Padding.Right, Height - Padding.Bottom);
            TextFormatFlags flags = TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis;
            if (!ShowKeyboardCues) flags |= TextFormatFlags.HidePrefix;
            int iconSize = (int)Math.Round(19 * scale), gap = (int)Math.Round(8 * scale);
            int textWidth = TextRenderer.MeasureText(Text, Font, Size.Empty, TextFormatFlags.SingleLine).Width;
            int groupWidth = textWidth + (icon == UiIcon.None ? 0 : iconSize + gap);
            int groupLeft = content.Left + Math.Max(0, (content.Width - groupWidth) / 2);
            if (icon != UiIcon.None)
            {
                Theme.DrawIcon(e.Graphics, icon, new RectangleF(groupLeft, (Height - iconSize) / 2f + (down ? 1 : 0), iconSize, iconSize), foreground);
                content.X = groupLeft + iconSize + gap;
                content.Width = Math.Max(0, Width - Padding.Right - content.X);
                flags |= TextFormatFlags.Left;
            }
            else flags |= TextFormatFlags.HorizontalCenter;
            if (down) content.Offset(0, 1);
            TextRenderer.DrawText(e.Graphics, Text, Font, content, foreground, flags);
            if (Focused && ShowFocusCues)
            {
                Rectangle focus = ClientRectangle; focus.Inflate(-4, -4);
                ControlPaint.DrawFocusRectangle(e.Graphics, focus, foreground, background);
            }
        }
    }

    internal sealed class WorkspaceTabs : TabControl
    {
        private static readonly UiIcon[] icons = { UiIcon.Certificate, UiIcon.Shield, UiIcon.Settings, UiIcon.Computers };

        public WorkspaceTabs()
        {
            DrawMode = TabDrawMode.OwnerDrawFixed;
            SizeMode = TabSizeMode.Fixed;
            ItemSize = new Size(202, 46);
            Padding = new Point(14, 7);
            HotTrack = true;
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            e.Graphics.Clear(Theme.White);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.Clear(Theme.White);
            int bottom = 0;
            for (int index = 0; index < TabPages.Count; index++)
            {
                Rectangle bounds = GetTabRect(index);
                RenderTab(e.Graphics, index, bounds);
                bottom = Math.Max(bottom, bounds.Bottom);
            }
            if (bottom > 0)
                using (var divider = new Pen(Theme.Border)) e.Graphics.DrawLine(divider, 0, bottom, ClientSize.Width, bottom);
        }

        protected override void OnDrawItem(DrawItemEventArgs e)
        {
            RenderTab(e.Graphics, e.Index, e.Bounds);
        }

        private void RenderTab(Graphics graphics, int index, Rectangle bounds)
        {
            if (index < 0 || index >= TabPages.Count) return;
            bool selected = index == SelectedIndex;
            bool enabled = TabPages[index].Enabled && Enabled;
            Color foreground = !enabled ? Color.FromArgb(159, 173, 189) : selected ? Theme.Blue : Theme.Muted;
            float scale = graphics.DpiX / 96f;
            using (var fill = new SolidBrush(selected ? Color.FromArgb(242, 246, 253) : Theme.White)) graphics.FillRectangle(fill, bounds);
            int iconSize = (int)Math.Round(19 * scale);
            int left = bounds.Left + (int)Math.Round(16 * scale);
            Theme.DrawIcon(graphics, index < icons.Length ? icons[index] : UiIcon.None,
                new RectangleF(left, bounds.Top + (bounds.Height - iconSize) / 2f, iconSize, iconSize), foreground);
            var textBounds = Rectangle.FromLTRB(left + iconSize + (int)Math.Round(9 * scale), bounds.Top,
                bounds.Right - (int)Math.Round(7 * scale), bounds.Bottom - (int)Math.Round(2 * scale));
            using (var font = new Font(Font, selected ? FontStyle.Bold : FontStyle.Regular))
                TextRenderer.DrawText(graphics, TabPages[index].Text, font, textBounds, foreground,
                    TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis);
            if (selected)
            {
                using (var line = new SolidBrush(Theme.Blue)) graphics.FillRectangle(line, bounds.Left + 12 * scale, bounds.Bottom - 3 * scale, bounds.Width - 24 * scale, 3 * scale);
                if (Focused && ShowFocusCues)
                {
                    Rectangle focus = bounds; focus.Inflate(-5, -6);
                    ControlPaint.DrawFocusRectangle(graphics, focus, foreground, Theme.White);
                }
            }
        }

        protected override void OnSelectedIndexChanged(EventArgs e)
        {
            base.OnSelectedIndexChanged(e);
            Invalidate();
        }

        protected override void OnControlAdded(ControlEventArgs e)
        {
            base.OnControlAdded(e);
            var page = e.Control as TabPage;
            if (page != null)
            {
                page.BackColor = Theme.White;
                page.UseVisualStyleBackColor = false;
            }
        }
    }

    internal sealed class BrandMark : Control
    {
        public BrandMark()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
            Size = new Size(42, 42);
            BackColor = Color.Transparent;
            TabStop = false;
            AccessibleName = "CertScope";
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            float side = Math.Min(Width, Height) - 2;
            var bounds = new RectangleF((Width - side) / 2, (Height - side) / 2, side, side);
            using (var shape = Theme.RoundedRect(bounds, side * .27f))
            using (var fill = new SolidBrush(Theme.Blue)) e.Graphics.FillPath(fill, shape);
            Theme.DrawIcon(e.Graphics, UiIcon.Shield, new RectangleF(bounds.X + side * .21f, bounds.Y + side * .15f, side * .58f, side * .65f), Theme.White, 1.6f);
            using (var outer = new SolidBrush(Theme.Canvas)) e.Graphics.FillEllipse(outer, bounds.Right - side * .32f, bounds.Bottom - side * .32f, side * .34f, side * .34f);
            using (var dot = new SolidBrush(Theme.Green)) e.Graphics.FillEllipse(dot, bounds.Right - side * .26f, bounds.Bottom - side * .26f, side * .22f, side * .22f);
            base.OnPaint(e);
        }
    }
}
