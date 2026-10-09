using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using AgentGuard.Core.Integration;

namespace AgentGuard.Tray;

/// <summary>Shield icons drawn at runtime, one colour per state, so there are no binary assets to keep in sync.</summary>
public static class TrayIcons
{
    private static readonly Dictionary<TrayLevel, Icon> Cache = new();

    public static Icon For(TrayLevel level)
    {
        lock (Cache)
        {
            if (Cache.TryGetValue(level, out var icon)) return icon;
            var (fill, mark) = level switch
            {
                TrayLevel.Protected => (Color.FromArgb(0x1F, 0x8A, 0x4C), Mark.Check),
                TrayLevel.Monitoring => (Color.FromArgb(0x5B, 0x64, 0x70), Mark.Eye),
                TrayLevel.Attention => (Color.FromArgb(0xD9, 0x8E, 0x04), Mark.Bang),
                TrayLevel.Stopped => (Color.FromArgb(0xC6, 0x28, 0x28), Mark.Stop),
                _ => (Color.FromArgb(0x9A, 0xA4, 0xAF), Mark.Dash),
            };
            icon = Draw(fill, mark, 32);
            Cache[level] = icon;
            return icon;
        }
    }

    private enum Mark { Check, Eye, Bang, Stop, Dash }

    private static Icon Draw(Color fill, Mark mark, int size)
    {
        using var bmp = new Bitmap(size, size);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            float s = size;
            using var shield = new GraphicsPath();
            shield.AddLine(s * 0.50f, s * 0.04f, s * 0.90f, s * 0.18f);
            shield.AddBezier(s * 0.90f, s * 0.18f, s * 0.90f, s * 0.62f, s * 0.72f, s * 0.84f, s * 0.50f, s * 0.97f);
            shield.AddBezier(s * 0.50f, s * 0.97f, s * 0.28f, s * 0.84f, s * 0.10f, s * 0.62f, s * 0.10f, s * 0.18f);
            shield.CloseFigure();
            using (var b = new SolidBrush(fill)) g.FillPath(b, shield);
            using var pen = new Pen(Color.White, s * 0.10f) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
            switch (mark)
            {
                case Mark.Check:
                    g.DrawLines(pen, new[] { new PointF(s * 0.32f, s * 0.50f), new PointF(s * 0.45f, s * 0.63f), new PointF(s * 0.69f, s * 0.38f) });
                    break;
                case Mark.Eye:
                    g.DrawEllipse(pen, s * 0.30f, s * 0.40f, s * 0.40f, s * 0.20f);
                    break;
                case Mark.Bang:
                    g.DrawLine(pen, s * 0.50f, s * 0.30f, s * 0.50f, s * 0.56f);
                    using (var dot = new SolidBrush(Color.White)) g.FillEllipse(dot, s * 0.445f, s * 0.66f, s * 0.11f, s * 0.11f);
                    break;
                case Mark.Stop:
                    g.DrawLine(pen, s * 0.36f, s * 0.36f, s * 0.64f, s * 0.64f);
                    g.DrawLine(pen, s * 0.64f, s * 0.36f, s * 0.36f, s * 0.64f);
                    break;
                default:
                    g.DrawLine(pen, s * 0.34f, s * 0.50f, s * 0.66f, s * 0.50f);
                    break;
            }
        }
        var handle = bmp.GetHicon();
        try { return (Icon)Icon.FromHandle(handle).Clone(); }
        finally { DestroyIcon(handle); }
    }

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr handle);
}
