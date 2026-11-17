using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using TopluImza.Validation;

namespace TopluImza.Batch;

/// <summary>
/// CSV ve JSON rapor yazıcı. CSV, Türkçe Excel'in doğrudan açabilmesi için UTF-8 BOM ve
/// noktalı virgül (;) ayırıcı kullanır.
/// </summary>
public static class ReportWriter
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static void WriteCsv(BatchSummary summary, string path)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Dosya;Biçim;Durum;Çıktı;SHA-256;Boyut (bayt);Doğrulandı;Süre (ms);Zaman (UTC);Mesaj");
        foreach (var i in summary.Items)
        {
            sb.AppendJoin(';', [
                Csv(i.File), Csv(i.Format), Csv(StatusText(i.Status)), Csv(i.Output), Csv(i.Sha256),
                i.SizeBytes.ToString(CultureInfo.InvariantCulture),
                i.Verified is null ? string.Empty : i.Verified.Value ? "evet" : "hayır",
                i.DurationMs.ToString(CultureInfo.InvariantCulture),
                i.TimeUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                Csv(i.Message)]);
            sb.AppendLine();
        }
        Write(path, sb.ToString());
    }

    public static void WriteJson(BatchSummary summary, string path)
    {
        var doc = new
        {
            tool = "TopluImza",
            version = typeof(ReportWriter).Assembly.GetName().Version?.ToString(3),
            signer = summary.Signer,
            started = summary.StartedUtc,
            finished = summary.FinishedUtc,
            cancelled = summary.Cancelled,
            totals = new { signed = summary.Signed, skipped = summary.Skipped, failed = summary.Failed, planned = summary.Planned },
            items = summary.Items,
        };
        Write(path, JsonSerializer.Serialize(doc, Json));
    }

    public static void WriteVerificationCsv(IReadOnlyList<VerificationReport> reports, string path)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Dosya;Sonuç;Biçim;İmzalayan;Beyan edilen zaman (UTC);Zaman damgası (UTC);Hatalar;Uyarılar");
        foreach (var r in reports)
        {
            if (r.Signatures.Count == 0)
            {
                sb.AppendJoin(';', [Csv(r.File), VerdictText(r.Verdict), "", "", "", "", Csv(r.Error), ""]);
                sb.AppendLine();
                continue;
            }
            foreach (var s in r.Signatures)
            {
                sb.AppendJoin(';', [
                    Csv(r.File), VerdictText(s.Verdict), Csv(s.Format), Csv(s.SignerName),
                    s.ClaimedSigningTime?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "",
                    s.TimestampTime?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "",
                    Csv(string.Join(" | ", s.Errors.Prepend(r.Error ?? string.Empty).Where(e => e.Length > 0))),
                    Csv(string.Join(" | ", s.Warnings))]);
                sb.AppendLine();
            }
        }
        Write(path, sb.ToString());
    }

    public static void WriteVerificationJson(IReadOnlyList<VerificationReport> reports, string path) =>
        Write(path, JsonSerializer.Serialize(reports.Select(r => new { r.File, Verdict = r.Verdict, r.Error, r.Signatures }), Json));

    public static string StatusText(ItemStatus s) => s switch
    {
        ItemStatus.Signed => "İMZALANDI",
        ItemStatus.Skipped => "ATLANDI",
        ItemStatus.Failed => "HATA",
        ItemStatus.Planned => "PLAN",
        _ => s.ToString(),
    };

    public static string VerdictText(Verdict v) => v switch
    {
        Verdict.Valid => "GEÇERLİ",
        Verdict.Indeterminate => "BELİRSİZ",
        _ => "GEÇERSİZ",
    };

    private static void Write(string path, string content)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (dir is not null) Directory.CreateDirectory(dir);
        File.WriteAllText(path, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
    }

    /// <summary>RFC 4180 tırnaklama; Excel formül enjeksiyonuna karşı =,+,-,@ ile başlayan değerlere ' eklenir.</summary>
    internal static string Csv(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        if (value[0] is '=' or '+' or '-' or '@' or '\t' or '\r') value = "'" + value;
        bool quote = value.IndexOfAny([';', '"', '\n', '\r', ',']) >= 0;
        return quote ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
    }
}
