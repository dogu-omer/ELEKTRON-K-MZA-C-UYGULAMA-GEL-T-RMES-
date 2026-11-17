using TopluImza.Pades;

namespace TopluImza.Validation;

/// <summary>PDF (PAdES / PKCS#7) imza doğrulayıcı.</summary>
public static class PdfVerifier
{
    public static IReadOnlyList<SignatureResult> Verify(byte[] pdf, ValidationOptions options)
    {
        var ranges = PdfSignatureLocator.FindAll(pdf);
        if (ranges.Count == 0)
        {
            return [];
        }
        var results = new List<SignatureResult>();
        for (int i = 0; i < ranges.Count; i++)
        {
            var range = ranges[i];
            byte[] cms;
            try
            {
                cms = range.ExtractCms(pdf);
            }
            catch (Exception ex) when (ex is FormatException or IOException or ArgumentException)
            {
                results.Add(new SignatureResult { Format = "PAdES", Verdict = Verdict.Invalid, Errors = [$"İmza değeri okunamadı: {ex.Message}"] });
                continue;
            }
            foreach (var r in CmsVerifier.Verify(cms, range.SignedBytes(pdf), "PAdES", options))
            {
                var warnings = r.Warnings.ToList();
                bool last = i == ranges.Count - 1;
                if (last && !range.CoversWholeFile(pdf.Length))
                {
                    warnings.Add("İmzadan sonra belgeye ekleme yapılmış (artımlı güncelleme); eklenen kısım imza kapsamında değil.");
                }
                results.Add(r with { ClaimedSigningTime = r.ClaimedSigningTime ?? PdfDate(pdf, range), Warnings = warnings, Verdict = r.Verdict == Verdict.Valid && warnings.Any(w => w.StartsWith("İmzadan sonra", StringComparison.Ordinal)) ? Verdict.Indeterminate : r.Verdict });
            }
        }
        return results;
    }

    /// <summary>İmza sözlüğündeki /M (D:YYYYMMDDHHmmSS+HH'mm') değeri; imzalayan beyanıdır.</summary>
    internal static DateTimeOffset? PdfDate(byte[] pdf, PdfSignatureRange range)
    {
        int from = Math.Max(0, range.ContentsStart - 1024);
        var text = System.Text.Encoding.Latin1.GetString(pdf, from, range.ContentsStart - from);
        var m = System.Text.RegularExpressions.Regex.Match(text, @"/M\s*\(D:(\d{14})(Z|[+-]\d{2}'?\d{2}'?)?\)", System.Text.RegularExpressions.RegexOptions.RightToLeft);
        if (!m.Success) return null;
        var dt = DateTime.ParseExact(m.Groups[1].Value, "yyyyMMddHHmmss", System.Globalization.CultureInfo.InvariantCulture);
        var offset = TimeSpan.Zero;
        var tz = m.Groups[2].Value.Replace("'", string.Empty);
        if (tz.Length == 5)
        {
            offset = new TimeSpan(int.Parse(tz.Substring(1, 2)), int.Parse(tz.Substring(3, 2)), 0);
            if (tz[0] == '-') offset = -offset;
        }
        return new DateTimeOffset(dt, offset);
    }
}
