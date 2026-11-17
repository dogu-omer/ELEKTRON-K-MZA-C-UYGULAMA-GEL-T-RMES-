using System.Text;

namespace TopluImza.Validation;

/// <summary>
/// Dosya türüne göre doğru doğrulayıcıyı seçen giriş noktası.
/// .pdf → PAdES, .xml → XAdES, .p7s/.p7m/.imz/.cms → CAdES (ayrık ise orijinal dosya gerekir).
/// </summary>
public static class SignatureVerifier
{
    public static readonly string[] DetachedExtensions = [".p7s"];
    public static readonly string[] CmsExtensions = [".p7s", ".p7m", ".imz", ".cms"];

    public static VerificationReport VerifyFile(string path, string? original, ValidationOptions options)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            var ext = Path.GetExtension(path).ToLowerInvariant();
            IReadOnlyList<SignatureResult> results;
            if (ext == ".pdf" || StartsWith(bytes, "%PDF-"))
            {
                results = PdfVerifier.Verify(bytes, options);
            }
            else if (ext == ".xml" || StartsWith(bytes, "<?xml"))
            {
                results = XmlVerifier.Verify(bytes, options);
            }
            else
            {
                original ??= GuessOriginal(path);
                byte[]? content = original is not null && File.Exists(original) ? File.ReadAllBytes(original) : null;
                if (DetachedExtensions.Contains(ext) && content is null)
                {
                    return new VerificationReport(path, [], "Ayrık imzanın orijinal dosyası bulunamadı (--original / --originals).");
                }
                results = CmsVerifier.Verify(bytes, content, "CAdES", options);
            }
            return results.Count == 0
                ? new VerificationReport(path, results, "Dosyada imza bulunamadı.")
                : new VerificationReport(path, results);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new VerificationReport(path, [], $"Dosya okunamadı: {ex.Message}");
        }
    }

    /// <summary>"rapor.docx.p7s" → "rapor.docx" (varsa).</summary>
    public static string? GuessOriginal(string signaturePath)
    {
        var ext = Path.GetExtension(signaturePath);
        if (!CmsExtensions.Contains(ext.ToLowerInvariant())) return null;
        var candidate = signaturePath[..^ext.Length];
        return File.Exists(candidate) ? candidate : null;
    }

    private static bool StartsWith(byte[] data, string ascii)
    {
        var prefix = Encoding.ASCII.GetBytes(ascii);
        int offset = data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF ? 3 : 0;
        return data.Length >= offset + prefix.Length && data.AsSpan(offset, prefix.Length).SequenceEqual(prefix);
    }
}
