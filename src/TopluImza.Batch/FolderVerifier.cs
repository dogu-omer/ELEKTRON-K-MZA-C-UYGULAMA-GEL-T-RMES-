using TopluImza.Validation;

namespace TopluImza.Batch;

/// <summary>Klasördeki imzalı dosyaları (.p7s, .imz, imza içeren PDF/XML) toplu doğrular.</summary>
public static class FolderVerifier
{
    /// <param name="originalsDir">Ayrık imzaların (.p7s) orijinalleri başka klasördeyse (ör. imza --out ile
    /// ayrı yazıldıysa) o klasör; göreli yol aynı kabul edilir.</param>
    public static IReadOnlyList<VerificationReport> Verify(string path, bool recursive, string? original, ValidationOptions options,
        IProgress<VerificationReport>? progress = null, string? originalsDir = null)
    {
        if (File.Exists(path))
        {
            var single = SignatureVerifier.VerifyFile(path, original, options);
            progress?.Report(single);
            return [single];
        }
        if (!Directory.Exists(path))
        {
            throw new DirectoryNotFoundException($"Klasör veya dosya bulunamadı: {path}");
        }
        var files = Directory.EnumerateFiles(path, "*", new EnumerationOptions { RecurseSubdirectories = recursive, IgnoreInaccessible = true })
            .Where(IsSignedCandidate)
            .Order(StringComparer.Ordinal)
            .ToList();
        var result = new List<VerificationReport>();
        foreach (var f in files)
        {
            string? orig = null;
            if (originalsDir is not null && Path.GetExtension(f).Equals(".p7s", StringComparison.OrdinalIgnoreCase))
            {
                orig = Path.Combine(originalsDir, Path.GetRelativePath(path, f)[..^4]);
            }
            var r = SignatureVerifier.VerifyFile(f, orig, options);
            result.Add(r with { File = Path.GetRelativePath(path, f) });
            progress?.Report(result[^1]);
        }
        return result;
    }

    private static bool IsSignedCandidate(string f)
    {
        var name = Path.GetFileName(f);
        var ext = Path.GetExtension(name).ToLowerInvariant();
        if (name.StartsWith(FileScanner.ReportPrefix, StringComparison.OrdinalIgnoreCase)) return false;
        if (SignatureVerifier.CmsExtensions.Contains(ext)) return true;
        try
        {
            return ext switch
            {
                ".pdf" => TopluImza.Pades.PdfSignatureLocator.HasSignature(File.ReadAllBytes(f)),
                ".xml" => File.ReadAllText(f).Contains("http://www.w3.org/2000/09/xmldsig#", StringComparison.Ordinal),
                _ => false,
            };
        }
        catch (IOException)
        {
            return false;
        }
    }
}
