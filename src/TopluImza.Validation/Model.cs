using System.Security.Cryptography.X509Certificates;

namespace TopluImza.Validation;

/// <summary>
/// Doğrulama sonucu (ETSI EN 319 102-1 ana göstergelerine benzer):
/// Valid = TOTAL-PASSED, Indeterminate = INDETERMINATE, Invalid = TOTAL-FAILED.
/// </summary>
public enum Verdict
{
    Valid = 0,
    Indeterminate = 1,
    Invalid = 2,
}

/// <summary>Tek bir imzanın sonucu.</summary>
public sealed record SignatureResult
{
    public required string Format { get; init; }

    public string? SignerName { get; init; }

    public string? SignerSubject { get; init; }

    public string? Issuer { get; init; }

    /// <summary>İmzalayanın beyan ettiği zaman (signing-time / SigningTime / PDF /M). Kanıt değildir.</summary>
    public DateTimeOffset? ClaimedSigningTime { get; init; }

    /// <summary>Zaman damgası zamanı (RFC 3161). Varsa güvenilir zaman budur.</summary>
    public DateTimeOffset? TimestampTime { get; init; }

    public Verdict Verdict { get; init; }

    public IReadOnlyList<string> Errors { get; init; } = [];

    public IReadOnlyList<string> Warnings { get; init; } = [];
}

/// <summary>Bir dosyanın doğrulama raporu.</summary>
public sealed record VerificationReport(string File, IReadOnlyList<SignatureResult> Signatures, string? Error = null)
{
    public Verdict Verdict =>
        Error is not null || Signatures.Count == 0
            ? Verdict.Invalid
            : Signatures.Max(s => s.Verdict);
}

/// <summary>Doğrulama seçenekleri.</summary>
public sealed record ValidationOptions
{
    /// <summary>Güvenilir kök sertifikalar (ör. Kamu SM kökleri). Boşsa işletim sistemi deposu kullanılır.</summary>
    public X509Certificate2Collection TrustAnchors { get; init; } = [];

    /// <summary>true: OCSP/CRL sorgusu yapılmaz.</summary>
    public bool Offline { get; init; }

    /// <summary>false: zincir/iptal denetimi atlanır, yalnızca kriptografik bütünlük denetlenir.</summary>
    public bool CheckChain { get; init; } = true;

    /// <summary>PEM/DER dosyası veya dizinden kök sertifikaları yükler.</summary>
    public static X509Certificate2Collection LoadTrust(string path)
    {
        var result = new X509Certificate2Collection();
        IEnumerable<string> files = Directory.Exists(path)
            ? Directory.EnumerateFiles(path).Where(f => Path.GetExtension(f).ToLowerInvariant() is ".crt" or ".cer" or ".pem" or ".der")
            : [path];
        foreach (var f in files)
        {
            var text = File.ReadAllText(f);
            if (text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
            {
                result.ImportFromPem(text);
            }
            else
            {
                result.Add(X509CertificateLoader.LoadCertificateFromFile(f));
            }
        }
        return result;
    }
}
