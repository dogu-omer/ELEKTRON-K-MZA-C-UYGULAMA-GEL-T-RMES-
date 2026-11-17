using System.Security.Cryptography.X509Certificates;

namespace TopluImza.Validation;

/// <summary>X.509 zincir ve iptal (OCSP/CRL) denetimi; .NET X509Chain üzerine kurulu.</summary>
internal static class CertificateChecker
{
    /// <summary>
    /// Zinciri <paramref name="atTime"/> anına göre kurar. Hata yoksa null; güven/iptal bilgisi
    /// eksikse "belirsiz" mesajı; kesin hata (iptal, imza bozuk) varsa "geçersiz" döner.
    /// </summary>
    public static (Verdict verdict, string? message) Check(
        X509Certificate2 cert,
        IEnumerable<X509Certificate2> extra,
        DateTimeOffset atTime,
        ValidationOptions options)
    {
        if (!options.CheckChain)
        {
            return (Verdict.Valid, null);
        }
        using var chain = new X509Chain();
        var policy = chain.ChainPolicy;
        policy.VerificationTime = atTime.LocalDateTime;
        policy.VerificationTimeIgnored = false;
        policy.RevocationMode = options.Offline ? X509RevocationMode.NoCheck : X509RevocationMode.Online;
        policy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        policy.UrlRetrievalTimeout = TimeSpan.FromSeconds(15);
        policy.ExtraStore.AddRange(extra.ToArray());
        if (options.TrustAnchors.Count > 0)
        {
            policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            policy.CustomTrustStore.AddRange(options.TrustAnchors);
        }

        bool ok = chain.Build(cert);
        if (ok)
        {
            return (Verdict.Valid, null);
        }
        var flags = chain.ChainStatus.Aggregate(X509ChainStatusFlags.NoError, (a, s) => a | s.Status);
        var text = string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()).Where(s => s.Length > 0).Distinct());
        if (flags.HasFlag(X509ChainStatusFlags.Revoked) || flags.HasFlag(X509ChainStatusFlags.NotSignatureValid))
        {
            return (Verdict.Invalid, $"Sertifika zinciri geçersiz: {text}");
        }
        if (flags.HasFlag(X509ChainStatusFlags.NotTimeValid))
        {
            return (Verdict.Invalid, $"Sertifika imza anında geçerlilik süresi dışında: {text}");
        }
        return (Verdict.Indeterminate, $"Sertifika zinciri doğrulanamadı (güvenilir kök/iptal bilgisi eksik): {text}");
    }
}
