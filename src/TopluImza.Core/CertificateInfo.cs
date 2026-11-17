using System.Security.Cryptography.X509Certificates;

namespace TopluImza.Core;

/// <summary>Sertifika özet bilgisi / human-readable certificate summary.</summary>
public sealed record CertificateInfo(
    string Label,
    string Subject,
    string Issuer,
    string SerialNumber,
    DateTime NotBefore,
    DateTime NotAfter,
    bool NonRepudiation,
    bool HasPrivateKey)
{
    public static CertificateInfo From(X509Certificate2 cert, string label, bool hasPrivateKey) => new(
        label,
        cert.Subject,
        cert.Issuer,
        cert.SerialNumber,
        cert.NotBefore.ToUniversalTime(),
        cert.NotAfter.ToUniversalTime(),
        HasNonRepudiation(cert),
        hasPrivateKey);

    /// <summary>
    /// Nitelikli elektronik sertifikalarda (5070 s. Kanun) imza anahtarı "nonRepudiation"
    /// (contentCommitment) kullanımıyla işaretlenir.
    /// </summary>
    public static bool HasNonRepudiation(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509KeyUsageExtension ku)
            {
                return ku.KeyUsages.HasFlag(X509KeyUsageFlags.NonRepudiation);
            }
        }
        return false;
    }

    /// <summary>Konu adından CN (ortak ad) değeri / common name.</summary>
    public static string CommonName(X509Certificate2 cert) =>
        cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false) is { Length: > 0 } cn ? cn : cert.Subject;
}
