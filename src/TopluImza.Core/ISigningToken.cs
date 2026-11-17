using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TopluImza.Core;

/// <summary>Anahtar türü / key type of the signing key.</summary>
public enum KeyType
{
    Rsa,
    Ec,
}

/// <summary>
/// İmza anahtarına erişim soyutlaması. Özel anahtar bu arayüzün dışına çıkmaz:
/// yalnızca özet (hash) imzalatılır. PKCS#11 (AKİS) ve test için PKCS#12 uygulamaları vardır.
/// Abstraction over a private key that never leaves its container; only digests are signed.
/// </summary>
public interface ISigningToken : IDisposable
{
    /// <summary>İmzalayan sertifika / signer certificate.</summary>
    X509Certificate2 Certificate { get; }

    /// <summary>Kartta/kapta bulunan ek zincir sertifikaları (imzalayan hariç).</summary>
    IReadOnlyList<X509Certificate2> ExtraCertificates { get; }

    KeyType KeyType { get; }

    /// <summary>
    /// Verilen özeti imzalar. RSA: PKCS#1 v1.5 imza değeri. EC: IEEE P1363 (r||s) biçimi.
    /// Signs a pre-computed digest. RSA returns a PKCS#1 v1.5 signature; EC returns r||s.
    /// </summary>
    byte[] SignDigest(byte[] digest, HashAlgorithmName hashAlgorithm);
}
