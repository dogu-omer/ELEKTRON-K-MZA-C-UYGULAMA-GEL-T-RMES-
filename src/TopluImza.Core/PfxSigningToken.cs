using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TopluImza.Core;

/// <summary>
/// PKCS#12 (.p12/.pfx) dosyasındaki anahtarla imza. Yalnızca test ve geliştirme içindir:
/// yazılım anahtarı "güvenli elektronik imza oluşturma aracı" değildir (5070 s. Kanun m.6).
/// Software key from a PKCS#12 file. For tests/development only; not a qualified signature device.
/// </summary>
public sealed class PfxSigningToken : ISigningToken
{
    private readonly RSA? _rsa;
    private readonly ECDsa? _ec;

    public PfxSigningToken(X509Certificate2 certificateWithKey, IEnumerable<X509Certificate2>? extra = null)
    {
        Certificate = certificateWithKey;
        ExtraCertificates = extra?.ToList() ?? [];
        _rsa = certificateWithKey.GetRSAPrivateKey();
        _ec = _rsa is null ? certificateWithKey.GetECDsaPrivateKey() : null;
        if (_rsa is null && _ec is null)
        {
            throw new SigningException("Sertifikanın özel anahtarı yok veya desteklenmiyor (RSA/EC).");
        }
        KeyType = _rsa is not null ? KeyType.Rsa : KeyType.Ec;
    }

    public static PfxSigningToken Load(string path, ReadOnlySpan<char> password)
    {
        var all = X509CertificateLoader.LoadPkcs12CollectionFromFile(path, password, X509KeyStorageFlags.EphemeralKeySet);
        var signer = all.Cast<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey)
            ?? throw new SigningException($"{path}: özel anahtarlı sertifika bulunamadı.");
        return new PfxSigningToken(signer, all.Cast<X509Certificate2>().Where(c => !ReferenceEquals(c, signer)));
    }

    public X509Certificate2 Certificate { get; }

    public IReadOnlyList<X509Certificate2> ExtraCertificates { get; }

    public KeyType KeyType { get; }

    public byte[] SignDigest(byte[] digest, HashAlgorithmName hashAlgorithm) =>
        _rsa is not null
            ? _rsa.SignHash(digest, hashAlgorithm, RSASignaturePadding.Pkcs1)
            : _ec!.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    public void Dispose()
    {
        _rsa?.Dispose();
        _ec?.Dispose();
    }
}
