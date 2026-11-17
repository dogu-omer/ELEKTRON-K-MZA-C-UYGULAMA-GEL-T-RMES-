using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TopluImza.Core;

/// <summary>
/// <see cref="ISigningToken"/>'ı .NET <see cref="RSA"/> türü gibi gösterir (ör. SignedXml için).
/// Özel anahtar dışa aktarılamaz; imza token'a yönlendirilir.
/// Adapts a token to <see cref="RSA"/> so framework APIs (SignedXml) can sign through it.
/// </summary>
public sealed class TokenRsa : RSA
{
    private readonly ISigningToken _token;
    private readonly RSA _public;

    public TokenRsa(ISigningToken token)
    {
        if (token.KeyType != KeyType.Rsa)
        {
            throw new SigningException("Bu işlem RSA anahtarı gerektirir.");
        }
        _token = token;
        _public = token.Certificate.GetRSAPublicKey() ?? throw new SigningException("Sertifikada RSA açık anahtarı yok.");
        KeySizeValue = _public.KeySize;
        LegalKeySizesValue = [new KeySizes(_public.KeySize, _public.KeySize, 0)];
    }

    public override RSAParameters ExportParameters(bool includePrivateParameters) =>
        includePrivateParameters
            ? throw new CryptographicException("Özel anahtar token dışına aktarılamaz.")
            : _public.ExportParameters(false);

    public override void ImportParameters(RSAParameters parameters) =>
        throw new NotSupportedException();

    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (padding != RSASignaturePadding.Pkcs1)
        {
            throw new CryptographicException("Yalnızca PKCS#1 v1.5 dolgusu desteklenir.");
        }
        return _token.SignDigest(hash, hashAlgorithm);
    }

    public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) =>
        _public.VerifyHash(hash, signature, hashAlgorithm, padding);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _public.Dispose();
        }
        base.Dispose(disposing);
    }
}
