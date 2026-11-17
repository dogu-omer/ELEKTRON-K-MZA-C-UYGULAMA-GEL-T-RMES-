using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using TopluImza.Core;

namespace TopluImza.Cades;

/// <summary>
/// Bouncy Castle CMS üreticisinin imza adımını <see cref="ISigningToken"/>'a yönlendirir.
/// Routes Bouncy Castle's signature step to the token (key stays on the card).
/// </summary>
internal sealed class TokenSignatureFactory : ISignatureFactory
{
    private readonly ISigningToken _token;
    private readonly HashAlgorithmName _hash;

    public TokenSignatureFactory(ISigningToken token, HashAlgorithmName hash)
    {
        _token = token;
        _hash = hash;
        AlgorithmDetails = SignatureAlgorithm(token.KeyType, hash);
    }

    public object AlgorithmDetails { get; }

    public IStreamCalculator<IBlockResult> CreateCalculator() => new Calculator(this);

    internal static AlgorithmIdentifier SignatureAlgorithm(KeyType keyType, HashAlgorithmName hash) => (keyType, hash.Name) switch
    {
        (KeyType.Rsa, "SHA256") => new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha256WithRsaEncryption, DerNull.Instance),
        (KeyType.Rsa, "SHA384") => new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha384WithRsaEncryption, DerNull.Instance),
        (KeyType.Rsa, "SHA512") => new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha512WithRsaEncryption, DerNull.Instance),
        (KeyType.Ec, "SHA256") => new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha256),
        (KeyType.Ec, "SHA384") => new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha384),
        (KeyType.Ec, "SHA512") => new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha512),
        _ => throw new NotSupportedException($"{keyType}/{hash.Name}"),
    };

    internal static DerObjectIdentifier DigestOid(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA256" => NistObjectIdentifiers.IdSha256,
        "SHA384" => NistObjectIdentifiers.IdSha384,
        "SHA512" => NistObjectIdentifiers.IdSha512,
        _ => throw new NotSupportedException(hash.Name),
    };

    /// <summary>IEEE P1363 (r||s) → DER SEQUENCE { r, s } (CMS ECDSA biçimi).</summary>
    internal static byte[] P1363ToDer(byte[] rs)
    {
        int half = rs.Length / 2;
        var r = new Org.BouncyCastle.Math.BigInteger(1, rs, 0, half);
        var s = new Org.BouncyCastle.Math.BigInteger(1, rs, half, half);
        return new DerSequence(new DerInteger(r), new DerInteger(s)).GetEncoded(Asn1Encodable.Der);
    }

    private sealed class Calculator(TokenSignatureFactory owner) : IStreamCalculator<IBlockResult>
    {
        private readonly MemoryStream _buffer = new();

        public Stream Stream => _buffer;

        public IBlockResult GetResult()
        {
            var digest = HashAlgorithms.Compute(owner._hash, _buffer.ToArray());
            var sig = owner._token.SignDigest(digest, owner._hash);
            if (owner._token.KeyType == KeyType.Ec)
            {
                sig = P1363ToDer(sig);
            }
            return new SimpleBlockResult(sig);
        }
    }
}
