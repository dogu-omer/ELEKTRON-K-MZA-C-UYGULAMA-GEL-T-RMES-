using System.Security.Cryptography;

namespace TopluImza.Core;

/// <summary>Özet algoritması yardımcıları / digest helpers.</summary>
public static class HashAlgorithms
{
    public static byte[] Compute(HashAlgorithmName name, ReadOnlySpan<byte> data) => name.Name switch
    {
        "SHA256" => SHA256.HashData(data),
        "SHA384" => SHA384.HashData(data),
        "SHA512" => SHA512.HashData(data),
        _ => throw new NotSupportedException($"Desteklenmeyen özet algoritması: {name.Name}"),
    };

    public static byte[] Compute(HashAlgorithmName name, Stream data) => name.Name switch
    {
        "SHA256" => SHA256.HashData(data),
        "SHA384" => SHA384.HashData(data),
        "SHA512" => SHA512.HashData(data),
        _ => throw new NotSupportedException($"Desteklenmeyen özet algoritması: {name.Name}"),
    };

    /// <summary>"sha256" → SHA256 (büyük/küçük harf duyarsız).</summary>
    public static HashAlgorithmName Parse(string value) => value.Trim().ToUpperInvariant().Replace("-", "") switch
    {
        "SHA256" => HashAlgorithmName.SHA256,
        "SHA384" => HashAlgorithmName.SHA384,
        "SHA512" => HashAlgorithmName.SHA512,
        _ => throw new ArgumentException($"Desteklenmeyen özet algoritması: {value} (sha256, sha384, sha512)"),
    };

    /// <summary>
    /// PKCS#1 v1.5 için DigestInfo (RFC 8017 §9.2) önekleri. CKM_RSA_PKCS ham DigestInfo bekler.
    /// </summary>
    public static byte[] DigestInfo(HashAlgorithmName name, byte[] digest)
    {
        byte[] prefix = name.Name switch
        {
            "SHA256" => [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
            "SHA384" => [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
            "SHA512" => [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],
            _ => throw new NotSupportedException($"Desteklenmeyen özet algoritması: {name.Name}"),
        };
        var result = new byte[prefix.Length + digest.Length];
        prefix.CopyTo(result, 0);
        digest.CopyTo(result, prefix.Length);
        return result;
    }
}
