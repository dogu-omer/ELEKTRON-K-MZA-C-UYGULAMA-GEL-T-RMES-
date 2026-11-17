using TopluImza.Cades;
using TopluImza.Core;
using TopluImza.Pades;
using TopluImza.Xades;

namespace TopluImza.Batch;

/// <summary>Bir dosyaya uygulanacak imza türü.</summary>
public enum SignatureKind
{
    CadesDetached,
    CadesAttached,
    Pades,
    Xades,
}

/// <summary>Dosya türüne göre doğru imzalayıcıyı seçer ve çıktı adını belirler.</summary>
public sealed class DocumentSigner(ISigningToken token, BatchOptions options)
{
    public static SignatureKind KindFor(string path, BatchOptions options)
    {
        if (options.Format == FormatMode.Auto)
        {
            switch (Path.GetExtension(path).ToLowerInvariant())
            {
                case ".pdf":
                    return SignatureKind.Pades;
                case ".xml":
                    return SignatureKind.Xades;
            }
        }
        return options.Attached ? SignatureKind.CadesAttached : SignatureKind.CadesDetached;
    }

    /// <summary>Çıktı yolu: rapor.docx → rapor.docx.p7s / .imz; belge.pdf → belge_imzali.pdf.</summary>
    public static string OutputPathFor(string inputFile, SignatureKind kind, BatchOptions options)
    {
        string dir = Path.GetDirectoryName(inputFile)!;
        if (options.OutputDirectory is not null)
        {
            var root = File.Exists(options.Input) ? Path.GetDirectoryName(Path.GetFullPath(options.Input))! : Path.GetFullPath(options.Input);
            var rel = Path.GetRelativePath(root, dir);
            dir = Path.GetFullPath(Path.Combine(options.OutputDirectory, rel));
        }
        var name = Path.GetFileName(inputFile);
        var stem = Path.GetFileNameWithoutExtension(inputFile);
        var ext = Path.GetExtension(inputFile);
        var outName = kind switch
        {
            SignatureKind.CadesDetached => name + ".p7s",
            SignatureKind.CadesAttached => name + ".imz",
            _ => stem + FileScanner.SignedSuffix + ext,
        };
        return Path.Combine(dir, outName);
    }

    public byte[] Sign(string inputFile, SignatureKind kind)
    {
        var cades = new CadesOptions { HashAlgorithm = options.HashAlgorithm, Timestamp = options.Timestamp };
        switch (kind)
        {
            case SignatureKind.CadesDetached:
            {
                using var s = File.OpenRead(inputFile);
                return new CadesSigner(token, cades).SignDetached(s);
            }
            case SignatureKind.CadesAttached:
            {
                using var s = File.OpenRead(inputFile);
                return new CadesSigner(token, cades).SignAttached(s);
            }
            case SignatureKind.Pades:
                return new PadesSigner(token, new PadesOptions { Cades = cades, Reason = options.Reason, Location = options.Location })
                    .Sign(File.ReadAllBytes(inputFile));
            case SignatureKind.Xades:
            {
                if (options.Timestamp is not null)
                {
                    throw new SigningException("XAdES-T henüz desteklenmiyor; XML'i --format cades ile zaman damgalı imzalayın.");
                }
                using var s = File.OpenRead(inputFile);
                return new XadesSigner(token, new XadesOptions { HashAlgorithm = options.HashAlgorithm }).Sign(s);
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(kind));
        }
    }
}
