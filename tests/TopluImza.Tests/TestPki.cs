using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using PdfSharp.Drawing;
using PdfSharp.Pdf;
using TopluImza.Cades;
using TopluImza.Core;
using BcX509 = Org.BouncyCastle.X509;

namespace TopluImza.Tests;

/// <summary>Testler için kök SM + imza sertifikası + zaman damgası sunucusu.</summary>
public sealed class TestPki : IDisposable
{
    private static readonly Lazy<TestPki> Shared = new(() => new TestPki());

    public static TestPki Instance => Shared.Value;

    public X509Certificate2 Root { get; }

    public X509Certificate2 RsaSigner { get; }

    public X509Certificate2 EcSigner { get; }

    public X509Certificate2 Tsa { get; }

    private TestPki()
    {
        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Test Kok SM, O=TopluImza Test, C=TR", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        rootReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootReq.PublicKey, false));
        Root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(5));

        RsaSigner = Issue("CN=Ayse Yilmaz, SERIALNUMBER=12345678901, C=TR", RSA.Create(2048), X509KeyUsageFlags.NonRepudiation, null);
        EcSigner = Issue("CN=Mehmet Kaya, C=TR", ECDsa.Create(ECCurve.NamedCurves.nistP256), X509KeyUsageFlags.NonRepudiation, null);
        Tsa = Issue("CN=Test Zaman Damgasi, C=TR", RSA.Create(2048), X509KeyUsageFlags.DigitalSignature,
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.8")], critical: true));
    }

    private X509Certificate2 Issue(string subject, AsymmetricAlgorithm key, X509KeyUsageFlags usage, X509Extension? extra)
    {
        CertificateRequest req = key switch
        {
            RSA rsa => new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ec => new CertificateRequest(subject, ec, HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException(),
        };
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
        if (extra is not null) req.CertificateExtensions.Add(extra);
        var serial = RandomNumberGenerator.GetBytes(12);
        serial[0] &= 0x7F;
        req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Root, true, false));
        using var rootKey = Root.GetRSAPrivateKey()!;
        using var issued = req.Create(Root.SubjectName, X509SignatureGenerator.CreateForRSA(rootKey, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2), serial);
        var withKey = key switch
        {
            RSA rsa => issued.CopyWithPrivateKey(rsa),
            ECDsa ec => issued.CopyWithPrivateKey(ec),
            _ => throw new NotSupportedException(),
        };
        // Taşınabilir kopya (Windows/macOS'ta geçici anahtar kapsayıcısı sorunlarını önler).
        return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12, "x"), "x", X509KeyStorageFlags.Exportable);
    }

    public ISigningToken RsaToken() => new PfxSigningToken(RsaSigner);

    public ISigningToken EcToken() => new PfxSigningToken(EcSigner);

    public Validation.ValidationOptions TrustOptions() => new() { TrustAnchors = [Root], Offline = true };

    public ITimestampClient TimestampClient() => new InMemoryTsa(Tsa);

    public void Dispose()
    {
    }

    /// <summary>Basit PDF üretir (PDFsharp).</summary>
    public static byte[] SamplePdf(string text = "Merhaba dünya")
    {
        using var doc = new PdfDocument();
        var page = doc.AddPage();
        using (var gfx = XGraphics.FromPdfPage(page))
        {
            gfx.DrawRectangle(XBrushes.LightGray, 40, 40, 200, 60);
        }
        doc.Info.Title = text;
        using var ms = new MemoryStream();
        doc.Save(ms, false);
        return ms.ToArray();
    }

    /// <summary>Bellekte RFC 3161 TSA.</summary>
    private sealed class InMemoryTsa(X509Certificate2 tsaCert) : ITimestampClient
    {
        private long _serial = 1;

        public byte[] GetTimestampToken(byte[] digest, HashAlgorithmName hashAlgorithm)
        {
            var key = DotNetUtilities.GetKeyPair(tsaCert.GetRSAPrivateKey()!).Private;
            var bcCert = new BcX509.X509Certificate(tsaCert.RawData);
            var gen = new TimeStampTokenGenerator(key, bcCert, Org.BouncyCastle.Asn1.Nist.NistObjectIdentifiers.IdSha256.Id, "1.2.3.4.1");
            gen.SetCertificates(CollectionUtilities.CreateStore(new[] { bcCert }));
            var reqGen = new TimeStampRequestGenerator();
            reqGen.SetCertReq(true);
            var req = reqGen.Generate(HttpTimestampClient_Oid(hashAlgorithm), digest);
            var token = gen.Generate(req, BigInteger.ValueOf(Interlocked.Increment(ref _serial)), DateTime.UtcNow);
            return token.GetEncoded();
        }

        private static string HttpTimestampClient_Oid(HashAlgorithmName h) => h.Name switch
        {
            "SHA384" => TspAlgorithms.Sha384,
            "SHA512" => TspAlgorithms.Sha512,
            _ => TspAlgorithms.Sha256,
        };
    }
}
