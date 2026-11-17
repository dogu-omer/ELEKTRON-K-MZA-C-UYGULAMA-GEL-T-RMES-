using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Utilities.Collections;
using TopluImza.Core;
using BcAttribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using AttributeTable = Org.BouncyCastle.Asn1.Cms.AttributeTable;
using Time = Org.BouncyCastle.Asn1.Cms.Time;
using BcX509 = Org.BouncyCastle.X509;

namespace TopluImza.Cades;

/// <summary>CAdES imza seçenekleri / CAdES options.</summary>
public sealed record CadesOptions
{
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;

    /// <summary>Verilirse imza değeri zaman damgalanır (CAdES-T). Yoksa CAdES-BES.</summary>
    public ITimestampClient? Timestamp { get; init; }

    /// <summary>signing-time özniteliği. PAdES'te kullanılmaz (ETSI EN 319 142-1 §6.3).</summary>
    public bool IncludeSigningTime { get; init; } = true;

    /// <summary>İmza zamanı; test için sabitlenebilir.</summary>
    public DateTimeOffset? SigningTime { get; init; }
}

/// <summary>
/// CAdES-BES / CAdES-T imza üreticisi (ETSI EN 319 122-1, RFC 5652). İmzalı öznitelikler:
/// content-type, message-digest, signing-certificate-v2 (RFC 5035) ve isteğe bağlı signing-time.
/// </summary>
public sealed class CadesSigner(ISigningToken token, CadesOptions? options = null)
{
    private readonly CadesOptions _options = options ?? new CadesOptions();

    /// <summary>Ayrık (detached) imza: içerik imzaya gömülmez, .p7s üretilir.</summary>
    public byte[] SignDetached(Stream content) => Sign(new CmsProcessableStream(content), encapsulate: false);

    /// <summary>Bütünleşik (attached/enveloping) imza: içerik imzanın içindedir (.imz).</summary>
    public byte[] SignAttached(Stream content)
    {
        // İçerik hem özet hem de gömme için iki kez okunur; bu yüzden belleğe alınır.
        using var ms = new MemoryStream();
        content.CopyTo(ms);
        return Sign(new CmsProcessableByteArray(ms.ToArray()), encapsulate: true);
    }

    /// <summary>Genel CMS imzası; PAdES bayt aralığı gibi özel içerikler için.</summary>
    public byte[] Sign(CmsTypedData content, bool encapsulate)
    {
        var bcCert = new BcX509.X509Certificate(token.Certificate.RawData);
        var certs = new List<BcX509.X509Certificate> { bcCert };
        certs.AddRange(token.ExtraCertificates
            .Where(c => !c.Equals(token.Certificate))
            .Select(c => new BcX509.X509Certificate(c.RawData)));

        var attrGen = new CadesSignedAttributes(token.Certificate.RawData, bcCert, _options);
        var sigInfoGen = new SignerInfoGeneratorBuilder()
            .WithSignedAttributeGenerator(attrGen)
            .Build(new TokenSignatureFactory(token, _options.HashAlgorithm), bcCert);

        var gen = new CmsSignedDataGenerator();
        gen.AddSignerInfoGenerator(sigInfoGen);
        gen.AddCertificates(CollectionUtilities.CreateStore(certs));
        CmsSignedData signed;
        try
        {
            signed = gen.Generate(content, encapsulate);
        }
        catch (CmsException ex)
        {
            throw new SigningException($"CMS imzası oluşturulamadı: {ex.Message}", ex);
        }

        if (_options.Timestamp is not null)
        {
            signed = AddSignatureTimestamp(signed, _options.Timestamp, _options.HashAlgorithm);
        }
        return signed.GetEncoded(Asn1Encodable.Der);
    }

    /// <summary>imza değerinin zaman damgasını (id-aa-signatureTimeStampToken) ekler → CAdES-T.</summary>
    internal static CmsSignedData AddSignatureTimestamp(CmsSignedData signed, ITimestampClient tsa, HashAlgorithmName hash)
    {
        var updated = new List<SignerInformation>();
        foreach (var signer in signed.GetSignerInfos().GetSigners())
        {
            var digest = HashAlgorithms.Compute(hash, signer.GetSignature());
            var token = tsa.GetTimestampToken(digest, hash);
            var attr = new BcAttribute(PkcsObjectIdentifiers.IdAASignatureTimeStampToken,
                new DerSet(Asn1Object.FromByteArray(token)));
            var vector = signer.UnsignedAttributes?.ToAsn1EncodableVector() ?? new Asn1EncodableVector();
            vector.Add(attr);
            updated.Add(SignerInformation.ReplaceUnsignedAttributes(signer, new AttributeTable(vector)));
        }
        return CmsSignedData.ReplaceSigners(signed, new SignerInformationStore(updated));
    }

    /// <summary>İmzalı öznitelik tablosu üreticisi.</summary>
    private sealed class CadesSignedAttributes(byte[] certDer, BcX509.X509Certificate cert, CadesOptions options)
        : CmsAttributeTableGenerator
    {
        public AttributeTable GetAttributes(IDictionary<CmsAttributeTableParameter, object> parameters)
        {
            var v = new Asn1EncodableVector();
            var contentType = (DerObjectIdentifier)parameters[CmsAttributeTableParameter.ContentType];
            var digest = (byte[])parameters[CmsAttributeTableParameter.Digest];
            v.Add(new BcAttribute(CmsAttributes.ContentType, new DerSet(contentType)));
            if (options.IncludeSigningTime)
            {
                var when = (options.SigningTime ?? DateTimeOffset.UtcNow).UtcDateTime;
                v.Add(new BcAttribute(CmsAttributes.SigningTime, new DerSet(new Time(when))));
            }
            v.Add(new BcAttribute(CmsAttributes.MessageDigest, new DerSet(new DerOctetString(digest))));
            v.Add(SigningCertificateV2(certDer, cert));
            return new AttributeTable(v);
        }
    }

    /// <summary>ESS signing-certificate-v2 (RFC 5035), SHA-256 ile.</summary>
    internal static BcAttribute SigningCertificateV2(byte[] certDer, BcX509.X509Certificate cert)
    {
        var hash = SHA256.HashData(certDer);
        var issuerSerial = new IssuerSerial(
            new GeneralNames(new GeneralName(cert.IssuerDN)),
            new DerInteger(cert.SerialNumber));
        var id = new EssCertIDv2(hash, issuerSerial);
        var scv2 = new SigningCertificateV2([id]);
        return new BcAttribute(PkcsObjectIdentifiers.IdAASigningCertificateV2, new DerSet(scv2));
    }
}

/// <summary>Akıştan okuyan CMS içeriği (büyük dosyaları belleğe almadan).</summary>
internal sealed class CmsProcessableStream(Stream stream) : CmsTypedData
{
    public DerObjectIdentifier ContentType => CmsObjectIdentifiers.Data;

    public object GetContent() => stream;

    public void Write(Stream output) => stream.CopyTo(output);
}
