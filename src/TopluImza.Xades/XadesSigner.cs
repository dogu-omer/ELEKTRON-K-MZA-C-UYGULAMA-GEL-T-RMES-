using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using TopluImza.Core;

namespace TopluImza.Xades;

/// <summary>XAdES seçenekleri / XAdES options.</summary>
public sealed record XadesOptions
{
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;

    public DateTimeOffset? SigningTime { get; init; }
}

/// <summary>
/// XAdES-BES enveloped imza (ETSI EN 319 132-1, W3C XMLDSig). İmza, kök öğenin son çocuğu
/// olarak eklenir; SignedProperties: SigningTime, SigningCertificateV2.
/// Şimdilik RSA anahtarlar desteklenir (Türkiye'deki nitelikli sertifikaların çoğu RSA'dır).
/// </summary>
public sealed class XadesSigner(ISigningToken token, XadesOptions? options = null)
{
    public const string XadesNs = "http://uri.etsi.org/01903/v1.3.2#";
    public const string SignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";

    private readonly XadesOptions _options = options ?? new XadesOptions();

    static XadesSigner()
    {
        // ISO-8859-9 (Türkçe) / windows-1254 kodlu XML'ler için.
        System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
    }

    public byte[] Sign(Stream xml)
    {
        if (token.KeyType != KeyType.Rsa)
        {
            throw new SigningException("XAdES şu an yalnızca RSA anahtarlarla destekleniyor; EC için CAdES kullanın.");
        }
        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        try
        {
            using var reader = XmlReader.Create(xml, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            doc.Load(reader);
        }
        catch (XmlException ex)
        {
            throw new SigningException($"XML okunamadı: {ex.Message}", ex);
        }
        if (doc.DocumentElement is null)
        {
            throw new SigningException("XML kök öğesi yok.");
        }

        string id = Guid.NewGuid().ToString("N")[..12];
        string sigId = "Signature-" + id;
        string spId = "SignedProperties-" + id;

        using var key = new TokenRsa(token);
        var qp = BuildQualifyingProperties(doc, sigId, spId);
        var signedProps = (XmlElement)qp.FirstChild!;
        var signedXml = new XadesSignedXml(doc, spId, signedProps) { SigningKey = key };
        signedXml.Signature.Id = sigId;
        signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = SignatureMethod(_options.HashAlgorithm);

        var docRef = new Reference(string.Empty) { DigestMethod = DigestMethod(_options.HashAlgorithm) };
        docRef.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        docRef.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(docRef);

        var spRef = new Reference("#" + spId) { Type = SignedPropertiesType, DigestMethod = DigestMethod(_options.HashAlgorithm) };
        spRef.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(spRef);

        var keyInfo = new KeyInfo();
        var x509 = new KeyInfoX509Data(token.Certificate);
        foreach (var extra in token.ExtraCertificates)
        {
            x509.AddCertificate(extra);
        }
        keyInfo.AddClause(x509);
        signedXml.KeyInfo = keyInfo;

        var holder = doc.CreateElement("holder");
        holder.AppendChild(qp);
        signedXml.AddObject(new DataObject { Data = holder.ChildNodes });

        try
        {
            signedXml.ComputeSignature();
        }
        catch (CryptographicException ex)
        {
            throw new SigningException($"XML imzası hesaplanamadı: {ex.Message}", ex);
        }
        doc.DocumentElement.AppendChild(doc.ImportNode(signedXml.GetXml(), deep: true));

        // Bildirimdeki kodlama korunur; UTF-8 ise BOM yazılmaz. (İmza kanonik UTF-8 üzerinden
        // hesaplandığı için dosya kodlaması imzanın geçerliliğini etkilemez.)
        var declared = (doc.FirstChild as XmlDeclaration)?.Encoding;
        var encoding = string.IsNullOrEmpty(declared) || declared.Equals("utf-8", StringComparison.OrdinalIgnoreCase)
            ? new System.Text.UTF8Encoding(false)
            : System.Text.Encoding.GetEncoding(declared);
        using var ms = new MemoryStream();
        using (var writer = XmlWriter.Create(ms, new XmlWriterSettings { Encoding = encoding, Indent = false }))
        {
            doc.Save(writer);
        }
        return ms.ToArray();
    }

    private XmlElement BuildQualifyingProperties(XmlDocument doc, string sigId, string spId)
    {
        const string ds = SignedXml.XmlDsigNamespaceUrl;
        var qp = doc.CreateElement("xades", "QualifyingProperties", XadesNs);
        qp.SetAttribute("xmlns:xades", XadesNs);
        qp.SetAttribute("Target", "#" + sigId);

        var sp = doc.CreateElement("xades", "SignedProperties", XadesNs);
        sp.SetAttribute("xmlns:xades", XadesNs);
        sp.SetAttribute("xmlns:ds", ds);
        sp.SetAttribute("Id", spId);
        qp.AppendChild(sp);

        var ssp = Append(doc, sp, "SignedSignatureProperties");
        var when = (_options.SigningTime ?? DateTimeOffset.UtcNow).UtcDateTime;
        Append(doc, ssp, "SigningTime").InnerText = XmlConvert.ToString(when, XmlDateTimeSerializationMode.Utc);

        var scv2 = Append(doc, ssp, "SigningCertificateV2");
        var cert = Append(doc, scv2, "Cert");
        var digest = Append(doc, cert, "CertDigest");
        var dm = doc.CreateElement("ds", "DigestMethod", ds);
        dm.SetAttribute("Algorithm", DigestMethod(_options.HashAlgorithm));
        digest.AppendChild(dm);
        var dv = doc.CreateElement("ds", "DigestValue", ds);
        dv.InnerText = Convert.ToBase64String(HashAlgorithms.Compute(_options.HashAlgorithm, token.Certificate.RawData));
        digest.AppendChild(dv);
        Append(doc, cert, "IssuerSerialV2").InnerText = IssuerSerialV2(token.Certificate);
        return qp;
    }

    private static XmlElement Append(XmlDocument doc, XmlElement parent, string localName)
    {
        var e = doc.CreateElement("xades", localName, XadesNs);
        parent.AppendChild(e);
        return e;
    }

    /// <summary>RFC 5035 IssuerSerial'ın DER kodlaması, base64 (XAdES 1.4.1 IssuerSerialV2).</summary>
    private static string IssuerSerialV2(X509Certificate2 cert)
    {
        var bc = new Org.BouncyCastle.X509.X509Certificate(cert.RawData);
        var issuerSerial = new Org.BouncyCastle.Asn1.X509.IssuerSerial(
            new Org.BouncyCastle.Asn1.X509.GeneralNames(new Org.BouncyCastle.Asn1.X509.GeneralName(bc.IssuerDN)),
            new Org.BouncyCastle.Asn1.DerInteger(bc.SerialNumber));
        return Convert.ToBase64String(issuerSerial.GetEncoded(Org.BouncyCastle.Asn1.Asn1Encodable.Der));
    }

    internal static string DigestMethod(HashAlgorithmName h) => h.Name switch
    {
        "SHA256" => SignedXml.XmlDsigSHA256Url,
        "SHA384" => SignedXml.XmlDsigSHA384Url,
        "SHA512" => SignedXml.XmlDsigSHA512Url,
        _ => throw new NotSupportedException(h.Name),
    };

    internal static string SignatureMethod(HashAlgorithmName h) => h.Name switch
    {
        "SHA256" => SignedXml.XmlDsigRSASHA256Url,
        "SHA384" => SignedXml.XmlDsigRSASHA384Url,
        "SHA512" => SignedXml.XmlDsigRSASHA512Url,
        _ => throw new NotSupportedException(h.Name),
    };

    /// <summary>
    /// SignedProperties henüz belgede değilken "#SignedProperties-…" referansını çözebilmek için.
    /// </summary>
    private sealed class XadesSignedXml(XmlDocument doc, string spId, XmlElement signedProperties) : SignedXml(doc)
    {
        public override XmlElement? GetIdElement(XmlDocument? document, string idValue) =>
            idValue == spId ? signedProperties : base.GetIdElement(document, idValue);
    }
}
