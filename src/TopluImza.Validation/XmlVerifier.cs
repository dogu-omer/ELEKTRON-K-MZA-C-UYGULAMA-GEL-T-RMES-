using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using TopluImza.Core;
using TopluImza.Xades;

namespace TopluImza.Validation;

/// <summary>XML (XAdES / XMLDSig) imza doğrulayıcı.</summary>
public static class XmlVerifier
{
    public static IReadOnlyList<SignatureResult> Verify(byte[] xml, ValidationOptions options)
    {
        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        try
        {
            using var reader = XmlReader.Create(new MemoryStream(xml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            doc.Load(reader);
        }
        catch (XmlException ex)
        {
            return [new SignatureResult { Format = "XAdES", Verdict = Verdict.Invalid, Errors = [$"XML okunamadı: {ex.Message}"] }];
        }
        var sigs = doc.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl).Cast<XmlElement>().ToList();
        var results = new List<SignatureResult>();
        foreach (var sig in sigs)
        {
            results.Add(VerifyOne(doc, sig, options));
        }
        return results;
    }

    private static SignatureResult VerifyOne(XmlDocument doc, XmlElement sigElement, ValidationOptions options)
    {
        var errors = new List<string>();
        var warnings = new List<string>();
        var signedXml = new SignedXml(doc);
        try
        {
            signedXml.LoadXml(sigElement);
        }
        catch (CryptographicException ex)
        {
            return new SignatureResult { Format = "XAdES", Verdict = Verdict.Invalid, Errors = [$"İmza öğesi okunamadı: {ex.Message}"] };
        }

        var certs = signedXml.KeyInfo?.OfType<KeyInfoX509Data>().SelectMany(d => d.Certificates?.Cast<X509Certificate>() ?? [])
            .Select(c => X509CertificateLoader.LoadCertificate(c.GetRawCertData())).ToList() ?? [];
        if (certs.Count == 0)
        {
            return new SignatureResult { Format = "XAdES", Verdict = Verdict.Indeterminate, Errors = ["İmzada X.509 sertifikası yok."] };
        }
        var cert = certs[0];
        bool ok;
        try
        {
            ok = signedXml.CheckSignature(cert, verifySignatureOnly: true);
        }
        catch (CryptographicException ex)
        {
            ok = false;
            errors.Add($"İmza doğrulanamadı: {ex.Message}");
        }
        if (!ok && errors.Count == 0)
        {
            errors.Add("İmza değeri veya referans özetleri eşleşmiyor (belge değiştirilmiş olabilir).");
        }

        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("xades", XadesSigner.XadesNs);
        bool isXades = sigElement.SelectSingleNode(".//xades:SignedProperties", ns) is not null;
        DateTimeOffset? claimed = null;
        if (sigElement.SelectSingleNode(".//xades:SigningTime", ns) is { } stNode &&
            DateTimeOffset.TryParse(stNode.InnerText, out var st))
        {
            claimed = st;
        }
        if (!isXades)
        {
            warnings.Add("XAdES nitelikli özellikleri yok (düz XMLDSig).");
        }
        else if (!signedXml.SignedInfo!.References.Cast<Reference>().Any(r => r.Type == XadesSigner.SignedPropertiesType))
        {
            errors.Add("SignedProperties imza kapsamında değil.");
        }

        var verdict = errors.Count > 0 ? Verdict.Invalid : Verdict.Valid;
        if (verdict == Verdict.Valid)
        {
            warnings.Add("Zaman damgası yok: imza zamanı yalnızca imzalayanın beyanıdır.");
            var (v, msg) = CertificateChecker.Check(cert, certs.Skip(1), claimed ?? DateTimeOffset.UtcNow, options);
            if (msg is not null)
            {
                (v == Verdict.Invalid ? errors : warnings).Add(msg);
                verdict = v;
            }
        }
        return new SignatureResult
        {
            Format = isXades ? "XAdES" : "XMLDSig",
            SignerName = CertificateInfo.CommonName(cert),
            SignerSubject = cert.Subject,
            Issuer = cert.Issuer,
            ClaimedSigningTime = claimed,
            Verdict = verdict,
            Errors = errors,
            Warnings = warnings,
        };
    }
}
