using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using TopluImza.Core;
using BcX509 = Org.BouncyCastle.X509;
using CmsAttributes = Org.BouncyCastle.Asn1.Cms.CmsAttributes;
using Time = Org.BouncyCastle.Asn1.Cms.Time;

namespace TopluImza.Validation;

/// <summary>CMS (CAdES/PAdES) imza doğrulayıcı.</summary>
public static class CmsVerifier
{
    /// <summary>
    /// CMS imzasını doğrular. <paramref name="detachedContent"/> ayrık imzalar için içeriktir;
    /// bütünleşik imzalarda null verilir.
    /// </summary>
    public static IReadOnlyList<SignatureResult> Verify(byte[] cms, byte[]? detachedContent, string format, ValidationOptions options)
    {
        CmsSignedData signed;
        try
        {
            signed = detachedContent is null
                ? new CmsSignedData(cms)
                : new CmsSignedData(new CmsProcessableByteArray(detachedContent), cms);
        }
        catch (Exception ex) when (ex is CmsException or IOException or ArgumentException or InvalidCastException)
        {
            return [new SignatureResult { Format = format, Verdict = Verdict.Invalid, Errors = [$"CMS yapısı okunamadı: {ex.Message}"] }];
        }
        if (detachedContent is null && signed.SignedContent is null)
        {
            return [new SignatureResult { Format = format, Verdict = Verdict.Invalid, Errors = ["Ayrık imza: orijinal dosya verilmedi (--original)."] }];
        }

        var certStore = signed.GetCertificates();
        var allCerts = certStore.EnumerateMatches(null).Select(c => X509CertificateLoader.LoadCertificate(c.GetEncoded())).ToList();
        var results = new List<SignatureResult>();
        foreach (var signer in signed.GetSignerInfos().GetSigners())
        {
            results.Add(VerifySigner(signer, certStore, allCerts, format, options));
        }
        if (results.Count == 0)
        {
            results.Add(new SignatureResult { Format = format, Verdict = Verdict.Invalid, Errors = ["İmzalayan bilgisi yok."] });
        }
        return results;
    }

    private static SignatureResult VerifySigner(
        SignerInformation signer,
        IStore<BcX509.X509Certificate> store,
        List<X509Certificate2> allCerts,
        string format,
        ValidationOptions options)
    {
        var errors = new List<string>();
        var warnings = new List<string>();
        var bcCert = store.EnumerateMatches(signer.SignerID).FirstOrDefault();
        if (bcCert is null)
        {
            return new SignatureResult { Format = format, Verdict = Verdict.Indeterminate, Errors = ["İmzalayan sertifikası imzada yok."] };
        }
        var cert = X509CertificateLoader.LoadCertificate(bcCert.GetEncoded());

        bool cryptoOk;
        try
        {
            cryptoOk = signer.Verify(bcCert);
        }
        catch (Exception ex) when (ex is CmsException or InvalidOperationException or ArgumentException)
        {
            cryptoOk = false;
            errors.Add($"İmza doğrulanamadı: {ex.Message}");
        }
        if (!cryptoOk && errors.Count == 0)
        {
            errors.Add("İmza değeri veya belge özeti eşleşmiyor (belge değiştirilmiş olabilir).");
        }

        DateTimeOffset? claimed = null;
        var st = signer.SignedAttributes?[CmsAttributes.SigningTime];
        if (st is not null)
        {
            claimed = Time.GetInstance(st.AttrValues[0]).ToDateTime();
        }

        // signing-certificate-v2 bağlaması (sertifika değiştirme saldırılarına karşı)
        var scv2 = signer.SignedAttributes?[PkcsObjectIdentifiers.IdAASigningCertificateV2];
        if (scv2 is not null)
        {
            var ids = SigningCertificateV2.GetInstance(scv2.AttrValues[0]).GetCerts();
            var first = ids.FirstOrDefault();
            var algOid = first?.HashAlgorithm.Algorithm.Id ?? "2.16.840.1.101.3.4.2.1";
            var expected = algOid switch
            {
                "2.16.840.1.101.3.4.2.2" => SHA384.HashData(cert.RawData),
                "2.16.840.1.101.3.4.2.3" => SHA512.HashData(cert.RawData),
                _ => SHA256.HashData(cert.RawData),
            };
            if (first is null || !first.GetCertHash().AsSpan().SequenceEqual(expected))
            {
                errors.Add("signing-certificate-v2 imzalayan sertifikayla eşleşmiyor.");
            }
        }
        else if (signer.SignedAttributes?[PkcsObjectIdentifiers.IdAASigningCertificate] is null)
        {
            warnings.Add("signing-certificate özniteliği yok (CAdES-BES gereği karşılanmıyor).");
        }

        DateTimeOffset? tsTime = null;
        var tsAttr = signer.UnsignedAttributes?[PkcsObjectIdentifiers.IdAASignatureTimeStampToken];
        if (tsAttr is not null)
        {
            try
            {
                var tst = new TimeStampToken(new CmsSignedData(tsAttr.AttrValues[0].GetEncoded(Asn1Encodable.Der)));
                var imprintAlg = tst.TimeStampInfo.HashAlgorithm.Algorithm.Id;
                var name = imprintAlg switch
                {
                    "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
                    "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
                    _ => HashAlgorithmName.SHA256,
                };
                var expected = HashAlgorithms.Compute(name, signer.GetSignature());
                if (!tst.TimeStampInfo.GetMessageImprintDigest().AsSpan().SequenceEqual(expected))
                {
                    errors.Add("Zaman damgası bu imzaya ait değil (özet eşleşmiyor).");
                }
                var tsaCert = tst.GetCertificates().EnumerateMatches(tst.SignerID).FirstOrDefault();
                if (tsaCert is null)
                {
                    warnings.Add("Zaman damgası sertifikası token içinde yok; TSA imzası denetlenemedi.");
                }
                else
                {
                    tst.Validate(tsaCert);
                    var tsaNet = X509CertificateLoader.LoadCertificate(tsaCert.GetEncoded());
                    var (v, msg) = CertificateChecker.Check(tsaNet,
                        tst.GetCertificates().EnumerateMatches(null).Select(c => X509CertificateLoader.LoadCertificate(c.GetEncoded())),
                        tst.TimeStampInfo.GenTime, options);
                    if (msg is not null)
                    {
                        (v == Verdict.Invalid ? errors : warnings).Add("TSA: " + msg);
                    }
                }
                tsTime = new DateTimeOffset(tst.TimeStampInfo.GenTime, TimeSpan.Zero);
            }
            catch (Exception ex) when (ex is TspException or CmsException or IOException or ArgumentException)
            {
                errors.Add($"Zaman damgası geçersiz: {ex.Message}");
            }
        }

        var verdict = errors.Count > 0 ? Verdict.Invalid : Verdict.Valid;
        if (verdict == Verdict.Valid)
        {
            var at = tsTime ?? claimed ?? DateTimeOffset.UtcNow;
            if (tsTime is null)
            {
                warnings.Add("Zaman damgası yok: imza zamanı yalnızca imzalayanın beyanıdır.");
            }
            var (v, msg) = CertificateChecker.Check(cert, allCerts, at, options);
            if (msg is not null)
            {
                (v == Verdict.Invalid ? errors : warnings).Add(msg);
                verdict = v;
            }
        }

        return new SignatureResult
        {
            Format = format,
            SignerName = CertificateInfo.CommonName(cert),
            SignerSubject = cert.Subject,
            Issuer = cert.Issuer,
            ClaimedSigningTime = claimed,
            TimestampTime = tsTime,
            Verdict = verdict,
            Errors = errors,
            Warnings = warnings,
        };
    }
}
