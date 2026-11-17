using System.Text;
using System.Xml;
using TopluImza.Core;
using TopluImza.Validation;
using TopluImza.Xades;

namespace TopluImza.Tests;

public class XadesTests
{
    private const string Xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<evrak no=\"42\">\n  <konu>UN 1203 Benzin sevkiyatı</konu>\n</evrak>\n";

    [Fact]
    public void Enveloped_xades_is_valid()
    {
        using var token = TestPki.Instance.RsaToken();
        var signed = new XadesSigner(token).Sign(new MemoryStream(Encoding.UTF8.GetBytes(Xml)));

        var r = Assert.Single(XmlVerifier.Verify(signed, TestPki.Instance.TrustOptions()));

        Assert.Equal(Verdict.Valid, r.Verdict);
        Assert.Equal("XAdES", r.Format);
        Assert.Equal("Ayse Yilmaz", r.SignerName);
        Assert.NotNull(r.ClaimedSigningTime);
    }

    [Fact]
    public void Signature_contains_signed_properties()
    {
        using var token = TestPki.Instance.RsaToken();
        var signed = new XadesSigner(token).Sign(new MemoryStream(Encoding.UTF8.GetBytes(Xml)));
        var doc = new XmlDocument();
        doc.LoadXml(Encoding.UTF8.GetString(signed));
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("xades", XadesSigner.XadesNs);

        Assert.NotNull(doc.SelectSingleNode("//xades:SigningCertificateV2", ns));
        Assert.NotNull(doc.SelectSingleNode("//xades:SigningTime", ns));
    }

    [Fact]
    public void Modified_xml_is_invalid()
    {
        using var token = TestPki.Instance.RsaToken();
        var signed = Encoding.UTF8.GetString(new XadesSigner(token).Sign(new MemoryStream(Encoding.UTF8.GetBytes(Xml))));
        var tampered = Encoding.UTF8.GetBytes(signed.Replace("UN 1203", "UN 1202"));

        var r = Assert.Single(XmlVerifier.Verify(tampered, TestPki.Instance.TrustOptions()));

        Assert.Equal(Verdict.Invalid, r.Verdict);
    }

    [Fact]
    public void Ec_key_is_rejected_with_clear_message()
    {
        using var token = TestPki.Instance.EcToken();
        var ex = Assert.Throws<SigningException>(() => new XadesSigner(token).Sign(new MemoryStream(Encoding.UTF8.GetBytes(Xml))));
        Assert.Contains("RSA", ex.Message);
    }

    [Fact]
    public void Dtd_is_refused()
    {
        using var token = TestPki.Instance.RsaToken();
        const string xxe = "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><a>&x;</a>";
        Assert.Throws<SigningException>(() => new XadesSigner(token).Sign(new MemoryStream(Encoding.UTF8.GetBytes(xxe))));
    }
}

public class XadesEncodingTests
{
    [Fact]
    public void Turkish_codepage_xml_keeps_its_encoding_and_verifies()
    {
        System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
        var enc = System.Text.Encoding.GetEncoding("ISO-8859-9");
        var bytes = enc.GetBytes("<?xml version=\"1.0\" encoding=\"ISO-8859-9\"?><evrak>Şişli Güneş Çağrı</evrak>");
        using var token = TestPki.Instance.RsaToken();

        var signed = new TopluImza.Xades.XadesSigner(token).Sign(new MemoryStream(bytes));

        Assert.Contains("Şişli Güneş Çağrı", enc.GetString(signed));
        Assert.Equal(TopluImza.Validation.Verdict.Valid,
            Assert.Single(TopluImza.Validation.XmlVerifier.Verify(signed, TestPki.Instance.TrustOptions())).Verdict);
    }
}
