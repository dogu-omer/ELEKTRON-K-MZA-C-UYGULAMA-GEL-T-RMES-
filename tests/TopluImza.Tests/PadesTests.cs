using System.Text;
using TopluImza.Cades;
using TopluImza.Core;
using TopluImza.Pades;
using TopluImza.Validation;

namespace TopluImza.Tests;

public class PadesTests
{
    [Fact]
    public void Signed_pdf_is_valid_and_uses_etsi_subfilter()
    {
        using var token = TestPki.Instance.RsaToken();
        var signed = new PadesSigner(token, new PadesOptions { Reason = "Onaylandı" }).Sign(TestPki.SamplePdf());

        var r = Assert.Single(PdfVerifier.Verify(signed, TestPki.Instance.TrustOptions()));

        Assert.Equal(Verdict.Valid, r.Verdict);
        Assert.Contains("/ETSI.CAdES.detached", Encoding.Latin1.GetString(signed));
        Assert.NotNull(r.ClaimedSigningTime);
    }

    [Fact]
    public void Pades_cms_has_no_signing_time_attribute()
    {
        using var token = TestPki.Instance.RsaToken();
        var signed = new PadesSigner(token).Sign(TestPki.SamplePdf());
        var range = PdfSignatureLocator.FindAll(signed).Single();
        var cms = new Org.BouncyCastle.Cms.CmsSignedData(range.ExtractCms(signed));
        var signer = cms.GetSignerInfos().GetSigners().Single();

        Assert.Null(signer.SignedAttributes![Org.BouncyCastle.Asn1.Cms.CmsAttributes.SigningTime]);
    }

    [Fact]
    public void Modified_pdf_is_invalid()
    {
        using var token = TestPki.Instance.RsaToken();
        var signed = new PadesSigner(token).Sign(TestPki.SamplePdf());
        var range = PdfSignatureLocator.FindAll(signed).Single();
        signed[range.Length1 / 2] ^= 0x20;

        var r = Assert.Single(PdfVerifier.Verify(signed, TestPki.Instance.TrustOptions()));

        Assert.Equal(Verdict.Invalid, r.Verdict);
    }

    [Fact]
    public void Appended_bytes_make_it_indeterminate()
    {
        using var token = TestPki.Instance.RsaToken();
        var signed = new PadesSigner(token).Sign(TestPki.SamplePdf());
        var appended = signed.Concat(Encoding.ASCII.GetBytes("\n% ek\n")).ToArray();

        var r = Assert.Single(PdfVerifier.Verify(appended, TestPki.Instance.TrustOptions()));

        Assert.Equal(Verdict.Indeterminate, r.Verdict);
    }

    [Fact]
    public void Timestamped_pdf_is_pades_t()
    {
        using var token = TestPki.Instance.RsaToken();
        var signed = new PadesSigner(token, new PadesOptions { Cades = new CadesOptions { Timestamp = TestPki.Instance.TimestampClient() } })
            .Sign(TestPki.SamplePdf());

        var r = Assert.Single(PdfVerifier.Verify(signed, TestPki.Instance.TrustOptions()));

        Assert.Equal(Verdict.Valid, r.Verdict);
        Assert.NotNull(r.TimestampTime);
    }

    [Fact]
    public void Already_signed_pdf_is_refused()
    {
        using var token = TestPki.Instance.RsaToken();
        var signer = new PadesSigner(token);
        var once = signer.Sign(TestPki.SamplePdf());

        var ex = Assert.Throws<SigningException>(() => signer.Sign(once));
        Assert.Contains("zaten imzalı", ex.Message);
    }

    [Fact]
    public void Not_a_pdf_gives_signing_exception()
    {
        using var token = TestPki.Instance.RsaToken();
        Assert.Throws<SigningException>(() => new PadesSigner(token).Sign(Encoding.ASCII.GetBytes("bu bir pdf değil")));
    }

    [Fact]
    public void Ec_key_signs_pdf()
    {
        using var token = TestPki.Instance.EcToken();
        var signed = new PadesSigner(token).Sign(TestPki.SamplePdf());
        Assert.Equal(Verdict.Valid, Assert.Single(PdfVerifier.Verify(signed, TestPki.Instance.TrustOptions())).Verdict);
    }
}
