using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using TopluImza.Cades;
using TopluImza.Validation;

namespace TopluImza.Tests;

public class CadesTests
{
    private static readonly byte[] Content = Encoding.UTF8.GetBytes("Tehlikeli madde taşımacılığı raporu — ADR 2025");

    [Fact]
    public void Detached_signature_is_valid_with_trusted_root()
    {
        using var token = TestPki.Instance.RsaToken();
        var p7s = new CadesSigner(token).SignDetached(new MemoryStream(Content));

        var results = CmsVerifier.Verify(p7s, Content, "CAdES", TestPki.Instance.TrustOptions());

        var r = Assert.Single(results);
        Assert.Equal(Verdict.Valid, r.Verdict);
        Assert.Equal("Ayse Yilmaz", r.SignerName);
        Assert.NotNull(r.ClaimedSigningTime);
        Assert.Empty(r.Errors);
    }

    [Fact]
    public void Detached_signature_has_cades_bes_attributes()
    {
        using var token = TestPki.Instance.RsaToken();
        var p7s = new CadesSigner(token).SignDetached(new MemoryStream(Content));
        var signer = new CmsSignedData(new CmsProcessableByteArray(Content), p7s).GetSignerInfos().GetSigners().Single();

        Assert.NotNull(signer.SignedAttributes![PkcsObjectIdentifiers.IdAASigningCertificateV2]);
        Assert.NotNull(signer.SignedAttributes[Org.BouncyCastle.Asn1.Cms.CmsAttributes.MessageDigest]);
        Assert.Null(new CmsSignedData(p7s).SignedContent);
    }

    [Fact]
    public void Tampered_content_is_invalid()
    {
        using var token = TestPki.Instance.RsaToken();
        var p7s = new CadesSigner(token).SignDetached(new MemoryStream(Content));
        var tampered = (byte[])Content.Clone();
        tampered[0] ^= 1;

        var r = Assert.Single(CmsVerifier.Verify(p7s, tampered, "CAdES", TestPki.Instance.TrustOptions()));

        Assert.Equal(Verdict.Invalid, r.Verdict);
        Assert.NotEmpty(r.Errors);
    }

    [Fact]
    public void Attached_signature_contains_content()
    {
        using var token = TestPki.Instance.RsaToken();
        var imz = new CadesSigner(token).SignAttached(new MemoryStream(Content));

        var r = Assert.Single(CmsVerifier.Verify(imz, null, "CAdES", TestPki.Instance.TrustOptions()));
        Assert.Equal(Verdict.Valid, r.Verdict);

        using var ms = new MemoryStream();
        new CmsSignedData(imz).SignedContent.Write(ms);
        Assert.Equal(Content, ms.ToArray());
    }

    [Fact]
    public void Untrusted_root_is_indeterminate_not_invalid()
    {
        using var token = TestPki.Instance.RsaToken();
        var p7s = new CadesSigner(token).SignDetached(new MemoryStream(Content));

        var r = Assert.Single(CmsVerifier.Verify(p7s, Content, "CAdES", new ValidationOptions { Offline = true }));

        Assert.Equal(Verdict.Indeterminate, r.Verdict);
    }

    [Fact]
    public void Timestamped_signature_is_cades_t()
    {
        using var token = TestPki.Instance.RsaToken();
        var options = new CadesOptions { Timestamp = TestPki.Instance.TimestampClient() };
        var p7s = new CadesSigner(token, options).SignDetached(new MemoryStream(Content));

        var r = Assert.Single(CmsVerifier.Verify(p7s, Content, "CAdES", TestPki.Instance.TrustOptions()));

        Assert.Equal(Verdict.Valid, r.Verdict);
        Assert.NotNull(r.TimestampTime);
        Assert.True(Math.Abs((r.TimestampTime!.Value - DateTimeOffset.UtcNow).TotalMinutes) < 5);
    }

    [Theory]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void Ec_key_and_hash_variants_verify(string hash)
    {
        using var token = TestPki.Instance.EcToken();
        var p7s = new CadesSigner(token, new CadesOptions { HashAlgorithm = new HashAlgorithmName(hash) }).SignDetached(new MemoryStream(Content));

        var r = Assert.Single(CmsVerifier.Verify(p7s, Content, "CAdES", TestPki.Instance.TrustOptions()));

        Assert.Equal(Verdict.Valid, r.Verdict);
        Assert.Equal("Mehmet Kaya", r.SignerName);
    }

    [Fact]
    public void Garbage_is_reported_as_invalid()
    {
        var r = Assert.Single(CmsVerifier.Verify([1, 2, 3, 4], Content, "CAdES", new ValidationOptions()));
        Assert.Equal(Verdict.Invalid, r.Verdict);
    }
}
