using System.Text;
using TopluImza.Core;
using TopluImza.Pkcs11;
using TopluImza.Validation;

namespace TopluImza.Tests;

/// <summary>
/// Gerçek PKCS#11 testi. TOPLUIMZA_TEST_PKCS11_LIB (ör. SoftHSM2 veya AKİS) ve
/// TOPLUIMZA_TEST_PKCS11_PIN verilmezse atlanır. CI'da SoftHSM2 ile çalışır.
/// </summary>
public sealed class Pkcs11FactAttribute : FactAttribute
{
    public Pkcs11FactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("TOPLUIMZA_TEST_PKCS11_LIB")) ||
            string.IsNullOrEmpty(Environment.GetEnvironmentVariable("TOPLUIMZA_TEST_PKCS11_PIN")))
        {
            Skip = "TOPLUIMZA_TEST_PKCS11_LIB / TOPLUIMZA_TEST_PKCS11_PIN tanımlı değil.";
        }
    }
}

public class Pkcs11IntegrationTests
{
    private static Pkcs11Session OpenAndLogin()
    {
        var session = Pkcs11Session.Open(Environment.GetEnvironmentVariable("TOPLUIMZA_TEST_PKCS11_LIB")!);
        using var pin = Secret.FromString(Environment.GetEnvironmentVariable("TOPLUIMZA_TEST_PKCS11_PIN")!);
        session.Login(pin);
        return session;
    }

    [Pkcs11Fact]
    public void Lists_certificates_and_signs_all_formats()
    {
        using var session = OpenAndLogin();
        Assert.NotEmpty(session.ListCertificates());
        using var token = session.CreateSigningToken();

        var content = Encoding.UTF8.GetBytes("PKCS#11 testi");
        var p7s = new Cades.CadesSigner(token).SignDetached(new MemoryStream(content));
        var noChain = new ValidationOptions { CheckChain = false };
        Assert.Equal(Verdict.Valid, Assert.Single(CmsVerifier.Verify(p7s, content, "CAdES", noChain)).Verdict);

        var pdf = new Pades.PadesSigner(token).Sign(TestPki.SamplePdf());
        Assert.Equal(Verdict.Valid, Assert.Single(PdfVerifier.Verify(pdf, noChain)).Verdict);

        if (token.KeyType == KeyType.Rsa)
        {
            var xml = new Xades.XadesSigner(token).Sign(new MemoryStream(Encoding.UTF8.GetBytes("<a>1</a>")));
            Assert.Equal(Verdict.Valid, Assert.Single(XmlVerifier.Verify(xml, noChain)).Verdict);
        }
    }

    /// <summary>Gerçek kartta deneme hakkı düşürmemek için yalnız TOPLUIMZA_TEST_ALLOW_WRONG_PIN=1 iken.</summary>
    [Pkcs11Fact]
    public void Wrong_pin_gives_clear_error()
    {
        if (Environment.GetEnvironmentVariable("TOPLUIMZA_TEST_ALLOW_WRONG_PIN") != "1")
        {
            return;
        }
        using var session = Pkcs11Session.Open(Environment.GetEnvironmentVariable("TOPLUIMZA_TEST_PKCS11_LIB")!);
        using var wrong = Secret.FromString("000000");
        var ex = Assert.Throws<SigningException>(() => session.Login(wrong));
        Assert.Contains("PIN", ex.Message);
    }
}
