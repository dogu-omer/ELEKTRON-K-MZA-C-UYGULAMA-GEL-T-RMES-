using System.Runtime.InteropServices;
using TopluImza.Cli;
using TopluImza.Core;
using TopluImza.Pkcs11;

namespace TopluImza.Tests;

public class CliAndLocatorTests
{
    [Fact]
    public void Pin_argument_is_rejected()
    {
        var ex = Assert.Throws<UsageException>(() => CliArgs.Parse(["sign", "dir", "--pin", "1234"]));
        Assert.Contains("PIN", ex.Message);
    }

    [Fact]
    public void Options_and_aliases_are_parsed()
    {
        var a = CliArgs.Parse(["imzala", "klasor", "-r", "--include", "*.pdf;*.docx", "--include=*.xml", "-o", "cikti", "--slot", "1"]);
        Assert.Equal("sign", a.Command);
        Assert.Equal(["klasor"], a.Positional);
        Assert.True(a.Has("--recursive"));
        Assert.Equal(["*.pdf", "*.docx", "*.xml"], a.GetList("--include"));
        Assert.Equal("cikti", a.Get("--out"));
        Assert.Equal(1, a.GetInt("--slot", 0));
    }

    [Fact]
    public void Unknown_option_is_usage_error()
    {
        Assert.Throws<UsageException>(() => CliArgs.Parse(["sign", "--bilinmeyen"]));
        Assert.Equal(Program.UsageError, Program.Main(["sign"]));
    }

    [Fact]
    public void Version_and_help_succeed()
    {
        Assert.Equal(Program.Ok, Program.Main(["version"]));
        Assert.Equal(Program.Ok, Program.Main(["help"]));
    }

    [Fact]
    public void Cli_signs_and_verifies_a_folder_with_pfx()
    {
        var dir = Directory.CreateTempSubdirectory("topluimza-cli-").FullName;
        try
        {
            File.WriteAllText(Path.Combine(dir, "a.txt"), "a");
            var pfx = Path.Combine(dir, "..", Path.GetFileName(dir) + ".p12");
            File.WriteAllBytes(pfx, TestPki.Instance.RsaSigner.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pkcs12, "parola"));
            var root = Path.Combine(dir, "..", Path.GetFileName(dir) + "-kok.pem");
            File.WriteAllText(root, TestPki.Instance.Root.ExportCertificatePem());

            var oldIn = Console.In;
            Console.SetIn(new StringReader("parola\n"));
            try
            {
                Assert.Equal(Program.Ok, Program.Main(["sign", dir, "--pfx", pfx, "--pin-stdin", "--yes", "--report", Path.Combine(dir, "imza-raporu-test")]));
            }
            finally
            {
                Console.SetIn(oldIn);
            }
            Assert.True(File.Exists(Path.Combine(dir, "a.txt.p7s")));
            Assert.True(File.Exists(Path.Combine(dir, "imza-raporu-test.csv")));
            Assert.Equal(Program.Ok, Program.Main(["verify", dir, "--trust", root, "--offline"]));
            File.WriteAllText(Path.Combine(dir, "a.txt"), "değişti");
            Assert.Equal(Program.Invalid, Program.Main(["verify", dir, "--trust", root, "--offline"]));
            File.Delete(pfx);
            File.Delete(root);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void Locator_prefers_environment_variable()
    {
        var loc = new Pkcs11LibraryLocator(_ => "/ozel/libakisp11.so", p => p == "/ozel/libakisp11.so", OSPlatform.Linux);
        Assert.Equal("/ozel/libakisp11.so", loc.Locate());
    }

    [Fact]
    public void Locator_uses_os_specific_candidates()
    {
        var win = new Pkcs11LibraryLocator(_ => null, p => p == @"C:\Windows\System32\akisp11.dll", OSPlatform.Windows);
        Assert.Equal(@"C:\Windows\System32\akisp11.dll", win.Locate());
        var mac = new Pkcs11LibraryLocator(_ => null, _ => false, OSPlatform.OSX);
        Assert.Null(mac.Locate());
        Assert.Contains("/usr/local/lib/libakisp11.dylib", mac.Candidates());
    }

    [Fact]
    public void Digest_info_has_correct_prefix_and_length()
    {
        var di = HashAlgorithms.DigestInfo(System.Security.Cryptography.HashAlgorithmName.SHA256, new byte[32]);
        Assert.Equal(51, di.Length);
        Assert.Equal(0x30, di[0]);
        Assert.Equal(64 + 19, HashAlgorithms.DigestInfo(System.Security.Cryptography.HashAlgorithmName.SHA512, new byte[64]).Length);
    }

    [Fact]
    public void Secret_is_cleared_and_masked()
    {
        var chars = "123456".ToCharArray();
        var s = new Secret(chars);
        Assert.Equal("****", s.ToString());
        s.Dispose();
        Assert.All(chars, c => Assert.Equal('\0', c));
    }
}
