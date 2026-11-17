using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

internal static class Program
{
    private const int MinimumRsaKeySize = 2048;
    private const int MaximumSignatureSize = 16 * 1024;

    private static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "help" or "--help" or "-h")
        {
            PrintUsage();
            return args.Length == 0 ? 2 : 0;
        }

        try
        {
            return args[0] switch
            {
                "sign" when args.Length == 4 => Sign(args[1], args[2], args[3]),
                "verify" when args.Length == 4 => Verify(args[1], args[2], args[3]),
                _ => InvalidArguments()
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
                                         or CryptographicException or ArgumentException
                                         or InvalidOperationException)
        {
            Console.Error.WriteLine($"Hata: {exception.Message}");
            return 2;
        }
    }

    private static int Sign(string inputPath, string signaturePath, string certificatePath)
    {
        EnsureDifferentFiles(inputPath, signaturePath);

        using var certificate = LoadSigningCertificate(certificatePath);
        using var rsa = certificate.GetRSAPrivateKey()
            ?? throw new CryptographicException("Sertifikada RSA özel anahtarı bulunamadı.");
        EnsureKeyStrength(rsa);

        byte[] signature;
        using (var input = File.OpenRead(inputPath))
        {
            signature = rsa.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        using (var output = new FileStream(signaturePath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            output.Write(signature);
        }

        Console.WriteLine($"İmza oluşturuldu: {signaturePath}");
        Console.WriteLine($"Sertifika parmak izi: {certificate.Thumbprint}");
        return 0;
    }

    private static int Verify(string inputPath, string signaturePath, string certificatePath)
    {
        using var certificate = new X509Certificate2(certificatePath);
        using var rsa = certificate.GetRSAPublicKey()
            ?? throw new CryptographicException("Sertifikada RSA açık anahtarı bulunamadı.");
        EnsureKeyStrength(rsa);

        var signature = File.ReadAllBytes(signaturePath);
        if (signature.Length != rsa.KeySize / 8 || signature.Length > MaximumSignatureSize)
        {
            Console.WriteLine("İmza geçersiz.");
            return 1;
        }

        bool isValid;
        using (var input = File.OpenRead(inputPath))
        {
            isValid = rsa.VerifyData(input, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        Console.WriteLine(isValid ? "İmza geçerli." : "İmza geçersiz.");
        return isValid ? 0 : 1;
    }

    private static X509Certificate2 LoadSigningCertificate(string certificatePath)
    {
        try
        {
            return new X509Certificate2(certificatePath, string.Empty, X509KeyStorageFlags.EphemeralKeySet);
        }
        catch (CryptographicException) when (!Console.IsInputRedirected)
        {
            Console.Write("PFX parolası (boş parola için Enter): ");
            var password = ReadPassword();
            Console.WriteLine();
            return new X509Certificate2(certificatePath, password, X509KeyStorageFlags.EphemeralKeySet);
        }
    }

    private static string ReadPassword()
    {
        var password = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                break;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (password.Length > 0)
                {
                    password.Length--;
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                password.Append(key.KeyChar);
            }
        }

        return password.ToString();
    }

    private static void EnsureDifferentFiles(string inputPath, string signaturePath)
    {
        if (string.Equals(Path.GetFullPath(inputPath), Path.GetFullPath(signaturePath),
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
        {
            throw new ArgumentException("İmza dosyası, imzalanacak dosyanın üzerine yazamaz.");
        }
    }

    private static void EnsureKeyStrength(RSA rsa)
    {
        if (rsa.KeySize < MinimumRsaKeySize)
        {
            throw new CryptographicException($"RSA anahtarı en az {MinimumRsaKeySize} bit olmalıdır.");
        }
    }

    private static int InvalidArguments()
    {
        PrintUsage();
        return 2;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Elektronik İmza - dosya imzalama ve doğrulama");
        Console.WriteLine("  ElektronikImza sign <dosya> <imza-dosyası> <sertifika.pfx>");
        Console.WriteLine("  ElektronikImza verify <dosya> <imza-dosyası> <sertifika.cer>");
        Console.WriteLine("  ElektronikImza help");
    }
}
