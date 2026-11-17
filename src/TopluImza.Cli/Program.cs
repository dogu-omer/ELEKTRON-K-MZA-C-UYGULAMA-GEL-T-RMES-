using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using TopluImza.Batch;
using TopluImza.Cades;
using TopluImza.Core;
using TopluImza.Pkcs11;
using TopluImza.Validation;

namespace TopluImza.Cli;

public static class Program
{
    public const int Ok = 0, Error = 1, UsageError = 2, Indeterminate = 3, Invalid = 4, PartialFailure = 5;

    public static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        try
        {
            var a = CliArgs.Parse(args);
            if (a.Has("--help")) a = CliArgs.Parse(["help"]);
            return a.Command switch
            {
                "sign" => Sign(a),
                "verify" => Verify(a),
                "list-certs" => ListCerts(a),
                "version" => PrintVersion(),
                "help" => PrintHelp(),
                _ => throw new UsageException($"Bilinmeyen komut: {a.Command}"),
            };
        }
        catch (UsageException ex)
        {
            Console.Error.WriteLine("Kullanım hatası: " + ex.Message);
            Console.Error.WriteLine("Yardım için: topluimza help");
            return UsageError;
        }
        catch (Exception ex) when (ex is SigningException or IOException or UnauthorizedAccessException or CryptographicException)
        {
            Console.Error.WriteLine("HATA: " + ex.Message);
            return Error;
        }
    }

    public static string Version =>
        typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    private static int PrintVersion()
    {
        Console.WriteLine($"topluimza {Version} (.NET {Environment.Version}, {System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier})");
        return Ok;
    }

    private static int PrintHelp()
    {
        Console.WriteLine(CliArgs.Usage);
        return Ok;
    }

    private static int ListCerts(CliArgs a)
    {
        using var session = Pkcs11Session.Open(ResolveLibrary(a), a.GetInt("--slot", 0));
        Console.WriteLine($"Kart: {session.TokenLabel}");
        var certs = session.ListCertificates();
        if (certs.Count == 0)
        {
            Console.WriteLine("Kartta sertifika yok.");
            return Ok;
        }
        foreach (var c in certs)
        {
            var i = c.Info;
            Console.WriteLine();
            Console.WriteLine($"  Etiket       : {i.Label}");
            Console.WriteLine($"  Sahip        : {i.Subject}");
            Console.WriteLine($"  Yayıncı      : {i.Issuer}");
            Console.WriteLine($"  Seri no      : {i.SerialNumber}");
            Console.WriteLine($"  Geçerlilik   : {i.NotBefore:yyyy-MM-dd} → {i.NotAfter:yyyy-MM-dd}");
            Console.WriteLine($"  İmza (NR)    : {(i.NonRepudiation ? "evet" : "hayır")}   Özel anahtar: {(i.HasPrivateKey ? "var" : "yok/PIN gerekli")}");
        }
        return Ok;
    }

    private static int Sign(CliArgs a)
    {
        var input = a.Positional.Count == 1 ? a.Positional[0] : throw new UsageException("sign tek bir klasör veya dosya bekler.");
        var format = (a.Get("--format") ?? "auto").ToLowerInvariant() switch
        {
            "auto" => FormatMode.Auto,
            "cades" => FormatMode.Cades,
            var f => throw new UsageException($"--format auto veya cades olmalı: {f}"),
        };
        var tsaUrl = a.Get("--tsa") ?? Environment.GetEnvironmentVariable("ESIGN_TSA_URL");
        ITimestampClient? tsa = null;
        if (!string.IsNullOrWhiteSpace(tsaUrl))
        {
            if (!Uri.TryCreate(tsaUrl, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
            {
                throw new UsageException($"Geçersiz TSA adresi: {tsaUrl}");
            }
            tsa = new HttpTimestampClient(uri, user: Environment.GetEnvironmentVariable("ESIGN_TSA_USER"),
                password: Environment.GetEnvironmentVariable("ESIGN_TSA_PASSWORD"));
        }
        var options = new BatchOptions
        {
            Input = input,
            OutputDirectory = a.Get("--out"),
            Recursive = a.Has("--recursive"),
            Include = a.GetList("--include"),
            Exclude = a.GetList("--exclude"),
            Format = format,
            Attached = a.Has("--attached"),
            Overwrite = a.Has("--overwrite"),
            VerifyAfterSign = !a.Has("--no-verify"),
            DryRun = a.Has("--dry-run"),
            HashAlgorithm = HashAlgorithms.Parse(a.Get("--hash") ?? "sha256"),
            Timestamp = tsa,
            Reason = a.Get("--reason"),
            Location = a.Get("--location"),
        };

        var files = FileScanner.Scan(options);
        Console.WriteLine($"{files.Count} dosya bulundu ({(options.Recursive ? "alt klasörler dahil" : "yalnız bu klasör")}).");
        if (files.Count == 0) return Ok;

        if (options.DryRun)
        {
            var plan = new BatchRunner(null, options).Run(new ConsoleProgress());
            WriteReports(plan, a, options);
            return Ok;
        }

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            if (!cts.IsCancellationRequested)
            {
                e.Cancel = true;
                cts.Cancel();
                Console.Error.WriteLine("\nDurduruluyor: mevcut dosya bitince çıkılacak (zorla çıkmak için tekrar Ctrl+C).");
            }
        };

        Pkcs11Session? session = null;
        ISigningToken token;
        var pfx = a.Get("--pfx");
        try
        {
            if (pfx is not null)
            {
                Console.Error.WriteLine("UYARI: --pfx yazılım anahtarıdır; 5070 sayılı Kanun kapsamında güvenli elektronik imza değildir.");
                using var pw = SecretPrompt.Read("PKCS#12 parolası: ", a.Has("--pin-stdin"));
                token = PfxSigningToken.Load(pfx, pw.Chars);
            }
            else
            {
                session = Pkcs11Session.Open(ResolveLibrary(a), a.GetInt("--slot", 0));
                using (var pin = SecretPrompt.Read($"Kart PIN'i ({session.TokenLabel}): ", a.Has("--pin-stdin")))
                {
                    if (pin.IsEmpty) throw new SigningException("PIN girilmedi.");
                    session.Login(pin);
                }
                token = session.CreateSigningToken(a.Get("--cert"));
            }

            using (token)
            {
                var signer = CertificateInfo.CommonName(token.Certificate);
                Console.WriteLine($"İmzalayan: {signer}  (geçerlilik sonu {token.Certificate.NotAfter:yyyy-MM-dd})");
                Console.WriteLine($"Zaman damgası: {(tsa is null ? "yok (BES)" : tsaUrl + " (T)")}");
                if (!Confirm(a, $"{files.Count} dosya '{signer}' adına imzalanacak. Devam edilsin mi? (e/h): "))
                {
                    Console.WriteLine("İptal edildi.");
                    return Ok;
                }
                var summary = new BatchRunner(token, options).Run(new ConsoleProgress(), cts.Token);
                WriteReports(summary, a, options);
                Console.WriteLine();
                Console.WriteLine($"Özet: {summary.Signed} imzalandı, {summary.Skipped} atlandı, {summary.Failed} hata" +
                                  (summary.Cancelled ? " (kullanıcı durdurdu)" : string.Empty));
                return summary.Failed > 0 ? PartialFailure : Ok;
            }
        }
        finally
        {
            session?.Dispose();
        }
    }

    private static int Verify(CliArgs a)
    {
        var input = a.Positional.Count == 1 ? a.Positional[0] : throw new UsageException("verify tek bir klasör veya dosya bekler.");
        var trustPath = a.Get("--trust") ?? Environment.GetEnvironmentVariable("ESIGN_TRUST_DIR");
        var options = new ValidationOptions
        {
            Offline = a.Has("--offline"),
            CheckChain = !a.Has("--no-chain"),
            TrustAnchors = string.IsNullOrWhiteSpace(trustPath) ? [] : ValidationOptions.LoadTrust(trustPath),
        };
        var reports = FolderVerifier.Verify(input, a.Has("--recursive"), a.Get("--original"), options, new VerifyProgress(), a.Get("--originals"));
        if (reports.Count == 0)
        {
            Console.WriteLine("Doğrulanacak imzalı dosya bulunamadı.");
            return Invalid;
        }
        var prefix = a.Get("--report");
        if (prefix is not null)
        {
            ReportWriter.WriteVerificationCsv(reports, prefix + ".csv");
            ReportWriter.WriteVerificationJson(reports, prefix + ".json");
            Console.WriteLine($"Rapor: {prefix}.csv, {prefix}.json");
        }
        var worst = reports.Max(r => r.Verdict);
        Console.WriteLine();
        Console.WriteLine($"Sonuç: {reports.Count(r => r.Verdict == Verdict.Valid)} geçerli, " +
                          $"{reports.Count(r => r.Verdict == Verdict.Indeterminate)} belirsiz, " +
                          $"{reports.Count(r => r.Verdict == Verdict.Invalid)} geçersiz");
        return worst switch { Verdict.Valid => Ok, Verdict.Indeterminate => Indeterminate, _ => Invalid };
    }

    private static void WriteReports(BatchSummary summary, CliArgs a, BatchOptions options)
    {
        var prefix = a.Get("--report");
        if (prefix is null)
        {
            var baseDir = options.OutputDirectory ?? (Directory.Exists(options.Input) ? options.Input : Path.GetDirectoryName(Path.GetFullPath(options.Input))!);
            prefix = Path.Combine(baseDir, $"{FileScanner.ReportPrefix}-{DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)}");
        }
        ReportWriter.WriteCsv(summary, prefix + ".csv");
        ReportWriter.WriteJson(summary, prefix + ".json");
        Console.WriteLine($"Rapor: {prefix}.csv, {prefix}.json");
    }

    private static bool Confirm(CliArgs a, string question)
    {
        if (a.Has("--yes")) return true;
        if (Console.IsInputRedirected || a.Has("--pin-stdin"))
        {
            throw new UsageException("Etkileşimsiz çalışmada onay için --yes verilmelidir.");
        }
        Console.Write(question);
        var answer = Console.ReadLine()?.Trim().ToLowerInvariant();
        return answer is "e" or "evet" or "y" or "yes";
    }

    private static string ResolveLibrary(CliArgs a)
    {
        var lib = a.Get("--lib");
        if (lib is not null) return lib;
        var locator = new Pkcs11LibraryLocator();
        return locator.Locate() ?? throw new SigningException(
            "PKCS#11 kütüphanesi bulunamadı. AKİS sürücüsünü kurun veya --lib / ESIGN_PKCS11_LIB verin. Denenen: " +
            string.Join(", ", locator.Candidates()));
    }

    private sealed class ConsoleProgress : IProgress<BatchItemResult>
    {
        public void Report(BatchItemResult i)
        {
            var mark = i.Status switch
            {
                ItemStatus.Signed => "[ OK ]",
                ItemStatus.Skipped => "[ATLA]",
                ItemStatus.Planned => "[PLAN]",
                _ => "[HATA]",
            };
            var detail = i.Status == ItemStatus.Signed || i.Status == ItemStatus.Planned ? "→ " + i.Output : i.Message;
            Console.WriteLine($"{mark} {i.Format,-18} {i.File}  {detail}");
        }
    }

    private sealed class VerifyProgress : IProgress<VerificationReport>
    {
        public void Report(VerificationReport r)
        {
            Console.WriteLine($"[{ReportWriter.VerdictText(r.Verdict)}] {r.File}");
            if (r.Error is not null) Console.WriteLine($"     ! {r.Error}");
            foreach (var s in r.Signatures)
            {
                var when = s.TimestampTime is { } t ? $"zaman damgası {t.UtcDateTime:yyyy-MM-dd HH:mm:ss} UTC"
                    : s.ClaimedSigningTime is { } c ? $"beyan {c.UtcDateTime:yyyy-MM-dd HH:mm:ss} UTC" : "zaman yok";
                Console.WriteLine($"     {s.Format}: {s.SignerName} ({when})");
                foreach (var e in s.Errors) Console.WriteLine($"     ✗ {e}");
                foreach (var w in s.Warnings) Console.WriteLine($"     ⚠ {w}");
            }
        }
    }
}
