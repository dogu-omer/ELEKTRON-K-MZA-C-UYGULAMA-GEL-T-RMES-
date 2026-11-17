using System.Diagnostics;
using System.Security.Cryptography;
using TopluImza.Core;
using TopluImza.Validation;

namespace TopluImza.Batch;

/// <summary>
/// Klasördeki tüm dosyaları sırayla imzalar. Bir dosyadaki hata diğerlerini durdurmaz; her
/// dosyanın sonucu rapora yazılır. Kart tek oturumla kullanılır (PIN bir kez). Çıktılar önce
/// geçici dosyaya yazılıp sonra yerine taşınır; yarım kalmış imza dosyası bırakılmaz.
/// </summary>
public sealed class BatchRunner(ISigningToken? token, BatchOptions options)
{
    public BatchSummary Run(IProgress<BatchItemResult>? progress = null, CancellationToken cancellation = default)
    {
        var started = DateTimeOffset.UtcNow;
        var files = FileScanner.Scan(options);
        var signer = token is null ? null : new DocumentSigner(token, options);
        if (!options.DryRun && signer is null)
        {
            throw new InvalidOperationException("İmza için token gerekli.");
        }
        var items = new List<BatchItemResult>(files.Count);
        bool cancelled = false;
        foreach (var file in files)
        {
            if (cancellation.IsCancellationRequested)
            {
                cancelled = true;
                break;
            }
            var item = ProcessOne(file, signer);
            items.Add(item);
            progress?.Report(item);
        }
        return new BatchSummary(items, token is null ? null : CertificateInfo.CommonName(token.Certificate), started, DateTimeOffset.UtcNow, cancelled);
    }

    private BatchItemResult ProcessOne(string file, DocumentSigner? signer)
    {
        var sw = Stopwatch.StartNew();
        var kind = DocumentSigner.KindFor(file, options);
        var output = DocumentSigner.OutputPathFor(file, kind, options);
        var format = FormatName(kind);
        var rel = DisplayPath(file);
        long size = 0;
        string? sha = null;
        try
        {
            size = new FileInfo(file).Length;
            if (File.Exists(output) && !options.Overwrite)
            {
                return new BatchItemResult { File = rel, Output = output, Format = format, Status = ItemStatus.Skipped, Message = "Çıktı zaten var (--overwrite ile üzerine yazılır).", SizeBytes = size };
            }
            if (options.DryRun)
            {
                return new BatchItemResult { File = rel, Output = output, Format = format, Status = ItemStatus.Planned, SizeBytes = size };
            }

            using (var s = File.OpenRead(file))
            {
                sha = Convert.ToHexString(SHA256.HashData(s)).ToLowerInvariant();
            }
            var signature = signer!.Sign(file, kind);
            Directory.CreateDirectory(Path.GetDirectoryName(output)!);
            var tmp = output + ".tmp-" + Environment.ProcessId;
            File.WriteAllBytes(tmp, signature);
            File.Move(tmp, output, overwrite: true);

            bool? verified = null;
            string? message = null;
            if (options.VerifyAfterSign)
            {
                var report = SignatureVerifier.VerifyFile(output, kind == SignatureKind.CadesDetached ? file : null,
                    new ValidationOptions { CheckChain = false, Offline = true });
                verified = report.Verdict == Verdict.Valid;
                if (verified == false)
                {
                    File.Delete(output);
                    message = "İmza sonrası doğrulama başarısız: " + (report.Error ?? string.Join("; ", report.Signatures.SelectMany(r => r.Errors)));
                }
            }
            return new BatchItemResult
            {
                File = rel, Output = output, Format = format, Sha256 = sha, SizeBytes = size,
                Status = verified == false ? ItemStatus.Failed : ItemStatus.Signed,
                Verified = verified, Message = message, DurationMs = sw.ElapsedMilliseconds,
            };
        }
        catch (Exception ex) when (ex is SigningException or IOException or UnauthorizedAccessException or CryptographicException)
        {
            return new BatchItemResult
            {
                File = rel, Output = null, Format = format, Sha256 = sha, SizeBytes = size,
                Status = ItemStatus.Failed, Message = ex.Message, DurationMs = sw.ElapsedMilliseconds,
            };
        }
    }

    private string DisplayPath(string file)
    {
        if (File.Exists(options.Input)) return Path.GetFileName(file);
        return Path.GetRelativePath(Path.GetFullPath(options.Input), file);
    }

    public static string FormatName(SignatureKind kind) => kind switch
    {
        SignatureKind.CadesDetached => "CAdES (ayrık)",
        SignatureKind.CadesAttached => "CAdES (bütünleşik)",
        SignatureKind.Pades => "PAdES",
        SignatureKind.Xades => "XAdES",
        _ => kind.ToString(),
    };
}
