using System.Text;
using TopluImza.Batch;
using TopluImza.Validation;

namespace TopluImza.Tests;

public sealed class BatchTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("topluimza-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Write(string rel, byte[] data)
    {
        var p = Path.Combine(_dir, rel);
        Directory.CreateDirectory(Path.GetDirectoryName(p)!);
        File.WriteAllBytes(p, data);
        return p;
    }

    private void Seed()
    {
        Write("rapor.pdf", TestPki.SamplePdf());
        Write("veri.xml", Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><a><b>1</b></a>"));
        Write("tablo.xlsx", [1, 2, 3, 4]);
        Write("alt/not.txt", Encoding.UTF8.GetBytes("alt klasör"));
        Write("alt/derin/yazi.docx", [9, 9, 9]);
        Write(".gizli", [0]);
    }

    [Fact]
    public void Scanner_respects_recursion_include_and_exclude()
    {
        Seed();
        var top = FileScanner.Scan(new BatchOptions { Input = _dir });
        Assert.Equal(["rapor.pdf", "tablo.xlsx", "veri.xml"], top.Select(Path.GetFileName));

        var all = FileScanner.Scan(new BatchOptions { Input = _dir, Recursive = true });
        Assert.Equal(5, all.Count);

        var pdfOnly = FileScanner.Scan(new BatchOptions { Input = _dir, Recursive = true, Include = ["*.PDF"] });
        Assert.Equal("rapor.pdf", Path.GetFileName(Assert.Single(pdfOnly)));

        var noDocx = FileScanner.Scan(new BatchOptions { Input = _dir, Recursive = true, Exclude = ["*.docx", "*.txt"] });
        Assert.Equal(3, noDocx.Count);
    }

    [Fact]
    public void Whole_folder_is_signed_and_report_lists_every_file()
    {
        Seed();
        var outDir = Path.Combine(_dir, "imzali");
        using var token = TestPki.Instance.RsaToken();
        var options = new BatchOptions { Input = _dir, OutputDirectory = outDir, Recursive = true };

        var summary = new BatchRunner(token, options).Run();

        Assert.Equal(5, summary.Signed);
        Assert.Equal(0, summary.Failed);
        Assert.True(File.Exists(Path.Combine(outDir, "rapor_imzali.pdf")));
        Assert.True(File.Exists(Path.Combine(outDir, "veri_imzali.xml")));
        Assert.True(File.Exists(Path.Combine(outDir, "tablo.xlsx.p7s")));
        Assert.True(File.Exists(Path.Combine(outDir, "alt", "derin", "yazi.docx.p7s")));
        Assert.All(summary.Items, i => Assert.True(i.Verified));
        Assert.All(summary.Items, i => Assert.Equal(64, i.Sha256!.Length));

        // Çıktı klasörü ikinci çalıştırmada taranmaz; var olanlar atlanır.
        var again = new BatchRunner(token, options).Run();
        Assert.Equal(5, again.Skipped);

        var overwrite = new BatchRunner(token, options with { Overwrite = true }).Run();
        Assert.Equal(5, overwrite.Signed);
    }

    [Fact]
    public void Signatures_next_to_files_are_not_resigned()
    {
        Seed();
        using var token = TestPki.Instance.RsaToken();
        var options = new BatchOptions { Input = _dir };
        Assert.Equal(3, new BatchRunner(token, options).Run().Signed);

        var second = FileScanner.Scan(options);
        Assert.Equal(3, second.Count);
        Assert.DoesNotContain(second, f => f.EndsWith(".p7s") || f.Contains("_imzali"));
    }

    [Fact]
    public void One_bad_file_does_not_stop_the_batch()
    {
        Write("bozuk.pdf", Encoding.ASCII.GetBytes("%PDF-1.4 bozuk"));
        Write("iyi.txt", Encoding.ASCII.GetBytes("iyi"));
        using var token = TestPki.Instance.RsaToken();

        var summary = new BatchRunner(token, new BatchOptions { Input = _dir }).Run();

        Assert.Equal(1, summary.Failed);
        Assert.Equal(1, summary.Signed);
        var failed = summary.Items.Single(i => i.Status == ItemStatus.Failed);
        Assert.Equal("bozuk.pdf", failed.File);
        Assert.False(File.Exists(Path.Combine(_dir, "bozuk_imzali.pdf")));
    }

    [Fact]
    public void Cades_mode_signs_pdf_as_detached_and_attached()
    {
        Write("a.pdf", TestPki.SamplePdf());
        using var token = TestPki.Instance.RsaToken();

        new BatchRunner(token, new BatchOptions { Input = _dir, Format = FormatMode.Cades }).Run();
        Assert.True(File.Exists(Path.Combine(_dir, "a.pdf.p7s")));

        new BatchRunner(token, new BatchOptions { Input = _dir, Format = FormatMode.Cades, Attached = true }).Run();
        Assert.True(File.Exists(Path.Combine(_dir, "a.pdf.imz")));
    }

    [Fact]
    public void Dry_run_writes_nothing()
    {
        Seed();
        var summary = new BatchRunner(null, new BatchOptions { Input = _dir, DryRun = true }).Run();
        Assert.Equal(3, summary.Planned);
        Assert.Empty(Directory.EnumerateFiles(_dir, "*.p7s", SearchOption.AllDirectories));
    }

    [Fact]
    public void Cancellation_stops_before_next_file()
    {
        Seed();
        using var token = TestPki.Instance.RsaToken();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var summary = new BatchRunner(token, new BatchOptions { Input = _dir }).Run(cancellation: cts.Token);
        Assert.True(summary.Cancelled);
        Assert.Empty(summary.Items);
    }

    [Fact]
    public void Single_file_input_is_supported()
    {
        var f = Write("tek.txt", [1]);
        using var token = TestPki.Instance.RsaToken();
        var summary = new BatchRunner(token, new BatchOptions { Input = f }).Run();
        Assert.Equal("tek.txt", Assert.Single(summary.Items).File);
        Assert.True(File.Exists(f + ".p7s"));
    }

    [Fact]
    public void Reports_are_written_as_csv_and_json()
    {
        Seed();
        using var token = TestPki.Instance.RsaToken();
        var summary = new BatchRunner(token, new BatchOptions { Input = _dir }).Run();
        var prefix = Path.Combine(_dir, "rapor-cikti", FileScanner.ReportPrefix);

        ReportWriter.WriteCsv(summary, prefix + ".csv");
        ReportWriter.WriteJson(summary, prefix + ".json");

        var csv = File.ReadAllBytes(prefix + ".csv");
        Assert.Equal([0xEF, 0xBB, 0xBF], csv[..3]);
        var lines = Encoding.UTF8.GetString(csv).Trim().Split('\n');
        Assert.Equal(4, lines.Length);
        Assert.StartsWith("\uFEFFDosya;Biçim;Durum", lines[0]);
        var json = File.ReadAllText(prefix + ".json");
        Assert.Contains("\"signed\": 3", json);
        Assert.Contains("Ayse Yilmaz", json);
    }

    [Fact]
    public void Csv_cells_are_escaped_against_formula_injection()
    {
        Assert.Equal("'=HYPERLINK(1)", ReportWriter.Csv("=HYPERLINK(1)"));
        Assert.Equal("\"a;b\"", ReportWriter.Csv("a;b"));
        Assert.Equal("\"x \"\"y\"\"\"", ReportWriter.Csv("x \"y\""));
    }

    [Fact]
    public void Folder_verification_finds_all_signatures()
    {
        Seed();
        using var token = TestPki.Instance.RsaToken();
        new BatchRunner(token, new BatchOptions { Input = _dir, Recursive = true }).Run();

        var reports = FolderVerifier.Verify(_dir, recursive: true, null, TestPki.Instance.TrustOptions());

        Assert.Equal(5, reports.Count);
        Assert.All(reports, r => Assert.Equal(Verdict.Valid, r.Verdict));
    }

    [Fact]
    public void Detached_signature_without_original_is_reported()
    {
        var f = Write("x.bin", [1, 2]);
        using var token = TestPki.Instance.RsaToken();
        new BatchRunner(token, new BatchOptions { Input = f }).Run();
        File.Delete(f);

        var report = SignatureVerifier.VerifyFile(f + ".p7s", null, TestPki.Instance.TrustOptions());

        Assert.Equal(Verdict.Invalid, report.Verdict);
        Assert.NotNull(report.Error);
    }
}

public sealed class OutputFolderVerifyTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("topluimza-ov-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void Detached_signatures_in_output_folder_verify_with_originals_dir()
    {
        var src = Path.Combine(_dir, "kaynak");
        Directory.CreateDirectory(Path.Combine(src, "alt"));
        File.WriteAllText(Path.Combine(src, "alt", "a.txt"), "a");
        var outDir = Path.Combine(_dir, "imzalar");
        using var token = TestPki.Instance.RsaToken();
        new BatchRunner(token, new BatchOptions { Input = src, OutputDirectory = outDir, Recursive = true }).Run();

        var without = FolderVerifier.Verify(outDir, true, null, TestPki.Instance.TrustOptions());
        Assert.Equal(TopluImza.Validation.Verdict.Invalid, Assert.Single(without).Verdict);

        var with = FolderVerifier.Verify(outDir, true, null, TestPki.Instance.TrustOptions(), originalsDir: src);
        Assert.Equal(TopluImza.Validation.Verdict.Valid, Assert.Single(with).Verdict);
    }
}
