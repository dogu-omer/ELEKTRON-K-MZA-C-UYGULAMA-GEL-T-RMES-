namespace TopluImza.Cli;

/// <summary>Basit, bağımlılıksız komut satırı ayrıştırıcı. PIN asla argüman olarak alınmaz.</summary>
public sealed class CliArgs
{
    private static readonly HashSet<string> Flags =
    [
        "-r", "--recursive", "--attached", "--overwrite", "--no-verify", "--dry-run", "--pin-stdin",
        "--yes", "-y", "--offline", "--no-chain", "--json", "-h", "--help",
    ];

    private static readonly HashSet<string> Valued =
    [
        "-o", "--out", "--include", "--exclude", "--format", "--tsa", "--hash", "--reason", "--location",
        "--report", "--lib", "--slot", "--cert", "--pfx", "--original", "--originals", "--trust",
    ];

    private readonly Dictionary<string, List<string>> _values = new(StringComparer.Ordinal);
    private readonly HashSet<string> _flags = new(StringComparer.Ordinal);

    public string Command { get; private set; } = "help";

    public List<string> Positional { get; } = [];

    public static CliArgs Parse(IReadOnlyList<string> argv)
    {
        var a = new CliArgs();
        if (argv.Count == 0) return a;
        a.Command = argv[0].ToLowerInvariant() switch
        {
            "-h" or "--help" or "yardim" or "yardım" => "help",
            "-v" or "--version" => "version",
            "imzala" => "sign",
            "dogrula" or "doğrula" => "verify",
            "sertifikalar" => "list-certs",
            var c => c,
        };
        for (int i = 1; i < argv.Count; i++)
        {
            var arg = argv[i];
            string? inline = null;
            if (arg.StartsWith("--", StringComparison.Ordinal) && arg.Contains('='))
            {
                inline = arg[(arg.IndexOf('=') + 1)..];
                arg = arg[..arg.IndexOf('=')];
            }
            if (arg is "--pin" or "--password")
            {
                throw new UsageException("Güvenlik nedeniyle PIN/parola argüman olarak verilemez (süreç listesinde görünür). Program soracaktır; otomasyon için --pin-stdin kullanın.");
            }
            if (Flags.Contains(arg))
            {
                a._flags.Add(Normalize(arg));
            }
            else if (Valued.Contains(arg))
            {
                var value = inline ?? (i + 1 < argv.Count ? argv[++i] : throw new UsageException($"{arg} bir değer bekliyor."));
                var key = Normalize(arg);
                if (!a._values.TryGetValue(key, out var list)) a._values[key] = list = [];
                list.Add(value);
            }
            else if (arg.StartsWith('-') && arg.Length > 1)
            {
                throw new UsageException($"Bilinmeyen seçenek: {arg}");
            }
            else
            {
                a.Positional.Add(argv[i]);
            }
        }
        return a;
    }

    public bool Has(string flag) => _flags.Contains(Normalize(flag));

    public string? Get(string name) => _values.TryGetValue(Normalize(name), out var l) ? l[^1] : null;

    /// <summary>Tekrarlanabilir veya ';'/',' ile ayrılmış değerler.</summary>
    public IReadOnlyList<string> GetList(string name) =>
        _values.TryGetValue(Normalize(name), out var l)
            ? l.SelectMany(v => v.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToList()
            : [];

    public int GetInt(string name, int fallback)
    {
        var v = Get(name);
        if (v is null) return fallback;
        return int.TryParse(v, out var n) && n >= 0 ? n : throw new UsageException($"{name} sayı olmalı: {v}");
    }

    private static string Normalize(string a) => a switch
    {
        "-r" => "--recursive",
        "-o" => "--out",
        "-y" => "--yes",
        "-h" => "--help",
        _ => a,
    };

    public const string Usage = """
        TopluImza — AKİS / PKCS#11 ile toplu elektronik imza (CAdES, PAdES, XAdES)
        Batch e-signature for folders with AKİS / PKCS#11 smart cards

        Kullanım / Usage:
          topluimza sign <klasör|dosya> [seçenekler]     Klasördeki tüm dosyaları imzala
          topluimza verify <klasör|dosya> [seçenekler]   İmzaları doğrula
          topluimza list-certs [--lib <yol>] [--slot <n>]
          topluimza version | help

        sign seçenekleri:
          -r, --recursive        Alt klasörleri de imzala
          -o, --out <dizin>      Çıktı klasörü (yapı korunur). Yoksa imzalar dosyaların yanına yazılır.
          --include <kalıp>      Yalnız eşleşenler, ör. "*.pdf;*.docx" (tekrarlanabilir)
          --exclude <kalıp>      Hariç tut, ör. "*.tmp"
          --format auto|cades    auto (varsayılan): .pdf→PAdES, .xml→XAdES, diğer→CAdES. cades: hepsi CAdES
          --attached             CAdES bütünleşik (.imz). Varsayılan ayrık (.p7s)
          --tsa <url>            RFC 3161 zaman damgası (CAdES-T / PAdES-T). Yoksa ESIGN_TSA_URL
          --hash sha256|sha384|sha512   Özet algoritması (varsayılan sha256)
          --reason <metin>       PDF imza nedeni;  --location <yer>  PDF imza yeri
          --overwrite            Var olan imza çıktılarının üzerine yaz (varsayılan: atla)
          --no-verify            İmza sonrası otomatik doğrulamayı kapat
          --dry-run              İmzalamadan neyin imzalanacağını göster
          --report <önek>        Rapor dosya öneki (varsayılan: imza-raporu-<zaman>.csv/.json)
          -y, --yes              Onay sorma (otomasyon)
          --lib <yol>            PKCS#11 kütüphanesi. Yoksa ESIGN_PKCS11_LIB veya bilinen AKİS yolları
          --slot <n>             Kartlı slot sırası (varsayılan 0)
          --cert <etiket|CN>     Birden fazla imza sertifikası varsa seçim
          --pin-stdin            PIN'i standart girdiden oku (otomasyon). Normalde gizli sorulur
          --pfx <dosya.p12>      TEST: kart yerine PKCS#12 dosyası (nitelikli imza değildir)

        verify seçenekleri:
          -r, --recursive   --original <dosya> (tek ayrık .p7s için)   --trust <dosya|dizin> (kök sertifikalar)
          --originals <dizin>  Ayrık imzaların orijinalleri başka klasördeyse (imza --out ile yazıldıysa)
          --offline (OCSP/CRL sorgusu yok)   --no-chain (yalnız bütünlük)   --report <önek>

        Çıkış kodları: 0 başarılı/geçerli, 1 hata, 2 kullanım hatası, 3 belirsiz, 4 geçersiz,
                       5 bazı dosyalar imzalanamadı.
        PIN asla argüman olarak verilmez, loglanmaz ve saklanmaz.
        """;
}

public sealed class UsageException(string message) : Exception(message);
