using System.Security.Cryptography;
using TopluImza.Cades;

namespace TopluImza.Batch;

/// <summary>Biçim seçimi / format selection.</summary>
public enum FormatMode
{
    /// <summary>.pdf → PAdES, .xml → XAdES, diğerleri → CAdES.</summary>
    Auto,

    /// <summary>Tüm dosyalar CAdES (ayrık .p7s veya bütünleşik .imz).</summary>
    Cades,
}

/// <summary>Toplu imza seçenekleri / batch signing options.</summary>
public sealed record BatchOptions
{
    /// <summary>İmzalanacak klasör veya tek dosya.</summary>
    public required string Input { get; init; }

    /// <summary>Çıktı klasörü; verilmezse imzalar dosyaların yanına yazılır. Alt klasör yapısı korunur.</summary>
    public string? OutputDirectory { get; init; }

    public bool Recursive { get; init; }

    /// <summary>Dahil edilecek dosya kalıpları (ör. "*.pdf"). Boşsa tümü.</summary>
    public IReadOnlyList<string> Include { get; init; } = [];

    /// <summary>Hariç tutulacak dosya kalıpları.</summary>
    public IReadOnlyList<string> Exclude { get; init; } = [];

    public FormatMode Format { get; init; } = FormatMode.Auto;

    /// <summary>CAdES: true → bütünleşik .imz, false → ayrık .p7s (varsayılan).</summary>
    public bool Attached { get; init; }

    /// <summary>Var olan çıktıların üzerine yaz; yoksa atlanır.</summary>
    public bool Overwrite { get; init; }

    /// <summary>İmzadan hemen sonra çıktıyı kriptografik olarak doğrula (önerilir).</summary>
    public bool VerifyAfterSign { get; init; } = true;

    /// <summary>Yalnızca neyin imzalanacağını listele, imza atma.</summary>
    public bool DryRun { get; init; }

    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;

    public ITimestampClient? Timestamp { get; init; }

    /// <summary>PDF imza nedeni.</summary>
    public string? Reason { get; init; }

    public string? Location { get; init; }
}
