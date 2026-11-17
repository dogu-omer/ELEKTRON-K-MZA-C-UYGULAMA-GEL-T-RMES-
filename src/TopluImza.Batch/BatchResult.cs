namespace TopluImza.Batch;

/// <summary>Dosya sonucu durumu.</summary>
public enum ItemStatus
{
    Signed,
    Skipped,
    Failed,
    Planned,
}

/// <summary>Toplu işlemde bir dosyanın sonucu (raporun bir satırı).</summary>
public sealed record BatchItemResult
{
    public required string File { get; init; }

    public string? Output { get; init; }

    public required string Format { get; init; }

    public required ItemStatus Status { get; init; }

    public string? Message { get; init; }

    /// <summary>İmzalanan dosyanın SHA-256 özeti (hex). Denetim izi içindir.</summary>
    public string? Sha256 { get; init; }

    public long SizeBytes { get; init; }

    /// <summary>Çıktı imzadan hemen sonra doğrulandı mı (null: denetlenmedi)?</summary>
    public bool? Verified { get; init; }

    public long DurationMs { get; init; }

    public DateTimeOffset TimeUtc { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>Toplu işlem özeti.</summary>
public sealed record BatchSummary(
    IReadOnlyList<BatchItemResult> Items,
    string? Signer,
    DateTimeOffset StartedUtc,
    DateTimeOffset FinishedUtc,
    bool Cancelled)
{
    public int Signed => Items.Count(i => i.Status == ItemStatus.Signed);

    public int Skipped => Items.Count(i => i.Status == ItemStatus.Skipped);

    public int Failed => Items.Count(i => i.Status == ItemStatus.Failed);

    public int Planned => Items.Count(i => i.Status == ItemStatus.Planned);
}
