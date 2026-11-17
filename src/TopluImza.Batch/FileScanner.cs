using System.IO.Enumeration;

namespace TopluImza.Batch;

/// <summary>
/// İmzalanacak dosyaları bulur. Gizli dosyalar, imza çıktıları (.p7s, .imz, *_imzali.*),
/// rapor dosyaları ve çıktı klasörünün içi atlanır; böylece aynı klasör tekrar
/// çalıştırıldığında imzalar yeniden imzalanmaz.
/// </summary>
public static class FileScanner
{
    public const string SignedSuffix = "_imzali";
    public const string ReportPrefix = "imza-raporu";

    public static IReadOnlyList<string> Scan(BatchOptions options)
    {
        if (File.Exists(options.Input))
        {
            return [Path.GetFullPath(options.Input)];
        }
        if (!Directory.Exists(options.Input))
        {
            throw new DirectoryNotFoundException($"Klasör veya dosya bulunamadı: {options.Input}");
        }
        var root = Path.GetFullPath(options.Input);
        var outDir = options.OutputDirectory is null ? null : Path.GetFullPath(options.OutputDirectory);
        var enumOptions = new EnumerationOptions
        {
            RecurseSubdirectories = options.Recursive,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.Hidden | FileAttributes.System,
            ReturnSpecialDirectories = false,
        };
        var files = Directory.EnumerateFiles(root, "*", enumOptions)
            .Where(f => outDir is null || !IsUnder(f, outDir))
            .Where(f => !Path.GetFileName(f).StartsWith('.'))
            .Where(f => !IsSignatureArtifact(f))
            .Where(f => options.Include.Count == 0 || options.Include.Any(p => Matches(p, f)))
            .Where(f => !options.Exclude.Any(p => Matches(p, f)))
            .Order(StringComparer.Ordinal)
            .ToList();
        return files;
    }

    /// <summary>Bu aracın ürettiği imza veya rapor dosyası mı?</summary>
    public static bool IsSignatureArtifact(string path)
    {
        var name = Path.GetFileName(path);
        var ext = Path.GetExtension(name).ToLowerInvariant();
        if (ext is ".p7s" or ".imz") return true;
        if (Path.GetFileNameWithoutExtension(name).EndsWith(SignedSuffix, StringComparison.OrdinalIgnoreCase)) return true;
        return name.StartsWith(ReportPrefix, StringComparison.OrdinalIgnoreCase) && ext is ".csv" or ".json";
    }

    private static bool Matches(string pattern, string path)
    {
        var name = Path.GetFileName(path);
        return FileSystemName.MatchesSimpleExpression(pattern.Trim(), name, ignoreCase: true);
    }

    private static bool IsUnder(string file, string dir)
    {
        var rel = Path.GetRelativePath(dir, file);
        return !rel.StartsWith("..", StringComparison.Ordinal) && !Path.IsPathRooted(rel);
    }
}
