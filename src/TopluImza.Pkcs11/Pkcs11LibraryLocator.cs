using System.Runtime.InteropServices;

namespace TopluImza.Pkcs11;

/// <summary>
/// PKCS#11 kütüphanesini bulur: önce ESIGN_PKCS11_LIB ortam değişkeni, sonra işletim
/// sistemine göre bilinen AKİS kurulum yolları. Yollar sürücü sürümüne göre değişebilir.
/// Locates the PKCS#11 module: ESIGN_PKCS11_LIB first, then well-known AKİS paths.
/// </summary>
public sealed class Pkcs11LibraryLocator
{
    public const string EnvVar = "ESIGN_PKCS11_LIB";

    public static readonly IReadOnlyList<string> LinuxCandidates =
    [
        "/usr/lib/libakisp11.so",
        "/usr/local/lib/libakisp11.so",
        "/usr/lib/x86_64-linux-gnu/libakisp11.so",
        "/usr/lib64/libakisp11.so",
    ];

    public static readonly IReadOnlyList<string> MacCandidates =
    [
        "/usr/local/lib/libakisp11.dylib",
        "/Library/AKIS/libakisp11.dylib",
    ];

    public static readonly IReadOnlyList<string> WindowsCandidates =
    [
        @"C:\Windows\System32\akisp11.dll",
        @"C:\Program Files\AKIS\akisp11.dll",
        @"C:\Program Files (x86)\AKIS\akisp11.dll",
    ];

    private readonly Func<string, string?> _env;
    private readonly Func<string, bool> _exists;
    private readonly OSPlatform _os;

    public Pkcs11LibraryLocator()
        : this(Environment.GetEnvironmentVariable, File.Exists, CurrentOs())
    {
    }

    public Pkcs11LibraryLocator(Func<string, string?> env, Func<string, bool> exists, OSPlatform os)
    {
        _env = env;
        _exists = exists;
        _os = os;
    }

    public string? Locate()
    {
        var fromEnv = _env(EnvVar);
        if (!string.IsNullOrWhiteSpace(fromEnv))
        {
            var p = fromEnv.Trim();
            return _exists(p) ? p : null;
        }
        return Candidates().FirstOrDefault(_exists);
    }

    public IReadOnlyList<string> Candidates()
    {
        if (_os == OSPlatform.Windows) return WindowsCandidates;
        if (_os == OSPlatform.OSX) return MacCandidates;
        if (_os == OSPlatform.Linux) return LinuxCandidates;
        return [];
    }

    private static OSPlatform CurrentOs() =>
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? OSPlatform.Windows
        : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? OSPlatform.OSX
        : OSPlatform.Linux;
}
