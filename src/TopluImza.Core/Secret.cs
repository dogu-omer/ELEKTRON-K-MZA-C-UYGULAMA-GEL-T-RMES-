using System.Text;

namespace TopluImza.Core;

/// <summary>
/// PIN/parola gibi gizli değerleri bellekte tutar ve iş bitince sıfırlar.
/// Değer hiçbir zaman loglanmaz, ToString() maskeli döner.
/// Holds a secret (PIN) as bytes and zeroes it on dispose; never printed.
/// </summary>
public sealed class Secret : IDisposable
{
    private readonly char[] _chars;
    private bool _disposed;

    public Secret(char[] chars) => _chars = chars;

    public static Secret FromString(string value) => new(value.ToCharArray());

    public ReadOnlySpan<char> Chars => _disposed ? throw new ObjectDisposedException(nameof(Secret)) : _chars;

    public bool IsEmpty => _chars.Length == 0;

    /// <summary>UTF-8 baytları; çağıran kullanım sonrası <c>Array.Clear</c> ile silmelidir.</summary>
    public byte[] ToUtf8Bytes() => Encoding.UTF8.GetBytes(Chars.ToArray());

    public override string ToString() => "****";

    public void Dispose()
    {
        if (!_disposed)
        {
            Array.Clear(_chars);
            _disposed = true;
        }
    }
}
