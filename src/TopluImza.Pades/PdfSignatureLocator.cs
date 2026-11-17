using System.Text;
using System.Text.RegularExpressions;

namespace TopluImza.Pades;

/// <summary>Bir PDF imzasının /ByteRange bilgisi ve /Contents (CMS) konumu.</summary>
public sealed record PdfSignatureRange(int Offset1, int Length1, int Offset2, int Length2)
{
    /// <summary>/Contents &lt;...&gt; başlangıcı ('&lt;' dahil).</summary>
    public int ContentsStart => Offset1 + Length1;

    /// <summary>/Contents sonu ('&gt;' sonrası).</summary>
    public int ContentsEnd => Offset2;

    public byte[] SignedBytes(byte[] pdf)
    {
        var result = new byte[Length1 + Length2];
        Buffer.BlockCopy(pdf, Offset1, result, 0, Length1);
        Buffer.BlockCopy(pdf, Offset2, result, Length1, Length2);
        return result;
    }

    /// <summary>/Contents içindeki CMS (DER); sondaki sıfır dolgusu atılır.</summary>
    public byte[] ExtractCms(byte[] pdf)
    {
        var hex = Encoding.ASCII.GetString(pdf, ContentsStart + 1, ContentsEnd - ContentsStart - 2).Trim();
        var raw = Convert.FromHexString(hex.Length % 2 == 0 ? hex : hex + "0");
        // Yer tutucu sıfırlarla doldurulur; yalnız ilk ASN.1 nesnesi okunur.
        using var asn1 = new Org.BouncyCastle.Asn1.Asn1InputStream(raw);
        var obj = asn1.ReadObject() ?? throw new FormatException("/Contents boş.");
        return obj.GetEncoded(Org.BouncyCastle.Asn1.Asn1Encodable.Der);
    }

    /// <summary>İmza belgenin sonuna kadar her şeyi kapsıyor mu (sonradan ekleme yok)?</summary>
    public bool CoversWholeFile(int fileLength) => Offset2 + Length2 == fileLength;
}

/// <summary>PDF içindeki imzaları (/ByteRange) ham baytlardan bulur; PDF kütüphanesi gerektirmez.</summary>
public static partial class PdfSignatureLocator
{
    [GeneratedRegex(@"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")]
    private static partial Regex ByteRangeRegex();

    public static bool HasSignature(byte[] pdf) => FindAll(pdf).Count > 0;

    public static IReadOnlyList<PdfSignatureRange> FindAll(byte[] pdf)
    {
        // Latin1: her bayt bir karaktere eşlenir, konumlar korunur.
        var text = Encoding.Latin1.GetString(pdf);
        var list = new List<PdfSignatureRange>();
        foreach (Match m in ByteRangeRegex().Matches(text))
        {
            var r = new PdfSignatureRange(
                int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value),
                int.Parse(m.Groups[3].Value), int.Parse(m.Groups[4].Value));
            bool sane = r.Offset1 == 0 && r.ContentsEnd > r.ContentsStart + 1 && r.Offset2 + r.Length2 <= pdf.Length
                        && pdf[r.ContentsStart] == (byte)'<' && pdf[r.ContentsEnd - 1] == (byte)'>';
            if (sane)
            {
                list.Add(r);
            }
        }
        return list;
    }
}
