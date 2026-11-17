using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using PdfSharp.Drawing;
using PdfSharp.Pdf.IO;
using PdfSharp.Pdf.Signatures;
using TopluImza.Cades;
using TopluImza.Core;

namespace TopluImza.Pades;

/// <summary>PAdES seçenekleri / PAdES options.</summary>
public sealed record PadesOptions
{
    public CadesOptions Cades { get; init; } = new();

    public string? Reason { get; init; }

    public string? Location { get; init; }

    public string? ContactInfo { get; init; }
}

/// <summary>
/// PAdES-B-B / B-T imza (ETSI EN 319 142-1, ISO 32000-1 §12.8). PDF yapısı (imza alanı, bayt aralığı,
/// yer tutucu) MIT lisanslı PDFsharp 6.2 ile hazırlanır; CMS imzası CAdES modülünde üretilir ve
/// /SubFilter ETSI.CAdES.detached olarak yazılır.
/// Sınır: PDFsharp belgeyi yeniden yazar (artımlı güncelleme değil), bu yüzden zaten imzalı PDF'ler
/// bozulmasın diye reddedilir.
/// </summary>
public sealed class PadesSigner(ISigningToken token, PadesOptions? options = null)
{
    private static readonly byte[] AdbeSubFilter = Encoding.ASCII.GetBytes("/adbe.pkcs7.detached");
    private static readonly byte[] EtsiSubFilter = Encoding.ASCII.GetBytes("/ETSI.CAdES.detached");

    private readonly PadesOptions _options = options ?? new PadesOptions();

    public byte[] Sign(byte[] pdf)
    {
        if (PdfSignatureLocator.HasSignature(pdf))
        {
            throw new SigningException(
                "PDF zaten imzalı; mevcut imzayı bozmamak için PAdES ile yeniden imzalanmadı (CAdES ile ayrık imzalayabilirsiniz).");
        }

        int reserved = _options.Cades.Timestamp is null ? 24_000 : 40_000;
        byte[] prepared = Prepare(pdf, reserved);

        var range = PdfSignatureLocator.FindAll(prepared).Single();
        int subFilterAt = IndexOf(prepared, AdbeSubFilter, 0, range.ContentsStart);
        if (subFilterAt < 0)
        {
            throw new SigningException("PDF imza sözlüğü beklenen biçimde değil (SubFilter bulunamadı).");
        }
        EtsiSubFilter.CopyTo(prepared, subFilterAt);

        var cadesOptions = _options.Cades with { IncludeSigningTime = false };
        var signer = new CadesSigner(token, cadesOptions);
        byte[] cms = signer.Sign(new ByteRangeContent(prepared, range), encapsulate: false);

        var hex = Encoding.ASCII.GetBytes(Convert.ToHexString(cms));
        int capacity = range.ContentsEnd - range.ContentsStart - 2;
        if (hex.Length > capacity)
        {
            throw new SigningException($"İmza ayrılan alana sığmadı ({cms.Length} bayt).");
        }
        hex.CopyTo(prepared, range.ContentsStart + 1);
        return prepared;
    }

    private byte[] Prepare(byte[] pdf, int reserved)
    {
        try
        {
            using var input = new MemoryStream(pdf, writable: false);
            using var doc = PdfReader.Open(input, PdfDocumentOpenMode.Modify);
            var opts = new DigitalSignatureOptions
            {
                Reason = _options.Reason ?? string.Empty,
                Location = _options.Location ?? string.Empty,
                ContactInfo = _options.ContactInfo ?? string.Empty,
                AppName = "TopluImza",
                Rectangle = new XRect(0, 0, 0, 0),
                PageIndex = 0,
            };
            DigitalSignatureHandler.ForDocument(doc, new PlaceholderSigner(reserved, CertificateInfo.CommonName(token.Certificate)), opts);
            using var output = new MemoryStream();
            doc.Save(output, closeStream: false);
            return output.ToArray();
        }
        catch (SigningException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new SigningException($"PDF açılamadı veya hazırlanamadı (şifreli/bozuk olabilir): {ex.Message}", ex);
        }
    }

    internal static int IndexOf(byte[] data, byte[] pattern, int start, int end)
    {
        var span = data.AsSpan(start, Math.Max(0, end - start));
        int i = span.IndexOf(pattern);
        return i < 0 ? -1 : start + i;
    }

    /// <summary>PDFsharp'a yalnızca yer ayırtan imzalayıcı; asıl imza sonradan yazılır.</summary>
    private sealed class PlaceholderSigner(int size, string name) : IDigitalSigner
    {
        public string CertificateName => name;

        public Task<int> GetSignatureSizeAsync() => Task.FromResult(size);

        public Task<byte[]> GetSignatureAsync(Stream stream) => Task.FromResult(Array.Empty<byte>());
    }

    /// <summary>/ByteRange'in kapsadığı iki parça (imza değeri hariç tüm belge).</summary>
    private sealed class ByteRangeContent(byte[] pdf, PdfSignatureRange range) : CmsTypedData
    {
        public DerObjectIdentifier ContentType => CmsObjectIdentifiers.Data;

        public object GetContent() => range.SignedBytes(pdf);

        public void Write(Stream output)
        {
            output.Write(pdf, range.Offset1, range.Length1);
            output.Write(pdf, range.Offset2, range.Length2);
        }
    }
}
