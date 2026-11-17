using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using TopluImza.Core;

namespace TopluImza.Cades;

/// <summary>RFC 3161 zaman damgası istemcisi / RFC 3161 time-stamp client.</summary>
public interface ITimestampClient
{
    /// <summary>Özetin zaman damgası token'ını (DER, CMS ContentInfo) döndürür.</summary>
    byte[] GetTimestampToken(byte[] digest, HashAlgorithmName hashAlgorithm);
}

/// <summary>
/// HTTP üzerinden RFC 3161 istemcisi. İsteğe bağlı HTTP Basic kimlik doğrulaması
/// (ESIGN_TSA_USER / ESIGN_TSA_PASSWORD). Kamu SM'nin özel (ESYA) kimlik doğrulama
/// protokolü desteklenmez.
/// </summary>
public sealed class HttpTimestampClient : ITimestampClient
{
    private readonly Uri _url;
    private readonly HttpClient _http;
    private readonly string? _user;
    private readonly string? _password;

    public HttpTimestampClient(Uri url, HttpClient? http = null, string? user = null, string? password = null)
    {
        _url = url;
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        _user = user;
        _password = password;
    }

    public byte[] GetTimestampToken(byte[] digest, HashAlgorithmName hashAlgorithm)
    {
        var gen = new TimeStampRequestGenerator();
        gen.SetCertReq(true);
        var nonce = new BigInteger(1, RandomNumberGenerator.GetBytes(16));
        var request = gen.Generate(TspOid(hashAlgorithm), digest, nonce);

        using var msg = new HttpRequestMessage(HttpMethod.Post, _url)
        {
            Content = new ByteArrayContent(request.GetEncoded()),
        };
        msg.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");
        if (!string.IsNullOrEmpty(_user))
        {
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_user}:{_password}"));
            msg.Headers.Authorization = new AuthenticationHeaderValue("Basic", token);
        }

        HttpResponseMessage resp;
        try
        {
            resp = _http.Send(msg);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new SigningException($"Zaman damgası sunucusuna ulaşılamadı ({_url.Host}): {ex.Message}", ex);
        }
        using (resp)
        {
            if (!resp.IsSuccessStatusCode)
            {
                throw new SigningException($"Zaman damgası sunucusu HTTP {(int)resp.StatusCode} döndürdü.");
            }
            using var stream = resp.Content.ReadAsStream();
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            var response = new TimeStampResponse(ms.ToArray());
            try
            {
                response.Validate(request);
            }
            catch (TspException ex)
            {
                throw new SigningException($"Zaman damgası yanıtı geçersiz: {ex.Message}", ex);
            }
            return response.TimeStampToken?.GetEncoded()
                ?? throw new SigningException($"Zaman damgası reddedildi: {response.GetStatusString()}");
        }
    }

    internal static string TspOid(HashAlgorithmName h) => h.Name switch
    {
        "SHA256" => TspAlgorithms.Sha256,
        "SHA384" => TspAlgorithms.Sha384,
        "SHA512" => TspAlgorithms.Sha512,
        _ => throw new NotSupportedException(h.Name),
    };
}
