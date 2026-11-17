using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;
using TopluImza.Core;

namespace TopluImza.Pkcs11;

/// <summary>Karttaki bir sertifika ve (varsa) eşleşen özel anahtar.</summary>
public sealed record TokenCertificate(X509Certificate2 Certificate, string Label, byte[] Id, bool HasPrivateKey)
{
    public CertificateInfo Info => CertificateInfo.From(Certificate, Label, HasPrivateKey);
}

/// <summary>
/// PKCS#11 kart/token oturumu (AKİS ve diğer PKCS#11 uyumlu kartlar). Özel anahtar kartta kalır;
/// yalnızca DigestInfo/özet karta gönderilir. PIN bir kez girilir, oturum boyunca geçerlidir ve
/// hiçbir yerde saklanmaz.
/// PKCS#11 session; the private key never leaves the card, the PIN is used once and not stored.
/// </summary>
public sealed class Pkcs11Session : IDisposable
{
    private readonly IPkcs11Library _library;
    private readonly ISession _session;
    private readonly Pkcs11InteropFactories _factories = new();
    private readonly object _lock = new();
    private bool _loggedIn;

    static Pkcs11Session()
    {
        // glibc 2.34+ dağıtımlarında (Ubuntu 22.04+, Debian 12, Pardus 23) "libdl.so" bağlantısı yoktur;
        // Pkcs11Interop'un aradığı "libdl" adını libdl.so.2 / libc.so.6'ya yönlendir.
        try
        {
            NativeLibrary.SetDllImportResolver(typeof(Pkcs11InteropFactories).Assembly, (name, _, _) =>
            {
                if (name == "libdl" && OperatingSystem.IsLinux())
                {
                    foreach (var candidate in new[] { "libdl.so.2", "libc.so.6" })
                    {
                        if (NativeLibrary.TryLoad(candidate, out var handle)) return handle;
                    }
                }
                return IntPtr.Zero;
            });
        }
        catch (InvalidOperationException)
        {
            // çözümleyici zaten kayıtlı
        }
    }

    private Pkcs11Session(IPkcs11Library library, ISession session, string tokenLabel)
    {
        _library = library;
        _session = session;
        TokenLabel = tokenLabel;
    }

    public string TokenLabel { get; }

    /// <summary>Kütüphaneyi yükler ve <paramref name="slotIndex"/>. kart takılı slotta oturum açar.</summary>
    public static Pkcs11Session Open(string libraryPath, int slotIndex = 0)
    {
        if (!File.Exists(libraryPath))
        {
            throw new SigningException($"PKCS#11 kütüphanesi bulunamadı: {libraryPath}");
        }
        var factories = new Pkcs11InteropFactories();
        IPkcs11Library? lib = null;
        try
        {
            lib = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, libraryPath, AppType.MultiThreaded);
            var slots = lib.GetSlotList(SlotsType.WithTokenPresent);
            if (slots.Count == 0)
            {
                throw new SigningException("Takılı kart/token bulunamadı. Kart okuyucuyu ve kartı kontrol edin.");
            }
            if (slotIndex < 0 || slotIndex >= slots.Count)
            {
                throw new SigningException($"Slot {slotIndex} yok; kartlı slot sayısı: {slots.Count}.");
            }
            var slot = slots[slotIndex];
            var label = slot.GetTokenInfo().Label.Trim();
            var session = slot.OpenSession(SessionType.ReadOnly);
            return new Pkcs11Session(lib, session, label);
        }
        catch (Pkcs11Exception ex)
        {
            lib?.Dispose();
            throw new SigningException($"PKCS#11 hatası: {ex.RV}", ex);
        }
        catch (Exception ex) when (ex is DllNotFoundException or BadImageFormatException or UnmanagedException)
        {
            lib?.Dispose();
            throw new SigningException($"PKCS#11 kütüphanesi yüklenemedi ({libraryPath}): {ex.Message}", ex);
        }
        catch
        {
            lib?.Dispose();
            throw;
        }
    }

    /// <summary>Kullanıcı PIN'i ile giriş. PIN baytları kullanım sonrası sıfırlanır.</summary>
    public void Login(Secret pin)
    {
        var bytes = pin.ToUtf8Bytes();
        try
        {
            lock (_lock)
            {
                _session.Login(CKU.CKU_USER, bytes);
                _loggedIn = true;
            }
        }
        catch (Pkcs11Exception ex) when (ex.RV == CKR.CKR_USER_ALREADY_LOGGED_IN)
        {
            _loggedIn = true;
        }
        catch (Pkcs11Exception ex) when (ex.RV is CKR.CKR_PIN_INCORRECT or CKR.CKR_PIN_INVALID or CKR.CKR_PIN_LEN_RANGE)
        {
            throw new SigningException("PIN hatalı. Dikkat: art arda hatalı girişler kartı bloke eder.", ex);
        }
        catch (Pkcs11Exception ex) when (ex.RV == CKR.CKR_PIN_LOCKED)
        {
            throw new SigningException("Kart PIN'i bloke olmuş. PUK ile açmanız gerekir.", ex);
        }
        catch (Pkcs11Exception ex)
        {
            throw new SigningException($"Giriş başarısız: {ex.RV}", ex);
        }
        finally
        {
            Array.Clear(bytes);
        }
    }

    /// <summary>Karttaki X.509 sertifikalarını listeler.</summary>
    public IReadOnlyList<TokenCertificate> ListCertificates()
    {
        lock (_lock)
        {
            var search = new List<IObjectAttribute>
            {
                _factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                _factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
            };
            var result = new List<TokenCertificate>();
            foreach (var handle in _session.FindAllObjects(search))
            {
                var attrs = _session.GetAttributeValue(handle, [CKA.CKA_VALUE, CKA.CKA_ID, CKA.CKA_LABEL]);
                var der = attrs[0].GetValueAsByteArray();
                if (der is null || der.Length == 0) continue;
                var cert = X509CertificateLoader.LoadCertificate(der);
                var id = attrs[1].GetValueAsByteArray() ?? [];
                var label = attrs[2].GetValueAsString() ?? string.Empty;
                result.Add(new TokenCertificate(cert, label, id, FindPrivateKeyUnlocked(id) is not null));
            }
            return result;
        }
    }

    /// <summary>
    /// İmza için sertifika seçer. <paramref name="label"/> verilirse etiket veya CN eşleşmesi;
    /// verilmezse özel anahtarı olan ve "nonRepudiation" kullanımlı tek sertifika.
    /// </summary>
    public ISigningToken CreateSigningToken(string? label = null)
    {
        if (!_loggedIn)
        {
            throw new SigningException("İmza için önce PIN ile giriş yapılmalıdır.");
        }
        var certs = ListCertificates();
        var withKey = certs.Where(c => c.HasPrivateKey).ToList();
        List<TokenCertificate> candidates;
        if (!string.IsNullOrWhiteSpace(label))
        {
            candidates = withKey.Where(c =>
                string.Equals(c.Label, label, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(CertificateInfo.CommonName(c.Certificate), label, StringComparison.OrdinalIgnoreCase)).ToList();
        }
        else
        {
            candidates = withKey.Where(c => CertificateInfo.HasNonRepudiation(c.Certificate)).ToList();
            if (candidates.Count == 0) candidates = withKey;
        }
        if (candidates.Count == 0)
        {
            throw new SigningException("Kartta imzaya uygun (özel anahtarlı) sertifika bulunamadı.");
        }
        if (candidates.Count > 1)
        {
            var names = string.Join(", ", candidates.Select(c => $"'{c.Label}'"));
            throw new SigningException($"Birden fazla uygun sertifika var ({names}); --cert ile etiket seçin.");
        }
        var chosen = candidates[0];
        var others = certs.Where(c => c != chosen).Select(c => c.Certificate).ToList();
        return new Pkcs11SigningToken(this, chosen, others);
    }

    internal byte[] Sign(byte[] id, KeyType keyType, byte[] data)
    {
        lock (_lock)
        {
            var key = FindPrivateKeyUnlocked(id) ?? throw new SigningException("Özel anahtar kartta bulunamadı.");
            var mech = _factories.MechanismFactory.Create(keyType == KeyType.Rsa ? CKM.CKM_RSA_PKCS : CKM.CKM_ECDSA);
            try
            {
                return _session.Sign(mech, key, data);
            }
            catch (Pkcs11Exception ex)
            {
                throw new SigningException($"Kart imza işlemini reddetti: {ex.RV}", ex);
            }
        }
    }

    private IObjectHandle? FindPrivateKeyUnlocked(byte[] id)
    {
        if (id.Length == 0) return null;
        var search = new List<IObjectAttribute>
        {
            _factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            _factories.ObjectAttributeFactory.Create(CKA.CKA_ID, id),
        };
        return _session.FindAllObjects(search).FirstOrDefault();
    }

    public void Dispose()
    {
        try
        {
            if (_loggedIn) _session.Logout();
        }
        catch (Pkcs11Exception)
        {
            // oturum zaten kapanmış olabilir
        }
        _session.Dispose();
        _library.Dispose();
    }
}

/// <summary>PKCS#11 anahtarı ile <see cref="ISigningToken"/>.</summary>
internal sealed class Pkcs11SigningToken : ISigningToken
{
    private readonly Pkcs11Session _session;
    private readonly byte[] _id;

    public Pkcs11SigningToken(Pkcs11Session session, TokenCertificate cert, IReadOnlyList<X509Certificate2> extra)
    {
        _session = session;
        _id = cert.Id;
        Certificate = cert.Certificate;
        ExtraCertificates = extra;
        using var ec = cert.Certificate.GetECDsaPublicKey();
        KeyType = ec is not null ? KeyType.Ec : KeyType.Rsa;
    }

    public X509Certificate2 Certificate { get; }

    public IReadOnlyList<X509Certificate2> ExtraCertificates { get; }

    public KeyType KeyType { get; }

    public byte[] SignDigest(byte[] digest, HashAlgorithmName hashAlgorithm)
    {
        var data = KeyType == KeyType.Rsa ? HashAlgorithms.DigestInfo(hashAlgorithm, digest) : digest;
        return _session.Sign(_id, KeyType, data);
    }

    public void Dispose()
    {
        // Oturumun sahibi Pkcs11Session'dır.
    }
}
