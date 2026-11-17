namespace TopluImza.Core;

/// <summary>İmza veya token hatası / signing or token failure.</summary>
public class SigningException : Exception
{
    public SigningException(string message) : base(message) { }

    public SigningException(string message, Exception inner) : base(message, inner) { }
}
