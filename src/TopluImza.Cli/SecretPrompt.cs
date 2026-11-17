using TopluImza.Core;

namespace TopluImza.Cli;

/// <summary>PIN/parolayı ekrana yansıtmadan okur.</summary>
internal static class SecretPrompt
{
    public static Secret Read(string prompt, bool fromStdin)
    {
        if (fromStdin || Console.IsInputRedirected)
        {
            var line = Console.In.ReadLine() ?? string.Empty;
            return Secret.FromString(line.TrimEnd('\r', '\n'));
        }
        Console.Error.Write(prompt);
        var buffer = new char[128];
        int length = 0;
        try
        {
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (length > 0) buffer[--length] = '\0';
                    continue;
                }
                if (!char.IsControl(key.KeyChar) && length < buffer.Length) buffer[length++] = key.KeyChar;
            }
            Console.Error.WriteLine();
            return new Secret(buffer[..length]);
        }
        finally
        {
            Array.Clear(buffer);
        }
    }
}
