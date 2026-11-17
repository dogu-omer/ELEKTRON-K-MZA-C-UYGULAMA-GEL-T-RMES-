using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using TopluImza.Batch;
using TopluImza.Cades;
using TopluImza.Core;
using TopluImza.Pkcs11;
using TopluImza.Validation;

namespace TopluImza.Gui;

/// <summary>
/// Basit masaüstü arayüz: klasör seç, PIN gir, tümünü imzala. Kod ile kurulur (XAML yok).
/// İş mantığı CLI ile aynı TopluImza.Batch modülündedir.
/// </summary>
public sealed class MainWindow : Window
{
    private readonly TextBox _folder = new() { PlaceholderText = "İmzalanacak klasör" };
    private readonly TextBox _output = new() { PlaceholderText = "(boş: imzalar dosyaların yanına yazılır)" };
    private readonly CheckBox _recursive = new() { Content = "Alt klasörler dahil" };
    private readonly CheckBox _cadesOnly = new() { Content = "Tüm dosyaları CAdES (.p7s) ile imzala" };
    private readonly CheckBox _overwrite = new() { Content = "Var olan imzaların üzerine yaz" };
    private readonly TextBox _include = new() { PlaceholderText = "ör. *.pdf;*.docx (boş: tümü)" };
    private readonly TextBox _tsa = new() { PlaceholderText = "https://... (boş: zaman damgasız BES)" };
    private readonly TextBox _reason = new() { PlaceholderText = "PDF imza nedeni (isteğe bağlı)" };
    private readonly TextBox _lib = new();
    private readonly NumericUpDown _slot = new() { Minimum = 0, Maximum = 16, Value = 0, Increment = 1, FormatString = "0" };
    private readonly TextBox _pin = new() { PasswordChar = '•', PlaceholderText = "Kart PIN'i" };
    private readonly Button _signButton = new() { Content = "Tümünü imzala" };
    private readonly Button _verifyButton = new() { Content = "Klasörü doğrula" };
    private readonly ProgressBar _progress = new() { Minimum = 0, Maximum = 1, Height = 8 };
    private readonly TextBlock _status = new() { TextWrapping = TextWrapping.Wrap };
    private readonly ObservableCollection<string> _log = [];
    private CancellationTokenSource? _cts;

    public MainWindow()
    {
        Title = "TopluImza — Toplu Elektronik İmza";
        Width = 860;
        Height = 720;
        MinWidth = 640;
        _lib.Text = Environment.GetEnvironmentVariable(Pkcs11LibraryLocator.EnvVar) ?? new Pkcs11LibraryLocator().Locate() ?? string.Empty;
        _lib.PlaceholderText = "PKCS#11 kütüphanesi (ör. libakisp11.so / akisp11.dll)";
        _tsa.Text = Environment.GetEnvironmentVariable("ESIGN_TSA_URL") ?? string.Empty;

        _signButton.Click += async (_, _) => await SignAsync();
        _verifyButton.Click += async (_, _) => await VerifyAsync();

        var form = new Grid
        {
            ColumnDefinitions = new ColumnDefinitions("170,*,Auto"),
            RowDefinitions = new RowDefinitions("Auto,Auto,Auto,Auto,Auto,Auto,Auto,Auto,Auto"),
            RowSpacing = 8,
            ColumnSpacing = 8,
        };
        int row = 0;
        AddRow(form, row++, "Klasör", _folder, PickButton(_folder));
        AddRow(form, row++, "Çıktı klasörü", _output, PickButton(_output));
        AddRow(form, row++, "Dosya kalıbı", _include, null);
        AddRow(form, row++, "Seçenekler", new StackPanel { Spacing = 4, Children = { _recursive, _cadesOnly, _overwrite } }, null);
        AddRow(form, row++, "Zaman damgası (TSA)", _tsa, null);
        AddRow(form, row++, "İmza nedeni", _reason, null);
        AddRow(form, row++, "PKCS#11 kütüphanesi", _lib, null);
        AddRow(form, row++, "Slot", _slot, null);
        AddRow(form, row++, "PIN", _pin, null);

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { _signButton, _verifyButton } };
        var cancel = new Button { Content = "Durdur" };
        cancel.Click += (_, _) => _cts?.Cancel();
        buttons.Children.Add(cancel);

        var list = new ListBox { ItemsSource = _log, FontFamily = new FontFamily("monospace"), FontSize = 12 };
        var note = new TextBlock
        {
            Text = "PIN yalnızca bu oturumda kullanılır; saklanmaz ve kaydedilmez. Her dosyanın sonucu klasöre CSV/JSON rapor olarak yazılır.",
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.7,
            FontSize = 12,
        };

        var root = new DockPanel { Margin = new Thickness(16) };
        var top = new StackPanel { Spacing = 10, Children = { form, buttons, _progress, _status, note } };
        DockPanel.SetDock(top, Dock.Top);
        root.Children.Add(top);
        root.Children.Add(new Border { Margin = new Thickness(0, 10, 0, 0), Child = list });
        Content = root;
    }

    private static void AddRow(Grid grid, int row, string label, Control editor, Control? extra)
    {
        var l = new TextBlock { Text = label, VerticalAlignment = VerticalAlignment.Center };
        Grid.SetRow(l, row);
        Grid.SetRow(editor, row);
        Grid.SetColumn(editor, 1);
        grid.Children.Add(l);
        grid.Children.Add(editor);
        if (extra is not null)
        {
            Grid.SetRow(extra, row);
            Grid.SetColumn(extra, 2);
            grid.Children.Add(extra);
        }
    }

    private Button PickButton(TextBox target)
    {
        var b = new Button { Content = "Seç…" };
        b.Click += async (_, _) =>
        {
            var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { AllowMultiple = false, Title = "Klasör seçin" });
            if (folders.Count > 0 && folders[0].TryGetLocalPath() is { } path)
            {
                target.Text = path;
            }
        };
        return b;
    }

    private void SetBusy(bool busy)
    {
        _signButton.IsEnabled = !busy;
        _verifyButton.IsEnabled = !busy;
    }

    private void Log(string line) => Dispatcher.UIThread.Post(() =>
    {
        _log.Add(line);
    });

    private async Task SignAsync()
    {
        var folder = _folder.Text?.Trim();
        if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder))
        {
            _status.Text = "Geçerli bir klasör seçin.";
            return;
        }
        ITimestampClient? tsa = null;
        if (!string.IsNullOrWhiteSpace(_tsa.Text))
        {
            if (!Uri.TryCreate(_tsa.Text.Trim(), UriKind.Absolute, out var uri))
            {
                _status.Text = "Zaman damgası adresi geçersiz.";
                return;
            }
            tsa = new HttpTimestampClient(uri, user: Environment.GetEnvironmentVariable("ESIGN_TSA_USER"),
                password: Environment.GetEnvironmentVariable("ESIGN_TSA_PASSWORD"));
        }
        var options = new BatchOptions
        {
            Input = folder,
            OutputDirectory = string.IsNullOrWhiteSpace(_output.Text) ? null : _output.Text.Trim(),
            Recursive = _recursive.IsChecked == true,
            Format = _cadesOnly.IsChecked == true ? FormatMode.Cades : FormatMode.Auto,
            Overwrite = _overwrite.IsChecked == true,
            Include = (_include.Text ?? string.Empty).Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            Timestamp = tsa,
            Reason = string.IsNullOrWhiteSpace(_reason.Text) ? null : _reason.Text,
        };
        var lib = _lib.Text?.Trim() ?? string.Empty;
        int slot = (int)(_slot.Value ?? 0);
        var pin = new Secret((_pin.Text ?? string.Empty).ToCharArray());
        _pin.Text = string.Empty;

        _log.Clear();
        SetBusy(true);
        _cts = new CancellationTokenSource();
        try
        {
            var files = FileScanner.Scan(options);
            _progress.Maximum = Math.Max(1, files.Count);
            _progress.Value = 0;
            _status.Text = $"{files.Count} dosya bulundu, kart açılıyor…";
            var token = _cts.Token;
            var summary = await Task.Run(() =>
            {
                using var session = Pkcs11Session.Open(lib, slot);
                using (pin)
                {
                    if (pin.IsEmpty) throw new SigningException("PIN girilmedi.");
                    session.Login(pin);
                }
                using var signingToken = session.CreateSigningToken();
                Log($"İmzalayan: {CertificateInfo.CommonName(signingToken.Certificate)}");
                var progress = new Progress<BatchItemResult>(i =>
                {
                    _progress.Value += 1;
                    _log.Add($"[{ReportWriter.StatusText(i.Status)}] {i.Format}  {i.File}  {(i.Status == ItemStatus.Signed ? string.Empty : i.Message)}");
                });
                var result = new BatchRunner(signingToken, options).Run(progress, token);
                var prefix = Path.Combine(options.OutputDirectory ?? folder,
                    $"{FileScanner.ReportPrefix}-{DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)}");
                ReportWriter.WriteCsv(result, prefix + ".csv");
                ReportWriter.WriteJson(result, prefix + ".json");
                Log($"Rapor: {prefix}.csv");
                return result;
            });
            _status.Text = $"Bitti: {summary.Signed} imzalandı, {summary.Skipped} atlandı, {summary.Failed} hata" +
                           (summary.Cancelled ? " (durduruldu)." : ".");
        }
        catch (Exception ex) when (ex is SigningException or IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
        {
            _status.Text = "HATA: " + ex.Message;
        }
        finally
        {
            pin.Dispose();
            SetBusy(false);
        }
    }

    private async Task VerifyAsync()
    {
        var folder = _folder.Text?.Trim();
        if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder))
        {
            _status.Text = "Geçerli bir klasör seçin.";
            return;
        }
        var target = string.IsNullOrWhiteSpace(_output.Text) ? folder : _output.Text.Trim();
        var originals = string.IsNullOrWhiteSpace(_output.Text) ? null : folder;
        _log.Clear();
        SetBusy(true);
        try
        {
            var trustDir = Environment.GetEnvironmentVariable("ESIGN_TRUST_DIR");
            var options = new ValidationOptions
            {
                TrustAnchors = string.IsNullOrWhiteSpace(trustDir) ? [] : ValidationOptions.LoadTrust(trustDir),
            };
            var recursive = _recursive.IsChecked == true;
            var reports = await Task.Run(() => FolderVerifier.Verify(target, recursive, null, options,
                new Progress<VerificationReport>(r =>
                {
                    _log.Add($"[{ReportWriter.VerdictText(r.Verdict)}] {r.File}  {r.Error}");
                    foreach (var s in r.Signatures)
                    {
                        _log.Add($"      {s.Format}: {s.SignerName}  {string.Join(" | ", s.Errors.Concat(s.Warnings))}");
                    }
                }), originals));
            _status.Text = $"{reports.Count(r => r.Verdict == Verdict.Valid)} geçerli, " +
                           $"{reports.Count(r => r.Verdict == Verdict.Indeterminate)} belirsiz, " +
                           $"{reports.Count(r => r.Verdict == Verdict.Invalid)} geçersiz.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
        {
            _status.Text = "HATA: " + ex.Message;
        }
        finally
        {
            SetBusy(false);
        }
    }
}
