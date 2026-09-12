using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public enum ColumnFilterKind { Values, Text, Number, Bytes, Duration, Timestamp }

public partial class ColumnFilterChoiceViewModel : ViewModelBase
{
    private readonly Action<string?, bool> _changed;
    public string? Value { get; }
    public string Label => Value == null ? "(Unavailable)" : Value.Length == 0 ? "(Blank)" : Value;
    [ObservableProperty] private bool isChecked;
    public ColumnFilterChoiceViewModel(string? value, bool selected, Action<string?, bool> changed)
    { Value = value; isChecked = selected; _changed = changed; }
    partial void OnIsCheckedChanged(bool value) => _changed(Value, value);
}

/// <summary>Shared draft/apply state. Reads are cancellable; closing or a newer search fences late replies.</summary>
public partial class ColumnFilterViewModel : ViewModelBase
{
    private readonly Func<string, CancellationToken, Task<ColumnFilterValuePage>> _load;
    private readonly Action _applied;
    private CancellationTokenSource? _loading;
    private long _version;
    private bool _allValues = true;
    private readonly HashSet<string?> _exceptions = new(StringComparer.Ordinal);
    private ColumnFilterCriteria _criteria = new();
    public ColumnFilterCriteria Criteria => _criteria;
    public bool IsActive => _criteria.IsActive;
    public string Key { get; }
    public ColumnFilterKind Kind { get; }
    public bool IsValues => Kind == ColumnFilterKind.Values;
    public bool IsText => Kind == ColumnFilterKind.Text;
    public bool IsRange => !IsValues && !IsText;
    public string InputHint => Kind switch
    {
        ColumnFilterKind.Values => "Search ignores case; checked values match exactly.",
        ColumnFilterKind.Timestamp => "Local: yyyy-MM-dd [HH:mm:ss], or ISO time with Z/offset. End date includes that day.",
        ColumnFilterKind.Bytes => "Bytes, or units: KiB, MiB, GiB (e.g. 10 MiB).",
        ColumnFilterKind.Duration => "Seconds or hh:mm:ss. Both bounds are inclusive.",
        ColumnFilterKind.Number => "Whole numbers. Both bounds are inclusive.",
        _ => "Literal text, ignoring case."
    };
    public ObservableCollection<ColumnFilterChoiceViewModel> Choices { get; } = new();
    [ObservableProperty] private bool isOpen;
    [ObservableProperty] private string valueSearch = string.Empty;
    [ObservableProperty] private string text = string.Empty;
    [ObservableProperty] private string lower = string.Empty;
    [ObservableProperty] private string upper = string.Empty;
    [ObservableProperty] private bool includeMissing;
    [ObservableProperty] private string error = string.Empty;
    [ObservableProperty] private string choiceStatus = string.Empty;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(CanApply))] private bool isLoading;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(CanApply))] private bool choicesAvailable;
    public bool CanApply => !IsLoading && (!IsValues || ChoicesAvailable);

    public ColumnFilterViewModel(string key, ColumnFilterKind kind,
        Func<string, CancellationToken, Task<ColumnFilterValuePage>> load, Action applied)
    { Key = key; Kind = kind; _load = load; _applied = applied; }

    public async Task OpenAsync()
    {
        Close();
        _allValues = _criteria.AllValues;
        _exceptions.Clear(); _exceptions.UnionWith(_criteria.Values);
        Text = _criteria.Text ?? string.Empty;
        Lower = FormatBound(_criteria.Minimum, _criteria.FromUtc);
        Upper = FormatBound(_criteria.Maximum, _criteria.ToUtc);
        IncludeMissing = _criteria.IncludeMissing;
        ValueSearch = string.Empty; Error = string.Empty;
        IsOpen = true;
        if (IsValues) await LoadChoicesAsync();
    }

    private string FormatBound(long? number, DateTime? time) => Kind switch
    {
        ColumnFilterKind.Timestamp => time?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty,
        ColumnFilterKind.Duration => number.HasValue ? ((decimal)number / TimeSpan.TicksPerSecond).ToString(CultureInfo.InvariantCulture) : string.Empty,
        _ => number?.ToString(CultureInfo.InvariantCulture) ?? string.Empty
    };

    partial void OnValueSearchChanged(string value) { if (IsOpen && IsValues) _ = LoadChoicesAsync(); }
    partial void OnIsOpenChanged(bool value) { if (!value) CancelLoading(); }
    private void CancelLoading()
    { _version++; _loading?.Cancel(); _loading?.Dispose(); _loading = null; IsLoading = false; }
    public void Close() { IsOpen = false; CancelLoading(); Choices.Clear(); }

    private async Task LoadChoicesAsync()
    {
        CancelLoading();
        var version = _version;
        _loading = new CancellationTokenSource(); var token = _loading.Token;
        IsLoading = true; ChoicesAvailable = false; Error = string.Empty; Choices.Clear();
        try
        {
            await Task.Delay(150, token);
            var result = await _load(ValueSearch, token);
            if (version != _version || !IsOpen || token.IsCancellationRequested) return;
            foreach (var value in result.Values)
                Choices.Add(new ColumnFilterChoiceViewModel(value, _exceptions.Contains(value) != _allValues, OnChoiceChanged));
            ChoiceStatus = result.HasMore ? "More values exist. Search to find them; other selections are retained."
                : $"{Choices.Count} distinct values. Other selections are retained.";
            ChoicesAvailable = true;
        }
        catch (OperationCanceledException ex)
        { if (version == _version && IsOpen && !token.IsCancellationRequested) Error = ex.Message; }
        catch (Exception ex) { if (version == _version) Error = $"Cannot load values: {ex.Message}"; }
        finally { if (version == _version) IsLoading = false; }
    }

    private void OnChoiceChanged(string? value, bool selected)
    { if (selected != _allValues) _exceptions.Add(value); else _exceptions.Remove(value); }

    [RelayCommand] private void SelectAll() => SetAll(true);
    [RelayCommand] private void SelectNone() => SetAll(false);
    private void SetAll(bool value)
    {
        _allValues = value; _exceptions.Clear();
        foreach (var choice in Choices) choice.IsChecked = value;
    }

    [RelayCommand]
    private void Apply()
    {
        if (!CanApply) return;
        try
        {
            var criteria = IsValues
                ? new ColumnFilterCriteria { AllValues = _allValues, Values = Array.AsReadOnly(_exceptions.ToArray()) }
                : IsText ? new ColumnFilterCriteria { Text = ColumnTextFilter.Normalize(Text) }
                : Kind == ColumnFilterKind.Timestamp
                    ? new ColumnFilterCriteria { FromUtc = ParseTime(Lower, false), ToUtc = ParseTime(Upper, true), IncludeMissing = IncludeMissing }
                    : new ColumnFilterCriteria { Minimum = ParseNumber(Lower), Maximum = ParseNumber(Upper), IncludeMissing = IncludeMissing };
            criteria.Validate();
            _criteria = criteria; OnPropertyChanged(nameof(IsActive));
            Close(); _applied();
        }
        catch (Exception ex) when (ex is FormatException or OverflowException or ArgumentException)
        { Error = ex.Message; }
    }

    public void Reset(bool notify = true)
    { _criteria = new(); OnPropertyChanged(nameof(IsActive)); Close(); if (notify) _applied(); }
    [RelayCommand] private void Clear() => Reset();
    [RelayCommand] private void Cancel() => Close();

    private long? ParseNumber(string input)
    {
        input = input.Trim(); if (input.Length == 0) return null;
        decimal multiplier = Kind == ColumnFilterKind.Duration ? TimeSpan.TicksPerSecond : 1;
        if (Kind == ColumnFilterKind.Duration && input.Contains(':'))
        {
            var duration = TimeSpan.Parse(input, CultureInfo.InvariantCulture);
            if (duration < TimeSpan.Zero) throw new FormatException("Use a nonnegative duration.");
            return duration.Ticks;
        }
        if (Kind == ColumnFilterKind.Bytes)
        {
            foreach (var (suffix, factor) in new[] { ("GiB", 1073741824m), ("MiB", 1048576m), ("KiB", 1024m), ("GB", 1000000000m), ("MB", 1000000m), ("KB", 1000m), ("B", 1m) })
                if (input.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                { multiplier = factor; input = input[..^suffix.Length].Trim(); break; }
        }
        var value = decimal.Parse(input, NumberStyles.AllowDecimalPoint | NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture) * multiplier;
        if (value < 0 || value != decimal.Truncate(value)) throw new FormatException("Use a nonnegative whole value in the column's base units.");
        return checked((long)value);
    }

    private static DateTime? ParseTime(string input, bool upper, TimeZoneInfo? timeZone = null)
    {
        input = input.Trim(); if (input.Length == 0) return null;
        var explicitOffset = input.EndsWith('Z') || input.LastIndexOf('+') > 9 || input.LastIndexOf('-') > 9;
        if (explicitOffset)
            return DateTimeOffset.Parse(input, CultureInfo.InvariantCulture, DateTimeStyles.None).UtcDateTime;
        var zone = timeZone ?? TimeZoneInfo.Local;
        var local = DateTime.ParseExact(input, new[] { "yyyy-MM-dd", "yyyy-MM-dd HH:mm", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm:ss.FFFFFFF" }, CultureInfo.InvariantCulture, DateTimeStyles.None);
        if (upper && input.Length == 10) local = local.AddDays(1).AddTicks(-1);
        if (zone.IsInvalidTime(local) || zone.IsAmbiguousTime(local))
            throw new FormatException("This local time is ambiguous or unavailable. Specify an ISO timestamp with Z or an offset.");
        return TimeZoneInfo.ConvertTimeToUtc(local, zone);
    }
}
