using System;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

/// <summary>
/// View model for the process notes tab.
/// Handles loading and saving process notes in the case annotation database.
/// </summary>
public partial class ProcessNotesViewModel : ViewModelBase
{
    public event EventHandler? NoteSaved;

    private AnnotationDatabaseService? _annotationStore;
    private AnnotationTarget? _currentTarget;
    private long _selectionLoadGeneration;
    
    [ObservableProperty]
    private string notesContent = string.Empty;
    
    [ObservableProperty]
    private string currentFilePath = string.Empty;
    
    [ObservableProperty]
    private string currentProcessName = string.Empty;
    
    [ObservableProperty]
    private string statusMessage = string.Empty;
    
    [ObservableProperty]
    private bool isLoading;
    
    [ObservableProperty]
    private bool hasUnsavedChanges;
    
    [ObservableProperty]
    private bool hasProcessSelected;
    
    public ProcessNotesViewModel(AnnotationDatabaseService? annotationStore)
    {
        _annotationStore = annotationStore;
    }

    public void SetAnnotationStore(AnnotationDatabaseService? annotationStore)
    {
        _selectionLoadGeneration++;
        _annotationStore = annotationStore;
        _currentTarget = null;
        NotesContent = string.Empty;
        CurrentFilePath = string.Empty;
        CurrentProcessName = string.Empty;
        IsLoading = false;
        HasUnsavedChanges = false;
        HasProcessSelected = false;
        StatusMessage = annotationStore == null
            ? "Annotation database is unavailable"
            : "No process selected";
    }
    
    /// <summary>
    /// Loads notes for the specified annotation target.
    /// </summary>
    [RelayCommand]
    public Task LoadNotesForTargetAsync(AnnotationTarget? target) =>
        LoadNotesForSelectionAsync(target, CancellationToken.None);

    public async Task LoadNotesForSelectionAsync(
        AnnotationTarget? target,
        CancellationToken cancellationToken)
    {
        var generation = ++_selectionLoadGeneration;
        if (target == null || string.IsNullOrWhiteSpace(target.TargetId))
        {
            _currentTarget = null;
            HasProcessSelected = false;
            NotesContent = string.Empty;
            CurrentFilePath = string.Empty;
            CurrentProcessName = string.Empty;
            IsLoading = false;
            StatusMessage = "No process selected";
            return;
        }

        if (_annotationStore == null)
        {
            _currentTarget = null;
            HasProcessSelected = false;
            NotesContent = string.Empty;
            CurrentFilePath = string.Empty;
            CurrentProcessName = target.ProcessName;
            IsLoading = false;
            StatusMessage = "Annotation database is unavailable";
            return;
        }
        
        _currentTarget = target;
        HasProcessSelected = true;
        CurrentProcessName = target.ProcessName;
        IsLoading = true;
        StatusMessage = "Loading notes...";
        var annotationStore = _annotationStore;
        
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = await annotationStore.LoadNoteAsync(target);
            cancellationToken.ThrowIfCancellationRequested();
            if (generation != _selectionLoadGeneration || !ReferenceEquals(_currentTarget, target))
            {
                return;
            }
            
            if (result.Success)
            {
                NotesContent = result.Content;
                CurrentFilePath = $"{result.DatabasePath} :: {result.TargetDisplay}";
                StatusMessage = result.Exists
                    ? $"Loaded note for {target.Label}"
                    : $"New note for {target.Label}";
                HasUnsavedChanges = false;
            }
            else
            {
                NotesContent = string.Empty;
                CurrentFilePath = annotationStore.DatabasePath;
                StatusMessage = result.ErrorMessage ?? "Failed to load notes";
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            if (generation != _selectionLoadGeneration || !ReferenceEquals(_currentTarget, target))
            {
                return;
            }

            NotesContent = string.Empty;
            CurrentFilePath = annotationStore.DatabasePath;
            StatusMessage = $"Failed to load notes: {ex.Message}";
        }
        finally
        {
            if (generation == _selectionLoadGeneration && ReferenceEquals(_currentTarget, target))
            {
                IsLoading = false;
            }
        }
    }
    
    /// <summary>
    /// Saves the current notes content.
    /// </summary>
    [RelayCommand]
    public async Task SaveNotesAsync()
    {
        if (_currentTarget == null)
        {
            StatusMessage = "No process selected";
            return;
        }

        if (_annotationStore == null)
        {
            StatusMessage = "Annotation database is unavailable";
            return;
        }
        
        IsLoading = true;
        StatusMessage = "Saving notes...";
        
        try
        {
            var result = await _annotationStore.SaveNoteAsync(_currentTarget, NotesContent);
            
            if (result.Success)
            {
                CurrentFilePath = $"{result.DatabasePath} :: {result.TargetDisplay}";
                StatusMessage = $"Saved note for {_currentTarget.Label}";
                HasUnsavedChanges = false;
                NoteSaved?.Invoke(this, EventArgs.Empty);
            }
            else
            {
                StatusMessage = result.ErrorMessage ?? "Failed to save notes";
                MessageBox.Show(result.ErrorMessage ?? "Failed to save notes", "Save Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        finally
        {
            IsLoading = false;
        }
    }
    
    /// <summary>
    /// Reloads notes from the active session annotation database.
    /// </summary>
    [RelayCommand]
    public async Task ReloadNotesAsync()
    {
        if (_currentTarget != null)
        {
            await LoadNotesForTargetAsync(_currentTarget);
        }
    }
    
    /// <summary>
    /// Called when notes content changes to track unsaved changes.
    /// </summary>
    partial void OnNotesContentChanged(string? oldValue, string newValue)
    {
        HasUnsavedChanges = true;
    }
}
