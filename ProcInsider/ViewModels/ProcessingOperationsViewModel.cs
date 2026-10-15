using System.Collections.ObjectModel;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.Input;

namespace ProcInsider.ViewModels;

/// <summary>Shell presentation for independent, caller-owned processing lifetimes.</summary>
public sealed class ProcessingOperationsViewModel
{
    private readonly Dispatcher _dispatcher = Dispatcher.CurrentDispatcher;
    public ObservableCollection<ProcessingOperation> Operations {get;}=[];
    public ProcessingOperation Begin(string title,CancellationToken token)
    {
        var operation=new ProcessingOperation(this,title,token);
        OnDispatcher(()=>Operations.Add(operation));
        return operation;
    }
    internal void End(ProcessingOperation operation)=>OnDispatcher(()=>Operations.Remove(operation));
    public void CancelAll()=>OnDispatcher(()=>{foreach(var operation in Operations.ToArray())operation.Cancel();});
    private void OnDispatcher(Action action){if(_dispatcher.CheckAccess())action();else _dispatcher.Invoke(action);}
}

public sealed class ProcessingOperation : IDisposable
{
    private readonly ProcessingOperationsViewModel _owner;
    private readonly CancellationTokenSource _cancellation;
    private readonly object _lifetime=new();
    private int _ended;
    public string Title {get;}
    public CancellationToken Token=>_cancellation.Token;
    public IRelayCommand CancelCommand {get;}
    internal ProcessingOperation(ProcessingOperationsViewModel owner,string title,CancellationToken token)
    {
        _owner=owner;Title=title;_cancellation=CancellationTokenSource.CreateLinkedTokenSource(token);
        CancelCommand=new RelayCommand(Cancel);
    }
    internal void Cancel(){lock(_lifetime){if(_ended==0)_cancellation.Cancel();}}
    public void Dispose()
    {
        lock(_lifetime){if(_ended!=0)return;_ended=1;}
        _owner.End(this);
        lock(_lifetime)_cancellation.Dispose();
    }
}
