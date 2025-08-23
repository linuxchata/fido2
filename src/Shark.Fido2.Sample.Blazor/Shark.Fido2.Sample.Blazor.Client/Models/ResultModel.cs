namespace Shark.Fido2.Sample.Blazor.Client.Models;

public class ResultModel<T> where T : class
{
    public T? Result { get; init; }

    public string? Message { get; init; }

    public bool IsSuccess => Result is not null;

    public static ResultModel<T> Create(T? result)
    {
        return new() { Result = result };
    }

    public static ResultModel<T> CreateFailed(string message)
    {
        return new() { Message = message };
    }
}
