namespace Shark.Fido2.Sample.Blazor.Client.Models;

public class Response<T>
    where T : class
{
    public T? Result { get; init; }

    public string? Message { get; init; }

    public bool IsSuccess => Result is not null;

    public static Response<T> Create(T? result)
    {
        return new() { Result = result };
    }

    public static Response<T> CreateFailed(string message)
    {
        return new() { Message = message };
    }
}
