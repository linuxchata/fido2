namespace Shark.Fido2.Domain;

public sealed class AssertionCompleteResult
{
    public bool IsValid { get; private set; }

    public string? Message { get; private set; }

    public static AssertionCompleteResult Create()
    {
        return new AssertionCompleteResult { IsValid = true };
    }

    public static AssertionCompleteResult CreateFailure(string message)
    {
        return new AssertionCompleteResult { IsValid = false, Message = message };
    }
}
