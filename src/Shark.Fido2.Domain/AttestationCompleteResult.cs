namespace Shark.Fido2.Domain;

public sealed class AttestationCompleteResult
{
    public bool IsValid { get; private set; }

    public string? Message { get; private set; }

    public static AttestationCompleteResult Create()
    {
        return new AttestationCompleteResult { IsValid = true };
    }

    public static AttestationCompleteResult CreateFailure(string message)
    {
        return new AttestationCompleteResult { IsValid = false, Message = message };
    }
}
