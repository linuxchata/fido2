namespace Shark.Fido2.Domain;

public sealed class AssertionCompleteResult
{
    public string Status { get; set; } = null!;

    public string? Message { get; set; }

    public static AssertionCompleteResult Create()
    {
        return new AssertionCompleteResult { Status = "ok" };
    }

    public static AssertionCompleteResult CreateFailure(string message)
    {
        return new AssertionCompleteResult { Status = "failed", Message = message };
    }
}
