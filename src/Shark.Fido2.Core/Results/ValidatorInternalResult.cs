namespace Shark.Fido2.Core.Results;

public class ValidatorInternalResult
{
    protected ValidatorInternalResult(bool isValid)
    {
        IsValid = isValid;
    }

    protected ValidatorInternalResult(bool isValid, string message)
    {
        IsValid = isValid;
        Message = message;
    }

    public bool IsValid { get; private set; }

    public string? Message { get; private set; }

    public static ValidatorInternalResult Valid()
    {
        return new ValidatorInternalResult(true);
    }

    public static ValidatorInternalResult Invalid(string message)
    {
        return new ValidatorInternalResult(false, message);
    }
}
