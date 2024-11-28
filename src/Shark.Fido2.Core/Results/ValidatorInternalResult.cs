namespace Shark.Fido2.Core.Results
{
    public class ValidatorInternalResult
    {
        public bool IsValid { get; private set; }

        public string? Message { get; private set; }

        public static ValidatorInternalResult Valid()
        {
            return new ValidatorInternalResult { IsValid = true };
        }

        public static ValidatorInternalResult Invalid(string message)
        {
            return new ValidatorInternalResult { IsValid = false, Message = message };
        }
    }
}
