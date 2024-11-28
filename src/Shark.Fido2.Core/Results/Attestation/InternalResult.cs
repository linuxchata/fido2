namespace Shark.Fido2.Core.Results.Attestation
{
    public class InternalResult<T>
        where T : class
    {
        public T? Value { get; private set; }

        public string? Message { get; private set; }

        public bool HasError { get; private set; }

        public InternalResult(T value)
        {
            Value = value;
            HasError = false;
        }

        public InternalResult(string message)
        {
            Message = message;
            HasError = true;
        }
    }
}
