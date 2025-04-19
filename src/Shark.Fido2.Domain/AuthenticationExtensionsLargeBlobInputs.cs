namespace Shark.Fido2.Domain;

public sealed class AuthenticationExtensionsLargeBlobInputs
{
    public string? Support { get; init; }

    public bool? Read { get; init; }

    public byte[]? Write { get; init; }
}
