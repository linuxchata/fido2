namespace Shark.Fido2.Domain.Extensions;

public sealed class AuthenticationExtensionsLargeBlobOutputs
{
    public bool? Supported { get; init; }

    public byte[]? Blob { get; init; }

    public bool? Written { get; init; }
}
