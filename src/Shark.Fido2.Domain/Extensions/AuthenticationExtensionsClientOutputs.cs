namespace Shark.Fido2.Domain.Extensions;

public sealed class AuthenticationExtensionsClientOutputs
{
    public bool? AppId { get; init; }

    public bool? AppIdExclude { get; init; }

    public IEnumerable<ulong[]>? UserVerificationMethod { get; init; }

    public CredentialPropertiesOutput? CredentialProperties { get; init; }

    public AuthenticationExtensionsLargeBlobOutputs? LargeBlob { get; init; }
}
