namespace Shark.Fido2.Domain;

public sealed class AuthenticationExtensionsClientInputs
{
    public string? AppId { get; init; }

    public string? AppIdExclude { get; init; }

    public bool? UserVerificationMethod { get; init; }

    public bool? CredentialProperties { get; init; }

    public AuthenticationExtensionsLargeBlobInputs? LargeBlob { get; init; }
}
