namespace Shark.Fido2.Domain.Options;

public sealed class PublicKeyCredentialCreationOptionsRequest
{
    public required string UserName { get; init; }

    public required string DisplayName { get; init; }

    public AuthenticatorSelectionCriteria? AuthenticatorSelection { get; init; }

    public string? Attestation { get; init; }
}
