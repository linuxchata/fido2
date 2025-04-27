namespace Shark.Fido2.Domain.Options;

public sealed class PublicKeyCredentialCreationOptionsRequest
{
    public required string Username { get; init; }

    public required string DisplayName { get; init; }

    public AuthenticatorSelectionCriteria? AuthenticatorSelection { get; init; }

    public string? Attestation { get; init; }
}
