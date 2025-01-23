namespace Shark.Fido2.Domain;

public sealed class AuthenticatorAttestationResponse
{
    public string ClientDataJson { get; set; } = null!;

    public string AttestationObject { get; set; } = null!;

    public string? Signature { get; set; }

    public string? UserHandler { get; set; }
}