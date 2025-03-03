namespace Shark.Fido2.Domain;

public sealed class AuthenticatorAssertionResponse
{
    public string ClientDataJson { get; set; } = null!;

    public string AuthenticatorData { get; set; } = null!;

    public string Signature { get; set; } = null!;

    public string? UserHandle { get; set; }
}
