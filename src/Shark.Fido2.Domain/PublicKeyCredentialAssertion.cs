namespace Shark.Fido2.Domain;

public sealed class PublicKeyCredentialAssertion
{
    public string Id { get; set; } = null!;

    public string RawId { get; set; } = null!;

    public AuthenticatorAssertionResponse Response { get; set; } = null!;

    public string Type { get; set; } = null!;
}
