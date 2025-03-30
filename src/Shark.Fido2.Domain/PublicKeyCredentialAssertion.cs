namespace Shark.Fido2.Domain;

/// <summary>
/// 5.1. PublicKeyCredential Interface
/// See: https://www.w3.org/TR/webauthn-2/#iface-pkcredential.
/// </summary>
public sealed class PublicKeyCredentialAssertion
{
    public required string Id { get; set; }

    public required string RawId { get; set; }

    public required AuthenticatorAssertionResponse Response { get; set; }

    public required string Type { get; set; }

    public required AuthenticationExtensionsClientOutputs Extensions { get; set; }
}
