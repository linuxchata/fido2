namespace Shark.Fido2.Domain;

/// <summary>
/// 5.2.2. Web Authentication Assertion (interface AuthenticatorAssertionResponse)
/// See: https://www.w3.org/TR/webauthn-2/#iface-authenticatorassertionresponse
/// </summary>
public sealed class AuthenticatorAssertionResponse
{
    public required string ClientDataJson { get; init; }

    public required string AuthenticatorData { get; init; }

    public required string Signature { get; init; }

    public string? UserHandle { get; init; }
}
