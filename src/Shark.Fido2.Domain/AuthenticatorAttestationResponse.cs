using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain;

/// <summary>
/// 5.2.1. Information About Public Key Credential (interface AuthenticatorAttestationResponse)
/// See: https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse.
/// </summary>
public sealed class AuthenticatorAttestationResponse
{
    public required string ClientDataJson { get; init; }

    public required string AttestationObject { get; init; }

    public required AuthenticatorTransport[] Transports { get; init; }
}