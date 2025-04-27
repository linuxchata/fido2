using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain.Options;

/// <summary>
/// 5.8.3. Credential Descriptor (dictionary PublicKeyCredentialDescriptor)
/// https://www.w3.org/TR/webauthn-2/#dictionary-credential-descriptor.
/// </summary>
public sealed class PublicKeyCredentialDescriptor
{
    public string Type { get; init; } = PublicKeyCredentialType.PublicKey;

    public required byte[] Id { get; init; }

    public AuthenticatorTransport[]? Transports { get; init; }
}
