using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain;

/// <summary>
/// 5.8.3. Credential Descriptor (dictionary PublicKeyCredentialDescriptor)
/// https://www.w3.org/TR/webauthn-2/#dictionary-credential-descriptor
/// </summary>
public sealed class PublicKeyCredentialDescriptor
{
    public string Type { get; set; } = PublicKeyCredentialType.PublicKey;

    public byte[] Id { get; set; } = null!;

    public AuthenticatorTransport[]? Transports { get; set; }
}
