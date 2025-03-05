using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain;

/// <summary>
/// 5.5. Options for Assertion Generation (dictionary PublicKeyCredentialRequestOptions)
/// https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options
/// </summary>
public sealed class PublicKeyCredentialRequestOptions
{
    public byte[] Challenge { get; set; } = null!;

    public ulong? Timeout { get; set; }

    public string? RpId { get; set; }

    public PublicKeyCredentialDescriptor[]? AllowCredentials { get; set; }

    public string? Username { get; set; }

    public UserVerificationRequirement? UserVerification { get; set; }
}
