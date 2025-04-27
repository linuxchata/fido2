using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain.Options;

/// <summary>
/// 5.5. Options for Assertion Generation (dictionary PublicKeyCredentialRequestOptions)
/// https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options.
/// </summary>
public sealed class PublicKeyCredentialRequestOptions
{
    public required byte[] Challenge { get; init; }

    public ulong? Timeout { get; init; }

    public string? RpId { get; init; }

    public PublicKeyCredentialDescriptor[]? AllowCredentials { get; init; }

    public string? Username { get; init; }

    public UserVerificationRequirement? UserVerification { get; init; }

    public AuthenticationExtensionsClientInputs? Extensions { get; init; }
}
