using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain.Options;

public sealed class PublicKeyCredentialRequestOptionsRequest
{
    public string? Username { get; init; }

    public UserVerificationRequirement? UserVerification { get; init; }
}
