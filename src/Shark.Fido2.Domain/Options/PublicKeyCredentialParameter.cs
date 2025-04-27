using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain.Options;

public sealed class PublicKeyCredentialParameter
{
    public string Type { get; init; } = PublicKeyCredentialType.PublicKey;

    public PublicKeyAlgorithm Algorithm { get; init; }
}
