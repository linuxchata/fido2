namespace Shark.Fido2.Metadata.Domain.Constants;

/// <summary>
/// Authenticator attestation types
/// SeeL https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#authenticator-attestation-types
/// </summary>
public static class AttestationType
{
    public const string BasicFull = "basic_full";

    public const string BasicSurrogate = "basic_surrogate";

    public const string Ecdaa = "ecdaa";

    public const string Attca = "attca";
}
