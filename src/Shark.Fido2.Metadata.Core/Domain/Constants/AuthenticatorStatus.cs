namespace Shark.Fido2.Metadata.Core.Domain.Constants;

internal static class AuthenticatorStatus
{
    /// <summary>
    /// See: https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#info-statuses.
    /// </summary>
    public readonly static HashSet<string> IncreasedRisk =
    [
        "USER_VERIFICATION_BYPASS",
        "ATTESTATION_KEY_COMPROMISE",
        "USER_KEY_REMOTE_COMPROMISE",
        "USER_KEY_PHYSICAL_COMPROMISE",
        "REVOKED",
    ];
}
