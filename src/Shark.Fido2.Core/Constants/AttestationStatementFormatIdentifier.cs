namespace Shark.Fido2.Core.Constants;

/// <summary>
/// WebAuthn Attestation Statement Format Identifiers
/// https://www.iana.org/assignments/webauthn/webauthn.xhtml
/// </summary>
internal static class AttestationStatementFormatIdentifier
{
    /// <summary>
    /// The "packed" attestation statement format is a WebAuthn-optimized format for attestation. It uses a very
    /// compact but still extensible encoding method. This format is implementable by authenticators with limited
    /// resources (e.g., secure elements).
    /// </summary>
    public const string Packed = "packed";

    /// <summary>
    /// The TPM attestation statement format returns an attestation statement in the same format as the packed
    /// attestation statement format, although the rawData and signature fields are computed differently.
    /// </summary>
    public const string Tpm = "tpm";

    /// <summary>
    /// Platform authenticators on versions "N", and later, may provide this proprietary "hardware attestation"
    /// statement.
    /// </summary>
    public const string AndroidKey = "android-key";

    /// <summary>
    /// Android-based platform authenticators MAY produce an attestation statement based on the Android SafetyNet API.
    /// </summary>
    public const string AndroidSafetyNet = "android-safetynet";

    /// <summary>
    /// Used with FIDO U2F authenticators.
    /// </summary>
    public const string FidoU2f = "fido-u2f";

    /// <summary>
    /// Used with Apple devices' platform authenticators.
    /// </summary>
    public const string Apple = "apple";

    /// <summary>
    /// Used to replace any authenticator-provided attestation statement when a WebAuthn Relying Party indicates
    /// it does not wish to receive attestation information.
    /// </summary>
    public const string None = "none";

    public readonly static HashSet<string> Supported =
    [
        Packed, Tpm, AndroidKey, AndroidSafetyNet, FidoU2f, Apple, None
    ];
}
