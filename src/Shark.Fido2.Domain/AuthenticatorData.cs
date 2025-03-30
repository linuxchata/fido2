namespace Shark.Fido2.Domain;

public sealed class AuthenticatorData
{
    /// <summary>
    /// Gets or sets SHA-256 hash of the RP ID the credential is scoped to.
    /// </summary>
    public byte[]? RpIdHash { get; set; }

    /// <summary>
    /// Gets or sets glags.
    /// </summary>
    public byte Flags { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether user is present.
    /// </summary>
    public bool UserPresent { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether user is verified.
    /// </summary>
    public bool UserVerified { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether an attested credential data included.
    /// </summary>
    public bool AttestedCredentialDataIncluded { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether extension data is included.
    /// </summary>
    public bool ExtensionDataIncluded { get; set; }

    /// <summary>
    /// Gets or sets a signature counter.
    /// </summary>
    public uint SignCount { get; set; }

    /// <summary>
    /// Gets or sets an attested credential data.
    /// </summary>
    public required AttestedCredentialData AttestedCredentialData { get; set; }

    public string Extensions { get; set; } = null!;
}
