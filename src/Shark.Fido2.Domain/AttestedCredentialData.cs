namespace Shark.Fido2.Domain;

/// <summary>
/// Attested Credential Data.
/// </summary>
public sealed class AttestedCredentialData
{
    public AttestedCredentialData()
    {
        CredentialPublicKey = new CredentialPublicKey();
    }

    /// <summary>
    /// Gets or sets the authenticator attestation GUID.
    /// </summary>
    public Guid AaGuid { get; set; }

    /// <summary>
    /// Gets or sets the credential ID.
    /// </summary>
    public byte[]? CredentialId { get; set; }

    /// <summary>
    /// Gets or sets the credential public key.
    /// </summary>
    public CredentialPublicKey? CredentialPublicKey { get; set; }
}
