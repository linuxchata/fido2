namespace Shark.Fido2.Domain;

/// <summary>
/// The credential.
/// </summary>
public sealed class Credential
{
    /// <summary>
    /// Gets or sets the unique identifier of the credential.
    /// </summary>
    public required byte[] CredentialId { get; set; }

    /// <summary>
    /// Gets or sets the user handle associated with the credential.
    /// </summary>
    public required byte[] UserHandle { get; set; }

    /// <summary>
    /// Gets or sets the username of the credential owner.
    /// </summary>
    public required string UserName { get; set; }

    /// <summary>
    /// Gets or sets the display name of the credential owner.
    /// </summary>
    public required string UserDisplayName { get; set; }

    /// <summary>
    /// Gets or sets the credential's public key.
    /// </summary>
    public required CredentialPublicKey CredentialPublicKey { get; set; }

    /// <summary>
    /// Gets or sets the authenticator’s signature counter.
    /// </summary>
    public uint SignCount { get; set; }

    /// <summary>
    /// Gets or sets the list of supported authenticator transports (e.g., "usb", "nfc", "ble").
    /// </summary>
    public string[]? Transports { get; set; }

    /// <summary>
    /// Gets or sets the timestamp when the credential was created.
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Gets or sets the timestamp when the credential was last updated.
    /// </summary>
    public DateTime? UpdatedAt { get; set; }

    /// <summary>
    /// Gets or sets the timestamp when the credential was last used.
    /// </summary>
    public DateTime? LastUsedAt { get; set; }
}
