namespace Shark.Fido2.Domain;

/// <summary>
/// The credential's descriptor.
/// </summary>
public sealed class CredentialDescriptor
{
    /// <summary>
    /// Gets or sets the unique identifier of the credential.
    /// </summary>
    public required byte[] CredentialId { get; set; }

    /// <summary>
    /// Gets or sets the list of supported authenticator transports (e.g., "usb", "nfc", "ble").
    /// </summary>
    public string[]? Transports { get; set; }
}
