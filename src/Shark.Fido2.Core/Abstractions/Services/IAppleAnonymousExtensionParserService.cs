namespace Shark.Fido2.Core.Abstractions.Services;

/// <summary>
/// The interface representing the logic to parse Apple Anonymous attestation extension data.
/// </summary>
public interface IAppleAnonymousExtensionParserService
{
    /// <summary>
    /// Parses Apple Anonymous attestation extension data.
    /// </summary>
    /// <param name="rawData">The raw byte array containing the Apple Anonymous attestation extension data.</param>
    /// <returns>The parsed nonce if successful; otherwise, null.</returns>
    byte[]? Parse(byte[] rawData);
}
