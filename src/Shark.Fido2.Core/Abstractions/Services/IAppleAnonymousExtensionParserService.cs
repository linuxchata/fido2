namespace Shark.Fido2.Core.Abstractions.Services;

/// <summary>
/// Apple Anonymous attestation extension parser service
/// </summary>
public interface IAppleAnonymousExtensionParserService
{
    /// <summary>
    /// Parses Apple Anonymous attestation extension data.
    /// </summary>
    /// <param name="rawData">Raw extension data.</param>
    /// <returns>Parsed extension data or null if parsing failed.</returns>
    byte[]? Parse(byte[] rawData);
}
