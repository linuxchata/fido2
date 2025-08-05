using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Services;

/// <summary>
/// The interface representing the logic to parse Android Key attestation extension data.
/// </summary>
public interface IAndroidKeyAttestationExtensionParserService
{
    /// <summary>
    /// Parses Android Key attestation extension data.
    /// </summary>
    /// <param name="rawData">The raw byte array containing the Android Key attestation extension data.</param>
    /// <returns>The parsed Android Key attestation data if successful; otherwise, null.</returns>
    AndroidKeyAttestation? Parse(byte[] rawData);
}
