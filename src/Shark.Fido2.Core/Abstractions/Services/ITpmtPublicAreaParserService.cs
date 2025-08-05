using Shark.Fido2.Domain.Tpm;

namespace Shark.Fido2.Core.Abstractions.Services;

/// <summary>
/// The interface representing the logic to parse TPM public area data.
/// </summary>
public interface ITpmtPublicAreaParserService
{
    /// <summary>
    /// Parses TPM public area data from raw bytes.
    /// </summary>
    /// <param name="pubArea">The raw byte array containing the TPM public area data.</param>
    /// <param name="tpmtPublic">The parsed TPM public area structure if successful.</param>
    /// <returns>True if parsing was successful; otherwise, false.</returns>
    bool Parse(byte[] pubArea, out TpmtPublic tpmtPublic);
}
