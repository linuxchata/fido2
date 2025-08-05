using Shark.Fido2.Domain.Tpm;

namespace Shark.Fido2.Core.Abstractions.Services;

/// <summary>
/// The interface representing the logic to parse TPM attestation data.
/// </summary>
public interface ITpmsAttestationParserService
{
    /// <summary>
    /// Parses TPM attestation data from certificate information bytes.
    /// </summary>
    /// <param name="certInfo">The raw byte array containing the TPM certificate information.</param>
    /// <param name="tpmsAttestation">The parsed TPM attestation structure if successful.</param>
    /// <returns>True if parsing was successful; otherwise, false.</returns>
    bool Parse(byte[] certInfo, out TpmsAttestation tpmsAttestation);
}
